// Core/TCP/TCPConnection.cs
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.TCP;

namespace Toxcore.Core.TCP
{
    /// <summary>
    /// Gestiona múltiples conexiones TCP (cliente y servidor).
    /// Traducción de TCP_connection.c usando TCPCommon.
    /// </summary>
    public sealed class TCPConnection : ITCPConnection, IDisposable
    {
        public const int MaxTcpConnections = 64;
        public const int TcpConnectionTimeout = 10;

        private readonly ConcurrentDictionary<int, TCPClient> _connections = new();
        private readonly ConcurrentDictionary<IPEndPoint, int> _endpointToId = new();

        private readonly MonoTime _monoTime;
        private readonly byte[] _selfPublicKey;
        private readonly byte[] _selfSecretKey;

        private TcpListener _listener; // Si actúa como servidor
        private ushort? _listeningPort;
        private bool _isListening;  // CORRECCIÓN: Trackear estado manualmente

        private int _nextConnectionId = 1;
        private bool _disposed;

        private const int TcpKeepaliveInterval = 30; // segundos
        private ulong _lastKeepaliveTime;


        public int ConnectionCount => _connections.Count;

        public event Action<int, byte[]> OnDataReceived;
        public event Action<int> OnConnected;
        public event Action<int> OnDisconnected;

        public TCPConnection(
            MonoTime monoTime,
            byte[] selfPublicKey,
            byte[] selfSecretKey)
        {
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));
            _selfSecretKey = selfSecretKey ?? throw new ArgumentNullException(nameof(selfSecretKey));
        }

        // CORRECCIÓN: Implementación sin usar TcpListener.Active
        public ushort? ListeningPort => _listeningPort;
        public bool IsListening => _isListening && _listener != null;  // Usar flag 

        public bool StartListening(ushort port)
        {
            try
            {
                _listener = new TcpListener(IPAddress.Any, port);
                _listener.Start();
                _listeningPort = port;
                _isListening = true;  // CORRECCIÓN: Marcar como escuchando
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCP] Failed to start listening on port {port}: {ex.Message}");
                _isListening = false;
                return false;
            }
        }

        // Método para detener servidor
        public void StopListening()
        {
            try
            {
                _isListening = false;  // CORRECCIÓN: Marcar primero
                _listener?.Stop();
                _listener = null;
                _listeningPort = null;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCP] Error stopping listener: {ex.Message}");
            }
        }

        public async Task<int> NewConnectionAsync(IPEndPoint relayEndpoint, byte[] relayPublicKey)
        {
            if (_connections.Count >= MaxTcpConnections)
            {
                Logger.Log.Warning("[TCPConnection] Max connections reached");
                return -1;
            }

            var client = new TCPClient(_monoTime, _selfPublicKey, _selfSecretKey);
            int connectionId = Interlocked.Increment(ref _nextConnectionId);

            client.OnConnected += () => OnConnected?.Invoke(connectionId);
            client.OnDisconnected += () =>
            {
                OnDisconnected?.Invoke(connectionId);
                RemoveConnection(connectionId);
            };
            client.OnDataReceived += data => OnDataReceived?.Invoke(connectionId, data);

            if (await client.ConnectAsync(relayEndpoint, relayPublicKey))
            {
                _connections[connectionId] = client;
                _endpointToId[relayEndpoint] = connectionId;
                return connectionId;
            }

            client.Dispose();
            return -1;
        }

        public bool SendData(int connectionId, byte[] data)
        {
            if (_connections.TryGetValue(connectionId, out var client))
            {
                return client.WritePacket(data, false);
            }
            return false;
        }

        public bool SendDataPriority(int connectionId, byte[] data)
        {
            if (_connections.TryGetValue(connectionId, out var client))
            {
                return client.WritePacket(data, true);
            }
            return false;
        }

        public byte GetConnectionStatus(int connectionId)
        {
            if (_connections.TryGetValue(connectionId, out var client))
            {
                return client.Status;
            }
            return 0;
        }

        public void KillConnection(int connectionId)
        {
            if (_connections.TryRemove(connectionId, out var client))
            {
                if (_endpointToId.TryGetValue(client.RemoteEndPoint, out _))
                {
                    _endpointToId.TryRemove(client.RemoteEndPoint, out _);
                }
                client.Disconnect();
                client.Dispose();
            }
        }

        private void RemoveConnection(int connectionId)
        {
            _connections.TryRemove(connectionId, out _);
        }

        public void DoTcp()
        {
            var now = _monoTime.GetSeconds();

            foreach (var kvp in _connections)
            {
                var client = kvp.Value;

                // Verificar timeouts
                if (client.Status == TCPClient.TcpClientConnected)
                {
                    // Enviar keepalive periódicamente
                    if (now - _lastKeepaliveTime > TcpKeepaliveInterval)
                    {
                        SendKeepalive(kvp.Key);
                        _lastKeepaliveTime = now;
                    }
                }

                if (!client.IsConnected && client.Status == TCPClient.TcpClientDisconnected)
                {
                    OnDisconnected?.Invoke(kvp.Key);
                    RemoveConnection(kvp.Key);
                }
            }
        }

        private void SendKeepalive(int connectionId)
        {
            if (_connections.TryGetValue(connectionId, out var client))
            {
                // Enviar paquete de ping TCP (tipo 0x01 según protocolo Tox TCP)
                var pingPacket = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 }; // Ping request ID = 0
                client.WritePacket(pingPacket, false);
                Logger.Log.Debug($"[TCP] Sent keepalive to connection {connectionId}");
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            StopListening();

            foreach (var client in _connections.Values)
            {
                client.Disconnect();
                client.Dispose();
            }
            _connections.Clear();
            _endpointToId.Clear();
        }
    }
}