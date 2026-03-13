// Core/TCP/TCPServer.cs
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.TCP;

namespace Toxcore.Core.TCP
{
    /// <summary>
    /// Servidor TCP para aceptar conexiones entrantes (modo relay).
    /// Traducción de TCP_server.c usando TCPCommon.
    /// </summary>
    public sealed class TCPServer : ITCPServer, IDisposable
    {
        public const int MaxIncomingConnections = 64;
        public const int TcpServerMaxConnections = 256;

        private readonly MonoTime _monoTime;
        private readonly byte[] _selfPublicKey;
        private readonly byte[] _selfSecretKey;

        private TcpListener _listener;
        private CancellationTokenSource _cts;
        private Task _acceptTask;
        private bool _running;

        // Conexiones entrantes activas
        private readonly ConcurrentDictionary<int, TCPConnectionState> _incomingConnections = new();
        private int _nextConnectionId = 1;

        public bool IsRunning => _running;
        public IPEndPoint LocalEndPoint => _listener?.LocalEndpoint as IPEndPoint;
        public int ConnectionCount => _incomingConnections.Count;

        public event Action<int, IPEndPoint> OnClientConnected;
        public event Action<int, byte[]> OnDataReceived;
        public event Action<int> OnClientDisconnected;

        public TCPServer(
            MonoTime monoTime,
            byte[] selfPublicKey,
            byte[] selfSecretKey)
        {
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));
            _selfSecretKey = selfSecretKey ?? throw new ArgumentNullException(nameof(selfSecretKey));
        }

        public bool Start(IPAddress bindAddress, ushort port)
        {
            try
            {
                _listener = new TcpListener(bindAddress, port);
                _listener.Start();
                _running = true;

                _cts = new CancellationTokenSource();
                _acceptTask = AcceptLoop(_cts.Token);

                Logger.Log.Info($"[TCPServer] Started on {bindAddress}:{port}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPServer] Failed to start: {ex.Message}");
                return false;
            }
        }

        private async Task AcceptLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    var endpoint = tcpClient.Client.RemoteEndPoint as IPEndPoint;

                    if (_incomingConnections.Count >= MaxIncomingConnections)
                    {
                        Logger.Log.Warning($"[TCPServer] Max connections reached, rejecting {endpoint}");
                        tcpClient.Close();
                        continue;
                    }

                    Logger.Log.Info($"[TCPServer] Client connected from {endpoint}");

                    // Crear estado de conexión
                    int connId = Interlocked.Increment(ref _nextConnectionId);
                    var conState = new TCPConnectionState
                    {
                        Sock = tcpClient.Client,
                        IpPort = endpoint
                    };

                    _incomingConnections[connId] = conState;

                    // Iniciar handshake en background
                    _ = HandleIncomingConnectionAsync(connId, tcpClient, endpoint, ct);

                    OnClientConnected?.Invoke(connId, endpoint);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[TCPServer] Accept error: {ex.Message}");
                    await Task.Delay(1000, ct);
                }
            }
        }

        private async Task HandleIncomingConnectionAsync(int connId, TcpClient tcpClient, IPEndPoint endpoint, CancellationToken ct)
        {
            try
            {
                // Recibir handshake del cliente
                if (!ProcessClientHandshake(connId))
                {
                    Logger.Log.Error($"[TCPServer] Handshake failed for {endpoint}");
                    DisconnectClient(connId);
                    return;
                }

                Logger.Log.Info($"[TCPServer] Handshake completed for {endpoint}");

                // Iniciar bucle de recepción
                await ReceiveLoopAsync(connId, ct);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPServer] Handler error for {endpoint}: {ex.Message}");
                DisconnectClient(connId);
            }
        }

        /// <summary>
        /// Procesa handshake entrante de cliente.
        /// Formato esperado: [ephemeral_public(32)][nonce(24)][encrypted_data]
        /// </summary>
        private bool ProcessClientHandshake(int connId)
        {
            if (!_incomingConnections.TryGetValue(connId, out var conState))
                return false;

            try
            {
                // Leer handshake completo
                var handshakeBuf = new byte[TCPCommon.TcpClientHandshakeSize];
                int read = conState.Sock.Receive(handshakeBuf);
                if (read != TCPCommon.TcpClientHandshakeSize)
                    return false;

                // Extraer componentes
                var ephemeralPublic = handshakeBuf.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
                var sentNonce = handshakeBuf.AsSpan(LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
                var cipher = handshakeBuf.AsSpan(LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

                // Derivar shared key: ephemeral_public + self_secret
                if (!LibSodium.TryCryptoBoxBeforeNm(conState.SharedKey, ephemeralPublic, _selfSecretKey))
                    return false;

                // Descifrar
                var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, sentNonce, conState.SharedKey))
                    return false;

                // Extraer public key permanente del cliente
                var clientPublicKey = plain.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();

                // Guardar nonce de envío (para respuestas)
                Buffer.BlockCopy(sentNonce, 0, conState.SentNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

                // Generar nonce de recepción (para recibir del cliente)
                var recvNonce = LibSodium.GenerateNonce();

                // Enviar respuesta de handshake usando TCPCommon
                if (!SendServerHandshakeResponse(conState, clientPublicKey, recvNonce))
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPServer] Process handshake failed: {ex.Message}");
                return false;
            }
        }

        private bool SendServerHandshakeResponse(TCPConnectionState conState, byte[] clientPublicKey, byte[] recvNonce)
        {
            try
            {
                // Datos a cifrar: [public_key_permanente(32)][nonce_recepcion(24)]
                var plain = new byte[TCPCommon.TcpHandshakePlainSize];
                Buffer.BlockCopy(_selfPublicKey, 0, plain, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(recvNonce, 0, plain, LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

                // Cifrar con sentNonce
                var cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, conState.SentNonce, conState.SharedKey))
                    return false;

                // Construir paquete: [nonce(24)][cipher]
                var packet = new byte[TCPCommon.TcpServerHandshakeSize];
                Buffer.BlockCopy(conState.SentNonce, 0, packet, 2, LibSodium.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(cipher, 0, packet, 2 + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

                // Escribir longitud al inicio (big-endian)
                packet[0] = (byte)((packet.Length - 2) >> 8);
                packet[1] = (byte)((packet.Length - 2) & 0xFF);

                // Enviar
                return conState.Sock.Send(packet) == packet.Length;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPServer] Send handshake response failed: {ex.Message}");
                return false;
            }
        }

        private async Task ReceiveLoopAsync(int connId, CancellationToken ct)
        {
            if (!_incomingConnections.TryGetValue(connId, out var conState))
                return;

            var recvNonce = new byte[LibSodium.CRYPTO_NONCE_SIZE];
            ushort nextPacketLength = 0;

            while (!ct.IsCancellationRequested && _running)
            {
                try
                {
                    var buffer = new byte[TCPCommon.MaxPacketSize];
                    int len = TCPConnectionHandler.ReadPacketTcpSecureConnection(
                        conState.Sock,
                        ref nextPacketLength,
                        conState.SharedKey,
                        recvNonce,
                        buffer,
                        (ushort)buffer.Length,
                        conState.IpPort);

                    if (len == -1)
                    {
                        Logger.Log.Error($"[TCPServer] Read error for {conState.IpPort}");
                        break;
                    }

                    if (len == 0)
                    {
                        await Task.Delay(10, ct);
                        continue;
                    }

                    OnDataReceived?.Invoke(connId, buffer.AsSpan(0, len).ToArray());
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[TCPServer] Receive error for {conState.IpPort}: {ex.Message}");
                    break;
                }
            }

            DisconnectClient(connId);
        }

        public bool WritePacket(int connId, ReadOnlySpan<byte> data, bool priority)
        {
            if (!_incomingConnections.TryGetValue(connId, out var conState))
                return false;

            return TCPConnectionHandler.WritePacketTcpSecureConnection(
                conState,
                data,
                (ushort)data.Length,
                priority) == 1;
        }

        public void DisconnectClient(int connId)
        {
            if (_incomingConnections.TryRemove(connId, out var conState))
            {
                // Limpiar colas
                TCPConnectionHandler.WipePriorityList(conState.PriorityQueueStart);

                // Limpiar secrets
                CryptographicOperations.ZeroMemory(conState.SharedKey);

                try
                {
                    conState.Sock?.Close();
                }
                catch { }

                OnClientDisconnected?.Invoke(connId);
                Logger.Log.Info($"[TCPServer] Client {connId} disconnected");
            }
        }

        public void Stop()
        {
            _running = false;
            _cts?.Cancel();

            foreach (var connId in _incomingConnections.Keys)
            {
                DisconnectClient(connId);
            }

            _listener?.Stop();
            Logger.Log.Info("[TCPServer] Stopped");
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
            _acceptTask?.Wait(TimeSpan.FromSeconds(2));
        }
    }
}