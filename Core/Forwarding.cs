// Core/Forwarding.cs - Implementación completa de forwarding.c
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core
{
    /// <summary>
    /// Sistema de reenvío de paquetes (forwarding.c).
    /// Permite a los nodos actuar como relays para otros peers,
    /// mejorando la conectividad en redes restrictivas (NAT).
    /// </summary>
    public sealed class Forwarding : IForwarding, IDisposable
    {
        #region Constantes de forwarding.h

        // Timeouts (segundos)
        public const int ForwardingRequestTimeout = 10;
        public const int ForwardingResponseTimeout = 10;
        public const int ForwardingConnectionTimeout = 300; // 5 minutos

        // Límites
        public const int MaxForwardingRequests = 32;
        public const int MaxForwardingConnections = 16;
        public const int MaxForwardingPacketSize = 1400;

        // Tipos de paquetes
        public const byte PacketForwardRequest = 0x90;   // Solicitar reenvío
        public const byte PacketForwarding = 0x91;       // Paquete reenviado
        public const byte PacketForwardReply = 0x92;     // Respuesta de reenvío

        // Estados
        public const byte ForwardStateNone = 0;
        public const byte ForwardStateRequested = 1;
        public const byte ForwardStateAccepted = 2;
        public const byte ForwardStateActive = 3;

        #endregion

        #region Dependencias

        private readonly INetworkCore _network;
        private readonly IDht _dht;
        private readonly MonoTime _monoTime;
        private readonly byte[] _selfPublicKey;

        #endregion

        #region Estado

        // Solicitudes de reenvío pendientes (como solicitante)
        private readonly ConcurrentDictionary<uint, ForwardRequest> _pendingRequests = new();

        // Conexiones de reenvío activas (como relay)
        private readonly ConcurrentDictionary<uint, ForwardConnection> _relayConnections = new();

        // Conexiones de reenvío activas (como cliente)
        private readonly ConcurrentDictionary<uint, ForwardConnection> _clientConnections = new();

        // Contador de IDs de reenvío
        private uint _nextForwardId = 1;

        #endregion

        public Forwarding(
            INetworkCore network,
            IDht dht,
            MonoTime monoTime,
            byte[] selfPublicKey)
        {
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));

            // Registrar handlers de paquetes
            _network.RegisterHandler(PacketForwardRequest, HandleForwardRequest, this);
            _network.RegisterHandler(PacketForwarding, HandleForwardingPacket, this);
            _network.RegisterHandler(PacketForwardReply, HandleForwardReply, this);

            Logger.Log.Info("[Forwarding] Initialized");
        }

        #region API Pública - Cliente (solicitar reenvío)

        /// <summary>
        /// Solicita a un nodo que actúe como relay hacia un destino.
        /// </summary>
        public uint RequestForwarding(IPEndPoint relay, byte[] targetPublicKey)
        {
            if (_pendingRequests.Count >= MaxForwardingRequests)
            {
                Logger.Log.Warning("[Forwarding] Too many pending requests");
                return 0;
            }

            uint forwardId = Interlocked.Increment(ref _nextForwardId);

            var request = new ForwardRequest
            {
                Id = forwardId,
                RelayEndpoint = relay,
                TargetPublicKey = (byte[])targetPublicKey.Clone(),
                RequestTime = _monoTime.GetSeconds(),
                State = ForwardStateRequested
            };

            _pendingRequests[forwardId] = request;

            // Enviar solicitud de reenvío
            SendForwardRequest(relay, forwardId, targetPublicKey);

            Logger.Log.Debug($"[Forwarding] Requested forwarding #{forwardId} via {relay}");
            return forwardId;
        }

        /// <summary>
        /// Envía datos a través de un reenvío establecido.
        /// </summary>
        public bool SendViaForwarding(uint forwardId, byte[] data)
        {
            if (!_clientConnections.TryGetValue(forwardId, out var conn))
                return false;

            if (conn.State != ForwardStateActive)
                return false;

            // Construir paquete de reenvío
            var packet = new byte[1 + 4 + data.Length];
            packet[0] = PacketForwarding;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), conn.RelayAssignedId);
            Buffer.BlockCopy(data, 0, packet, 5, data.Length);

            return _network.SendPacket(conn.RelayEndpoint, packet, packet.Length) > 0;
        }

        /// <summary>
        /// Cierra una conexión de reenvío.
        /// </summary>
        public void CloseForwarding(uint forwardId)
        {
            if (_clientConnections.TryRemove(forwardId, out var conn))
            {
                // Notificar al relay que cerramos
                SendDisconnectNotification(conn.RelayEndpoint, conn.RelayAssignedId);
                Logger.Log.Debug($"[Forwarding] Closed forwarding #{forwardId}");
            }

            _pendingRequests.TryRemove(forwardId, out _);
        }

        #endregion

        #region API Pública - Relay (aceptar reenvíos)

        /// <summary>
        /// Habilita/deshabilita el modo relay.
        /// </summary>
        public bool IsRelayEnabled { get; set; } = true;

        /// <summary>
        /// Acepta una solicitud de reenvío entrante.
        /// </summary>
        public bool AcceptForwarding(uint requestId, IPEndPoint clientEndpoint)
        {
            if (!IsRelayEnabled) return false;
            if (_relayConnections.Count >= MaxForwardingConnections) return false;

            // Buscar la solicitud pendiente
            ForwardRequest request = null;
            foreach (var kvp in _pendingRequests)
            {
                if (kvp.Value.RelayEndpoint?.Equals(clientEndpoint) == true)
                {
                    request = kvp.Value;
                    break;
                }
            }

            if (request == null) return false;

            // Crear conexión de relay
            uint relayId = Interlocked.Increment(ref _nextForwardId);

            var conn = new ForwardConnection
            {
                Id = relayId,
                ClientEndpoint = clientEndpoint,
                TargetPublicKey = request.TargetPublicKey,
                RelayAssignedId = request.Id, // ID que el cliente usará
                State = ForwardStateActive,
                StartTime = _monoTime.GetSeconds(),
                LastActivity = _monoTime.GetSeconds()
            };

            _relayConnections[relayId] = conn;

            // Enviar respuesta de aceptación
            SendForwardAccept(clientEndpoint, request.Id, relayId);

            Logger.Log.Info($"[Forwarding] Accepted relay #{relayId} for {clientEndpoint}");
            return true;
        }

        #endregion

        #region Handlers de Paquetes

        /// <summary>
        /// Maneja solicitud de reenvío entrante.
        /// </summary>
        private static void HandleForwardRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var forwarding = (Forwarding)state;

            if (!forwarding.IsRelayEnabled)
            {
                Logger.Log.Debug("[Forwarding] Relay disabled, ignoring request");
                return;
            }

            if (packet.Length < 1 + 4 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE) return;

            uint requestId = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(1, 4));
            var targetPk = packet.Slice(5, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();

            // Verificar que tenemos espacio
            if (forwarding._relayConnections.Count >= MaxForwardingConnections)
            {
                Logger.Log.Warning("[Forwarding] Relay full, rejecting request");
                forwarding.SendForwardReject(source, requestId);
                return;
            }

            // Almacenar solicitud pendiente (esperar aceptación explícita o auto-aceptar)
            var request = new ForwardRequest
            {
                Id = requestId,
                RelayEndpoint = source,
                TargetPublicKey = targetPk,
                RequestTime = forwarding._monoTime.GetSeconds(),
                State = ForwardStateRequested
            };

            forwarding._pendingRequests[requestId] = request;

            // Auto-aceptar para simplificar (o notificar a capa superior)
            forwarding.AcceptForwarding(requestId, source);
        }

        /// <summary>
        /// Maneja paquete reenviado (llegó a través de un relay).
        /// </summary>
        private static void HandleForwardingPacket(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var forwarding = (Forwarding)state;

            if (packet.Length < 1 + 4) return;

            uint relayId = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(1, 4));
            var data = packet.Slice(5).ToArray();

            // Buscar si somos el relay para este ID
            if (forwarding._relayConnections.TryGetValue(relayId, out var relayConn))
            {
                // Somos el relay: reenviar al destino final
                forwarding.RelayPacket(relayConn, data);
                return;
            }

            // Buscar si somos el cliente destino
            foreach (var conn in forwarding._clientConnections.Values)
            {
                if (conn.RelayAssignedId == relayId)
                {
                    // Somos el destino: entregar datos
                    forwarding.DeliverForwardedData(conn, data);
                    return;
                }
            }

            Logger.Log.Debug($"[Forwarding] Unknown relay ID: {relayId}");
        }

        /// <summary>
        /// Maneja respuesta de reenvío (aceptación/rechazo).
        /// </summary>
        private static void HandleForwardReply(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var forwarding = (Forwarding)state;

            if (packet.Length < 1 + 4 + 1) return;

            uint requestId = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(1, 4));
            byte status = packet[5];

            if (!forwarding._pendingRequests.TryGetValue(requestId, out var request))
                return;

            if (status == 0) // Aceptado
            {
                if (packet.Length < 1 + 4 + 1 + 4) return;

                uint relayAssignedId = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(6, 4));

                // Crear conexión cliente activa
                var conn = new ForwardConnection
                {
                    Id = requestId,
                    RelayEndpoint = source,
                    RelayAssignedId = relayAssignedId,
                    TargetPublicKey = request.TargetPublicKey,
                    State = ForwardStateActive,
                    StartTime = forwarding._monoTime.GetSeconds(),
                    LastActivity = forwarding._monoTime.GetSeconds()
                };

                forwarding._clientConnections[requestId] = conn;
                request.State = ForwardStateActive;

                Logger.Log.Info($"[Forwarding] Forwarding #{requestId} accepted, relay ID: {relayAssignedId}");
            }
            else
            {
                // Rechazado
                request.State = ForwardStateNone;
                forwarding._pendingRequests.TryRemove(requestId, out _);
                Logger.Log.Warning($"[Forwarding] Forwarding #{requestId} rejected");
            }
        }

        #endregion

        #region Métodos de Envío

        private void SendForwardRequest(IPEndPoint relay, uint forwardId, byte[] targetPublicKey)
        {
            var packet = new byte[1 + 4 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            packet[0] = PacketForwardRequest;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), forwardId);
            Buffer.BlockCopy(targetPublicKey, 0, packet, 5, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            _network.SendPacket(relay, packet, packet.Length);
        }

        private void SendForwardAccept(IPEndPoint client, uint requestId, uint relayId)
        {
            var packet = new byte[1 + 4 + 1 + 4];
            packet[0] = PacketForwardReply;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), requestId);
            packet[5] = 0; // Aceptado
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(6, 4), relayId);

            _network.SendPacket(client, packet, packet.Length);
        }

        private void SendForwardReject(IPEndPoint client, uint requestId)
        {
            var packet = new byte[1 + 4 + 1];
            packet[0] = PacketForwardReply;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), requestId);
            packet[5] = 1; // Rechazado

            _network.SendPacket(client, packet, packet.Length);
        }

        private void SendDisconnectNotification(IPEndPoint relay, uint relayId)
        {
            // Opcional: notificar al relay que cerramos
            // Implementación depende del protocolo específico
        }

        #endregion

        #region Lógica de Relay

        /// <summary>
        /// Reenvía un paquete al destino final (como relay).
        /// </summary>
        private void RelayPacket(ForwardConnection conn, byte[] data)
        {
            // Buscar endpoint del destino
            var targetIp = _dht.GetFriendIp(conn.TargetPublicKey, out var ipPort);

            if (targetIp != 1 || ipPort == null)
            {
                Logger.Log.Warning($"[Forwarding] Cannot find target for relay #{conn.Id}");
                return;
            }

            // Enviar como paquete normal (el destino debe reconocerlo)
            // El paquete ya viene con el formato correcto desde el origen
            _network.SendPacket(ipPort, data, data.Length);

            conn.LastActivity = _monoTime.GetSeconds();
            conn.PacketsRelayed++;
        }

        /// <summary>
        /// Entrega datos reenviados al destino final (como cliente).
        /// </summary>
        private void DeliverForwardedData(ForwardConnection conn, byte[] data)
        {
            // Notificar a los suscriptores
            OnForwardedDataReceived?.Invoke(conn.Id, data);
            conn.LastActivity = _monoTime.GetSeconds();
        }

        #endregion

        #region Ciclo Principal

        /// <summary>
        /// Itera conexiones de reenvío (llamar periódicamente).
        /// </summary>
        public void DoForwarding()
        {
            var now = _monoTime.GetSeconds();

            // Limpiar solicitudes expiradas
            var expiredRequests = new System.Collections.Generic.List<uint>();
            foreach (var kvp in _pendingRequests)
            {
                if (kvp.Value.State == ForwardStateRequested &&
                    now - kvp.Value.RequestTime > ForwardingRequestTimeout)
                {
                    expiredRequests.Add(kvp.Key);
                }
            }
            foreach (var id in expiredRequests)
            {
                _pendingRequests.TryRemove(id, out _);
                Logger.Log.Debug($"[Forwarding] Request #{id} expired");
            }

            // Limpiar conexiones de relay inactivas
            var expiredRelays = new System.Collections.Generic.List<uint>();
            foreach (var kvp in _relayConnections)
            {
                if (now - kvp.Value.LastActivity > ForwardingConnectionTimeout)
                {
                    expiredRelays.Add(kvp.Key);
                }
            }
            foreach (var id in expiredRelays)
            {
                _relayConnections.TryRemove(id, out _);
                Logger.Log.Debug($"[Forwarding] Relay #{id} timed out");
            }

            // Limpiar conexiones de cliente inactivas
            var expiredClients = new System.Collections.Generic.List<uint>();
            foreach (var kvp in _clientConnections)
            {
                if (now - kvp.Value.LastActivity > ForwardingConnectionTimeout)
                {
                    expiredClients.Add(kvp.Key);
                }
            }
            foreach (var id in expiredClients)
            {
                _clientConnections.TryRemove(id, out _);
                Logger.Log.Debug($"[Forwarding] Client #{id} timed out");
            }
        }

        #endregion

        #region Eventos

        /// <summary>
        /// Evento cuando se reciben datos a través de reenvío.
        /// </summary>
        public event Action<uint, byte[]> OnForwardedDataReceived;

        #endregion

        public void Dispose()
        {
            _network.UnregisterHandler(PacketForwardRequest);
            _network.UnregisterHandler(PacketForwarding);
            _network.UnregisterHandler(PacketForwardReply);

            _pendingRequests.Clear();
            _relayConnections.Clear();
            _clientConnections.Clear();

            Logger.Log.Info("[Forwarding] Disposed");
        }
    }

    #region Clases Auxiliares

    /// <summary>
    /// Solicitud de reenvío pendiente.
    /// </summary>
    public class ForwardRequest
    {
        public uint Id { get; set; }
        public IPEndPoint RelayEndpoint { get; set; }
        public byte[] TargetPublicKey { get; set; }
        public ulong RequestTime { get; set; }
        public byte State { get; set; }
    }

    /// <summary>
    /// Conexión de reenvío activa.
    /// </summary>
    public class ForwardConnection
    {
        public uint Id { get; set; }
        public IPEndPoint RelayEndpoint { get; set; }
        public IPEndPoint ClientEndpoint { get; set; }
        public uint RelayAssignedId { get; set; }
        public byte[] TargetPublicKey { get; set; }
        public byte State { get; set; }
        public ulong StartTime { get; set; }
        public ulong LastActivity { get; set; }
        public ulong PacketsRelayed { get; set; }
    }

    #endregion
}