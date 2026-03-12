// Core/Announce.cs - Implementación completa de announce.c
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using Toxcore.Core.Crypto;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Sistema de anuncio de presencia en DHT (announce.c).
    /// Permite a los nodos anunciarse para ser encontrados por sus amigos.
    /// Distinto a OnionAnnounce: este es para el DHT global, no onion routing.
    /// </summary>
    public sealed class Announce : IAnnounce, IDisposable
    {
        #region Constantes de announce.h

        // Timeouts (segundos)
        public const int AnnounceInterval = 20;           // Intervalo entre anuncios
        public const int AnnounceTimeout = 10;              // Timeout de solicitud
        public const int AnnouncePeerTimeout = 300;         // 5 minutos
        public const int AnnounceSelfTimeout = 600;        // 10 minutos

        // Límites
        public const int MaxAnnouncePeers = 64;
        public const int MaxStoredAnnounces = 128;
        public const int MaxDataSize = 1024;

        // Tamaños de paquetes
        public const int AnnouncePacketSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + (4 + 4 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_MAC_SIZE);
        public const int AnnounceResponseSize = 1 + LibSodium.CRYPTO_NONCE_SIZE + (4 + 4 + LibSodium.CRYPTO_MAC_SIZE);

        // Tipos de paquetes
        public const byte PacketAnnounceRequest = 0x93;     // Solicitar anuncio
        public const byte PacketAnnounceResponse = 0x94;    // Respuesta de anuncio
        public const byte PacketDataRequest = 0x95;         // Solicitar datos
        public const byte PacketDataResponse = 0x96;        // Respuesta con datos

        // Estados
        public const byte AnnounceStatusNone = 0;
        public const byte AnnounceStatusSent = 1;
        public const byte AnnounceStatusConfirmed = 2;

        #endregion

        #region Dependencias

        private readonly INetworkCore _network;
        private readonly IDht _dht;
        private readonly IForwarding _forwarding;
        private readonly MonoTime _monoTime;
        private readonly byte[] _selfPublicKey;
        private readonly byte[] _selfSecretKey;

        #endregion

        #region Estado

        // Anuncios de otros peers que almacenamos
        private readonly ConcurrentDictionary<byte[], StoredAnnounce> _storedAnnounces = new(ByteArrayComparer.Instance);

        // Nuestros propios anuncios pendientes/activos
        private readonly ConcurrentDictionary<uint, SelfAnnounce> _selfAnnounces = new();

        // Peers a los que nos hemos anunciado (para reenvío de búsquedas)
        private readonly ConcurrentDictionary<byte[], AnnouncedPeer> _announcedPeers = new(ByteArrayComparer.Instance);

        // Datos asociados a nuestro anuncio (nombre, status, etc.)
        private byte[] _selfAnnounceData = Array.Empty<byte>();
        private ulong _lastSelfAnnounceTime;
        private uint _selfAnnounceCounter;

        #endregion

        public Announce(
            INetworkCore network,
            IDht dht,
            IForwarding forwarding,
            MonoTime monoTime,
            byte[] selfPublicKey,
            byte[] selfSecretKey)
        {
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _forwarding = forwarding;
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));
            _selfSecretKey = selfSecretKey ?? throw new ArgumentNullException(nameof(selfSecretKey));

            // Registrar handlers
            _network.RegisterHandler(PacketAnnounceRequest, HandleAnnounceRequest, this);
            _network.RegisterHandler(PacketAnnounceResponse, HandleAnnounceResponse, this);
            _network.RegisterHandler(PacketDataRequest, HandleDataRequest, this);
            _network.RegisterHandler(PacketDataResponse, HandleDataResponse, this);

            Logger.Log.Info("[Announce] Initialized");
        }

        #region API Pública - Auto-anuncio

        /// <summary>
        /// Establece los datos a anunciar (nombre, status, etc.).
        /// </summary>
        public void SetSelfData(byte[] data)
        {
            _selfAnnounceData = data ?? Array.Empty<byte>();
            if (_selfAnnounceData.Length > MaxDataSize)
            {
                Array.Resize(ref _selfAnnounceData, MaxDataSize);
            }
        }

        /// <summary>
        /// Inicia el proceso de auto-anuncio en la red.
        /// </summary>
        public void StartSelfAnnounce()
        {
            var now = _monoTime.GetSeconds();

            // No anunciar demasiado frecuentemente
            if (now - _lastSelfAnnounceTime < AnnounceInterval)
                return;

            _lastSelfAnnounceTime = now;
            _selfAnnounceCounter++;

            // Obtener nodos cercanos para anunciarnos
            var closeNodes = new NodeFormat[8];
            int numNodes = _dht.GetCloseNodes(_selfPublicKey, closeNodes, null, false, false);

            Logger.Log.Info($"[Announce] Starting self-announce to {numNodes} close nodes");

            // Anunciarnos a cada nodo cercano
            for (int i = 0; i < numNodes; i++)
            {
                var node = closeNodes[i];
                if (node.PublicKey == null || node.IpPort == null) continue;

                // Verificar si ya nos anunciamos recientemente a este nodo
                if (_announcedPeers.TryGetValue(node.PublicKey, out var peer))
                {
                    if (now - peer.LastAnnounce < AnnounceInterval)
                        continue;
                }

                SendAnnounceRequest(node.IpPort, node.PublicKey, _selfAnnounceData);
            }
        }

        /// <summary>
        /// Busca un peer por su clave pública.
        /// </summary>
        public bool SearchPeer(byte[] publicKey, out IPEndPoint endpoint, out byte[] data)
        {
            endpoint = null;
            data = null;

            // Primero buscar en anuncios almacenados localmente
            if (_storedAnnounces.TryGetValue(publicKey, out var stored))
            {
                if (_monoTime.GetSeconds() - stored.Timestamp < AnnouncePeerTimeout)
                {
                    endpoint = stored.IpPort;
                    data = stored.Data;
                    return true;
                }
            }

            // Buscar en DHT (amigos)
            if (_dht.GetFriendIp(publicKey, out var ipPort) == 1)
            {
                endpoint = ipPort;
                return true;
            }

            // Si no encontramos, iniciar búsqueda en la red
            InitiatePeerSearch(publicKey);
            return false;
        }

        #endregion

        #region Métodos de Envío

        /// <summary>
        /// Envía solicitud de anuncio a un nodo.
        /// </summary>
        private void SendAnnounceRequest(IPEndPoint target, byte[] targetPublicKey, byte[] data)
        {
            var sharedKey = _dht.GetSharedKeySent(targetPublicKey);
            if (sharedKey == null)
            {
                Logger.Log.Debug($"[Announce] No shared key for {target}");
                return;
            }

            var nonce = LibSodium.GenerateNonce();
            uint pingId = (uint)Interlocked.Increment(ref _selfAnnounceCounter);

            // Construir payload
            var payload = new byte[4 + 4 + data.Length];
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0, 4), pingId);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4, 4), (uint)data.Length);
            Buffer.BlockCopy(data, 0, payload, 8, data.Length);

            // Cifrar
            var cipher = new byte[payload.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, payload, nonce, sharedKey))
                return;

            // Construir paquete
            var packet = new byte[1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + cipher.Length];
            packet[0] = PacketAnnounceRequest;
            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(target, packet, packet.Length);

            // Registrar anuncio pendiente
            var announce = new SelfAnnounce
            {
                TargetPublicKey = (byte[])targetPublicKey.Clone(),
                TargetEndpoint = target,
                PingId = pingId,
                SentTime = _monoTime.GetSeconds(),
                Status = AnnounceStatusSent,
                Data = (byte[])data.Clone()
            };

            _selfAnnounces[pingId] = announce;

            // Actualizar registro de peer anunciado
            _announcedPeers[targetPublicKey] = new AnnouncedPeer
            {
                PublicKey = (byte[])targetPublicKey.Clone(),
                LastAnnounce = _monoTime.GetSeconds(),
                Endpoint = target
            };

            Logger.Log.Debug($"[Announce] Sent announce request to {target}");
        }

        /// <summary>
        /// Envía respuesta de anuncio.
        /// </summary>
        private void SendAnnounceResponse(IPEndPoint target, byte[] targetPublicKey, uint pingId, byte status, byte[] data)
        {
            var sharedKey = _dht.GetSharedKeyRecv(targetPublicKey);
            if (sharedKey == null) return;

            var nonce = LibSodium.GenerateNonce();

            // Construir payload
            var payload = new byte[4 + 4 + (data?.Length ?? 0)];
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0, 4), pingId);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4, 4), status);
            if (data != null && data.Length > 0)
            {
                Buffer.BlockCopy(data, 0, payload, 8, Math.Min(data.Length, payload.Length - 8));
            }

            // Cifrar
            var cipher = new byte[payload.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, payload, nonce, sharedKey))
                return;

            // Construir paquete
            var packet = new byte[1 + LibSodium.CRYPTO_NONCE_SIZE + cipher.Length];
            packet[0] = PacketAnnounceResponse;
            Buffer.BlockCopy(nonce, 0, packet, 1, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(target, packet, packet.Length);
        }

        /// <summary>
        /// Inicia búsqueda de un peer en la red.
        /// </summary>
        private void InitiatePeerSearch(byte[] publicKey)
        {
            // Buscar en nodos cercanos al target
            var closeNodes = new NodeFormat[8];
            int numNodes = _dht.GetCloseNodes(publicKey, closeNodes, null, false, false);

            for (int i = 0; i < numNodes; i++)
            {
                var node = closeNodes[i];
                if (node.PublicKey == null) continue;

                // Enviar solicitud de datos
                RequestPeerData(node.IpPort, node.PublicKey, publicKey);
            }

            // Si no encontramos directamente, usar forwarding
            if (numNodes == 0 && _forwarding != null)
            {
                // Encontrar un relay y pedirle que busque
                var relayNodes = new NodeFormat[4];
                int numRelays = _dht.GetCloseNodes(_selfPublicKey, relayNodes, null, false, false);

                for (int i = 0; i < numRelays; i++)
                {
                    // Solicitar forwarding para buscar al peer
                    // Esto es una extensión que usa forwarding para anuncios
                }
            }
        }

        /// <summary>
        /// Solicita datos de un peer a un nodo específico.
        /// </summary>
        private void RequestPeerData(IPEndPoint target, byte[] targetPublicKey, byte[] searchPublicKey)
        {
            var sharedKey = _dht.GetSharedKeySent(targetPublicKey);
            if (sharedKey == null) return;

            var nonce = LibSodium.GenerateNonce();

            // Payload: solo la public key buscada
            var payload = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            Buffer.BlockCopy(searchPublicKey, 0, payload, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var cipher = new byte[payload.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, payload, nonce, sharedKey))
                return;

            var packet = new byte[1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + cipher.Length];
            packet[0] = PacketDataRequest;
            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(target, packet, packet.Length);
        }

        #endregion

        #region Handlers de Paquetes

        /// <summary>
        /// Maneja solicitud de anuncio entrante.
        /// </summary>
        private static void HandleAnnounceRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var announce = (Announce)state;

            if (packet.Length < 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_MAC_SIZE + 8)
                return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            var sharedKey = announce._dht.GetSharedKeyRecv(senderPk);
            if (sharedKey == null) return;

            // Descifrar
            var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
            {
                Logger.Log.Debug("[Announce] Failed to decrypt announce request");
                return;
            }

            if (plain.Length < 8) return;

            uint pingId = BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(0, 4));
            uint dataLen = BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(4, 4));

            if (dataLen > plain.Length - 8) dataLen = (uint)(plain.Length - 8);

            var data = new byte[dataLen];
            Buffer.BlockCopy(plain, 8, data, 0, (int)dataLen);

            // Almacenar anuncio
            var stored = new StoredAnnounce
            {
                PublicKey = (byte[])senderPk.Clone(),
                IpPort = source,
                Data = data,
                Timestamp = announce._monoTime.GetSeconds(),
                PingId = pingId
            };

            // Verificar límite de almacenamiento
            if (announce._storedAnnounces.Count >= MaxStoredAnnounces)
            {
                announce.CleanupOldestStored();
            }

            announce._storedAnnounces[senderPk] = stored;

            Logger.Log.Debug($"[Announce] Stored announce from {BitConverter.ToString(senderPk.Take(8).ToArray())}");

            // Responder confirmando
            announce.SendAnnounceResponse(source, senderPk, pingId, 0, null); // status 0 = OK
        }

        /// <summary>
        /// Maneja respuesta de anuncio.
        /// </summary>
        private static void HandleAnnounceResponse(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var announce = (Announce)state;

            if (packet.Length < 1 + LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_MAC_SIZE + 8)
                return;

            var nonce = packet.Slice(1, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            // Necesitamos encontrar qué shared key usar
            // Buscamos en nuestros anuncios pendientes
            byte[] senderPk = null;
            foreach (var peer in announce._announcedPeers.Values)
            {
                if (peer.Endpoint.Equals(source))
                {
                    senderPk = peer.PublicKey;
                    break;
                }
            }

            if (senderPk == null) return;

            var sharedKey = announce._dht.GetSharedKeyRecv(senderPk);
            if (sharedKey == null) return;

            var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            uint pingId = BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(0, 4));
            uint status = BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(4, 4));

            if (announce._selfAnnounces.TryGetValue(pingId, out var selfAnnounce))
            {
                if (status == 0)
                {
                    selfAnnounce.Status = AnnounceStatusConfirmed;
                    Logger.Log.Info($"[Announce] Self-announce confirmed by {source}");
                }
                else
                {
                    selfAnnounce.Status = AnnounceStatusNone;
                    Logger.Log.Warning($"[Announce] Self-announce rejected by {source}");
                }
            }
        }

        /// <summary>
        /// Maneja solicitud de datos de peer.
        /// </summary>
        private static void HandleDataRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var announce = (Announce)state;

            if (packet.Length < 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_MAC_SIZE + LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            var sharedKey = announce._dht.GetSharedKeyRecv(senderPk);
            if (sharedKey == null) return;

            var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            var searchPk = plain.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();

            // Buscar si tenemos este anuncio
            if (announce._storedAnnounces.TryGetValue(searchPk, out var stored))
            {
                // Verificar que no haya expirado
                if (announce._monoTime.GetSeconds() - stored.Timestamp < AnnouncePeerTimeout)
                {
                    // Responder con los datos
                    announce.SendDataResponse(source, senderPk, stored);
                }
            }
        }

        /// <summary>
        /// Maneja respuesta con datos de peer.
        /// </summary>
        private static void HandleDataResponse(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var announce = (Announce)state;

            if (packet.Length < 1 + LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_MAC_SIZE + 7)
            {
                Logger.Log.Debug("[Announce] Data response too short");
                return;
            }

            var nonce = packet.Slice(1, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            // Buscar quién solicitó estos datos (necesitamos el shared key)
            byte[] requesterPk = null;
            foreach (var peer in announce._announcedPeers.Values)
            {
                if (peer.Endpoint.Equals(source))
                {
                    requesterPk = peer.PublicKey;
                    break;
                }
            }

            if (requesterPk == null)
            {
                Logger.Log.Debug("[Announce] Data response from unknown peer");
                return;
            }

            var sharedKey = announce._dht.GetSharedKeyRecv(requesterPk);
            if (sharedKey == null) return;

            // Descifrar
            var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
            {
                Logger.Log.Debug("[Announce] Failed to decrypt data response");
                return;
            }

            // Parsear datos: [IP_Port][datos_del_peer]
            if (plain.Length < 7) return;

            // Extraer IP/Port del peer encontrado
            var ipPortLen = plain[0] == 10 ? 19 : 7;
            if (plain.Length < ipPortLen) return;

            IPEndPoint peerEndpoint;
            if (plain[0] == 2) // IPv4
            {
                // CORREGIDO: Usar ArraySegment o Buffer.BlockCopy en lugar de Slice
                var ipBytes = new byte[4];
                Buffer.BlockCopy(plain, 1, ipBytes, 0, 4);
                var ip = new IPAddress(ipBytes);
                var port = (plain[5] << 8) | plain[6];
                peerEndpoint = new IPEndPoint(ip, port);
            }
            else if (plain[0] == 10) // IPv6
            {
                // CORREGIDO: Usar Buffer.BlockCopy
                var ipBytes = new byte[16];
                Buffer.BlockCopy(plain, 1, ipBytes, 0, 16);
                var ip = new IPAddress(ipBytes);
                var port = (plain[17] << 8) | plain[18];
                peerEndpoint = new IPEndPoint(ip, port);
            }
            else
            {
                Logger.Log.Warning("[Announce] Unknown address family in data response");
                return;
            }

            // Extraer datos del peer (nombre, status, etc.)
            var peerData = plain.Length > ipPortLen
                ? new byte[plain.Length - ipPortLen]  // CORREGIDO: Crear array manualmente
                : Array.Empty<byte>();

            if (peerData.Length > 0)
            {
                Buffer.BlockCopy(plain, ipPortLen, peerData, 0, peerData.Length);
            }

            // Extraer public key del peer (debería estar en los datos o derivarse)
            // En una implementación real, el peer data incluiría la public key
            byte[] peerPublicKey = ExtractPublicKeyFromData(peerData);

            Logger.Log.Info($"[Announce] Found peer at {peerEndpoint} with {peerData.Length} bytes of data");

            // NOTIFICAR A LA CAPA SUPERIOR (Messenger/FriendConnection)
            // Esto permite que el sistema intente conectar con el peer encontrado
            announce.NotifyPeerFound?.Invoke(peerPublicKey, peerEndpoint, peerData);
        }

        /// <summary>
        /// Evento cuando se encuentra un peer mediante búsqueda de announce.
        /// </summary>
        public event Action<byte[], IPEndPoint, byte[]> NotifyPeerFound;

        private static byte[] ExtractPublicKeyFromData(byte[] data)
        {
            // CORREGIDO: Usar ArraySegment o copia manual
            if (data.Length >= LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
            {
                var result = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(data, 0, result, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                return result;
            }
            return null;
        }

        /// <summary>
        /// Envía respuesta con datos de peer.
        /// </summary>
        private void SendDataResponse(IPEndPoint target, byte[] targetPublicKey, StoredAnnounce stored)
        {
            var sharedKey = _dht.GetSharedKeyRecv(targetPublicKey);
            if (sharedKey == null) return;

            var nonce = LibSodium.GenerateNonce();

            // Payload: IP/Port + datos
            var ipPortBytes = IpPortToBytes(stored.IpPort);
            var payload = new byte[ipPortBytes.Length + stored.Data.Length];
            Buffer.BlockCopy(ipPortBytes, 0, payload, 0, ipPortBytes.Length);
            Buffer.BlockCopy(stored.Data, 0, payload, ipPortBytes.Length, stored.Data.Length);

            var cipher = new byte[payload.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, payload, nonce, sharedKey))
                return;

            var packet = new byte[1 + LibSodium.CRYPTO_NONCE_SIZE + cipher.Length];
            packet[0] = PacketDataResponse;
            Buffer.BlockCopy(nonce, 0, packet, 1, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(target, packet, packet.Length);
        }

        #endregion

        #region Utilidades

        private byte[] IpPortToBytes(IPEndPoint ipPort)
        {
            bool isIPv6 = ipPort.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            var bytes = new byte[isIPv6 ? 19 : 7];

            bytes[0] = isIPv6 ? (byte)10 : (byte)2;
            var ipBytes = ipPort.Address.GetAddressBytes();
            Buffer.BlockCopy(ipBytes, 0, bytes, 1, ipBytes.Length);
            bytes[bytes.Length - 2] = (byte)(ipPort.Port >> 8);
            bytes[bytes.Length - 1] = (byte)(ipPort.Port & 0xFF);

            return bytes;
        }

        private void CleanupOldestStored()
        {
            var now = _monoTime.GetSeconds();
            byte[] oldestKey = null;
            ulong oldestTime = ulong.MaxValue;

            foreach (var kvp in _storedAnnounces)
            {
                if (kvp.Value.Timestamp < oldestTime)
                {
                    oldestTime = kvp.Value.Timestamp;
                    oldestKey = kvp.Key;
                }
            }

            if (oldestKey != null)
            {
                _storedAnnounces.TryRemove(oldestKey, out _);
            }
        }

        #endregion

        #region Ciclo Principal

        /// <summary>
        /// Itera el sistema de anuncios (llamar periódicamente).
        /// </summary>
        public void DoAnnounce()
        {
            var now = _monoTime.GetSeconds();

            // Auto-anuncio periódico
            StartSelfAnnounce();

            // Limpiar anuncios expirados
            var expired = new System.Collections.Generic.List<byte[]>();
            foreach (var kvp in _storedAnnounces)
            {
                if (now - kvp.Value.Timestamp > AnnouncePeerTimeout)
                {
                    expired.Add(kvp.Key);
                }
            }
            foreach (var key in expired)
            {
                _storedAnnounces.TryRemove(key, out _);
            }

            // Limpiar anuncios propios expirados
            var expiredSelf = new System.Collections.Generic.List<uint>();
            foreach (var kvp in _selfAnnounces)
            {
                if (kvp.Value.Status == AnnounceStatusSent &&
                    now - kvp.Value.SentTime > AnnounceTimeout)
                {
                    expiredSelf.Add(kvp.Key);
                }
            }
            foreach (var id in expiredSelf)
            {
                _selfAnnounces.TryRemove(id, out _);
            }

            // Limpiar peers anunciados antiguos
            var expiredPeers = new System.Collections.Generic.List<byte[]>();
            foreach (var kvp in _announcedPeers)
            {
                if (now - kvp.Value.LastAnnounce > AnnounceSelfTimeout)
                {
                    expiredPeers.Add(kvp.Key);
                }
            }
            foreach (var key in expiredPeers)
            {
                _announcedPeers.TryRemove(key, out _);
            }
        }

        #endregion

        public void Dispose()
        {
            _network.UnregisterHandler(PacketAnnounceRequest);
            _network.UnregisterHandler(PacketAnnounceResponse);
            _network.UnregisterHandler(PacketDataRequest);
            _network.UnregisterHandler(PacketDataResponse);

            _storedAnnounces.Clear();
            _selfAnnounces.Clear();
            _announcedPeers.Clear();

            Logger.Log.Info("[Announce] Disposed");
        }
    }

    #region Clases Auxiliares

    /// <summary>
    /// Anuncio de otro peer almacenado localmente.
    /// </summary>
    public class StoredAnnounce
    {
        public byte[] PublicKey { get; set; }
        public IPEndPoint IpPort { get; set; }
        public byte[] Data { get; set; }
        public ulong Timestamp { get; set; }
        public uint PingId { get; set; }
    }

    /// <summary>
    /// Nuestro propio anuncio pendiente.
    /// </summary>
    public class SelfAnnounce
    {
        public byte[] TargetPublicKey { get; set; }
        public IPEndPoint TargetEndpoint { get; set; }
        public uint PingId { get; set; }
        public ulong SentTime { get; set; }
        public byte Status { get; set; }
        public byte[] Data { get; set; }
    }

    /// <summary>
    /// Peer al que nos hemos anunciado.
    /// </summary>
    public class AnnouncedPeer
    {
        public byte[] PublicKey { get; set; }
        public IPEndPoint Endpoint { get; set; }
        public ulong LastAnnounce { get; set; }
    }

    #endregion
}