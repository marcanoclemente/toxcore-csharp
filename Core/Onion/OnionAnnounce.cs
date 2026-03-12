// Core/Onion/OnionAnnounce.cs - VERSIÓN CORREGIDA
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Toxcore.Core.Crypto;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.Onion;

namespace ToxCore.Core.Onion
{
    /// <summary>
    /// Sistema de anuncios vía onion routing corregido.
    /// Usa el sendback funcional del OnionCore para respuestas.
    /// </summary>
    public sealed class OnionAnnounce : IOnionAnnounce, IDisposable
    {
        private readonly IOnionCore _onionCore;
        private readonly MonoTime _monoTime;
        private readonly IDht _dht;

        // Tabla de anuncios almacenados localmente
        private readonly ConcurrentDictionary<byte[], OnionAnnounceEntry> _storedAnnouncements;
        private readonly ByteArrayComparer _keyComparer = ByteArrayComparer.Instance;

        // Requests pendientes
        private readonly ConcurrentDictionary<ulong, PendingRequest> _pendingRequests;
        private ulong _nextRequestId = 1;

        // Callbacks
        private OnionSearchCallback _searchCallback;
        private OnionAnnounceCallback _announceCallback;

        // Constantes del protocolo
        private const int OnionAnnounceTimeout = 300; // 5 minutos
        private const int MaxStoredAnnouncements = 1000;
        private const int AnnouncementTTL = 600; // 10 minutos
        private const int OnionAnnounceDataSize = 64;
        private const int PingIdSize = 32;

        // Packet type IDs según onion_announce.c
        private const byte PacketAnnounceRequest = 0x87;
        private const byte PacketAnnounceResponse = 0x88;
        private const byte PacketSearchRequest = 0x85;
        private const byte PacketSearchResponse = 0x86;

        public OnionAnnounce(IOnionCore onionCore, MonoTime monoTime, IDht dht = null)
        {
            _onionCore = onionCore ?? throw new ArgumentNullException(nameof(onionCore));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _dht = dht;

            _storedAnnouncements = new ConcurrentDictionary<byte[], OnionAnnounceEntry>(_keyComparer);
            _pendingRequests = new ConcurrentDictionary<ulong, PendingRequest>();

            // Registrar handlers
            _onionCore.RegisterPacketHandler(PacketAnnounceRequest, HandleAnnounceRequestPacket);
            _onionCore.RegisterPacketHandler(PacketAnnounceResponse, HandleAnnounceResponsePacket);
            _onionCore.RegisterPacketHandler(PacketSearchRequest, HandleSearchRequestPacket);
            _onionCore.RegisterPacketHandler(PacketSearchResponse, HandleSearchResponsePacket);

            _onionCore.SetOnionDataHandler(HandleOnionData);

            Logger.Log.Info("[ONIONANNOUNCE] Initialized with corrected sendback support");
        }

        #region IOnionAnnounce Implementation

        /// <summary>
        /// Publica un anuncio en la red onion.
        /// CORRECCIÓN: Usa el sendback del OnionCore para recibir la confirmación.
        /// </summary>
        public bool AnnounceOnion(IPEndPoint[] path, byte[] publicKey, byte[] nonce, byte[] data = null)
        {
            if (path?.Length != 3 || publicKey?.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return false;

            if (data != null && data.Length > OnionAnnounceDataSize)
                data = data.AsSpan(0, OnionAnnounceDataSize).ToArray();

            try
            {
                ulong requestId = GenerateRequestId();
                byte[] packet = BuildAnnouncePacket(requestId, publicKey, nonce, data);
                byte[] packetNonce = LibSodium.GenerateNonce();

                // Enviar vía onion core - el sendback permitirá recibir la respuesta
                bool sent = _onionCore.SendOnionPacket(path, null, packet, packetNonce);

                if (sent)
                {
                    _pendingRequests[requestId] = new PendingRequest
                    {
                        RequestId = requestId,
                        Type = RequestType.Announce,
                        Timestamp = _monoTime.GetSeconds(),
                        PublicKey = (byte[])publicKey.Clone(),
                        Data = data != null ? (byte[])data.Clone() : null,
                        Path = path.Select(p => new IPEndPoint(p.Address, p.Port)).ToArray(),
                        Nonce = (byte[])packetNonce.Clone()
                    };

                    Logger.Log.Debug($"[ONIONANNOUNCE] Sent announce request {requestId} with sendback");
                }

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] AnnounceOnion failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Busca anuncios para una clave pública específica.
        /// CORRECCIÓN: Usa el sendback para recibir resultados.
        /// </summary>
        public bool SearchOnion(IPEndPoint[] path, byte[] targetPublicKey, byte[] searchNonce)
        {
            if (path?.Length != 3 || targetPublicKey?.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return false;

            try
            {
                ulong requestId = GenerateRequestId();
                byte[] packet = BuildSearchPacket(requestId, targetPublicKey, searchNonce);
                byte[] packetNonce = LibSodium.GenerateNonce();

                bool sent = _onionCore.SendOnionPacket(path, null, packet, packetNonce);

                if (sent)
                {
                    _pendingRequests[requestId] = new PendingRequest
                    {
                        RequestId = requestId,
                        Type = RequestType.Search,
                        Timestamp = _monoTime.GetSeconds(),
                        TargetPublicKey = (byte[])targetPublicKey.Clone(),
                        SearchNonce = (byte[])searchNonce.Clone(),
                        Path = path.Select(p => new IPEndPoint(p.Address, p.Port)).ToArray(),
                        Nonce = (byte[])packetNonce.Clone()
                    };

                    Logger.Log.Debug($"[ONIONANNOUNCE] Sent search request {requestId} with sendback");
                }

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] SearchOnion failed: {ex.Message}");
                return false;
            }
        }

        public void SetSearchCallback(OnionSearchCallback callback)
        {
            _searchCallback = callback;
        }

        public void SetAnnounceCallback(OnionAnnounceCallback callback)
        {
            _announceCallback = callback;
        }

        public void DoOnionAnnounce()
        {
            ulong now = _monoTime.GetSeconds();

            // Limpiar requests expirados
            var expiredRequests = _pendingRequests
                .Where(kvp => now - kvp.Value.Timestamp > OnionAnnounceTimeout)
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var reqId in expiredRequests)
            {
                if (_pendingRequests.TryRemove(reqId, out var req))
                {
                    Logger.Log.Debug($"[ONIONANNOUNCE] Request {reqId} timed out");

                    if (req.Type == RequestType.Announce)
                    {
                        _announceCallback?.Invoke(false, null, null);
                    }
                }
            }

            // Limpiar anuncios expirados
            var expiredAnnounces = _storedAnnouncements
                .Where(kvp => now - kvp.Value.Timestamp > AnnouncementTTL)
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var key in expiredAnnounces)
            {
                _storedAnnouncements.TryRemove(key, out _);
            }

            // Limitar tamaño de tabla
            while (_storedAnnouncements.Count > MaxStoredAnnouncements)
            {
                var oldest = _storedAnnouncements.OrderBy(kvp => kvp.Value.Timestamp).FirstOrDefault();
                if (oldest.Key != null)
                {
                    _storedAnnouncements.TryRemove(oldest.Key, out _);
                }
            }
        }

        #endregion

        #region Construcción de Paquetes

        /// <summary>
        /// CORREGIDO: Construye paquete de anuncio con requestId en datos cifrados.
        /// El requestId no va en plaintext para evitar tracking.
        /// </summary>
        private byte[] BuildAnnouncePacket(ulong requestId, byte[] publicKey, byte[] nonce, byte[] data)
        {
            using var ms = new System.IO.MemoryStream();

            // Tipo de paquete (va en la capa cifrada, no aquí)
            // Lo que va en plaintext es mínimo

            // Datos a cifrar: [tipo][requestId][publicKey][nonce][data opcional]
            ms.WriteByte(PacketAnnounceRequest);

            byte[] reqIdBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(reqIdBytes, requestId);
            ms.Write(reqIdBytes, 0, 8);

            ms.Write(publicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            ms.Write(nonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

            if (data != null && data.Length > 0)
            {
                ms.Write(data, 0, Math.Min(data.Length, OnionAnnounceDataSize));
            }

            return ms.ToArray(); // Esto se cifrará en las capas onion
        }

        private byte[] BuildSearchPacket(ulong requestId, byte[] targetPublicKey, byte[] searchNonce)
        {
            using var ms = new System.IO.MemoryStream();

            ms.WriteByte(PacketSearchRequest);

            byte[] reqIdBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(reqIdBytes, requestId);
            ms.Write(reqIdBytes, 0, 8);

            ms.Write(targetPublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            ms.Write(searchNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

            return ms.ToArray();
        }

        private byte[] BuildAnnounceResponse(ulong requestId, bool success, byte[] pingId, IPEndPoint[] closeNodes)
        {
            using var ms = new System.IO.MemoryStream();

            ms.WriteByte(PacketAnnounceResponse);

            byte[] reqIdBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(reqIdBytes, requestId);
            ms.Write(reqIdBytes, 0, 8);

            ms.WriteByte(success ? (byte)1 : (byte)0);

            if (success && pingId != null)
            {
                ms.Write(pingId, 0, Math.Min(pingId.Length, PingIdSize));

                if (closeNodes != null)
                {
                    foreach (var node in closeNodes.Take(4))
                    {
                        byte[] serialized = SerializeNode(node);
                        ms.Write(serialized, 0, serialized.Length);
                    }
                }
            }

            return ms.ToArray();
        }

        private byte[] BuildSearchResponse(ulong requestId, bool found, OnionAnnounceEntry entry)
        {
            using var ms = new System.IO.MemoryStream();

            ms.WriteByte(PacketSearchResponse);

            byte[] reqIdBytes = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(reqIdBytes, requestId);
            ms.Write(reqIdBytes, 0, 8);

            ms.WriteByte(found ? (byte)1 : (byte)0);

            if (found && entry != null)
            {
                byte[] endpointData = SerializeEndpoint(entry.Endpoint);
                ms.Write(endpointData, 0, endpointData.Length);

                ms.Write(entry.PublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

                if (entry.Data != null)
                {
                    ms.Write(entry.Data, 0, entry.Data.Length);
                }
            }

            return ms.ToArray();
        }

        #endregion

        #region Handlers de Paquetes

        /// <summary>
        /// Maneja una solicitud de anuncio entrante.
        /// CORRECCIÓN: Usa SendOnionResponse para enviar la respuesta vía sendback.
        /// </summary>
        private void HandleAnnounceRequestPacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data?.Length < 1 + 8 + 32 + 24) return;

            try
            {
                int offset = 1;

                ulong requestId = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
                offset += 8;

                byte[] publicKey = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                Array.Copy(data, offset, publicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                offset += LibSodium.CRYPTO_PUBLIC_KEY_SIZE;

                byte[] announceNonce = new byte[LibSodium.CRYPTO_NONCE_SIZE];
                Array.Copy(data, offset, announceNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);
                offset += LibSodium.CRYPTO_NONCE_SIZE;

                byte[] extraData = null;
                if (data.Length > offset)
                {
                    int dataLen = Math.Min(data.Length - offset, OnionAnnounceDataSize);
                    extraData = new byte[dataLen];
                    Array.Copy(data, offset, extraData, 0, dataLen);
                }

                // Almacenar anuncio
                StoreAnnouncement(publicKey, source, announceNonce, extraData);

                // Generar ping_id
                byte[] pingId = GeneratePingId(publicKey, announceNonce);

                // Obtener nodos cercanos
                IPEndPoint[] closeNodes = GetCloseNodes(publicKey);

                // Construir respuesta
                byte[] response = BuildAnnounceResponse(requestId, true, pingId, closeNodes);

                // CORRECCIÓN CRÍTICA: Usar SendOnionResponse con el nonce original
                // El nonce original está en data[1+8 ... 1+8+23] (después del requestId)
                byte[] originalNonce = new byte[LibSodium.CRYPTO_NONCE_SIZE];
                Array.Copy(data, 1 + 8, originalNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

                bool sent = _onionCore.SendOnionResponse(source, originalNonce, response);

                Logger.Log.Debug($"[ONIONANNOUNCE] Stored announcement for {Convert.ToHexString(publicKey)[..16]}..., response sent: {sent}");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] HandleAnnounceRequest error: {ex.Message}");
            }
        }

        private void HandleAnnounceResponsePacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data?.Length < 1 + 8 + 1) return;

            try
            {
                int offset = 1;

                ulong requestId = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
                offset += 8;

                bool success = data[offset++] != 0;

                if (!_pendingRequests.TryRemove(requestId, out var request) || request.Type != RequestType.Announce)
                {
                    Logger.Log.Debug($"[ONIONANNOUNCE] Unknown or expired announce response: {requestId}");
                    return;
                }

                byte[] pingId = null;
                IPEndPoint[] nodes = null;

                if (success && data.Length > offset)
                {
                    int pingIdLen = Math.Min(data.Length - offset, PingIdSize);
                    pingId = new byte[pingIdLen];
                    Array.Copy(data, offset, pingId, 0, pingIdLen);
                    offset += pingIdLen;

                    if (data.Length > offset)
                    {
                        nodes = ExtractNodesFromData(data, offset);
                    }
                }

                _announceCallback?.Invoke(success, pingId, nodes);
                Logger.Log.Debug($"[ONIONANNOUNCE] Announce {requestId} result: {success}");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] HandleAnnounceResponse error: {ex.Message}");
            }
        }

        /// <summary>
        /// Maneja una solicitud de búsqueda entrante.
        /// CORRECCIÓN: Usa SendOnionResponse para la respuesta.
        /// </summary>
        private void HandleSearchRequestPacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data?.Length < 1 + 8 + 32) return;

            try
            {
                int offset = 1;

                ulong requestId = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
                offset += 8;

                byte[] targetKey = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                Array.Copy(data, offset, targetKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

                // Buscar en tabla local
                var entry = FindAnnouncement(targetKey);
                bool found = entry != null;

                // Construir respuesta
                byte[] response = BuildSearchResponse(requestId, found, entry);

                // CORRECCIÓN: Usar SendOnionResponse con el nonce original
                byte[] originalNonce = new byte[LibSodium.CRYPTO_NONCE_SIZE];
                Array.Copy(data, 1 + 8, originalNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

                bool sent = _onionCore.SendOnionResponse(source, originalNonce, response);

                Logger.Log.Debug($"[ONIONANNOUNCE] Search request {requestId}: {(found ? "found" : "not found")}, response sent: {sent}");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] HandleSearchRequest error: {ex.Message}");
            }
        }

        private void HandleSearchResponsePacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data?.Length < 1 + 8 + 1) return;

            try
            {
                int offset = 1;

                ulong requestId = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
                offset += 8;

                bool found = data[offset++] != 0;

                if (!_pendingRequests.TryRemove(requestId, out var request) || request.Type != RequestType.Search)
                {
                    return;
                }

                if (found && data.Length > offset + 6 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                {
                    if (TryDeserializeEndpoint(data.AsSpan(offset), out var endpoint, ref offset))
                    {
                        byte[] announcedKey = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                        Array.Copy(data, offset, announcedKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                        offset += LibSodium.CRYPTO_PUBLIC_KEY_SIZE;

                        byte[] announceData = null;
                        if (data.Length > offset)
                        {
                            announceData = new byte[data.Length - offset];
                            Array.Copy(data, offset, announceData, 0, announceData.Length);
                        }

                        _searchCallback?.Invoke(request.TargetPublicKey, announcedKey, announceData, endpoint);
                        Logger.Log.Info($"[ONIONANNOUNCE] Search found result at {endpoint}");
                    }
                }
                else
                {
                    Logger.Log.Debug($"[ONIONANNOUNCE] Search {requestId}: not found");
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONANNOUNCE] HandleSearchResponse error: {ex.Message}");
            }
        }

        /// <summary>
        /// CORREGIDO: Procesa datos onion recibidos según su tipo.
        /// </summary>
        private void HandleOnionData(IPEndPoint source, byte[] data, byte[] nonce)
        {
            if (data == null || data.Length < 1) return;

            byte packetType = data[0];

            Logger.Log.Debug($"[ONIONANNOUNCE] Received onion data type {packetType:X2} ({data.Length} bytes) from {source}");

            // Los handlers específicos ya registrados procesan los tipos conocidos
            // Este es el fallback para tipos no registrados o procesamiento adicional

            switch (packetType)
            {
                case PacketAnnounceRequest:
                case PacketAnnounceResponse:
                case PacketSearchRequest:
                case PacketSearchResponse:
                    // Ya manejados por handlers registrados
                    break;

                default:
                    Logger.Log.Debug($"[ONIONANNOUNCE] Unknown packet type {packetType:X2}, ignoring");
                    break;
            }
        }

        #endregion

        #region Operaciones de Almacenamiento

        private void StoreAnnouncement(byte[] publicKey, IPEndPoint endpoint, byte[] nonce, byte[] data)
        {
            var entry = new OnionAnnounceEntry
            {
                PublicKey = (byte[])publicKey.Clone(),
                Endpoint = endpoint,
                Nonce = (byte[])nonce.Clone(),
                Data = data != null ? (byte[])data.Clone() : null,
                Timestamp = _monoTime.GetSeconds()
            };

            _storedAnnouncements[publicKey] = entry;
        }

        private OnionAnnounceEntry FindAnnouncement(byte[] publicKey)
        {
            if (_storedAnnouncements.TryGetValue(publicKey, out var entry))
            {
                if (_monoTime.GetSeconds() - entry.Timestamp <= AnnouncementTTL)
                {
                    return entry;
                }
                _storedAnnouncements.TryRemove(publicKey, out _);
            }
            return null;
        }

        #endregion

        #region Utilidades

        private ulong GenerateRequestId()
        {
            return (ulong)Interlocked.Increment(ref _nextRequestId);
        }

        /// <summary>
        /// CORREGIDO: Genera pingId usando SHA512 (más cercano a generichash de libsodium).
        /// En Tox original usa crypto_generichash (BLAKE2b), pero SHA512 es aceptable.
        /// </summary>
        private byte[] GeneratePingId(byte[] publicKey, byte[] nonce)
        {
            using var sha512 = System.Security.Cryptography.SHA512.Create();

            // Datos: publicKey + nonce + timestamp
            var timestamp = BitConverter.GetBytes(_monoTime.GetSeconds());

            sha512.TransformBlock(publicKey, 0, publicKey.Length, null, 0);
            sha512.TransformBlock(nonce, 0, nonce.Length, null, 0);
            sha512.TransformFinalBlock(timestamp, 0, timestamp.Length);

            // Usar primeros 32 bytes del SHA512 (tamaño de pingId estándar)
            byte[] hash = sha512.Hash;
            byte[] pingId = new byte[32];
            Buffer.BlockCopy(hash, 0, pingId, 0, 32);

            return pingId;
        }

        private IPEndPoint[] GetCloseNodes(byte[] publicKey)
        {
            if (_dht == null) return null;

            try
            {
                var nodes = new NodeFormat[DhtConstants.MaxSentNodes];
                int count = _dht.GetCloseNodes(publicKey, nodes, null, false, true);

                var result = new List<IPEndPoint>();
                for (int i = 0; i < count && i < 4; i++)
                {
                    result.Add(nodes[i].IpPort);
                }
                return result.ToArray();
            }
            catch
            {
                return null;
            }
        }

        private byte[] SerializeNode(IPEndPoint endpoint)
        {
            using var ms = new System.IO.MemoryStream();

            bool isIPv6 = endpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            ms.WriteByte(isIPv6 ? (byte)10 : (byte)2);

            var ipBytes = isIPv6 ? endpoint.Address.GetAddressBytes() : endpoint.Address.MapToIPv4().GetAddressBytes();
            ms.Write(ipBytes, 0, ipBytes.Length);

            var portBytes = BitConverter.GetBytes((ushort)endpoint.Port);
            if (BitConverter.IsLittleEndian) Array.Reverse(portBytes);
            ms.Write(portBytes, 0, 2);

            return ms.ToArray();
        }

        private byte[] SerializeEndpoint(IPEndPoint endpoint)
        {
            return SerializeNode(endpoint);
        }

        private bool TryDeserializeEndpoint(ReadOnlySpan<byte> data, out IPEndPoint endpoint, ref int offset)
        {
            endpoint = null;
            if (offset >= data.Length) return false;

            try
            {
                byte family = data[offset++];
                int ipSize = (family == 10) ? 16 : 4;

                if (offset + ipSize + 2 > data.Length) return false;

                var ipBytes = data.Slice(offset, ipSize).ToArray();
                offset += ipSize;

                ushort port = (ushort)((data[offset] << 8) | data[offset + 1]);
                offset += 2;

                endpoint = new IPEndPoint(new IPAddress(ipBytes), port);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private IPEndPoint[] ExtractNodesFromData(byte[] data, int offset)
        {
            var nodes = new List<IPEndPoint>();

            while (offset < data.Length)
            {
                if (!TryDeserializeEndpoint(data.AsSpan(offset), out var ep, ref offset))
                    break;
                nodes.Add(ep);
            }

            return nodes.ToArray();
        }

        #endregion

        public void Dispose()
        {
            _onionCore.UnregisterPacketHandler(PacketAnnounceRequest);
            _onionCore.UnregisterPacketHandler(PacketAnnounceResponse);
            _onionCore.UnregisterPacketHandler(PacketSearchRequest);
            _onionCore.UnregisterPacketHandler(PacketSearchResponse);

            _pendingRequests.Clear();
            _storedAnnouncements.Clear();

            Logger.Log.Info("[ONIONANNOUNCE] Disposed");
        }

        #region Clases Auxiliares

        private class OnionAnnounceEntry
        {
            public byte[] PublicKey { get; set; }
            public IPEndPoint Endpoint { get; set; }
            public byte[] Nonce { get; set; }
            public byte[] Data { get; set; }
            public ulong Timestamp { get; set; }
        }

        private class PendingRequest
        {
            public ulong RequestId { get; set; }
            public RequestType Type { get; set; }
            public ulong Timestamp { get; set; }
            public byte[] PublicKey { get; set; }
            public byte[] TargetPublicKey { get; set; }
            public byte[] Data { get; set; }
            public byte[] SearchNonce { get; set; }
            public IPEndPoint[] Path { get; set; }
            public byte[] Nonce { get; set; }
        }

        private enum RequestType
        {
            Announce,
            Search
        }

        #endregion
    }
}