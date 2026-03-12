// Core/Onion/OnionClient.cs - VERSIÓN CORREGIDA
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using Toxcore.Core.Crypto;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.Onion;

namespace ToxCore.Core.Onion
{
    /// <summary>
    /// Cliente onion corregido para ToxCore.
    /// Usa el OnionCore corregido con sendback funcional.
    /// </summary>
    public sealed class OnionClient : IOnionClient, IDisposable
    {
        private readonly IOnionCore _onionCore;
        private readonly IDht _dht;
        private readonly MonoTime _monoTime;

        private readonly ConcurrentDictionary<int, OnionPath> _paths = new();
        private readonly ConcurrentDictionary<byte[], PendingFriendSearch> _friendSearches = new(ByteArrayComparer.Instance);
        private int _nextPathId = 1;

        // Constantes de onion_client.c
        private const int OnionClientMaxPaths = 8;
        private const int OnionPathTimeout = 300; // 5 minutos
        private const int OnionFriendSearchTimeout = 60;

        // Estados de path
        private const byte PathStateActive = 1;
        private const byte PathStateFailed = 2;

        // Packet types para datos onion
        private const byte PacketGenericData = 0x03;
        private const byte PacketFriendSearch = 0x04;
        private const byte PacketFriendSearchResponse = 0x05;
        private const byte PacketPathDestroy = 0x02;

        public event Action<int, IPEndPoint, byte[]> OnDataReceived;
        public event Action<int> OnPathEstablished;
        public event Action<int> OnPathTimeout;
        public event Action<byte[], IPEndPoint> OnFriendFound;

        public int ActivePathsCount => _paths.Count(p => p.Value.State == PathStateActive);

        public OnionClient(IOnionCore onionCore, IDht dht, MonoTime monoTime)
        {
            _onionCore = onionCore ?? throw new ArgumentNullException(nameof(onionCore));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));

            // Registrar handlers para tipos de paquetes específicos
            _onionCore.RegisterPacketHandler(PacketGenericData, HandleGenericDataPacket);
            _onionCore.RegisterPacketHandler(PacketFriendSearchResponse, HandleFriendSearchResponsePacket);
            _onionCore.RegisterPacketHandler(PacketPathDestroy, HandlePathDestroyPacket);

            // Establecer handler de datos general
            _onionCore.SetOnionDataHandler(HandleOnionData);

            Logger.Log.Info("[ONIONCLIENT] Initialized with corrected OnionCore");
        }

        #region IOnionClient Implementation

        /// <summary>
        /// CORREGIDO: Crea un path onion de 3 nodos distintos.
        /// Espera confirmación antes de marcar como establecido.
        /// </summary>
        public bool CreatePath(out int pathId)
        {
            pathId = -1;

            if (_paths.Count >= OnionClientMaxPaths)
            {
                Logger.Log.Warning("[ONIONCLIENT] Max paths reached");
                return false;
            }

            // Intentar obtener nodos únicos
            var nodes = GetUniquePathNodes(3);
            if (nodes.Length < 3)
            {
                Logger.Log.Warning("[ONIONCLIENT] Not enough unique nodes for path");
                return false;
            }

            pathId = Interlocked.Increment(ref _nextPathId);

            var path = new OnionPath
            {
                PathId = pathId,
                Nodes = nodes,
                CreatedTime = _monoTime.GetSeconds(),
                LastUsed = _monoTime.GetSeconds(),
                State = PathStateActive,
                ResponseReceived = false
            };

            _paths[pathId] = path;

            Logger.Log.Info($"[ONIONCLIENT] Created path {pathId}: {nodes[0]} -> {nodes[1]} -> {nodes[2]}");

            // Enviar ping de prueba para verificar el path
            SendPathTest(pathId);

            return true;
        }

        /// <summary>
        /// NUEVO: Obtiene nodos únicos para un path.
        /// </summary>
        private IPEndPoint[] GetUniquePathNodes(int count)
        {
            var candidates = new List<IPEndPoint>();
            var attempts = 0;
            const int maxAttempts = 10;

            while (candidates.Count < count && attempts < maxAttempts)
            {
                var node = _onionCore.GetPathNodes(1).FirstOrDefault();

                if (node != null && !candidates.Any(c => IpPortEqual(c, node)))
                {
                    candidates.Add(node);
                }

                attempts++;
            }

            return candidates.ToArray();
        }

        /// <summary>
        /// NUEVO: Compara endpoints IP/Port.
        /// </summary>
        private bool IpPortEqual(IPEndPoint a, IPEndPoint b)
        {
            if (a == null || b == null) return false;
            if (a.Port != b.Port) return false;
            return a.Address.Equals(b.Address);
        }

        /// <summary>
        /// CORREGIDO: Envía un paquete de prueba usando tipo estándar.
        /// Usa tipo 0x03 (Generic Data) en lugar de 0xFF no estándar.
        /// </summary>
        private bool SendPathTest(int pathId)
        {
            if (!_paths.TryGetValue(pathId, out var path))
                return false;

            try
            {
                using var ms = new System.IO.MemoryStream();
                // Usar tipo estándar 0x03 (Generic Data) con flag de test
                ms.WriteByte(0x03); // PacketGenericData
                ms.Write(BitConverter.GetBytes(pathId), 0, 4);
                ms.WriteByte(0x01); // Flag: path test

                var testData = ms.ToArray();
                var nonce = LibSodium.GenerateNonce();

                bool sent = _onionCore.SendOnionPacket(path.Nodes, null, testData, nonce);

                if (sent)
                {
                    Logger.Log.Debug($"[ONIONCLIENT] Sent path test for {pathId}");
                }

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.Debug($"[ONIONCLIENT] Error sending path test: {ex.Message}");
                return false;
            }
        }

        public void KillPath(int pathId)
        {
            if (!_paths.TryRemove(pathId, out var path))
                return;

            if (path.State == PathStateActive)
            {
                try
                {
                    // Notificar al último nodo sobre destrucción del path
                    using var ms = new System.IO.MemoryStream();
                    ms.WriteByte(PacketPathDestroy);
                    ms.Write(BitConverter.GetBytes(pathId), 0, 4);

                    var destroyData = ms.ToArray();
                    var nonce = LibSodium.GenerateNonce();

                    _onionCore.SendOnionPacket(path.Nodes, null, destroyData, nonce);
                }
                catch (Exception ex)
                {
                    Logger.Log.Debug($"[ONIONCLIENT] Error sending path destroy: {ex.Message}");
                }
            }

            Logger.Log.Debug($"[ONIONCLIENT] Killed path {pathId}");
        }

        /// <summary>
        /// Envía datos a través de un path onion específico.
        /// CORRECCIÓN: Usa el sendback del OnionCore para recibir respuestas.
        /// </summary>
        public bool SendData(int pathId, byte[] destPublicKey, byte[] data)
        {
            if (!_paths.TryGetValue(pathId, out var path))
            {
                Logger.Log.Warning($"[ONIONCLIENT] Path {pathId} not found");
                return false;
            }

            if (path.State != PathStateActive)
            {
                Logger.Log.Warning($"[ONIONCLIENT] Path {pathId} not active");
                return false;
            }

            path.LastUsed = _monoTime.GetSeconds();

            try
            {
                using var ms = new System.IO.MemoryStream();
                ms.WriteByte(PacketGenericData);
                ms.Write(BitConverter.GetBytes(pathId), 0, 4);
                ms.Write(data, 0, data.Length);

                var packetData = ms.ToArray();
                var packetNonce = LibSodium.GenerateNonce();

                bool sent = _onionCore.SendOnionPacket(path.Nodes, destPublicKey, packetData, packetNonce);

                if (sent)
                {
                    Logger.Log.Debug($"[ONIONCLIENT] Sent {data.Length} bytes on path {pathId}");
                }

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCLIENT] Error sending data on path {pathId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Busca un amigo enviando consultas por múltiples paths.
        /// CORRECCIÓN: Usa el sendback para recibir respuestas.
        /// </summary>
        public bool FindFriend(byte[] friendPublicKey)
        {
            if (friendPublicKey == null || friendPublicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return false;

            // Asegurar paths activos
            var activePaths = _paths.Values.Where(p => p.State == PathStateActive).ToList();

            while (activePaths.Count < 2 && _paths.Count < OnionClientMaxPaths)
            {
                if (CreatePath(out int newPathId))
                {
                    if (_paths.TryGetValue(newPathId, out var newPath))
                    {
                        activePaths.Add(newPath);
                    }
                }
                else
                {
                    break;
                }
            }

            if (activePaths.Count == 0)
            {
                Logger.Log.Warning("[ONIONCLIENT] No active paths for friend search");
                return false;
            }

            var searchNonce = LibSodium.GenerateNonce();
            bool anySent = false;

            foreach (var path in activePaths.Take(3))
            {
                try
                {
                    using var ms = new System.IO.MemoryStream();
                    ms.WriteByte(PacketFriendSearch);
                    ms.Write(friendPublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                    ms.Write(searchNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

                    var searchData = ms.ToArray();
                    var packetNonce = LibSodium.GenerateNonce();

                    if (_onionCore.SendOnionPacket(path.Nodes, null, searchData, packetNonce))
                    {
                        anySent = true;
                        path.LastUsed = _monoTime.GetSeconds();
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log.Debug($"[ONIONCLIENT] Error sending search on path {path.PathId}: {ex.Message}");
                }
            }

            if (!anySent) return false;

            _friendSearches[friendPublicKey] = new PendingFriendSearch
            {
                PublicKey = (byte[])friendPublicKey.Clone(),
                StartTime = _monoTime.GetSeconds(),
                SearchNonce = (byte[])searchNonce.Clone(),
                PathsUsed = activePaths.Take(3).Select(p => p.PathId).ToArray()
            };

            Logger.Log.Debug($"[ONIONCLIENT] Searching for friend {Logger.SafeKeyThumb(friendPublicKey)} via {activePaths.Count} paths");
            return true;
        }

        public void DoOnionClient()
        {
            var now = _monoTime.GetSeconds();

            // Limpiar paths inactivos
            var expiredPaths = _paths.Where(kvp =>
                kvp.Value.State == PathStateActive &&
                now - kvp.Value.LastUsed > OnionPathTimeout
            ).Select(kvp => kvp.Key).ToArray();

            foreach (var pathId in expiredPaths)
            {
                if (_paths.TryGetValue(pathId, out var path))
                {
                    path.State = PathStateFailed;
                    Logger.Log.Debug($"[ONIONCLIENT] Path {pathId} timed out");
                    OnPathTimeout?.Invoke(pathId);
                }
            }

            // Limpiar búsquedas expiradas
            var expiredSearches = _friendSearches.Where(kvp =>
                now - kvp.Value.StartTime > OnionFriendSearchTimeout
            ).Select(kvp => kvp.Key).ToArray();

            foreach (var pk in expiredSearches)
            {
                _friendSearches.TryRemove(pk, out _);
            }

            // Mantener mínimo de paths activos
            var activeCount = _paths.Values.Count(p => p.State == PathStateActive);
            if (activeCount < 2 && _paths.Count < OnionClientMaxPaths)
            {
                CreatePath(out _);
            }
        }

        #endregion

        #region Handlers de Paquetes

        private void HandleOnionData(IPEndPoint source, byte[] data, byte[] nonce)
        {
            if (data == null || data.Length < 1) return;

            byte packetType = data[0];

            // Los handlers específicos ya procesan los tipos conocidos
            Logger.Log.Debug($"[ONIONCLIENT] Received onion data type {packetType:X2} from {source}");
        }

        /// <summary>
        /// CORREGIDO: Maneja datos genéricos y confirma path si es respuesta a test.
        /// </summary>
        private void HandleGenericDataPacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data.Length < 5) return;

            try
            {
                int pathId = BitConverter.ToInt32(data, 1);

                // Verificar si es respuesta a path test (byte 5 = 0x01)
                bool isPathTestResponse = data.Length >= 6 && data[5] == 0x01;

                if (isPathTestResponse)
                {
                    // Confirmar que el path funciona
                    if (_paths.TryGetValue(pathId, out var path))
                    {
                        if (!path.ResponseReceived)
                        {
                            path.ResponseReceived = true;
                            path.LastUsed = _monoTime.GetSeconds();

                            Logger.Log.Info($"[ONIONCLIENT] Path {pathId} confirmed via sendback");

                            // AHORA sí notificar establecimiento
                            OnPathEstablished?.Invoke(pathId);
                        }
                    }
                    return;
                }

                // Datos normales
                var payload = data.AsSpan(5).ToArray();
                OnDataReceived?.Invoke(pathId, source, payload);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCLIENT] HandleGenericData error: {ex.Message}");
            }
        }

        private void HandleFriendSearchResponsePacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            // Formato: [tipo(0x05)][friend_pk(32)][ip_port(variable)][data...]
            if (data.Length < 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + 7) return;

            try
            {
                int offset = 1;

                var friendPk = data.AsSpan(offset, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
                offset += LibSodium.CRYPTO_PUBLIC_KEY_SIZE;

                if (!_friendSearches.TryRemove(friendPk, out var search))
                {
                    Logger.Log.Debug("[ONIONCLIENT] Received search response for unknown friend");
                    return;
                }

                // Extraer endpoint
                if (!TryDeserializeIpPort(data.AsSpan(offset), out var endpoint))
                {
                    Logger.Log.Warning("[ONIONCLIENT] Failed to deserialize endpoint in search response");
                    return;
                }

                Logger.Log.Info($"[ONIONCLIENT] Found friend at {endpoint} via sendback");
                OnFriendFound?.Invoke(friendPk, endpoint);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCLIENT] HandleFriendSearchResponse error: {ex.Message}");
            }
        }

        private void HandlePathDestroyPacket(IPEndPoint source, byte[] data, byte[] senderPublicKey)
        {
            if (data.Length < 5) return;

            try
            {
                int pathId = BitConverter.ToInt32(data, 1);

                if (_paths.TryRemove(pathId, out _))
                {
                    Logger.Log.Debug($"[ONIONCLIENT] Path {pathId} destroyed by remote via sendback");
                    OnPathTimeout?.Invoke(pathId);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCLIENT] HandlePathDestroy error: {ex.Message}");
            }
        }

        #endregion

        #region Utilidades

        private bool TryDeserializeIpPort(ReadOnlySpan<byte> data, out IPEndPoint endpoint)
        {
            endpoint = null;
            if (data.Length < 1) return false;

            try
            {
                byte family = data[0];
                int ipSize = (family == 10) ? 16 : 4;

                if (data.Length < 1 + ipSize + 2) return false;

                var ipBytes = data.Slice(1, ipSize).ToArray();
                ushort port = (ushort)((data[1 + ipSize] << 8) | data[1 + ipSize + 1]);

                endpoint = new IPEndPoint(new IPAddress(ipBytes), port);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        public void Dispose()
        {
            _onionCore.UnregisterPacketHandler(PacketGenericData);
            _onionCore.UnregisterPacketHandler(PacketFriendSearchResponse);
            _onionCore.UnregisterPacketHandler(PacketPathDestroy);

            foreach (var pathId in _paths.Keys.ToArray())
            {
                KillPath(pathId);
            }

            _paths.Clear();
            _friendSearches.Clear();

            Logger.Log.Info("[ONIONCLIENT] Disposed");
        }

        #region Clases Auxiliares

        private class OnionPath
        {
            public int PathId { get; set; }
            public IPEndPoint[] Nodes { get; set; }
            public ulong CreatedTime { get; set; }
            public ulong LastUsed { get; set; }
            public byte State { get; set; }
            public bool ResponseReceived { get; set; }
        }

        private class PendingFriendSearch
        {
            public byte[] PublicKey { get; set; }
            public ulong StartTime { get; set; }
            public byte[] SearchNonce { get; set; }
            public int[] PathsUsed { get; set; }
        }

        #endregion
    }
}