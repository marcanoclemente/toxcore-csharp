// Core/FriendConnection.cs - VERSIÓN COMPLETA Y FUNCIONAL v3.0
// Integrada con NetCrypto v2.0 (IDs numéricos)
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using Toxcore.Core.Crypto;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.Onion;

namespace Toxcore.Core
{
    /// <summary>
    /// Implementación completa y funcional de gestión de conexiones de amigos.
    /// Traducción fiel de friend_connection.c - Gestiona conexiones P2P cifradas.
    /// 
    /// INTEGRACIONES:
    /// - NetCrypto v2.0: Usa IDs numéricos de conexión, SetDirectIpPort
    /// - OnionClient: Paths onion para fallback
    /// - DHT: Gestión de amigos con lock tokens
    /// - LAN Discovery: Descubrimiento de peers en red local
    /// </summary>
    public sealed class FriendConnection : IFriendConnection, IDisposable
    {
        #region Constantes (de friend_connection.h)

        public const int FriendPingInterval = 8;
        public const int FriendConnectionTimeout = 32;
        public const int FriendDhtTimeout = 70;
        public const int ShareRelaysInterval = 120;
        public const int LanDiscoveryInterval = 10;

        private const int MaxFriendConnectionsConst = 256;
        private const int HandshakeTimeoutConst = 15;
        private const int MaxOnionFallbackAttempts = 3;
        private const int PortsPerDiscovery = 10;

        public const int MaxFriendConnectionPacketSize = 1400;
        public const int MaxFriendConnectionCallbacks = 2;

        public const int MessengerCallbackIndex = 0;
        public const int GroupchatCallbackIndex = 1;

        public const byte PacketIdAlive = 16;
        public const byte PacketIdShareRelays = 17;
        public const byte PacketIdFriendRequests = 18;

        public const int FriendMaxStoredTcpRelays = 16;
        public const int MaxSharedRelays = 4;
        public const int MaxFriendTcpConnections = 4;

        
        #endregion

        #region Dependencias

        private readonly INetCrypto _netCrypto;
        private readonly IDht _dht;
        private readonly IOnionClient _onionClient;
        private readonly MonoTime _monoTime;
        private readonly INetworkCore _network;
        private readonly ILanDiscoveryService _lanDiscovery;

        #endregion

        #region Estado

        private readonly ConcurrentDictionary<int, FriendConn> _friendConnections;
        private readonly ConcurrentDictionary<byte[], int> _publicKeyToNumber;
        private int _nextFriendNumber;
        private readonly ConcurrentDictionary<int, FriendConnCallbacks[]> _requestCallbacks;

        private FriendConnectionStatusCallback _globalStatusCallback;
        private object _globalStatusCallbackObject;

        private FriendRequestReceivedCallback _friendRequestCallback;
        private object _friendRequestCallbackObject;

        private ulong _lastLanDiscovery;
        private ushort _nextLanPort;

        private readonly ReaderWriterLockSlim _connectionLock = new(LockRecursionPolicy.NoRecursion);

        #endregion

        #region Propiedades

        public int MaxFriendConnections => MaxFriendConnectionsConst;
        public int ConnectionCount => _friendConnections.Count;
        public int ConnectionTimeout => FriendConnectionTimeout;
        public int PingInterval => FriendPingInterval;

        #endregion

        #region Constructor

        public FriendConnection(
            INetCrypto netCrypto,
            IDht dht,
            IOnionClient onionClient,
            MonoTime monoTime,
            INetworkCore network)
        {
            _netCrypto = netCrypto ?? throw new ArgumentNullException(nameof(netCrypto));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _onionClient = onionClient ?? throw new ArgumentNullException(nameof(onionClient));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _network = network ?? throw new ArgumentNullException(nameof(network));

            // Suscribirse a eventos de NetCrypto (una sola vez)
            _netCrypto.OnConnectionSecured += HandleNewConnections;
            _netCrypto.OnDataReceived += HandleNetCryptoData;

            // CORRECCIÓN: Mover suscripción a OnionClient aquí (una sola vez)
            _onionClient.OnDataReceived += HandleOnionDataReceived;
            _onionClient.OnFriendFound += HandleOnionFriendFound;

            Logger.Log.Info("[FriendConnection] Initialized");
        }

        #endregion

        #region IFriendConnection Implementation

        public bool CreateConnection(byte[] friendPublicKey, out int friendNumber)
        {
            friendNumber = -1;

            if (friendPublicKey == null || friendPublicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
            {
                Logger.Log.Error("[FriendConnection] Invalid public key");
                return false;
            }

            if (ConnectionCount >= MaxFriendConnectionsConst)
            {
                Logger.Log.Error("[FriendConnection] Max connections reached");
                return false;
            }

            if (_publicKeyToNumber.TryGetValue(friendPublicKey, out int existingNumber))
            {
                friendNumber = existingNumber;
                var existingConn = _friendConnections[friendNumber];

                if (existingConn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_NONE)
                {
                    existingConn.IncrementLock();
                    Logger.Log.Debug($"[FriendConnection] Incremented lock for friend {friendNumber}");
                }
                else
                {
                    Logger.Log.Debug($"[FriendConnection] Reconnecting existing friend {existingNumber}");
                    InitiateConnection(existingConn);
                }

                return true;
            }

            friendNumber = Interlocked.Increment(ref _nextFriendNumber);

            var conn = new FriendConn
            {
                FriendNumber = friendNumber,
                FriendPublicKey = (byte[])friendPublicKey.Clone(),
                Status = FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING,
                CreateTime = _monoTime.GetSeconds(),
                LastPingSent = 0,
                LastPongTime = 0,
                CryptoConnectionId = -1,
                OnionFallbackAttempts = 0,
                IsOnionFallback = false,
                OnionPathId = -1,
                LockCount = 1,

                TcpRelays = new NodeFormat[FriendMaxStoredTcpRelays],
                TcpRelayCounter = 0,

                DhtTempPk = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE],
                DhtLockToken = 0,
                DhtIpPort = null,
                DhtPkLastrecv = 0,
                DhtIpPortLastrecv = 0,

                Callbacks = new FriendConnCallbacks[MaxFriendConnectionCallbacks]
            };

            if (_friendConnections.TryAdd(friendNumber, conn))
            {
                _publicKeyToNumber[conn.FriendPublicKey] = friendNumber;

                Logger.Log.Info($"[FriendConnection] Created connection for friend {friendNumber}");

                // Setup onion
                try
                {
                    if (_onionClient.CreatePath(out int pathId))
                    {
                        conn.OnionPathId = pathId;
                        _onionClient.FindFriend(friendPublicKey);
                    }

                    
                }
                catch (Exception ex)
                {
                    Logger.Log.Warning($"[FriendConnection] Could not setup onion: {ex.Message}");
                }

                InitiateConnection(conn);
                return true;
            }

            return false;
        }

        public bool KillConnection(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            int newLockCount = conn.DecrementLock();

            if (newLockCount > 0)
            {
                Logger.Log.Debug($"[FriendConnection] Decremented lock for friend {friendNumber}, not killing");
                return true;
            }

            return KillConnectionInternal(friendNumber, conn);
        }

        private bool KillConnectionInternal(int friendNumber, FriendConn conn)
        {
            if (!_friendConnections.TryRemove(friendNumber, out _))
                return false;

            _publicKeyToNumber.TryRemove(conn.FriendPublicKey, out _);

            if (conn.OnionPathId >= 0)
            {
                try { _onionClient.KillPath(conn.OnionPathId); } catch { }
            }

            // Cerrar conexión crypto por ID
            if (conn.CryptoConnectionId >= 0)
            {
                try { _netCrypto.CloseConnection(conn.CryptoConnectionId); } catch { }
            }

            if (conn.DhtLockToken > 0)
            {
                try { _dht.DeleteFriend(conn.FriendPublicKey, conn.DhtLockToken); } catch { }
            }

            NotifyStatusChange(friendNumber, FriendConnectionStatus.FRIENDCONN_STATUS_NONE);

            Logger.Log.Info($"[FriendConnection] Killed connection for friend {friendNumber}");
            return true;
        }

        public FriendConnectionStatus GetConnectionStatus(int friendNumber)
        {
            if (_friendConnections.TryGetValue(friendNumber, out var conn))
                return conn.Status;

            return FriendConnectionStatus.FRIENDCONN_STATUS_NONE;
        }

        public bool IsFriendConnected(int friendNumber)
        {
            return GetConnectionStatus(friendNumber) == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED;
        }

        public int GetCryptoConnectionId(int friendNumber)
        {
            if (_friendConnections.TryGetValue(friendNumber, out var conn))
                return conn.CryptoConnectionId;

            return -1;
        }

        public bool LockConnection(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            conn.IncrementLock();
            return true;
        }

        public bool GetFriendPublicKeys(int friendNumber, out byte[] realPk, out byte[] dhtTempPk)
        {
            realPk = null;
            dhtTempPk = null;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            realPk = (byte[])conn.FriendPublicKey.Clone();
            dhtTempPk = (byte[])conn.DhtTempPk.Clone();
            return true;
        }

        public void SetDhtTempPk(int friendNumber, byte[] dhtTempPk, object userdata)
        {
            DhtPkCallback(friendNumber, dhtTempPk, userdata);
        }

        public int GetOnionFriendNumber(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return -1;

            return conn.OnionPathId;
        }

        public IPEndPoint GetDhtIpPort(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return null;

            return conn.DhtIpPort;
        }

        public int SendData(int friendNumber, byte[] data)
        {
            if (data == null || data.Length == 0)
                return -1;

            if (data.Length > MaxFriendConnectionPacketSize)
            {
                Logger.Log.Error($"[FriendConnection] Data too large: {data.Length} bytes");
                return -1;
            }

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return -1;

            if (conn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
                return -1;

            if (conn.CryptoConnectionId < 0 && !conn.IsOnionFallback)
                return -1;

            try
            {
                int sent;

                if (conn.IsOnionFallback && conn.OnionPathId >= 0)
                {
                    var packet = new byte[data.Length + 1];
                    packet[0] = PacketIdAlive;
                    Buffer.BlockCopy(data, 0, packet, 1, data.Length);

                    sent = _onionClient.SendData(conn.OnionPathId, conn.FriendPublicKey, packet) ? data.Length : -1;
                }
                else
                {
                    // Usar el endpoint actual de la conexión crypto
                    var endpoint = _netCrypto.GetEndpointForPublicKey(conn.FriendPublicKey);
                    if (endpoint == null)
                        return -1;

                    sent = _netCrypto.SendData(endpoint, data);
                }

                if (sent > 0)
                {
                    conn.LastActivityTime = _monoTime.GetSeconds();
                }

                return sent > 0 ? data.Length : -1;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendConnection] SendData error: {ex.Message}");
                return -1;
            }
        }

        public int SendDataPriority(int friendNumber, byte[] data)
        {
            return SendData(friendNumber, data);
        }

        public int SendLossyData(int friendNumber, byte[] data)
        {
            if (data == null || data.Length == 0 || data.Length > MaxFriendConnectionPacketSize)
                return -1;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return -1;

            if (conn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
                return -1;

            if (conn.CryptoConnectionId < 0 && !conn.IsOnionFallback)
                return -1;

            try
            {
                var endpoint = _netCrypto.GetEndpointForPublicKey(conn.FriendPublicKey);
                if (endpoint == null)
                    return -1;

                int sent = _netCrypto.SendData(endpoint, data);
                return sent > 0 ? data.Length : -1;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendConnection] SendLossyData error: {ex.Message}");
                return -1;
            }
        }

        public int SendFriendRequestPacket(int friendNumber, uint nospamNum, byte[] message)
        {
            if (message == null || message.Length == 0)
                return -1;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return -1;

            var packet = new byte[1 + sizeof(uint) + message.Length];
            packet[0] = PacketIdFriendRequests;
            BitConverter.GetBytes(nospamNum).CopyTo(packet, 1);
            message.CopyTo(packet, 1 + sizeof(uint));

            if (conn.Status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
            {
                var endpoint = _netCrypto.GetEndpointForPublicKey(conn.FriendPublicKey);
                if (endpoint == null)
                    return -1;

                int sent = _netCrypto.SendData(endpoint, packet);
                return sent > 0 ? 1 : 0;
            }
            else
            {
                if (conn.OnionPathId >= 0)
                {
                    bool sent = _onionClient.SendData(conn.OnionPathId, conn.FriendPublicKey, packet);
                    return sent ? 1 : 0;
                }
                return -1;
            }
        }

        public bool SetConnectionCallbacks(int friendNumber, int index,
            FriendConnectionStatusCallback statusCallback,
            FriendConnectionDataCallback dataCallback,
            FriendConnectionDataCallback lossyDataCallback,
            object callbackObject, int callbackId)
        {
            if (index < 0 || index >= MaxFriendConnectionCallbacks)
                return false;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            conn.Callbacks[index] = new FriendConnCallbacks
            {
                StatusCallback = statusCallback,
                DataCallback = dataCallback,
                LossyDataCallback = lossyDataCallback,
                CallbackObject = callbackObject,
                CallbackId = callbackId
            };

            return true;
        }

        public void RegisterStatusCallback(FriendConnectionStatusCallback callback, object userData)
        {
            if (callback == null) return;

            foreach (var kvp in _friendConnections)
            {
                SetConnectionCallbacks(kvp.Key, MessengerCallbackIndex, callback, null, null, userData, 0);
            }
        }

        public void RegisterDataCallback(FriendConnectionDataCallback callback, object userData)
        {
            if (callback == null) return;

            foreach (var kvp in _friendConnections)
            {
                SetConnectionCallbacks(kvp.Key, MessengerCallbackIndex, null, callback, null, userData, 0);
            }
        }

        public void RegisterLossyDataCallback(FriendConnectionDataCallback callback, object userData)
        {
            if (callback == null) return;

            foreach (var kvp in _friendConnections)
            {
                SetConnectionCallbacks(kvp.Key, MessengerCallbackIndex, null, null, callback, userData, 0);
            }
        }

        public void RegisterRequestCallback(FriendConnectionRequestCallback callback, object userData)
        {
            Logger.Log.Warning("[FriendConnection] Use SetFriendRequestCallback instead");
        }

        public void UnregisterStatusCallback(FriendConnectionStatusCallback callback)
        {
            foreach (var kvp in _friendConnections)
            {
                for (int i = 0; i < MaxFriendConnectionCallbacks; i++)
                {
                    if (kvp.Value.Callbacks[i]?.StatusCallback == callback)
                        kvp.Value.Callbacks[i].StatusCallback = null;
                }
            }
        }

        public void UnregisterDataCallback(FriendConnectionDataCallback callback)
        {
            foreach (var kvp in _friendConnections)
            {
                for (int i = 0; i < MaxFriendConnectionCallbacks; i++)
                {
                    if (kvp.Value.Callbacks[i]?.DataCallback == callback)
                        kvp.Value.Callbacks[i].DataCallback = null;
                }
            }
        }

        public void SetGlobalStatusCallback(FriendConnectionStatusCallback callback, object userData)
        {
            _globalStatusCallback = callback;
            _globalStatusCallbackObject = userData;
        }

        public byte[] GetFriendPublicKey(int friendNumber)
        {
            if (_friendConnections.TryGetValue(friendNumber, out var conn))
                return (byte[])conn.FriendPublicKey.Clone();

            return null;
        }

        public int GetFriendNumber(byte[] publicKey)
        {
            if (publicKey == null) return -1;

            if (_publicKeyToNumber.TryGetValue(publicKey, out int friendNumber))
                return friendNumber;

            return -1;
        }

        public void SetCryptoConnectionId(int friendNumber, int cryptoConnectionId)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            conn.CryptoConnectionId = cryptoConnectionId;
            Logger.Log.Debug($"[FriendConnection] Friend {friendNumber} crypto connection ID set to {cryptoConnectionId}");
        }

        public void NotifyCryptoConnected(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            bool statusChanged = false;

            if (conn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
            {
                statusChanged = true;
                conn.Status = FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED;
                conn.LastPongTime = _monoTime.GetSeconds();
                conn.LastActivityTime = _monoTime.GetSeconds();
                conn.ShareRelaysLastSent = 0;
            }

            if (statusChanged)
            {
                Logger.Log.Info($"[FriendConnection] Friend {friendNumber} connected");
                NotifyStatusChange(friendNumber, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED);
                SendPing(friendNumber);
            }
        }

        public void NotifyCryptoDisconnected(int friendNumber, FriendConnectionDisconnectReason reason)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            bool statusChanged = false;

            if (conn.Status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
            {
                statusChanged = true;
                conn.DhtPkLastrecv = _monoTime.GetSeconds();
            }

            conn.Status = FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING;
            conn.CryptoConnectionId = -1;
            conn.HostingTcpRelay = false;

            if (statusChanged)
            {
                Logger.Log.Info($"[FriendConnection] Friend {friendNumber} disconnected: {reason}");
                NotifyStatusChange(friendNumber, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING);
            }
        }

        public void DoFriendConnections()
        {
            var now = _monoTime.GetSeconds();

            foreach (var kvp in _friendConnections.ToArray())
            {
                var conn = kvp.Value;
                int friendNumber = kvp.Key;

                try
                {
                    ProcessConnectionMaintenance(conn, friendNumber, now);
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[FriendConnection] Error processing friend {friendNumber}: {ex.Message}");
                }
            }

            if (_lanDiscovery != null && _lanDiscovery.Enabled)
            {
                DoLanDiscovery(now);
            }
        }

        public void SetFriendRequestCallback(FriendRequestReceivedCallback callback, object obj)
        {
            _friendRequestCallback = callback;
            _friendRequestCallbackObject = obj;

            _netCrypto.RegisterPacketHandler(NetCrypto.PacketFriendRequest, HandleFriendRequestPacket);

            Logger.Log.Info("[FriendConnection] Friend request callback registered");
        }

        #endregion

        #region Métodos Privados

        private void InitiateConnection(FriendConn conn)
        {
            if (conn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_NONE &&
                conn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING)
                return;

            Logger.Log.Info($"[FriendConnection] Initiating connection to friend {conn.FriendNumber}");

            conn.LastConnectionAttempt = _monoTime.GetSeconds();
        }

        private void ProcessConnectionMaintenance(FriendConn conn, int friendNumber, ulong now)
        {
            if (conn.Status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING)
            {
                // Timeout DHT temp key (70 segundos)
                if (conn.DhtPkLastrecv > 0 && conn.DhtPkLastrecv + (ulong)FriendDhtTimeout < now)
                {
                    if (conn.DhtLockToken > 0)
                    {
                        try
                        {
                            _dht.DeleteFriend(conn.FriendPublicKey, conn.DhtLockToken);
                            conn.DhtLockToken = 0;
                            Array.Clear(conn.DhtTempPk, 0, conn.DhtTempPk.Length);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log.Error($"[FriendConnection] Error deleting DHT friend: {ex.Message}");
                        }
                    }
                }

                if (conn.DhtIpPortLastrecv > 0 && conn.DhtIpPortLastrecv + (ulong)FriendDhtTimeout < now)
                {
                    conn.DhtIpPort = null;
                }

                if (conn.DhtLockToken > 0)
                {
                    if (FriendNewConnection(friendNumber))
                    {
                        if (conn.DhtIpPort != null)
                        {
                            // Usar SetDirectIpPort si ya teníamos conexión
                            if (conn.CryptoConnectionId >= 0)
                            {
                                _netCrypto.SetDirectIpPort(conn.CryptoConnectionId, conn.DhtIpPort, true);
                            }
                        }

                        ConnectToSavedTcpRelays(friendNumber, MaxFriendTcpConnections / 2);
                    }
                }
            }
            else if (conn.Status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
            {
                if (conn.LastPingSent + (ulong)FriendPingInterval < now)
                {
                    SendPing(friendNumber);
                }

                if (conn.ShareRelaysLastSent + (ulong)ShareRelaysInterval < now)
                {
                    SendRelays(friendNumber);
                }

                if (conn.LastPongTime + (ulong)FriendConnectionTimeout < now)
                {
                    Logger.Log.Warning($"[FriendConnection] Friend {friendNumber} timeout");

                    if (conn.CryptoConnectionId >= 0)
                    {
                        _netCrypto.CloseConnection(conn.CryptoConnectionId);
                        conn.CryptoConnectionId = -1;
                    }

                    NotifyCryptoDisconnected(friendNumber, FriendConnectionDisconnectReason.FRIENDCONN_DISCONNECT_TIMEOUT);
                }
            }
        }

        private bool FriendNewConnection(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            if (conn.CryptoConnectionId >= 0)
                return false;

            if (conn.DhtLockToken == 0)
                return false;

            try
            {
                if (conn.DhtIpPort == null)
                    return false;

                if (!_netCrypto.EstablishSecureConnection(conn.DhtIpPort, conn.FriendPublicKey))
                    return false;

                // El ID real se asignará cuando se confirme la conexión
                conn.CryptoConnectionId = 0; // Placeholder

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendConnection] Error creating new connection: {ex.Message}");
                return false;
            }
        }

        private void DoLanDiscovery(ulong now)
        {
            if (_lastLanDiscovery + (ulong)LanDiscoveryInterval < now)
            {
                if (_lanDiscovery == null)
                    return;

                _lanDiscovery.SendDiscovery();

                _nextLanPort = (ushort)(_nextLanPort + PortsPerDiscovery);
                if (_nextLanPort > NetworkConstants.ToxPortRangeTo)
                    _nextLanPort = NetworkConstants.ToxPortRangeFrom + 1;

                _lastLanDiscovery = now;
            }
        }

        private void SendPing(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            if (conn.CryptoConnectionId < 0 && !conn.IsOnionFallback)
                return;

            try
            {
                var packet = new byte[] { PacketIdAlive };

                int sent;
                if (conn.IsOnionFallback && conn.OnionPathId >= 0)
                {
                    sent = _onionClient.SendData(conn.OnionPathId, conn.FriendPublicKey, packet) ? 1 : -1;
                }
                else
                {
                    var endpoint = _netCrypto.GetEndpointForPublicKey(conn.FriendPublicKey);
                    sent = endpoint != null ? _netCrypto.SendData(endpoint, packet) : -1;
                }

                if (sent > 0)
                {
                    conn.LastPingSent = _monoTime.GetSeconds();
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendConnection] Error sending ping: {ex.Message}");
            }
        }

        private void HandleNewConnections(IPEndPoint endpoint, byte[] publicKey)
        {
            if (publicKey == null)
                return;

            int friendNumber = GetFriendNumber(publicKey);

            if (friendNumber < 0)
            {
                HandleIncomingConnection(publicKey, endpoint);
                return;
            }

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            // Obtener el ID de conexión de NetCrypto
            int cryptoId = _netCrypto.GetConnectionId(endpoint);
            if (cryptoId < 0)
                cryptoId = _netCrypto.GetConnectionId(publicKey);

            if (conn.CryptoConnectionId >= 0 && conn.CryptoConnectionId != cryptoId)
            {
                Logger.Log.Warning($"[FriendConnection] Duplicate connection for friend {friendNumber}");
                return;
            }

            conn.CryptoConnectionId = cryptoId;

            if (endpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                endpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                // Usar SetDirectIpPort para actualizar la ruta
                if (conn.DhtIpPort != null && !conn.DhtIpPort.Equals(endpoint))
                {
                    _netCrypto.SetDirectIpPort(cryptoId, endpoint, true);
                }

                conn.DhtIpPort = endpoint;
                conn.DhtIpPortLastrecv = _monoTime.GetSeconds();
            }

            NotifyCryptoConnected(friendNumber);
        }

        private void HandleNetCryptoData(IPEndPoint endpoint, byte[] data)
        {
            if (data == null || data.Length < 1)
                return;

            byte[] publicKey = _netCrypto.GetPublicKeyForEndpoint(endpoint);
            if (publicKey == null)
                return;

            int friendNumber = GetFriendNumber(publicKey);
            if (friendNumber < 0)
                return;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            byte packetType = data[0];

            if (packetType == PacketIdAlive)
            {
                conn.LastPongTime = _monoTime.GetSeconds();
                conn.LastActivityTime = _monoTime.GetSeconds();
                return;
            }

            if (packetType == PacketIdShareRelays)
            {
                int offset = 1;
                while (offset < data.Length)
                {
                    if (TryDeserializeNode(data.AsSpan(offset), out var node, ref offset))
                    {
                        AddTcpRelay(friendNumber, node.IpPort, node.PublicKey);
                    }
                    else
                    {
                        break;
                    }
                }
                return;
            }

            if (packetType == PacketIdFriendRequests)
            {
                if (_friendRequestCallback != null)
                {
                    _friendRequestCallback(_friendRequestCallbackObject, publicKey, data, (uint)data.Length, null);
                }
                return;
            }

            NotifyDataReceived(friendNumber, data, false);
        }

        private void HandleFriendRequestPacket(IPEndPoint source, byte[] data, int length)
        {
            if (data == null || length < 1)
                return;

            if (length < 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return;

            byte[] senderPublicKey = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            Buffer.BlockCopy(data, 1, senderPublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            int messageOffset = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint);
            int messageLength = length - messageOffset;

            byte[] messageData = new byte[Math.Max(0, messageLength)];
            if (messageLength > 0)
            {
                Buffer.BlockCopy(data, messageOffset, messageData, 0, messageLength);
            }

            if (_friendRequestCallback != null)
            {
                try
                {
                    _friendRequestCallback(
                        _friendRequestCallbackObject,
                        senderPublicKey,
                        messageData,
                        (uint)messageData.Length,
                        null);
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[FriendConnection] Friend request callback error: {ex.Message}");
                }
            }
        }

        private void HandleOnionDataReceived(int pathId, IPEndPoint source, byte[] data)
        {
            int friendNumber = -1;
            foreach (var kvp in _friendConnections)
            {
                if (kvp.Value.OnionPathId == pathId)
                {
                    friendNumber = kvp.Key;
                    break;
                }
            }

            if (friendNumber < 0)
                return;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            if (data.Length < 1)
                return;

            byte packetType = data[0];
            byte[] payload = data.Length > 1 ? data.AsSpan(1).ToArray() : Array.Empty<byte>();

            switch (packetType)
            {
                case PacketIdAlive:
                    conn.LastPongTime = _monoTime.GetSeconds();
                    conn.LastActivityTime = _monoTime.GetSeconds();
                    break;

                case PacketIdShareRelays:
                    break;

                case PacketIdFriendRequests:
                    break;

                default:
                    NotifyDataReceived(friendNumber, payload, false);
                    break;
            }
        }

        private void HandleOnionFriendFound(byte[] publicKey, IPEndPoint endpoint)
        {
            int friendNumber = GetFriendNumber(publicKey);
            if (friendNumber < 0)
                return;

            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            conn.DhtIpPort = endpoint;
            conn.DhtIpPortLastrecv = _monoTime.GetSeconds();

            if (conn.Status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING)
            {
                FriendNewConnection(friendNumber);
            }
        }

        /// <summary>
        /// Maneja conexiones entrantes de desconocidos.
        /// Equivalente a handle_new_connections() en friend_connection.c cuando
        /// la conexión no está en nuestra lista de amigos.
        /// 
        /// Esto ocurre cuando:
        /// 1. Alguien nos envía una solicitud de amistad
        /// 2. Un amigo se conecta desde una IP diferente (NAT, móvil, etc.)
        /// 3. Reconexión después de timeout
        /// </summary>
        private void HandleIncomingConnection(byte[] publicKey, IPEndPoint endpoint)
        {
            Logger.Log.Debug($"[FriendConnection] Incoming connection from unknown peer {endpoint}, " +
                             $"PK: {Logger.SafeKeyThumb(publicKey)}");

            // Verificar si ya tenemos este amigo pero con diferente endpoint
            int existingFriendNumber = GetFriendNumber(publicKey);

            if (existingFriendNumber >= 0)
            {
                // Ya tenemos este amigo, actualizar conexión
                if (_friendConnections.TryGetValue(existingFriendNumber, out var existingConn))
                {
                    // Obtener el ID de conexión de NetCrypto
                    int cryptoId = _netCrypto.GetConnectionId(endpoint);
                    if (cryptoId < 0)
                        cryptoId = _netCrypto.GetConnectionId(publicKey);

                    if (cryptoId >= 0)
                    {
                        // Actualizar ID de conexión
                        existingConn.CryptoConnectionId = cryptoId;

                        // Actualizar endpoint si es diferente
                        if (existingConn.DhtIpPort == null || !existingConn.DhtIpPort.Equals(endpoint))
                        {
                            // Usar SetDirectIpPort para migrar la conexión
                            _netCrypto.SetDirectIpPort(cryptoId, endpoint, true);
                            existingConn.DhtIpPort = endpoint;
                            existingConn.DhtIpPortLastrecv = _monoTime.GetSeconds();
                        }

                        // Si estábamos en estado NONE o CONNECTING, notificar como conectado
                        if (existingConn.Status != FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED)
                        {
                            NotifyCryptoConnected(existingFriendNumber);
                        }

                        Logger.Log.Info($"[FriendConnection] Reconnected existing friend {existingFriendNumber} from {endpoint}");
                        return;
                    }
                }
            }

            // Verificar si hay callbacks de request registrados
            // En el C original, esto verifica si Messenger está esperando conexiones entrantes
            if (_requestCallbacks.Count > 0)
            {
                // Crear conexión temporal para el callback
                // Esto permite que Messenger maneje la solicitud
                if (CreateConnection(publicKey, out int tempFriendNumber))
                {
                    if (_friendConnections.TryGetValue(tempFriendNumber, out var conn))
                    {
                        // Obtener el ID de conexión de NetCrypto
                        int cryptoId = _netCrypto.GetConnectionId(endpoint);
                        if (cryptoId >= 0)
                        {
                            conn.CryptoConnectionId = cryptoId;
                            conn.DhtIpPort = endpoint;
                            conn.DhtIpPortLastrecv = _monoTime.GetSeconds();

                            // Notificar a los callbacks de request
                            bool accepted = false;
                            for (int i = 0; i < MaxFriendConnectionCallbacks; i++)
                            {
                                var cb = conn.Callbacks[i];
                                if (cb?.StatusCallback != null)
                                {
                                    try
                                    {
                                        // En el C original, esto llama al callback de Messenger
                                        // que decide si aceptar la conexión
                                        cb.StatusCallback(tempFriendNumber, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING, cb.CallbackObject);
                                        accepted = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        Logger.Log.Error($"[FriendConnection] Request callback error: {ex.Message}");
                                    }
                                }
                            }

                            if (accepted)
                            {
                                NotifyCryptoConnected(tempFriendNumber);
                                Logger.Log.Info($"[FriendConnection] Accepted incoming connection from {endpoint} as friend {tempFriendNumber}");
                                return;
                            }
                            else
                            {
                                // No se aceptó, matar la conexión temporal
                                KillConnection(tempFriendNumber);
                            }
                        }
                    }
                }
            }

            // Si llegamos aquí, no se pudo manejar la conexión
            // Cerrarla en NetCrypto para liberar recursos
            Logger.Log.Warning($"[FriendConnection] Rejecting incoming connection from {endpoint} - no handler accepted it");

            int rejectCryptoId = _netCrypto.GetConnectionId(endpoint);
            if (rejectCryptoId >= 0)
            {
                _netCrypto.CloseConnection(rejectCryptoId);
            }
            else
            {
                // Fallback: cerrar por endpoint
                _netCrypto.CloseConnection(endpoint);
            }
        }

        private void DhtPkCallback(int friendNumber, byte[] dhtPublicKey, object userdata)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            if (dhtPublicKey.SequenceEqual(conn.DhtTempPk))
                return;

            ChangeDhtPk(friendNumber, dhtPublicKey);

            if (conn.CryptoConnectionId >= 0)
            {
                _netCrypto.CloseConnection(conn.CryptoConnectionId);
                conn.CryptoConnectionId = -1;
                NotifyCryptoDisconnected(friendNumber, FriendConnectionDisconnectReason.FRIENDCONN_DISCONNECT_NONE);
            }
        }

        private void DhtIpCallback(int friendNumber, IPEndPoint ipPort)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            // CRÍTICO: Usar SetDirectIpPort para actualizar la ruta en NetCrypto
            if (conn.CryptoConnectionId >= 0 && ipPort != null)
            {
                bool result = _netCrypto.SetDirectIpPort(conn.CryptoConnectionId, ipPort, true);
                if (!result)
                {
                    Logger.Log.Warning($"[FriendConnection] Could not set direct IP/Port for friend {friendNumber}");
                }
            }

            conn.DhtIpPort = ipPort;
            conn.DhtIpPortLastrecv = _monoTime.GetSeconds();

            if (conn.HostingTcpRelay)
            {
                AddTcpRelay(friendNumber, ipPort, conn.DhtTempPk);
                conn.HostingTcpRelay = false;
            }
        }

        private void ChangeDhtPk(int friendNumber, byte[] dhtPublicKey)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            conn.DhtPkLastrecv = _monoTime.GetSeconds();

            if (conn.DhtLockToken > 0)
            {
                try
                {
                    _dht.DeleteFriend(conn.DhtTempPk, conn.DhtLockToken);
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[FriendConnection] Could not delete DHT peer: {ex.Message}");
                    return;
                }
                conn.DhtLockToken = 0;
            }

            try
            {
                int result = _dht.AddFriend(dhtPublicKey, out uint lockToken,
                    (data, number, ipPort) => DhtIpCallback(number, ipPort), friendNumber);

                if (result == 0)
                {
                    conn.DhtLockToken = lockToken;
                    Array.Copy(dhtPublicKey, conn.DhtTempPk, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendConnection] Could not add DHT friend: {ex.Message}");
            }
        }

        private bool AddTcpRelay(int friendNumber, IPEndPoint ipPort, byte[] publicKey)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return false;

            uint index = (uint)(conn.TcpRelayCounter % FriendMaxStoredTcpRelays);

            for (int i = 0; i < FriendMaxStoredTcpRelays; i++)
            {
                if (conn.TcpRelays[i].PublicKey != null &&
                    conn.TcpRelays[i].PublicKey.SequenceEqual(publicKey))
                {
                    conn.TcpRelays[i] = NodeFormat.Empty;
                }
            }

            conn.TcpRelays[index] = new NodeFormat
            {
                IpPort = ipPort,
                PublicKey = publicKey
            };
            conn.TcpRelayCounter++;

            Logger.Log.Debug($"[FriendConnection] Added TCP relay for friend {friendNumber} at {ipPort}");
            return true;
        }

        private void ConnectToSavedTcpRelays(int friendNumber, int number)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            if (conn.CryptoConnectionId < 0)
                return;

            int connected = 0;
            for (int i = 0; i < FriendMaxStoredTcpRelays && connected < number; i++)
            {
                uint index = (uint)((conn.TcpRelayCounter - (uint)(i + 1)) % FriendMaxStoredTcpRelays);

                if (conn.TcpRelays[index].PublicKey == null)
                    continue;

                connected++;
            }
        }

        private void SendRelays(int friendNumber)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            if (conn.CryptoConnectionId < 0 && !conn.IsOnionFallback)
                return;

            var relaysToSend = conn.TcpRelays
                .Where(r => r.PublicKey != null)
                .Take(MaxSharedRelays)
                .ToArray();

            if (relaysToSend.Length == 0)
                return;

            using var ms = new System.IO.MemoryStream();
            ms.WriteByte(PacketIdShareRelays);

            foreach (var relay in relaysToSend)
            {
                byte[] serialized = SerializeNode(relay);
                ms.Write(serialized, 0, serialized.Length);
            }

            var packet = ms.ToArray();

            int sent;
            if (conn.IsOnionFallback && conn.OnionPathId >= 0)
            {
                sent = _onionClient.SendData(conn.OnionPathId, conn.FriendPublicKey, packet) ? packet.Length : -1;
            }
            else
            {
                var endpoint = _netCrypto.GetEndpointForPublicKey(conn.FriendPublicKey);
                sent = endpoint != null ? _netCrypto.SendData(endpoint, packet) : -1;
            }

            if (sent > 0)
            {
                conn.ShareRelaysLastSent = _monoTime.GetSeconds();
                Logger.Log.Debug($"[FriendConnection] Sent {relaysToSend.Length} TCP relays to friend {friendNumber}");
            }
        }

        private byte[] SerializeNode(NodeFormat node)
        {
            using var ms = new System.IO.MemoryStream();
            bool isIPv6 = node.IpPort.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

            ms.WriteByte(isIPv6 ? (byte)10 : (byte)2);

            var ipBytes = isIPv6 ?
                node.IpPort.Address.GetAddressBytes() :
                node.IpPort.Address.MapToIPv4().GetAddressBytes();

            ms.Write(ipBytes, 0, ipBytes.Length);

            var portBytes = BitConverter.GetBytes((ushort)node.IpPort.Port);
            if (BitConverter.IsLittleEndian) Array.Reverse(portBytes);
            ms.Write(portBytes, 0, 2);

            ms.Write(node.PublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            return ms.ToArray();
        }

        private bool TryDeserializeNode(ReadOnlySpan<byte> data, out NodeFormat node, ref int offset)
        {
            node = NodeFormat.Empty;
            if (data.Length < 1) return false;

            try
            {
                byte family = data[0];
                bool isIPv6 = family == 10;
                int ipSize = isIPv6 ? 16 : 4;
                int totalSize = 1 + ipSize + 2 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE;

                if (data.Length < totalSize) return false;

                var ipBytes = data.Slice(1, ipSize).ToArray();
                ushort port = (ushort)((data[1 + ipSize] << 8) | data[1 + ipSize + 1]);
                var pk = data.Slice(1 + ipSize + 2, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();

                node = new NodeFormat
                {
                    PublicKey = pk,
                    IpPort = new IPEndPoint(new IPAddress(ipBytes), port)
                };

                offset += totalSize;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void NotifyStatusChange(int friendNumber, FriendConnectionStatus status)
        {
            _globalStatusCallback?.Invoke(friendNumber, status, _globalStatusCallbackObject);

            if (_friendConnections.TryGetValue(friendNumber, out var conn))
            {
                for (int i = 0; i < MaxFriendConnectionCallbacks; i++)
                {
                    var cb = conn.Callbacks[i];
                    if (cb?.StatusCallback != null)
                    {
                        try
                        {
                            cb.StatusCallback(friendNumber, status, cb.CallbackObject);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log.Error($"[FriendConnection] Status callback error: {ex.Message}");
                        }
                    }
                }
            }
        }

        private void NotifyDataReceived(int friendNumber, byte[] data, bool lossy)
        {
            if (!_friendConnections.TryGetValue(friendNumber, out var conn))
                return;

            for (int i = 0; i < MaxFriendConnectionCallbacks; i++)
            {
                var cb = conn.Callbacks[i];
                var callback = lossy ? cb?.LossyDataCallback : cb?.DataCallback;

                if (callback != null)
                {
                    try
                    {
                        callback(friendNumber, data, cb.CallbackObject);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log.Error($"[FriendConnection] Data callback error: {ex.Message}");
                    }
                }
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_netCrypto != null)
            {
                _netCrypto.OnConnectionSecured -= HandleNewConnections;
                _netCrypto.OnDataReceived -= HandleNetCryptoData;
            }

            if (_onionClient != null)
            {
                _onionClient.OnDataReceived -= HandleOnionDataReceived;
                _onionClient.OnFriendFound -= HandleOnionFriendFound;
            }

            foreach (var friendNumber in _friendConnections.Keys.ToArray())
            {
                if (_friendConnections.TryGetValue(friendNumber, out var conn))
                {
                    KillConnectionInternal(friendNumber, conn);
                }
            }

            _friendConnections.Clear();
            _publicKeyToNumber.Clear();

            _connectionLock.Dispose();

            Logger.Log.Info("[FriendConnection] Disposed");
        }

        #endregion

        #region Clases Auxiliares

        private class FriendConn
        {
            private int _lockCount;

            public int LockCount
            {
                get => _lockCount;
                set => _lockCount = value;
            }

            public int IncrementLock() => Interlocked.Increment(ref _lockCount);
            public int DecrementLock() => Interlocked.Decrement(ref _lockCount);

            public int FriendNumber { get; set; }
            public byte[] FriendPublicKey { get; set; }
            public FriendConnectionStatus Status { get; set; }
            public int CryptoConnectionId { get; set; } = -1;
            public int OnionPathId { get; set; } = -1;

            public ulong CreateTime { get; set; }
            public ulong LastPingSent { get; set; }
            public ulong LastPongTime { get; set; }
            public ulong LastActivityTime { get; set; }
            public ulong LastConnectionAttempt { get; set; }
            public ulong ShareRelaysLastSent { get; set; }

            public int OnionFallbackAttempts { get; set; }
            public bool IsOnionFallback { get; set; }

            public NodeFormat[] TcpRelays { get; set; }
            public uint TcpRelayCounter { get; set; }
            public bool HostingTcpRelay { get; set; }

            public byte[] DhtTempPk { get; set; }
            public uint DhtLockToken { get; set; }
            public IPEndPoint DhtIpPort { get; set; }
            public ulong DhtPkLastrecv { get; set; }
            public ulong DhtIpPortLastrecv { get; set; }

            public FriendConnCallbacks[] Callbacks { get; set; }
        }

        private class FriendConnCallbacks
        {
            public FriendConnectionStatusCallback StatusCallback { get; set; }
            public FriendConnectionDataCallback DataCallback { get; set; }
            public FriendConnectionDataCallback LossyDataCallback { get; set; }
            public object CallbackObject { get; set; }
            public int CallbackId { get; set; }
        }

        #endregion
    }
}