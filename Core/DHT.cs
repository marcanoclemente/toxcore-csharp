// Core/DHT.cs - Implementación completa corregida del DHT de ToxCore
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core
{
    /// <summary>
    /// Implementación completa y corregida de la tabla hash distribuida (DHT).
    /// Traducción fiel de dht.c con todas las correcciones para conexión real.
    /// </summary>
    public sealed class DHT : IDht, IDisposable
    {
        #region Constantes de dht.c

        private const int KillNodeTimeout = DhtConstants.BadNodeTimeout + DhtConstants.PingInterval;
        private const int CRYPTOSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE;

        // Tamaños de paquetes DHT
        private const int PingPlainSize = 1 + sizeof(ulong);
        private const int DhtPingSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + PingPlainSize + LibSodium.CRYPTO_MAC_SIZE;
        private const int NodesRequestSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_MAC_SIZE;
        private const int NodesResponseHeaderSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + sizeof(ushort);
        private const int MaxNodesResponseSize = NodesResponseHeaderSize + (DhtConstants.MaxSentNodes * DhtConstants.PackedNodeSizeIp6) + LibSodium.CRYPTO_MAC_SIZE;

        // NAT Punching
        private const int NatPingPlainSize = 1 + sizeof(ulong);
        private const int NatPingPacketSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + NatPingPlainSize + LibSodium.CRYPTO_MAC_SIZE;

        // Ping data size para PingArray
        private const int PingDataSize = LibSodium.CRYPTO_PUBLIC_KEY_SIZE + 18; // IP_Port serializado max (IPv6)

        #endregion

        #region Dependencias

        private readonly INetworkCore _network;
        private readonly MonoTime _monoTime;
        private readonly ISharedKeyCache _sharedKeysRecv;
        private readonly ISharedKeyCache _sharedKeysSent;
        private readonly ILanDiscoveryService _lanDiscovery;
        private readonly bool _holePunchingEnabled;
        private readonly bool _lanDiscoveryEnabled;

        #endregion

        #region Estado DHT

        private readonly byte[] _selfPublicKey = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
        private readonly byte[] _selfSecretKey = new byte[LibSodium.CRYPTO_SECRET_KEY_SIZE];

        // Listas de clientes (close_list) - LclientLength buckets de MaxFriendClients nodos cada uno
        private readonly ClientData[] _closeClientList;
        private ulong _closeLastNodesRequest;
        private uint _closeBootstrapTimes;

        // Lista de amigos (DHT friends)
        private DhtFriend[] _friendsList = Array.Empty<DhtFriend>();
        private ushort _numFriends;

        // Nodos cargados desde estado guardado
        private NodeFormat[] _loadedNodesList;
        private uint _loadedNumNodes;
        private uint _loadedNodesIndex;

        // Bootstrap
        private readonly NodeFormat[] _toBootstrap = new NodeFormat[DhtConstants.MaxCloseToBootstrapNodes];
        private uint _numToBootstrap;

        // Handlers de paquetes criptográficos
        private readonly CryptopacketHandler[] _cryptoPacketHandlers = new CryptopacketHandler[256];

        // Callbacks
        private DhtNodesResponseCallback _nodesResponseCallback;

        // PingArray interno para tracking de pings DHT
        private readonly PingArray _pingArray;

        // Lock para thread-safety
        private readonly object _lockDht = new();

        // Tiempo cacheado
        private ulong _curTime;
        private ulong _lastBootstrapAttempt;
        private int _bootstrapAttempts;

        #endregion

        #region Constructor e inicialización

        public DHT(
            INetworkCore network,
            MonoTime monoTime,
            ISharedKeyCache sharedKeysRecv,
            ISharedKeyCache sharedKeysSent,
            ILanDiscoveryService lanDiscovery = null!,
            bool holePunchingEnabled = true,
            bool lanDiscoveryEnabled = true,
            byte[] selfPublicKey = null!,
            byte[] selfSecretKey = null!)
        {
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _sharedKeysRecv = sharedKeysRecv ?? throw new ArgumentNullException(nameof(sharedKeysRecv));
            _sharedKeysSent = sharedKeysSent ?? throw new ArgumentNullException(nameof(sharedKeysSent));
            _holePunchingEnabled = holePunchingEnabled;
            _lanDiscoveryEnabled = lanDiscoveryEnabled;
            _lanDiscovery = lanDiscovery;

            // Inicializar PingArray para pings DHT (512 entradas, 5 segundos timeout)
            _pingArray = new PingArray(monoTime, DhtConstants.DhtPingArraySize, DhtConstants.PingTimeout);

            // Inicializar lista close - LclientLength * MaxFriendClients
            _closeClientList = new ClientData[DhtConstants.LclientList];
            for (int i = 0; i < _closeClientList.Length; i++)
                _closeClientList[i] = new ClientData();

            // Generar o usar keys proporcionadas
            if (selfPublicKey != null && selfSecretKey != null)
            {
                Buffer.BlockCopy(selfPublicKey, 0, _selfPublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(selfSecretKey, 0, _selfSecretKey, 0, LibSodium.CRYPTO_SECRET_KEY_SIZE);
            }
            else
            {
                LibSodium.TryCryptoBoxKeyPair(_selfPublicKey, _selfSecretKey);
            }

            // Crear amigos "fake" iniciales (para onion routing)
            InitializeFakeFriends();

            Logger.Log.Info($"[DHT] Initialized with public key: {Logger.SafeKeyThumb(_selfPublicKey)}");
        }

        public ushort LocalPort
        {
            get
            {
                if (_network is IUDPPortProvider udpProvider)
                    return udpProvider.LocalPort;

                // Fallback por reflection
                try
                {
                    var prop = _network.GetType().GetProperty("LocalPort");
                    if (prop != null)
                    {
                        var val = prop.GetValue(_network);
                        if (val is ushort u16) return u16;
                        if (val is int i32 && i32 > 0) return (ushort)i32;
                    }
                }
                catch { }

                return _network.Port;
            }
        }

        private void InitializeFakeFriends()
        {
            for (int i = 0; i < DhtConstants.DhtFakeFriendNumber; i++)
            {
                var randomPk = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                var randomSk = new byte[LibSodium.CRYPTO_SECRET_KEY_SIZE];
                LibSodium.TryCryptoBoxKeyPair(randomPk, randomSk);

                var result = AddFriend(randomPk, out _, null!, 0);
                if (result != 0)
                {
                    Logger.Log.Error($"[DHT] Failed to add fake friend {i}");
                    return;
                }
            }
        }

        #endregion

        #region IDht Implementation

        public ReadOnlySpan<byte> SelfPublicKey => _selfPublicKey;
        public ReadOnlySpan<byte> SelfSecretKey => _selfSecretKey;

        public bool IsConnected
        {
            get
            {
                var now = GetCurrentTime();
                lock (_lockDht)
                {
                    for (int i = 0; i < _closeClientList.Length; i++)
                    {
                        if (!AssocTimeout(now, _closeClientList[i].Assoc4) ||
                            !AssocTimeout(now, _closeClientList[i].Assoc6))
                            return true;
                    }
                }
                return false;
            }
        }

        public bool NonLanConnected
        {
            get
            {
                var now = GetCurrentTime();
                lock (_lockDht)
                {
                    for (int i = 0; i < _closeClientList.Length; i++)
                    {
                        var client = _closeClientList[i];
                        if ((!AssocTimeout(now, client.Assoc4) && !IsLanAddress(client.Assoc4.IpPort?.Address!)) ||
                            (!AssocTimeout(now, client.Assoc6) && !IsLanAddress(client.Assoc6.IpPort?.Address!)))
                            return true;
                    }
                }
                return false;
            }
        }

        public ushort NumFriends => _numFriends;

        public void CallbackNodesResponse(DhtNodesResponseCallback callback)
        {
            _nodesResponseCallback = callback;
        }

        public int AddFriend(byte[] publicKey, out uint lockToken, DhtIpCallback ipCallback = null!, int number = 0)
        {
            lockToken = 0;
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return -1;

            lock (_lockDht)
            {
                var friendNum = IndexOfFriendPk(publicKey);
                if (friendNum != uint.MaxValue)
                {
                    // Amigo ya existe, agregar callback
                    var token = DhtFriendLock(ref _friendsList[friendNum], ipCallback, number);
                    if (token == 0) return -1;
                    lockToken = token;
                    return 0;
                }

                // Crear nuevo amigo
                var newFriends = new DhtFriend[_numFriends + 1];
                if (_numFriends > 0)
                    Array.Copy(_friendsList, newFriends, _numFriends);

                newFriends[_numFriends] = new DhtFriend();
                ref var newFriend = ref newFriends[_numFriends];
                Buffer.BlockCopy(publicKey, 0, newFriend.PublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                newFriend.Nat.NatPingId = (ulong)Environment.TickCount64;

                _friendsList = newFriends;
                _numFriends++;

                lockToken = DhtFriendLock(ref _friendsList[_numFriends - 1], ipCallback, number);

                // Bootstrap inicial
                var nodes = new NodeFormat[DhtConstants.MaxSentNodes];
                int numNodes = GetCloseNodesInternal(publicKey, nodes, null, true, false);

                newFriend.NumToBootstrap = (uint)Math.Min(numNodes, DhtConstants.MaxSentNodes);
                if (newFriend.NumToBootstrap > 0)
                    Array.Copy(nodes, newFriend.ToBootstrap, (int)newFriend.NumToBootstrap);

                return 0;
            }
        }

        public int DeleteFriend(byte[] publicKey, uint lockToken)
        {
            if (publicKey == null) return -1;

            lock (_lockDht)
            {
                var friendNum = IndexOfFriendPk(publicKey);
                if (friendNum == uint.MaxValue) return -1;

                ref var friend = ref _friendsList[friendNum];
                DhtFriendUnlock(ref friend, lockToken);

                if (friend.LockFlags > 0) return 0;

                _numFriends--;
                if (_numFriends != friendNum)
                    _friendsList[friendNum] = _friendsList[_numFriends];

                if (_numFriends == 0)
                {
                    _friendsList = Array.Empty<DhtFriend>();
                }
                else
                {
                    var temp = new DhtFriend[_numFriends];
                    Array.Copy(_friendsList, temp, _numFriends);
                    _friendsList = temp;
                }

                return 0;
            }
        }

        public byte[] GetPublicKeyByIpPort(IPEndPoint endpoint)
        {
            if (endpoint == null) return null;

            lock (_lockDht)
            {
                try
                {
                    var now = GetCurrentTime();
                    var searchIp = endpoint.Address;
                    ushort searchPort = (ushort)endpoint.Port;

                    // Buscar en close_client_list
                    for (int i = 0; i < _closeClientList.Length; i++)
                    {
                        var client = _closeClientList[i];
                        if (client.PublicKey == null) continue;

                        if (!IsUnspec(client.Assoc4.IpPort) && !AssocTimeout(now, client.Assoc4))
                        {
                            if (IpPortMatches(client.Assoc4.IpPort, searchIp, searchPort))
                                return (byte[])client.PublicKey.Clone();
                        }

                        if (!IsUnspec(client.Assoc6.IpPort) && !AssocTimeout(now, client.Assoc6))
                        {
                            if (IpPortMatches(client.Assoc6.IpPort, searchIp, searchPort))
                                return (byte[])client.PublicKey.Clone();
                        }
                    }

                    // Buscar en lista de amigos
                    for (int i = 0; i < _numFriends; i++)
                    {
                        var friend = _friendsList[i];
                        if (friend.ClientList == null) continue;

                        for (int j = 0; j < friend.ClientList.Length; j++)
                        {
                            var client = friend.ClientList[j];
                            if (client.PublicKey == null) continue;

                            if (!IsUnspec(client.Assoc4.IpPort) && !AssocTimeout(now, client.Assoc4))
                            {
                                if (IpPortMatches(client.Assoc4.IpPort, searchIp, searchPort))
                                    return (byte[])client.PublicKey.Clone();
                            }

                            if (!IsUnspec(client.Assoc6.IpPort) && !AssocTimeout(now, client.Assoc6))
                            {
                                if (IpPortMatches(client.Assoc6.IpPort, searchIp, searchPort))
                                    return (byte[])client.PublicKey.Clone();
                            }
                        }
                    }

                    return null;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[DHT] Error in GetPublicKeyByIpPort: {ex.Message}");
                    return null;
                }
            }
        }

        public int GetFriendIp(byte[] publicKey, out IPEndPoint ipPort)
        {
            ipPort = null!;  // CORREGIDO: null-forgiving operator para out param
            if (publicKey == null) return -1;

            lock (_lockDht)  // CORREGIDO: usar _lockDht (no _friendsLock)
            {
                var friendIndex = IndexOfFriendPk(publicKey);
                if (friendIndex == uint.MaxValue) return -1;

                // CORREGIDO: DhtFriend es struct, usar ref para evitar copia
                ref var friend = ref _friendsList[friendIndex];  // CORREGIDO: _friendsList (no _friends)

                var now = GetCurrentTime();

                // CORREGIDO: ClientList es array de structs, usar ref
                for (int i = 0; i < friend.ClientList.Length; i++)
                {
                    ref var client = ref friend.ClientList[i];  // CORREGIDO: ref para struct

                    // CORREGIDO: Verificar PublicKey no sea null
                    if (client.PublicKey == null) continue;

                    if (PkEqual(client.PublicKey, publicKey))
                    {
                        // CORREGIDO: LastPinged está en Assoc4/Assoc6 (IpPtsPng), no en ClientData
                        // Verificar timeout usando AssocTimeout
                        if (!AssocTimeout(now, client.Assoc6))
                        {
                            ipPort = client.Assoc6.IpPort;
                            return 1;
                        }
                        if (!AssocTimeout(now, client.Assoc4))
                        {
                            ipPort = client.Assoc4.IpPort;
                            return 1;
                        }
                        return 0;  // Encontrado pero timeout
                    }
                }
                return -1;  // No encontrado
            }
        }

        public bool Bootstrap(IPEndPoint ipPort, byte[] publicKey)
        {
            if (PkEqual(publicKey, _selfPublicKey)) return true;

            // Agregar a lista de bootstrap pendiente
            lock (_lockDht)
            {
                if (_numToBootstrap < DhtConstants.MaxCloseToBootstrapNodes)
                {
                    _toBootstrap[_numToBootstrap] = new NodeFormat
                    {
                        PublicKey = (byte[])publicKey.Clone(),
                        IpPort = ipPort
                    };
                    _numToBootstrap++;
                }
            }

            return SendNodesRequest(ipPort, publicKey, _selfPublicKey);
        }

        public bool BootstrapFromAddress(string address, bool ipv6Enabled, bool dnsEnabled, ushort port, byte[] publicKey)
        {
            try
            {
                var family = ipv6Enabled ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                var addresses = Dns.GetHostAddresses(address);

                foreach (var ip in addresses)
                {
                    if (ip.AddressFamily == family || (ipv6Enabled && ip.AddressFamily == AddressFamily.InterNetwork))
                    {
                        var ep = new IPEndPoint(ip, port);
                        Bootstrap(ep, publicKey);

                        if (!ipv6Enabled) break;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Warning($"[DHT] Bootstrap failed for {address}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Dispatcher principal de paquetes DHT - equivalente a dht_handle_packet en C.
        /// </summary>
        public void DHT_handle_packet(byte[] data, int length, IPPort source)
        {
            if (data == null || length < 1) return;

            var sourceEp = new IPEndPoint(source.IP.ToIPAddress(), source.Port);

            // Verificar que es un paquete DHT válido (primer byte)
            byte packetType = data[0];

            switch ((NetPacketType)packetType)
            {
                case NetPacketType.PingRequest:
                    HandlePingRequest(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                case NetPacketType.PingResponse:
                    HandlePingResponse(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                case NetPacketType.NodesRequest:
                    HandleNodesRequest(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                case NetPacketType.NodesResponse:
                    HandleNodesResponse(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                case NetPacketType.Crypto:
                    HandleCryptoPacket(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                case NetPacketType.LanDiscovery:
                    HandleLanDiscovery(this, sourceEp, data.AsSpan(0, length), null);
                    break;

                default:
                    Logger.Log.DebugF("[DHT] Unknown packet type: 0x{0:X2}", packetType);
                    break;
            }
        }

        public void DoDht()
        {
            var curTime = _monoTime.GetSeconds();
            if (_curTime == curTime) return;
            _curTime = curTime;

            lock (_lockDht)
            {
                // Cargar nodos si es primera vez
                if (_loadedNumNodes > 0 && !NonLanConnected)
                {
                    ConnectAfterLoad();
                }

                // Bootstrap repetitivo hasta conexión
                if (!NonLanConnected && _monoTime.IsTimeout(_lastBootstrapAttempt, 5))
                {
                    DoBootstrap();
                    _lastBootstrapAttempt = curTime;
                    _bootstrapAttempts++;

                    // Limitar intentos para no spamear
                    if (_bootstrapAttempts > 100)
                    {
                        _bootstrapAttempts = 0;
                        Logger.Log.Warning("[DHT] Bootstrap attempts exceeded, resetting");
                    }
                }

                DoClose();
                DoDhtFriends();
                DoNat();
            }
        }

        public int GetCloseNodes(byte[] publicKey, NodeFormat[] nodesList, AddressFamily? family = null, bool isLan = false, bool wantAnnounce = false)
        {
            if (nodesList == null || nodesList.Length < DhtConstants.MaxSentNodes)
                throw new ArgumentException("nodesList must have at least MaxSentNodes capacity");

            lock (_lockDht)
            {
                return GetCloseNodesInternal(publicKey, nodesList, family, isLan, wantAnnounce);
            }
        }

        public bool AddToList(NodeFormat[] nodesList, uint length, byte[] pk, IPEndPoint ipPort, byte[] cmpPk)
        {
            if (nodesList == null || pk == null || ipPort == null || cmpPk == null) return false;

            var pkCur = (byte[])pk.Clone();
            var ipPortCur = ipPort;

            bool inserted = false;

            for (int i = 0; i < length && i < nodesList.Length; i++)
            {
                if (IdClosest(cmpPk, nodesList[i].PublicKey, pkCur) == 2)
                {
                    var pkBak = nodesList[i].PublicKey;
                    var ipPortBak = nodesList[i].IpPort;

                    nodesList[i].PublicKey = pkCur;
                    nodesList[i].IpPort = ipPortCur;

                    pkCur = pkBak;
                    ipPortCur = ipPortBak;
                    inserted = true;
                }
            }

            return inserted;
        }

        public bool IsNodeAddableToCloseList(byte[] publicKey, IPEndPoint ipPort)
        {
            if (publicKey == null || ipPort == null) return false;

            lock (_lockDht)
            {
                return AddToClose(publicKey, ipPort, true);
            }
        }

        public int RoutePacket(byte[] publicKey, ReadOnlySpan<byte> packet)
        {
            if (publicKey == null || packet.IsEmpty) return -1;

            lock (_lockDht)
            {
                for (int i = 0; i < _closeClientList.Length; i++)
                {
                    if (_closeClientList[i].PublicKey != null &&
                        PkEqual(publicKey, _closeClientList[i].PublicKey))
                    {
                        var client = _closeClientList[i];
                        IpPtsPng assoc;

                        if (!IsUnspec(client.Assoc6.IpPort))
                            assoc = client.Assoc6;
                        else if (!IsUnspec(client.Assoc4.IpPort))
                            assoc = client.Assoc4;
                        else
                            continue;

                        var data = packet.ToArray();
                        return _network.SendPacket(assoc.IpPort, data, data.Length);
                    }
                }
            }
            return -1;
        }

        public uint RouteToFriend(byte[] friendId, NetPacket packet)
        {
            if (friendId == null || packet.Data.IsEmpty) return 0;

            lock (_lockDht)
            {
                var friendNum = IndexOfFriendPk(friendId);
                if (friendNum == uint.MaxValue) return 0;

                ref var friend = ref _friendsList[friendNum];
                var ipList = new IPEndPoint[DhtConstants.MaxFriendClients];
                int ipNum = FriendIpList(ref friend, ipList);

                if (ipNum < DhtConstants.MaxFriendClients / 4) return 0;

                uint count = 0;
                var packetBytes = packet.Data.ToArray();

                for (int i = 0; i < ipNum; i++)
                {
                    var sent = _network.SendPacket(ipList[i], packetBytes, packetBytes.Length);
                    if (sent == packetBytes.Length)
                        count++;
                }

                return count;
            }
        }

        public uint AddToLists(IPEndPoint ipPort, byte[] publicKey)
        {
            if (ipPort == null || publicKey == null) return 0;

            var ippCopy = IpPortNormalize(ipPort);
            uint used = 0;

            lock (_lockDht)
            {
                // Agregar a close_list
                bool inCloseList = ClientOrIpPortInList(_closeClientList, publicKey, ippCopy);
                if (inCloseList || AddToClose(publicKey, ippCopy, false))
                {
                    used++;
                }

                // Agregar a friends
                for (int i = 0; i < _numFriends; i++)
                {
                    ref var friend = ref _friendsList[i];
                    bool inList = ClientOrIpPortInList(friend.ClientList, publicKey, ippCopy);

                    if (inList || ReplaceAll(friend.ClientList, publicKey, ippCopy, friend.PublicKey))
                    {
                        if (PkEqual(publicKey, friend.PublicKey))
                        {
                            NotifyFriendIpFound(ref friend, ippCopy);
                        }
                        used++;
                    }
                }
            }

            return used;
        }

        public void RegisterCryptoHandler(byte packetId, CryptoPacketHandlerCallback callback, object state = null!)
        {
            if (packetId >= 255) return;
            _cryptoPacketHandlers[packetId] = new CryptopacketHandler
            {
                Function = callback,
                Object = state
            };
        }

        public uint GetSaveSize()
        {
            lock (_lockDht)
            {
                uint numv4 = 0, numv6 = 0;

                foreach (var client in _closeClientList)
                {
                    if (client.Assoc4.Timestamp != 0) numv4++;
                    if (client.Assoc6.Timestamp != 0) numv6++;
                }

                return (uint)(sizeof(uint) + 8 +
                    (DhtConstants.PackedNodeSizeIp4 * numv4) +
                    (DhtConstants.PackedNodeSizeIp6 * numv6));
            }
        }

        public void Save(Span<byte> data)
        {
            if (data.Length < GetSaveSize()) throw new ArgumentException("Buffer too small");

            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(0, 4), DhtConstants.DhtStateCookieGlobal);

            int offset = 8;

            lock (_lockDht)
            {
                // Guardar nodos IPv4
                foreach (var client in _closeClientList)
                {
                    if (client.Assoc4.Timestamp != 0 && client.PublicKey != null)
                    {
                        if (PackNode(data.Slice(offset), client.PublicKey, client.Assoc4.IpPort, false))
                            offset += DhtConstants.PackedNodeSizeIp4;
                    }
                }

                // Guardar nodos IPv6
                foreach (var client in _closeClientList)
                {
                    if (client.Assoc6.Timestamp != 0 && client.PublicKey != null)
                    {
                        if (PackNode(data.Slice(offset), client.PublicKey, client.Assoc6.IpPort, true))
                            offset += DhtConstants.PackedNodeSizeIp6;
                    }
                }
            }

            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(4, 4), (uint)(offset - 8));
        }

        public int Load(ReadOnlySpan<byte> data)
        {
            if (data.Length < sizeof(uint)) return -1;

            uint cookie = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
            if (cookie != DhtConstants.DhtStateCookieGlobal) return -1;

            if (data.Length < 8) return -1;
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
            if (data.Length < 8 + length) return -1;

            var nodes = new List<NodeFormat>();
            int offset = 8;

            while (offset < 8 + length)
            {
                if (UnpackNode(data.Slice(offset), out var node))
                {
                    nodes.Add(node);
                    offset += node.IpPort.AddressFamily == AddressFamily.InterNetworkV6
                        ? DhtConstants.PackedNodeSizeIp6
                        : DhtConstants.PackedNodeSizeIp4;
                }
                else
                {
                    break;
                }
            }

            _loadedNodesList = nodes.ToArray();
            _loadedNumNodes = (uint)nodes.Count;
            _loadedNodesIndex = 0;

            return 0;
        }

        public int ConnectAfterLoad()
        {
            lock (_lockDht)
            {
                if (_loadedNodesList == null || _loadedNumNodes == 0) return -1;

                if (NonLanConnected)
                {
                    _loadedNodesList = null!;
                    _loadedNumNodes = 0;
                    return 0;
                }

                for (uint i = 0; i < _loadedNumNodes && i < DhtConstants.SaveBootstrapFrequency; i++)
                {
                    uint index = _loadedNodesIndex % _loadedNumNodes;
                    Bootstrap(_loadedNodesList[index].IpPort, _loadedNodesList[index].PublicKey);
                    _loadedNodesIndex++;
                }
            }

            return 0;
        }

        public byte[] GetSharedKeyRecv(byte[] publicKey) =>
            _sharedKeysRecv?.Lookup(publicKey)!;

        public byte[] GetSharedKeySent(byte[] publicKey) =>
            _sharedKeysSent?.Lookup(publicKey)!;

        public void SetHolePunchingEnabled(bool enabled)
        {
            // Implementación en futura versión
        }

        #endregion

        #region Gestión de nodos cercanos (close_list) - CORREGIDO

        private int GetCloseNodesInternal(byte[] publicKey, NodeFormat[] nodesList, AddressFamily? family, bool isLan, bool wantAnnounce)
        {
            for (int i = 0; i < nodesList.Length; i++)
                nodesList[i] = NodeFormat.Empty;

            int saFamily = family switch
            {
                AddressFamily.InterNetwork => 2,
                AddressFamily.InterNetworkV6 => 10,
                _ => 0
            };

            uint numNodes = 0;

            GetCloseNodesInner(publicKey, nodesList, ref numNodes, saFamily, _closeClientList, isLan, wantAnnounce);

            for (int i = 0; i < _numFriends; i++)
            {
                GetCloseNodesInner(publicKey, nodesList, ref numNodes, saFamily, _friendsList[i].ClientList, isLan, wantAnnounce);
            }

            return (int)numNodes;
        }

        private void GetCloseNodesInner(byte[] publicKey, NodeFormat[] nodesList, ref uint numNodesPtr,
            int saFamily, ClientData[] clientList, bool isLan, bool wantAnnounce)
        {
            if (saFamily != 2 && saFamily != 10 && saFamily != 0) return;

            uint numNodes = numNodesPtr;
            var now = GetCurrentTime();

            for (int i = 0; i < clientList.Length && numNodes < DhtConstants.MaxSentNodes; i++)
            {
                var client = clientList[i];
                IpPtsPng ipptp = new IpPtsPng();

                if (saFamily == 2) ipptp = client.Assoc4;
                else if (saFamily == 10) ipptp = client.Assoc6;
                else if (client.Assoc4.Timestamp >= client.Assoc6.Timestamp) ipptp = client.Assoc4;
                else ipptp = client.Assoc6;

                if (AssocTimeout(now, ipptp)) continue;
                if (IsLanAddress(ipptp.IpPort?.Address) && !isLan) continue;

                // Verificar duplicados
                bool alreadyInList = false;
                for (int j = 0; j < numNodes; j++)
                {
                    if (PkEqual(nodesList[j].PublicKey, client.PublicKey))
                    {
                        alreadyInList = true;
                        break;
                    }
                }
                if (alreadyInList) continue;

                nodesList[numNodes] = new NodeFormat
                {
                    PublicKey = (byte[])client.PublicKey.Clone(),
                    IpPort = ipptp.IpPort
                };
                numNodes++;
            }

            numNodesPtr = numNodes;
        }

        /// <summary>
        /// Agrega nodo a close_list con lógica de reemplazo LRU corregida.
        /// </summary>
        private bool AddToClose(byte[] publicKey, IPEndPoint ipPort, bool simulate)
        {
            // Calcular índice de bucket basado en XOR distance
            int bucketIdx = BitByBitCmp(publicKey, _selfPublicKey);
            if (bucketIdx >= DhtConstants.LclientLength) bucketIdx = DhtConstants.LclientLength - 1;

            var now = GetCurrentTime();
            int startIdx = bucketIdx * DhtConstants.MaxFriendClients;

            lock (_lockDht)
            {
                // Primero: buscar slot vacío
                for (int i = 0; i < DhtConstants.MaxFriendClients; i++)
                {
                    ref var client = ref _closeClientList[startIdx + i];
                    if (AssocTimeout(now, client.Assoc4) && AssocTimeout(now, client.Assoc6))
                    {
                        if (simulate) return true;

                        client.PublicKey = (byte[])publicKey.Clone();
                        UpdateClientWithReset(ref client, ipPort);
                        return true;
                    }
                }

                // Si no hay slot vacío y no es simulación, reemplazar el más lejano
                if (!simulate)
                {
                    int replaceIdx = FindFarthestNode(startIdx, DhtConstants.MaxFriendClients, publicKey);
                    if (replaceIdx >= 0)
                    {
                        ref var client = ref _closeClientList[replaceIdx];
                        client.PublicKey = (byte[])publicKey.Clone();
                        UpdateClientWithReset(ref client, ipPort);
                        return true;
                    }
                }

                return false;
            }
        }

        /// <summary>
        /// Encuentra el nodo más lejano en un rango de la lista.
        /// </summary>
        private int FindFarthestNode(int startIdx, int count, byte[] targetPk)
        {
            int farthestIdx = -1;
            int maxDistance = -1;
            var now = GetCurrentTime();

            for (int i = 0; i < count; i++)
            {
                int idx = startIdx + i;
                var client = _closeClientList[idx];

                // Solo considerar nodos válidos
                if (client.PublicKey == null ||
                    (AssocTimeout(now, client.Assoc4) && AssocTimeout(now, client.Assoc6)))
                    continue;

                // Calcular distancia XOR
                int distance = CalculateXorDistance(client.PublicKey, targetPk);

                if (distance > maxDistance)
                {
                    maxDistance = distance;
                    farthestIdx = idx;
                }
            }

            return farthestIdx;
        }

        /// <summary>
        /// Calcula distancia XOR entre dos claves públicas.
        /// </summary>
        private int CalculateXorDistance(byte[] pk1, byte[] pk2)
        {
            int distance = 0;
            for (int i = 0; i < LibSodium.CRYPTO_PUBLIC_KEY_SIZE; i++)
            {
                byte xor = (byte)(pk1[i] ^ pk2[i]);
                // Contar bits set (distancia de Hamming ponderada por posición)
                for (int j = 0; j < 8; j++)
                {
                    if ((xor & (1 << (7 - j))) != 0)
                        distance += (i * 8) + j;
                }
            }
            return distance;
        }

        private static void UpdateClientWithReset(ref ClientData client, IPEndPoint ipPort)
        {
            if (ipPort.AddressFamily == AddressFamily.InterNetwork)
            {
                client.Assoc4 = new IpPtsPng
                {
                    IpPort = ipPort,
                    Timestamp = (ulong)Environment.TickCount64 / 1000
                };
            }
            else
            {
                client.Assoc6 = new IpPtsPng
                {
                    IpPort = ipPort,
                    Timestamp = (ulong)Environment.TickCount64 / 1000
                };
            }
        }

        private bool ClientOrIpPortInList(ClientData[] list, byte[] publicKey, IPEndPoint ipPort)
        {
            var now = GetCurrentTime();

            for (int i = 0; i < list.Length; i++)
            {
                if (list[i].PublicKey != null && PkEqual(list[i].PublicKey, publicKey))
                {
                    UpdateClientTimestamp(ref list[i], ipPort, now);
                    return true;
                }
            }

            for (int i = 0; i < list.Length; i++)
            {
                var assoc = ipPort.AddressFamily == AddressFamily.InterNetwork ? list[i].Assoc4 : list[i].Assoc6;
                if (assoc.IpPort?.Equals(ipPort) == true)
                {
                    list[i].PublicKey = (byte[])publicKey.Clone();
                    if (ipPort.AddressFamily == AddressFamily.InterNetwork)
                        list[i].Assoc4 = new IpPtsPng { IpPort = ipPort, Timestamp = now };
                    else
                        list[i].Assoc6 = new IpPtsPng { IpPort = ipPort, Timestamp = now };
                    return true;
                }
            }

            return false;
        }

        private void UpdateClientTimestamp(ref ClientData client, IPEndPoint ipPort, ulong now)
        {
            if (ipPort.AddressFamily == AddressFamily.InterNetwork)
            {
                client.Assoc4 = new IpPtsPng
                {
                    IpPort = ipPort,
                    Timestamp = now,
                    LastPinged = client.Assoc4.LastPinged,
                    RetIpPort = client.Assoc4.RetIpPort,
                    RetTimestamp = client.Assoc4.RetTimestamp
                };
            }
            else
            {
                client.Assoc6 = new IpPtsPng
                {
                    IpPort = ipPort,
                    Timestamp = now,
                    LastPinged = client.Assoc6.LastPinged,
                    RetIpPort = client.Assoc6.RetIpPort,
                    RetTimestamp = client.Assoc6.RetTimestamp
                };
            }
        }

        private bool ReplaceAll(ClientData[] list, byte[] publicKey, IPEndPoint ipPort, byte[] compPublicKey)
        {
            var now = GetCurrentTime();

            // Buscar slot vacío o el más lejano para reemplazar
            int replaceIdx = -1;
            int maxDistance = -1;

            for (int i = 0; i < list.Length; i++)
            {
                if (AssocTimeout(now, list[i].Assoc4) && AssocTimeout(now, list[i].Assoc6))
                {
                    replaceIdx = i;
                    break;
                }

                // Calcular distancia XOR para encontrar el más lejano
                if (list[i].PublicKey != null)
                {
                    int dist = CalculateXorDistance(list[i].PublicKey, compPublicKey);
                    if (dist > maxDistance)
                    {
                        maxDistance = dist;
                        replaceIdx = i;
                    }
                }
            }

            if (replaceIdx >= 0)
            {
                list[replaceIdx] = new ClientData
                {
                    PublicKey = (byte[])publicKey.Clone(),
                    Assoc4 = ipPort.AddressFamily == AddressFamily.InterNetwork ?
                        new IpPtsPng { IpPort = ipPort, Timestamp = now } : list[replaceIdx].Assoc4,
                    Assoc6 = ipPort.AddressFamily == AddressFamily.InterNetworkV6 ?
                        new IpPtsPng { IpPort = ipPort, Timestamp = now } : list[replaceIdx].Assoc6
                };
                return true;
            }
            return false;
        }

        #endregion

        #region Gestión de amigos (DHT friends)

        private uint IndexOfFriendPk(byte[] publicKey)
        {
            for (uint i = 0; i < _numFriends; i++)
            {
                if (_friendsList[i].PublicKey != null && PkEqual(_friendsList[i].PublicKey, publicKey))
                    return i;
            }
            return uint.MaxValue;
        }

        private uint DhtFriendLock(ref DhtFriend friend, DhtIpCallback ipCallback, int number)
        {
            for (byte lockNum = 0; lockNum < DhtConstants.DhtFriendMaxLocks; lockNum++)
            {
                uint lockToken = (uint)(1 << lockNum);
                if ((friend.LockFlags & lockToken) == 0)
                {
                    friend.LockFlags |= lockToken;
                    if (friend.Callbacks[lockNum] == null)
                        friend.Callbacks[lockNum] = new DhtFriendCallback();
                    friend.Callbacks[lockNum].IpCallback = ipCallback;
                    friend.Callbacks[lockNum].Data = null;
                    friend.Callbacks[lockNum].Number = number;
                    return lockToken;
                }
            }
            return 0;
        }

        private void DhtFriendUnlock(ref DhtFriend friend, uint lockToken)
        {
            if ((lockToken & friend.LockFlags) == 0) return;

            for (byte lockNum = 0; lockNum < DhtConstants.DhtFriendMaxLocks; lockNum++)
            {
                if (((1 << lockNum) & lockToken) > 0)
                {
                    friend.LockFlags &= ~lockToken;
                    if (friend.Callbacks[lockNum] != null)
                    {
                        friend.Callbacks[lockNum].IpCallback = null;
                    }
                    return;
                }
            }
        }

        private void NotifyFriendIpFound(ref DhtFriend friend, IPEndPoint ipPort)
        {
            for (int i = 0; i < DhtConstants.DhtFriendMaxLocks; i++)
            {
                if ((friend.LockFlags & (1 << i)) > 0 && friend.Callbacks[i] != null)
                {
                    var callback = friend.Callbacks[i].IpCallback;
                    if (callback != null)
                    {
                        callback(friend.Callbacks[i].Data, friend.Callbacks[i].Number, ipPort);
                    }
                }
            }
        }

        private int FriendIpList(ref DhtFriend friend, IPEndPoint[] ipPortList)
        {
            int count = 0;
            var now = GetCurrentTime();

            for (int i = 0; i < friend.ClientList.Length && count < ipPortList.Length; i++)
            {
                var client = friend.ClientList[i];

                if (!IsUnspec(client.Assoc4.IpPort) && !AssocTimeout(now, client.Assoc4))
                {
                    ipPortList[count++] = client.Assoc4.IpPort;
                }

                if (count < ipPortList.Length && !IsUnspec(client.Assoc6.IpPort) && !AssocTimeout(now, client.Assoc6))
                {
                    ipPortList[count++] = client.Assoc6.IpPort;
                }
            }

            return count;
        }

        #endregion

        #region Sistema de Ping DHT integrado

        /// <summary>
        /// Envía ping request DHT usando PingArray para tracking.
        /// </summary>
        private void SendPingRequest(IPEndPoint ipPort, byte[] publicKey)
        {
            if (PkEqual(publicKey, _selfPublicKey)) return;

            var sharedKey = _sharedKeysSent.Lookup(publicKey);
            if (sharedKey == null) return;

            // Agregar a PingArray para tracking
            byte[] pingData = new byte[PingDataSize];
            Buffer.BlockCopy(publicKey, 0, pingData, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            byte[] ipPortBytes = IpPortToBytes(ipPort);
            Buffer.BlockCopy(ipPortBytes, 0, pingData, LibSodium.CRYPTO_PUBLIC_KEY_SIZE, Math.Min(ipPortBytes.Length, 18));

            ulong pingId = _pingArray.Add(pingData);
            if (pingId == 0) return;

            // Construir paquete
            byte[] packet = new byte[DhtPingSize];
            packet[0] = (byte)NetPacketType.PingRequest;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[PingPlainSize];
            plain[0] = (byte)NetPacketType.PingRequest;
            Buffer.BlockCopy(BitConverter.GetBytes(pingId), 0, plain, 1, sizeof(ulong));

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(ipPort, packet, packet.Length);
        }

        private void SendPingResponse(IPEndPoint ipPort, byte[] publicKey, ulong pingId, byte[] sharedKey)
        {
            if (PkEqual(publicKey, _selfPublicKey)) return;

            byte[] packet = new byte[DhtPingSize];
            packet[0] = (byte)NetPacketType.PingResponse;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[PingPlainSize];
            plain[0] = (byte)NetPacketType.PingResponse;
            Buffer.BlockCopy(BitConverter.GetBytes(pingId), 0, plain, 1, sizeof(ulong));

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(ipPort, packet, packet.Length);
        }

        private static void HandlePingRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;
            if (packet.Length != DhtPingSize) return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, dht._selfPublicKey)) return;

            var sharedKey = dht._sharedKeysRecv.Lookup(senderPk);
            if (sharedKey == null) return;

            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[PingPlainSize];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            if (plain[0] != (byte)NetPacketType.PingRequest) return;

            ulong pingId = BitConverter.ToUInt64(plain, 1);

            // Responder
            dht.SendPingResponse(source, senderPk, pingId, sharedKey);

            // Agregar a listas
            dht.AddToLists(source, senderPk);
        }

        private static void HandlePingResponse(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;
            if (packet.Length != DhtPingSize) return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, dht._selfPublicKey)) return;

            var sharedKey = dht._sharedKeysSent.Lookup(senderPk);
            if (sharedKey == null) return;

            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[PingPlainSize];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            if (plain[0] != (byte)NetPacketType.PingResponse) return;

            ulong pingId = BitConverter.ToUInt64(plain, 1);

            // Verificar en PingArray
            byte[] data = new byte[PingDataSize];
            if (dht._pingArray.Check(pingId, data) != PingDataSize)
                return;

            // Verificar que el public key coincide
            if (!PkEqual(senderPk, data.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray()))
                return;

            // Agregar a listas DHT
            dht.AddToLists(source, senderPk);
        }

        #endregion

        #region NAT Punching

        private bool SendNatPingRequest(IPEndPoint ipPort, byte[] friendPublicKey, ulong natPingId)
        {
            if (PkEqual(friendPublicKey, _selfPublicKey)) return false;

            var sharedKey = _sharedKeysSent.Lookup(friendPublicKey);
            if (sharedKey == null) return false;

            byte[] packet = new byte[NatPingPacketSize];
            packet[0] = (byte)NetPacketType.Crypto;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[NatPingPlainSize];
            plain[0] = DhtConstants.NatPingRequest;
            Buffer.BlockCopy(BitConverter.GetBytes(natPingId), 0, plain, 1, sizeof(ulong));

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return false;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            return _network.SendPacket(ipPort, packet, packet.Length) == packet.Length;
        }

        private bool SendNatPingResponse(IPEndPoint ipPort, byte[] friendPublicKey, ulong natPingId)
        {
            if (PkEqual(friendPublicKey, _selfPublicKey)) return false;

            var sharedKey = _sharedKeysRecv.Lookup(friendPublicKey);
            if (sharedKey == null) return false;

            byte[] packet = new byte[NatPingPacketSize];
            packet[0] = (byte)NetPacketType.Crypto;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[NatPingPlainSize];
            plain[0] = DhtConstants.NatPingResponse;
            Buffer.BlockCopy(BitConverter.GetBytes(natPingId), 0, plain, 1, sizeof(ulong));

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return false;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            return _network.SendPacket(ipPort, packet, packet.Length) == packet.Length;
        }

        private void HandleNatPing(object state, IPEndPoint source, ReadOnlySpan<byte> packet, byte[] senderPk, byte[] sharedKey)
        {
            var dht = (DHT)state;

            if (packet.Length < NatPingPlainSize + LibSodium.CRYPTO_MAC_SIZE) return;

            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[NatPingPlainSize];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            byte natType = plain[0];
            ulong natPingId = BitConverter.ToUInt64(plain, 1);

            lock (dht._lockDht)
            {
                for (int i = 0; i < dht._numFriends; i++)
                {
                    ref var friend = ref dht._friendsList[i];
                    if (!PkEqual(friend.PublicKey, senderPk)) continue;

                    if (natType == DhtConstants.NatPingRequest)
                    {
                        dht.SendNatPingResponse(source, senderPk, natPingId);
                        friend.Nat.RecvNatPingTimestamp = dht.GetCurrentTime();
                    }
                    else if (natType == DhtConstants.NatPingResponse)
                    {
                        if (friend.Nat.NatPingId == natPingId)
                        {
                            friend.Nat.NatPingTimestamp = dht.GetCurrentTime();
                            dht.PunchHoles(ref friend);
                        }
                    }
                }
            }
        }

        private void PunchHoles(ref DhtFriend friend)
        {
            if (!_holePunchingEnabled) return;

            var now = GetCurrentTime();

            if (friend.Nat.PunchingTimestamp + DhtConstants.PunchInterval > now) return;

            friend.Nat.PunchingTimestamp = now;

            var ipList = new IPEndPoint[DhtConstants.MaxFriendClients];
            int ipNum = FriendIpList(ref friend, ipList);

            if (ipNum == 0) return;

            for (int i = 0; i < ipNum && i < DhtConstants.MaxNormalPunchingTries; i++)
            {
                for (int j = 0; j < DhtConstants.MaxPunchingPorts; j++)
                {
                    int port = ipList[i].Port + j - (DhtConstants.MaxPunchingPorts / 2);
                    if (port <= 0 || port > 65535) continue;

                    var target = new IPEndPoint(ipList[i].Address, port);
                    SendPingRequest(target, friend.PublicKey);
                }
            }
        }

        #endregion

        #region Requests de Nodos (Nodes Request/Response) - CORREGIDO

        private bool SendNodesRequest(IPEndPoint ipPort, byte[] publicKey, byte[] clientId)
        {
            if (PkEqual(publicKey, _selfPublicKey)) return false;

            var sharedKey = _sharedKeysSent.Lookup(publicKey);
            if (sharedKey == null) return false;

            byte[] packet = new byte[NodesRequestSize];
            packet[0] = (byte)NetPacketType.NodesRequest;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            Buffer.BlockCopy(clientId, 0, plain, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return false;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            Logger.Log.DebugF("[DHT] Sending nodes request to {0}", ipPort);
            return _network.SendPacket(ipPort, packet, packet.Length) == packet.Length;
        }

        /// <summary>
        /// CORREGIDO: Ahora usa el nonce del request para la respuesta.
        /// </summary>
        private bool SendNodesResponse(IPEndPoint ipPort, byte[] publicKey, byte[] requestNonce, byte[] clientId)
        {
            if (PkEqual(publicKey, _selfPublicKey)) return false;

            var sharedKey = _sharedKeysRecv.Lookup(publicKey);
            if (sharedKey == null) return false;

            // Obtener nodos cercanos al clientId
            var nodesList = new NodeFormat[DhtConstants.MaxSentNodes];
            int numNodes = GetCloseNodesInternal(clientId, nodesList, null, true, false);

            if (numNodes == 0) return false;

            // Empaquetar nodos
            byte[] nodesData = new byte[DhtConstants.MaxSentNodes * DhtConstants.PackedNodeSizeIp6];
            int nodesDataLen = 0;

            for (int i = 0; i < numNodes; i++)
            {
                bool isIPv6 = nodesList[i].IpPort.AddressFamily == AddressFamily.InterNetworkV6;
                int nodeSize = isIPv6 ? DhtConstants.PackedNodeSizeIp6 : DhtConstants.PackedNodeSizeIp4;

                if (PackNode(nodesData.AsSpan(nodesDataLen), nodesList[i].PublicKey, nodesList[i].IpPort, isIPv6))
                    nodesDataLen += nodeSize;
            }

            if (nodesDataLen == 0) return false;

            // Construir paquete
            byte[] packet = new byte[NodesResponseHeaderSize + nodesDataLen + LibSodium.CRYPTO_MAC_SIZE];
            packet[0] = (byte)NetPacketType.NodesResponse;

            Buffer.BlockCopy(_selfPublicKey, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            // CORRECCIÓN: Usar el nonce del request, no generar nuevo
            Buffer.BlockCopy(requestNonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE), (ushort)numNodes);

            // Cifrar datos de nodos
            byte[] cipher = new byte[nodesDataLen + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, nodesData.AsSpan(0, nodesDataLen).ToArray(), requestNonce, sharedKey))
                return false;

            Buffer.BlockCopy(cipher, 0, packet, NodesResponseHeaderSize, cipher.Length);

            return _network.SendPacket(ipPort, packet, packet.Length) == packet.Length;
        }

        private static void HandleNodesRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;

            if (packet.Length != NodesRequestSize)
            {
                Logger.Log.DebugF("[DHT] Invalid nodes request size: {0}", packet.Length);
                return;
            }

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, dht._selfPublicKey))
            {
                Logger.Log.Debug("[DHT] Received nodes request from self");
                return;
            }

            var sharedKey = dht._sharedKeysRecv.Lookup(senderPk);
            if (sharedKey == null) return;

            // Descifrar
            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            // CORRECCIÓN: Pasar el nonce del request para la respuesta
            dht.SendNodesResponse(source, senderPk, nonce, plain);
            dht.AddToLists(source, senderPk);

            Logger.Log.DebugF("[DHT] Received nodes request from {0}", source);
        }

        private static void HandleNodesResponse(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;

            if (packet.Length < NodesResponseHeaderSize + LibSodium.CRYPTO_MAC_SIZE)
            {
                Logger.Log.DebugF("[DHT] Nodes response too short: {0}", packet.Length);
                return;
            }

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, dht._selfPublicKey)) return;

            var sharedKey = dht._sharedKeysSent.Lookup(senderPk);
            if (sharedKey == null) return;

            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            ushort numNodes = BinaryPrimitives.ReadUInt16LittleEndian(packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, 2));

            var cipher = packet.Slice(NodesResponseHeaderSize).ToArray();
            int plainLen = cipher.Length - LibSodium.CRYPTO_MAC_SIZE;
            byte[] plain = new byte[plainLen];

            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            // Desempaquetar nodos
            int offset = 0;
            for (int i = 0; i < numNodes; i++)
            {
                if (UnpackNode(plain.AsSpan(offset), out var node))
                {
                    dht.AddToLists(node.IpPort, node.PublicKey);
                    dht._nodesResponseCallback?.Invoke(dht, node, userdata);

                    offset += node.IpPort.AddressFamily == AddressFamily.InterNetworkV6
                        ? DhtConstants.PackedNodeSizeIp6
                        : DhtConstants.PackedNodeSizeIp4;
                }
                else
                {
                    break;
                }
            }

            Logger.Log.DebugF("[DHT] Received nodes response from {0} with {1} nodes", source, numNodes);
        }

        #endregion

        #region Serialización de paquetes (pack/unpack nodes)

        private static bool PackNode(Span<byte> buffer, byte[] publicKey, IPEndPoint ipPort, bool isIPv6)
        {
            if (isIPv6)
            {
                if (buffer.Length < DhtConstants.PackedNodeSizeIp6) return false;

                buffer[0] = 10; // TOX_AF_INET6
                ipPort.Address.GetAddressBytes().CopyTo(buffer.Slice(1, 16));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(17, 2), (ushort)ipPort.Port);
                publicKey.AsSpan().CopyTo(buffer.Slice(19, 32));
            }
            else
            {
                if (buffer.Length < DhtConstants.PackedNodeSizeIp4) return false;

                buffer[0] = 2; // TOX_AF_INET
                var ip4Bytes = ipPort.Address.MapToIPv4().GetAddressBytes();
                ip4Bytes.CopyTo(buffer.Slice(1, 4));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(5, 2), (ushort)ipPort.Port);
                publicKey.AsSpan().CopyTo(buffer.Slice(7, 32));
            }

            return true;
        }

        private static bool UnpackNode(ReadOnlySpan<byte> data, out NodeFormat node)
        {
            node = NodeFormat.Empty;

            if (data.Length < 1) return false;

            byte family = data[0];
            bool isIPv6;
            int expectedSize;

            switch (family)
            {
                case 2: // TOX_AF_INET
                    isIPv6 = false;
                    expectedSize = DhtConstants.PackedNodeSizeIp4;
                    break;
                case 10: // TOX_AF_INET6
                    isIPv6 = true;
                    expectedSize = DhtConstants.PackedNodeSizeIp6;
                    break;
                default:
                    return false;
            }

            if (data.Length < expectedSize) return false;

            IPAddress address;
            int portOffset;
            int pkOffset;

            if (isIPv6)
            {
                byte[] ipBytes = data.Slice(1, 16).ToArray();
                address = new IPAddress(ipBytes);
                portOffset = 17;
                pkOffset = 19;
            }
            else
            {
                byte[] ipBytes = data.Slice(1, 4).ToArray();
                address = new IPAddress(ipBytes);
                portOffset = 5;
                pkOffset = 7;
            }

            ushort port = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(portOffset, 2));
            byte[] publicKey = data.Slice(pkOffset, 32).ToArray();

            node = new NodeFormat
            {
                PublicKey = publicKey,
                IpPort = new IPEndPoint(address, port)
            };

            return true;
        }

        private byte[] IpPortToBytes(IPEndPoint ipPort)
        {
            var addrBytes = ipPort.Address.GetAddressBytes();
            var result = new byte[18];

            int ipLen = addrBytes.Length;
            Buffer.BlockCopy(addrBytes, 0, result, 0, ipLen);
            result[ipLen] = (byte)(ipPort.Port >> 8);
            result[ipLen + 1] = (byte)(ipPort.Port & 0xFF);

            return result;
        }

        #endregion

        #region Handlers de paquetes de red - CORREGIDO

        /// <summary>
        /// CORREGIDO: Ahora re-encripta paquetes para routing en lugar de reenviar crudo.
        /// </summary>
        private static void HandleCryptoPacket(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;

            if (packet.Length < LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE + 1 + LibSodium.CRYPTO_MAC_SIZE)
            {
                Logger.Log.DebugF("[DHT] Crypto packet too short: {0}", packet.Length);
                return;
            }

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            var targetPk = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            // Si es para nosotros
            if (targetPk.SequenceEqual(dht._selfPublicKey))
            {
                // Verificar si es NAT ping
                if (packet.Length == NatPingPacketSize)
                {
                    var sharedKeyB = dht._sharedKeysRecv.Lookup(senderPk);
                    if (sharedKeyB != null)
                    {
                        dht.HandleNatPing(dht, source, packet, senderPk, sharedKeyB);
                        return;
                    }
                }

                // Buscar handler registrado
                var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
                var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

                var sharedKey = dht._sharedKeysRecv.Lookup(senderPk);
                if (sharedKey == null) return;

                byte[] plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                    return;

                byte packetId = plain[0];
                var handler = dht._cryptoPacketHandlers[packetId];

                // CORRECCIÓN: Verificar que Function no sea null antes de invocar
                if (handler.Function != null)
                {
                    handler.Function(handler.Object, source, senderPk, plain.AsSpan(1), userdata);
                }
                else
                {
                    Logger.Log.DebugF("[DHT] No handler for crypto packet type {0:X2}", packetId);
                }
            }
            else
            {
                // CORRECCIÓN: Re-encriptar para el destino, no reenviar crudo
                dht.RouteCryptoPacket(targetPk.ToArray(), senderPk, packet);
            }
        }

        /// <summary>
        /// NUEVO: Rutea paquetes criptográficos re-encriptándolos para el destino.
        /// </summary>
        private void RouteCryptoPacket(byte[] targetPk, byte[] senderPk, ReadOnlySpan<byte> encryptedPacket)
        {
            // Buscar el nodo destino en nuestra tabla
            IPEndPoint targetEndpoint = null;

            lock (_lockDht)
            {
                for (int i = 0; i < _closeClientList.Length; i++)
                {
                    if (_closeClientList[i].PublicKey != null &&
                        PkEqual(_closeClientList[i].PublicKey, targetPk))
                    {
                        var client = _closeClientList[i];
                        var now = GetCurrentTime();

                        if (!AssocTimeout(now, client.Assoc6))
                        {
                            targetEndpoint = client.Assoc6.IpPort;
                            break;
                        }
                        if (!AssocTimeout(now, client.Assoc4))
                        {
                            targetEndpoint = client.Assoc4.IpPort;
                            break;
                        }
                    }
                }
            }

            if (targetEndpoint == null)
            {
                Logger.Log.Debug("[DHT] Cannot route crypto packet: target not found");
                return;
            }

            // Extraer nonce y datos cifrados del paquete original
            var nonce = encryptedPacket.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = encryptedPacket.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            // Descifrar con nuestra clave compartida con el remitente
            var sharedKeyWithSender = _sharedKeysRecv.Lookup(senderPk);
            if (sharedKeyWithSender == null) return;

            byte[] plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKeyWithSender))
                return;

            // Re-encriptar con nuestra clave compartida con el destino
            var sharedKeyWithTarget = _sharedKeysSent.Lookup(targetPk);
            if (sharedKeyWithTarget == null) return;

            var newNonce = LibSodium.GenerateNonce();
            byte[] newCipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(newCipher, plain, newNonce, sharedKeyWithTarget))
                return;

            // Construir nuevo paquete
            byte[] routedPacket = new byte[1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE + newCipher.Length];
            routedPacket[0] = (byte)NetPacketType.Crypto;
            Buffer.BlockCopy(senderPk, 0, routedPacket, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(targetPk, 0, routedPacket, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(newNonce, 0, routedPacket, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(newCipher, 0, routedPacket, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 2 + LibSodium.CRYPTO_NONCE_SIZE, newCipher.Length);

            _network.SendPacket(targetEndpoint, routedPacket, routedPacket.Length);
            Logger.Log.DebugF("[DHT] Routed crypto packet from {0} to {1}",
                Logger.SafeKeyThumb(senderPk), Logger.SafeKeyThumb(targetPk));
        }

        private static void HandleLanDiscovery(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var dht = (DHT)state;

            if (dht._lanDiscovery != null && !dht._lanDiscovery.IsLanIp(source.Address))
            {
                Logger.Log.Debug($"[DHT] LAN discovery from non-LAN IP {source} - rejected");
                return;
            }

            if (!dht._lanDiscoveryEnabled) return;
            if (packet.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE + 1) return;

            var publicKey = packet.Slice(1).ToArray();
            dht.Bootstrap(source, publicKey);

            Logger.Log.DebugF("[DHT] LAN discovery from {0}", source);
        }

        #endregion

        #region Ciclo principal (DoDht) - CORREGIDO

        private void DoBootstrap()
        {
            // Bootstrap desde nodos cargados
            if (_loadedNumNodes > 0)
            {
                ConnectAfterLoad();
            }

            // Bootstrap desde lista de nodos pendientes
            for (int i = 0; i < _numToBootstrap; i++)
            {
                if (_toBootstrap[i].PublicKey != null && _toBootstrap[i].IpPort != null)
                {
                    SendNodesRequest(_toBootstrap[i].IpPort, _toBootstrap[i].PublicKey, _selfPublicKey);
                }
            }
            _numToBootstrap = 0;
        }

        private void DoClose()
        {
            var now = GetCurrentTime();

            // Solicitar nodos periódicamente
            if (_monoTime.IsTimeout(_closeLastNodesRequest, DhtConstants.NodesRequestInterval))
            {
                _closeLastNodesRequest = now;

                var randomNodes = GetRandomNodesFromCloseList(2);
                foreach (var node in randomNodes)
                {
                    SendNodesRequest(node.IpPort, node.PublicKey, _selfPublicKey);
                    SendPingRequest(node.IpPort, node.PublicKey);
                }
            }
        }

        private void DoDhtFriends()
        {
            var now = GetCurrentTime();

            for (int i = 0; i < _numFriends; i++)
            {
                ref var friend = ref _friendsList[i];

                // Bootstrap inicial
                for (int j = 0; j < friend.NumToBootstrap; j++)
                {
                    SendNodesRequest(friend.ToBootstrap[j].IpPort, friend.ToBootstrap[j].PublicKey, friend.PublicKey);
                }
                friend.NumToBootstrap = 0;

                // Enviar pings NAT periódicamente
                if (friend.Nat.NatPingTimestamp + DhtConstants.PingInterval <= now)
                {
                    friend.Nat.NatPingId = (ulong)Random.Shared.NextInt64();
                    friend.Nat.NatPingTimestamp = now;

                    for (int j = 0; j < friend.ClientList.Length; j++)
                    {
                        ref var client = ref friend.ClientList[j];
                        if (!IsUnspec(client.Assoc4.IpPort) && !AssocTimeout(now, client.Assoc4))
                        {
                            SendNatPingRequest(client.Assoc4.IpPort, friend.PublicKey, friend.Nat.NatPingId);
                        }
                        if (!IsUnspec(client.Assoc6.IpPort) && !AssocTimeout(now, client.Assoc6))
                        {
                            SendNatPingRequest(client.Assoc6.IpPort, friend.PublicKey, friend.Nat.NatPingId);
                        }
                    }
                }

                // Solicitar nodos cercanos al amigo periódicamente
                if (friend.LastNodesRequest + DhtConstants.NodesRequestInterval <= now)
                {
                    friend.LastNodesRequest = now;

                    int requestsSent = 0;
                    for (int j = 0; j < friend.ClientList.Length && requestsSent < 4; j++)
                    {
                        ref var client = ref friend.ClientList[j];
                        if (!IsUnspec(client.Assoc4.IpPort) && !AssocTimeout(now, client.Assoc4))
                        {
                            SendNodesRequest(client.Assoc4.IpPort, client.PublicKey, friend.PublicKey);
                            SendPingRequest(client.Assoc4.IpPort, client.PublicKey);
                            requestsSent++;
                        }
                        else if (!IsUnspec(client.Assoc6.IpPort) && !AssocTimeout(now, client.Assoc6))
                        {
                            SendNodesRequest(client.Assoc6.IpPort, client.PublicKey, friend.PublicKey);
                            SendPingRequest(client.Assoc6.IpPort, client.PublicKey);
                            requestsSent++;
                        }
                    }
                }
            }
        }

        private void DoNat()
        {
            if (!_holePunchingEnabled) return;

            var now = GetCurrentTime();

            for (int i = 0; i < _numFriends; i++)
            {
                ref var friend = ref _friendsList[i];

                if (friend.Nat.HolePunching &&
                    friend.Nat.PunchingTimestamp + DhtConstants.PunchInterval <= now)
                {
                    PunchHoles(ref friend);
                }
            }
        }

        private NodeFormat[] GetRandomNodesFromCloseList(int count)
        {
            var result = new List<NodeFormat>();
            var now = GetCurrentTime();

            var validNodes = new List<ClientData>();
            for (int i = 0; i < _closeClientList.Length; i++)
            {
                if (_closeClientList[i].PublicKey != null &&
                    (!AssocTimeout(now, _closeClientList[i].Assoc4) || !AssocTimeout(now, _closeClientList[i].Assoc6)))
                {
                    validNodes.Add(_closeClientList[i]);
                }
            }

            if (validNodes.Count > 0)
            {
                var random = new Random();
                var selected = validNodes.OrderBy(x => random.Next()).Take(count);

                foreach (var node in selected)
                {
                    var assoc = !AssocTimeout(now, node.Assoc6) ? node.Assoc6 : node.Assoc4;
                    result.Add(new NodeFormat
                    {
                        PublicKey = node.PublicKey,
                        IpPort = assoc.IpPort
                    });
                }
            }

            return result.ToArray();
        }

        #endregion

        #region Utilidades privadas

        private static int IdClosest(byte[] pk, byte[] pk1, byte[] pk2)
        {
            for (int i = 0; i < LibSodium.CRYPTO_PUBLIC_KEY_SIZE; i++)
            {
                byte distance1 = (byte)(pk[i] ^ pk1[i]);
                byte distance2 = (byte)(pk[i] ^ pk2[i]);

                if (distance1 < distance2) return 1;
                if (distance1 > distance2) return 2;
            }
            return 0;
        }

        private static int BitByBitCmp(byte[] pk1, byte[] pk2)
        {
            for (int i = 0; i < LibSodium.CRYPTO_PUBLIC_KEY_SIZE; i++)
            {
                if (pk1[i] == pk2[i]) continue;

                for (int j = 0; j < 8; j++)
                {
                    byte mask = (byte)(1 << (7 - j));
                    if ((pk1[i] & mask) != (pk2[i] & mask))
                        return i * 8 + j;
                }
                break;
            }
            return LibSodium.CRYPTO_PUBLIC_KEY_SIZE * 8;
        }

        private static bool AssocTimeout(ulong curTime, IpPtsPng assoc) =>
            assoc?.Timestamp == 0 || assoc.Timestamp + DhtConstants.BadNodeTimeout <= curTime;

        private static bool AssocKillTimeout(ulong curTime, IpPtsPng assoc) =>
            assoc?.Timestamp == 0 || assoc.Timestamp + KillNodeTimeout <= curTime;

        private static IPEndPoint IpPortNormalize(IPEndPoint ipPort)
        {
            if (ipPort.Address.IsIPv4MappedToIPv6)
                return new IPEndPoint(ipPort.Address.MapToIPv4(), ipPort.Port);
            return ipPort;
        }

        private static bool PkEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            return a.AsSpan().SequenceEqual(b);
        }

        private static bool IsLanAddress(IPAddress ip)
        {
            if (ip == null) return false;
            if (IPAddress.IsLoopback(ip)) return true;

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return bytes[0] == 10 ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168) ||
                       (bytes[0] == 169 && bytes[1] == 254);
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();
                if (bytes[0] == 0xFF && bytes[1] == 0x02) return true; // Link-local multicast
                if ((bytes[0] & 0xFE) == 0xFE && (bytes[1] & 0xC0) == 0x80) return true; // Link-local
                if ((bytes[0] & 0xFE) == 0xFC) return true; // Unique local
            }
            return false;
        }

        private static bool IsUnspec(IPEndPoint ep) =>
            ep == null || ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.IPv6Any);

        private ulong GetCurrentTime() => _monoTime.GetSeconds();

        private bool IpPortMatches(IPEndPoint stored, IPAddress searchIp, ushort searchPort)
        {
            if (stored == null || stored.Port != searchPort) return false;

            var storedIp = stored.Address;

            if (storedIp.Equals(searchIp)) return true;

            if (storedIp.IsIPv4MappedToIPv6 && searchIp.AddressFamily == AddressFamily.InterNetwork)
                return storedIp.MapToIPv4().Equals(searchIp);

            if (searchIp.IsIPv4MappedToIPv6 && storedIp.AddressFamily == AddressFamily.InterNetwork)
                return searchIp.MapToIPv4().Equals(storedIp);

            return false;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _pingArray?.Dispose();
            _lanDiscovery?.Kill();
            CryptographicOperations.ZeroMemory(_selfSecretKey);
            Logger.Log.Info("[DHT] Disposed");
        }

        #endregion
    }

    #region Estructuras de datos DHT

    public struct DhtFriend
    {
        public byte[] PublicKey;
        public ClientData[] ClientList;
        public ulong LastNodesRequest;
        public uint BootstrapTimes;
        public NatState Nat;
        public uint LockFlags;
        public DhtFriendCallback[] Callbacks;
        public NodeFormat[] ToBootstrap;
        public uint NumToBootstrap;

        public DhtFriend()
        {
            PublicKey = new byte[32];
            ClientList = new ClientData[DhtConstants.MaxFriendClients];
            for (int i = 0; i < ClientList.Length; i++) ClientList[i] = new ClientData();
            Callbacks = new DhtFriendCallback[DhtConstants.DhtFriendMaxLocks];
            ToBootstrap = new NodeFormat[DhtConstants.MaxSentNodes];
            Nat = new NatState();
        }
    }

    public struct NatState
    {
        public bool HolePunching;
        public uint PunchingIndex;
        public uint Tries;
        public uint PunchingIndex2;
        public ulong PunchingTimestamp;
        public ulong RecvNatPingTimestamp;
        public ulong NatPingId;
        public ulong NatPingTimestamp;
    }

    public struct CryptopacketHandler
    {
        public CryptoPacketHandlerCallback Function;
        public object Object;
    }

    #endregion
}