// Core/Messenger.cs - CORREGIDO (arreglar conflictos de tipos y callbacks)
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using Toxcore.Core.Crypto;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.Onion;

namespace ToxCore.Core
{
    public sealed class Messenger : IMessenger, IDisposable
    {
        #region Constantes del Protocolo

        public const uint ToxVersionMajor = 0;
        public const uint ToxVersionMinor = 2;
        public const uint ToxVersionPatch = 18;

        public const int ToxPublicKeySize = 32;
        public const int ToxSecretKeySize = 32;
        public const int ToxAddressSize = 38;
        public const int ToxMaxNameLength = 128;
        public const int ToxMaxStatusMessageLength = 1007;
        public const int ToxMaxFriendRequestLength = 1016;
        public const int ToxMaxMessageLength = 1372;

        private const byte PacketIdFriendRequest = 0x20;
        private const byte PacketIdFriendMessage = 0x21;
        private const byte PacketIdFriendName = 0x22;
        private const byte PacketIdFriendStatusMessage = 0x23;
        private const byte PacketIdFriendUserStatus = 0x24;

        #endregion

        #region Dependencias Inyectadas

        private readonly MonoTime _monoTime;
        private readonly INetworkCore _network;
        private readonly IDht _dht;
        private readonly INetCrypto _netCrypto;
        private readonly IOnionClient _onionClient;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;
        private readonly IPing _ping;

        #endregion

        #region Estado del Messenger

        private readonly byte[] _selfPublicKey = new byte[ToxPublicKeySize];
        private readonly byte[] _selfSecretKey = new byte[ToxSecretKeySize];
        private uint _nospam;
        private ushort _checksum;

        private byte[] _selfName = Array.Empty<byte>();
        private byte[] _selfStatusMessage = Array.Empty<byte>();
        private ToxUserStatus _selfStatus = ToxUserStatus.Online;

        private readonly ConcurrentDictionary<int, Friend> _friends = new();
        private int _nextFriendNumber = 1;

        private ToxConnectionStatus _selfConnectionStatus = ToxConnectionStatus.None;
        private ulong _lastConnectionStatusCheck;

        private bool _isRunning;
        private readonly object _iterateLock = new();

        #endregion

        #region Callbacks Públicos (API limpia)

        private MessengerFriendRequestCallback _friendRequestCallback;
        private FriendMessageCallback _friendMessageCallback;
        private FriendNameCallback _friendNameCallback;
        private FriendStatusMessageCallback _friendStatusMessageCallback;
        private FriendToxConnectionStatusCallback _friendToxConnectionStatusCallback;
        private FriendStatusCallback _friendStatusCallback;
        private SelfConnectionStatusCallback _selfConnectionStatusCallback;

        #endregion

        #region Callbacks Internos (para comunicación con componentes)

        // Estos deben coincidir EXACTAMENTE con los delegates de las interfaces
        private readonly FriendConnectionStatusCallback _internalStatusCallback;
        private readonly FriendConnectionDataCallback _internalDataCallback;
        private readonly FriendRequestCallback _internalRequestCallback;

        #endregion

        #region Constructor

        public Messenger(
            MonoTime monoTime,
            INetworkCore network,
            IDht dht,
            INetCrypto netCrypto,
            IOnionClient onionClient,
            IFriendConnection friendConnection,
            IFriendRequests friendRequests,
            IPing ping,
            byte[] selfPublicKey = null,
            byte[] selfSecretKey = null,
            MessengerOptions options = null)
        {
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _netCrypto = netCrypto ?? throw new ArgumentNullException(nameof(netCrypto));
            _onionClient = onionClient ?? throw new ArgumentNullException(nameof(onionClient));
            _friendConnection = friendConnection ?? throw new ArgumentNullException(nameof(friendConnection));
            _friendRequests = friendRequests ?? throw new ArgumentNullException(nameof(friendRequests));
            _ping = ping ?? throw new ArgumentNullException(nameof(ping));

            options ??= new MessengerOptions();

            // Inicializar claves
            if (selfPublicKey != null && selfSecretKey != null &&
                selfPublicKey.Length == ToxPublicKeySize && selfSecretKey.Length == ToxSecretKeySize)
            {
                Buffer.BlockCopy(selfPublicKey, 0, _selfPublicKey, 0, ToxPublicKeySize);
                Buffer.BlockCopy(selfSecretKey, 0, _selfSecretKey, 0, ToxSecretKeySize);
            }
            else
            {
                LibSodium.TryCryptoBoxKeyPair(_selfPublicKey, _selfSecretKey);
            }

            _nospam = (uint)new Random().NextInt64();
            UpdateChecksum();

            // Crear callbacks internos con las firmas EXACTAS de las interfaces
            _internalStatusCallback = new FriendConnectionStatusCallback(OnFriendConnectionStatusChanged);
            _internalDataCallback = new FriendConnectionDataCallback(OnFriendDataReceived);
            _internalRequestCallback = new FriendRequestCallback(OnFriendRequestReceivedInternal);

            // Registrar callbacks en los componentes
            _friendRequests.SetFriendRequestCallback(_internalRequestCallback, this);
            _friendRequests.Init(_friendConnection);

            _friendConnection.RegisterStatusCallback(_internalStatusCallback, this);
            _friendConnection.RegisterDataCallback(_internalDataCallback, this);

            _netCrypto.RegisterPacketHandler(PacketIdFriendRequest, HandleNetCryptoFriendRequest);

            Logger.Log.Info($"[MESSENGER] Initialized with public key: {Logger.SafeKeyThumb(_selfPublicKey)}");
        }



        #endregion

        #region IMessenger Implementation - Propiedades

        public ReadOnlySpan<byte> SelfPublicKey => _selfPublicKey;

        public byte[] SelfAddress
        {
            get
            {
                var address = new byte[ToxAddressSize];
                Buffer.BlockCopy(_selfPublicKey, 0, address, 0, ToxPublicKeySize);
                BinaryPrimitives.WriteUInt32BigEndian(address.AsSpan(ToxPublicKeySize), _nospam);
                BinaryPrimitives.WriteUInt16BigEndian(address.AsSpan(ToxPublicKeySize + 4), _checksum);
                return address;
            }
        }

        public ToxConnectionStatus SelfConnectionStatus
        {
            get
            {
                UpdateConnectionStatus();
                return _selfConnectionStatus;
            }
        }

        public int FriendCount => _friends.Count;

        public bool IsRunning => _isRunning;

        public void Start() => _isRunning = true;
        public void Stop() => _isRunning = false;

        #endregion

        #region IMessenger Implementation - Callbacks Públicos

        public void SetFriendRequestCallback(MessengerFriendRequestCallback callback) =>
            _friendRequestCallback = callback;

        public void SetFriendMessageCallback(FriendMessageCallback callback) =>
            _friendMessageCallback = callback;

        public void SetFriendNameCallback(FriendNameCallback callback) =>
            _friendNameCallback = callback;

        public void SetFriendStatusMessageCallback(FriendStatusMessageCallback callback) =>
            _friendStatusMessageCallback = callback;

        public void SetFriendToxConnectionStatusCallback(FriendToxConnectionStatusCallback callback) =>
            _friendToxConnectionStatusCallback = callback;

        public void SetFriendStatusCallback(FriendStatusCallback callback) =>
            _friendStatusCallback = callback;

        public void SetSelfConnectionStatusCallback(SelfConnectionStatusCallback callback) =>
            _selfConnectionStatusCallback = callback;

        #endregion

        #region IMessenger Implementation - Gestión de Amigos

        public ToxFriendAddError AddFriend(byte[] address, byte[] message, uint length, out int friendNumber)
        {
            friendNumber = -1;

            if (address == null || address.Length != ToxAddressSize)
                return ToxFriendAddError.Null;

            if (message == null && length > 0)
                return ToxFriendAddError.Null;

            if (length > ToxMaxFriendRequestLength)
                return ToxFriendAddError.TooLong;

            if (length == 0)
                return ToxFriendAddError.NoMessage;

            var publicKey = new byte[ToxPublicKeySize];
            Buffer.BlockCopy(address, 0, publicKey, 0, ToxPublicKeySize);
            uint nospam = BinaryPrimitives.ReadUInt32BigEndian(address.AsSpan(ToxPublicKeySize));
            ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(address.AsSpan(ToxPublicKeySize + 4));

            if (!VerifyAddressChecksum(address))
                return ToxFriendAddError.BadChecksum;

            if (publicKey.AsSpan().SequenceEqual(_selfPublicKey))
                return ToxFriendAddError.OwnKey;

            var existingNum = GetFriendByPublicKey(publicKey);
            if (existingNum >= 0)
            {
                friendNumber = existingNum;
                return ToxFriendAddError.AlreadySent;
            }

            if (!_friendConnection.CreateConnection(publicKey, out friendNumber))
                return ToxFriendAddError.Malloc;

            var friend = new Friend
            {
                FriendNumber = friendNumber,
                PublicKey = (byte[])publicKey.Clone(),
                Nospam = nospam,
                Status = ToxConnectionStatus.None,
                UserStatus = ToxUserStatus.Online,
                Name = Array.Empty<byte>(),
                StatusMessage = Array.Empty<byte>(),
                FriendRequestSent = true,
                FriendRequestMessage = length > 0 ? message.AsSpan(0, (int)length).ToArray() : Array.Empty<byte>()
            };

            _friends[friendNumber] = friend;
            SendFriendRequest(friend, message, length);

            Logger.Log.Info($"[MESSENGER] Added friend {friendNumber} with request");
            return ToxFriendAddError.Ok;
        }

        public bool AddFriendNoRequest(byte[] publicKey, out int friendNumber)
        {
            friendNumber = -1;

            if (publicKey == null || publicKey.Length != ToxPublicKeySize)
                return false;

            if (publicKey.AsSpan().SequenceEqual(_selfPublicKey))
                return false;

            var existingNum = GetFriendByPublicKey(publicKey);
            if (existingNum >= 0)
            {
                friendNumber = existingNum;
                return true;
            }

            if (!_friendConnection.CreateConnection(publicKey, out friendNumber))
                return false;

            var friend = new Friend
            {
                FriendNumber = friendNumber,
                PublicKey = (byte[])publicKey.Clone(),
                Status = ToxConnectionStatus.None,
                UserStatus = ToxUserStatus.Online,
                Name = Array.Empty<byte>(),
                StatusMessage = Array.Empty<byte>(),
                FriendRequestSent = false
            };

            _friends[friendNumber] = friend;

            Logger.Log.Info($"[MESSENGER] Added friend {friendNumber} (no request)");
            return true;
        }

        public bool DeleteFriend(int friendNumber)
        {
            if (!_friends.TryRemove(friendNumber, out var friend))
                return false;

            _friendConnection.KillConnection(friendNumber);
            _friendRequests.RemoveRequestReceived(friend.PublicKey);

            Logger.Log.Info($"[MESSENGER] Deleted friend {friendNumber}");
            return true;
        }

        public int GetFriendByPublicKey(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != ToxPublicKeySize)
                return -1;

            foreach (var kvp in _friends)
            {
                if (kvp.Value.PublicKey.AsSpan().SequenceEqual(publicKey))
                    return kvp.Key;
            }
            return -1;
        }

        public bool GetFriendPublicKey(int friendNumber, out byte[] publicKey)
        {
            publicKey = null;
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return false;

            publicKey = (byte[])friend.PublicKey.Clone();
            return true;
        }

        public bool FriendExists(int friendNumber) => _friends.ContainsKey(friendNumber);

        public ToxConnectionStatus GetFriendConnectionStatus(int friendNumber)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return ToxConnectionStatus.None;

            return friend.Status;
        }

        public int[] GetFriendList() => _friends.Keys.ToArray();

        #endregion

        #region IMessenger Implementation - Envío de Mensajes

        public ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType messageType,
            byte[] message, uint length, out uint messageId)
        {
            messageId = 0;

            if (!_friends.TryGetValue(friendNumber, out var friend))
                return ToxFriendSendMessageError.FriendNotFound;

            if (friend.Status == ToxConnectionStatus.None)
                return ToxFriendSendMessageError.FriendNotConnected;

            if (length > ToxMaxMessageLength)
                return ToxFriendSendMessageError.TooLong;

            if (length == 0)
                return ToxFriendSendMessageError.Empty;

            var packet = new byte[1 + 4 + length];
            packet[0] = messageType == ToxMessageType.Action ? (byte)0x41 : (byte)0x40;

            messageId = GenerateMessageId();
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), messageId);

            if (length > 0)
                Buffer.BlockCopy(message, 0, packet, 5, (int)length);

            var result = _friendConnection.SendData(friendNumber, packet);

            if (result < 0)
                return ToxFriendSendMessageError.SendQ;

            Logger.Log.Debug($"[MESSENGER] Sent message {messageId} to friend {friendNumber}");
            return ToxFriendSendMessageError.Ok;
        }

        public ToxFriendSendMessageError SendAction(int friendNumber, byte[] action, uint length, out uint messageId) =>
            SendMessage(friendNumber, ToxMessageType.Action, action, length, out messageId);

        #endregion

        #region IMessenger Implementation - Atributos del Usuario

        public bool SetSelfName(byte[] name, uint length)
        {
            if (length > ToxMaxNameLength)
                return false;

            _selfName = length > 0 ? name.AsSpan(0, (int)length).ToArray() : Array.Empty<byte>();
            BroadcastToFriends(PacketIdFriendName, _selfName);

            Logger.Log.Info($"[MESSENGER] Set self name: {System.Text.Encoding.UTF8.GetString(_selfName)}");
            return true;
        }

        public byte[] GetSelfName() => (byte[])_selfName.Clone();
        public uint GetSelfNameSize() => (uint)_selfName.Length;

        public bool SetSelfStatusMessage(byte[] message, uint length)
        {
            if (length > ToxMaxStatusMessageLength)
                return false;

            _selfStatusMessage = length > 0 ? message.AsSpan(0, (int)length).ToArray() : Array.Empty<byte>();
            BroadcastToFriends(PacketIdFriendStatusMessage, _selfStatusMessage);

            Logger.Log.Info($"[MESSENGER] Set self status message");
            return true;
        }

        public byte[] GetSelfStatusMessage() => (byte[])_selfStatusMessage.Clone();
        public uint GetSelfStatusMessageSize() => (uint)_selfStatusMessage.Length;

        public void SetSelfStatus(ToxUserStatus status)
        {
            _selfStatus = status;
            var data = new[] { (byte)status };
            BroadcastToFriends(PacketIdFriendUserStatus, data);

            Logger.Log.Info($"[MESSENGER] Set self status: {status}");
        }

        public ToxUserStatus GetSelfStatus() => _selfStatus;

        public void SetSelfNospam(uint nospam)
        {
            _nospam = nospam;
            UpdateChecksum();
            Logger.Log.Info($"[MESSENGER] Set nospam to {nospam:X8}");
        }

        public uint GetSelfNospam() => _nospam;

        #endregion

        #region IMessenger Implementation - Atributos de Amigos

        public bool GetFriendName(int friendNumber, out byte[] name)
        {
            name = null;
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return false;

            name = (byte[])friend.Name.Clone();
            return true;
        }

        public uint GetFriendNameSize(int friendNumber)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return 0;
            return (uint)friend.Name.Length;
        }

        public bool GetFriendStatusMessage(int friendNumber, out byte[] message)
        {
            message = null;
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return false;

            message = (byte[])friend.StatusMessage.Clone();
            return true;
        }

        public uint GetFriendStatusMessageSize(int friendNumber)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return 0;
            return (uint)friend.StatusMessage.Length;
        }

        public ToxUserStatus GetFriendStatus(int friendNumber)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return ToxUserStatus.Online;
            return friend.UserStatus;
        }

        public ulong GetFriendLastOnline(int friendNumber)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return 0;
            return friend.LastOnline;
        }

        #endregion

        #region IMessenger Implementation - Bootstrap y Networking

        public bool Bootstrap(string address, ushort port, byte[] publicKey)
        {
            if (string.IsNullOrEmpty(address) || publicKey == null || publicKey.Length != ToxPublicKeySize)
                return false;

            try
            {
                var ips = Dns.GetHostAddresses(address);
                if (ips.Length == 0)
                {
                    Logger.Log.Warning($"[MESSENGER] Could not resolve {address}");
                    return false;
                }

                foreach (var ip in ips)
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                        ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        var endpoint = new IPEndPoint(ip, port);
                        var result = _dht.Bootstrap(endpoint, publicKey);

                        if (result)
                        {
                            Logger.Log.Info($"[MESSENGER] Bootstrapping to {endpoint}");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[MESSENGER] Bootstrap error: {ex.Message}");
            }

            return false;
        }

        public bool AddTcpRelay(string address, ushort port, byte[] publicKey) =>
            Bootstrap(address, port, publicKey);

        public void Reconnect()
        {
            _dht.DoDht();
            Logger.Log.Info("[MESSENGER] Forced reconnection");
        }

        #endregion

        #region IMessenger Implementation - Ciclo Principal

        public void Iterate()
        {
            lock (_iterateLock)
            {
                if (!_isRunning) return;

                try
                {
                    _monoTime.Update();
                    _dht.DoDht();
                    _ping.Iterate();
                    _netCrypto.DoNetCrypto();
                    _friendConnection.DoFriendConnections();
                    _onionClient.DoOnionClient();
                    UpdateConnectionStatus();
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[MESSENGER] Iterate error: {ex.Message}");
                }
            }
        }

        public uint GetIterationInterval() => 10;

        #endregion

        #region IMessenger Implementation - Persistencia

        public uint GetSaveDataSize()
        {
            uint size = 4; // Cookie global
            size += 8 + 4 + ToxPublicKeySize + ToxSecretKeySize; // Nospam y claves
            size += 8 + _dht.GetSaveSize(); // DHT
            size += 8 + (uint)_friends.Count * (ToxPublicKeySize + 1024); // Amigos
            size += 8 + (uint)_selfName.Length; // Nombre
            size += 8 + (uint)_selfStatusMessage.Length; // Status message
            size += 8 + 1; // Status
            size += 8; // TCP relays
            size += 8; // Path nodes
            size += 8; // End
            return size;
        }

        public void GetSaveData(Span<byte> data)
        {
            int offset = 0;

            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(offset, 4), State.StateCookieGlobal);
            offset += 4;

            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType,
                (uint)(4 + ToxPublicKeySize + ToxSecretKeySize), State.StateTypeNospamKeys);
            BinaryPrimitives.WriteUInt32LittleEndian(data.Slice(offset, 4), _nospam);
            offset += 4;
            _selfPublicKey.CopyTo(data.Slice(offset, ToxPublicKeySize));
            offset += ToxPublicKeySize;
            _selfSecretKey.CopyTo(data.Slice(offset, ToxSecretKeySize));
            offset += ToxSecretKeySize;

            var dhtSize = _dht.GetSaveSize();
            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType, dhtSize, State.StateTypeDht);
            _dht.Save(data.Slice(offset, (int)dhtSize));
            offset += (int)dhtSize;

            var friendsData = SerializeFriends();
            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType,
                (uint)friendsData.Length, State.StateTypeFriends);
            friendsData.CopyTo(data.Slice(offset));
            offset += friendsData.Length;

            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType,
                (uint)_selfName.Length, State.StateTypeName);
            _selfName.CopyTo(data.Slice(offset));
            offset += _selfName.Length;

            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType,
                (uint)_selfStatusMessage.Length, State.StateTypeStatusMessage);
            _selfStatusMessage.CopyTo(data.Slice(offset));
            offset += _selfStatusMessage.Length;

            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType, 1, State.StateTypeStatus);
            data[offset] = (byte)_selfStatus;
            offset += 1;

            offset += State.WriteSectionHeader(data.Slice(offset), State.StateCookieType, 0, State.StateTypeEnd);
        }

        public bool LoadSaveData(ReadOnlySpan<byte> data)
        {
            if (data.Length < 4) return false;

            var cookie = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(0, 4));
            if (cookie != State.StateCookieGlobal)
            {
                Logger.Log.Error("[MESSENGER] Invalid save data cookie");
                return false;
            }

            int offset = 4;
            while (offset < data.Length)
            {
                if (data.Length - offset < 8) break;

                var length = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
                var typeField = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset + 4, 4));
                var sectionType = (ushort)(typeField & 0xFFFF);

                offset += 8;

                if (data.Length - offset < length) break;

                var sectionData = data.Slice(offset, (int)length);
                offset += (int)length;

                switch (sectionType)
                {
                    case State.StateTypeNospamKeys:
                        if (length >= 4 + ToxPublicKeySize + ToxSecretKeySize)
                        {
                            _nospam = BinaryPrimitives.ReadUInt32LittleEndian(sectionData.Slice(0, 4));
                            sectionData.Slice(4, ToxPublicKeySize).CopyTo(_selfPublicKey);
                            sectionData.Slice(4 + ToxPublicKeySize, ToxSecretKeySize).CopyTo(_selfSecretKey);
                            UpdateChecksum();
                        }
                        break;

                    case State.StateTypeDht:
                        _dht.Load(sectionData);
                        break;

                    case State.StateTypeFriends:
                        DeserializeFriends(sectionData);
                        break;

                    case State.StateTypeName:
                        _selfName = sectionData.ToArray();
                        break;

                    case State.StateTypeStatusMessage:
                        _selfStatusMessage = sectionData.ToArray();
                        break;

                    case State.StateTypeStatus:
                        if (length >= 1)
                            _selfStatus = (ToxUserStatus)sectionData[0];
                        break;

                    case State.StateTypeEnd:
                        return true;
                }
            }

            Logger.Log.Info("[MESSENGER] Save data loaded successfully");
            return true;
        }

        #endregion

        #region IMessenger Implementation - Utilidades

        public (uint major, uint minor, uint patch) GetVersion() =>
            (ToxVersionMajor, ToxVersionMinor, ToxVersionPatch);

        public bool IsAddressValid(ReadOnlySpan<byte> address)
        {
            if (address.Length != ToxAddressSize) return false;
            return VerifyAddressChecksum(address);
        }

        public byte[] GetMessageHash(byte[] message, uint length)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(message, 0, (int)length);
        }

        #endregion

        #region Métodos Privados - Handlers Internos (firmas exactas de las interfaces)

        // Handler para FriendRequestCallback de IFriendRequests
        // Firma: void(object obj, byte[] publicKey, byte[] message, uint length, object userdata)
        private void OnFriendRequestReceivedInternal(object obj, byte[] publicKey, byte[] message, uint length, object userdata)
        {
            Logger.Log.Info($"[MESSENGER] Friend request received from {Logger.SafeKeyThumb(publicKey)}");

            // CORRECCIÓN: NO agregar automáticamente. Solo notificar al callback.
            // El usuario debe llamar a AddFriendNoRequest explícitamente si quiere aceptar.

            _friendRequestCallback?.Invoke(publicKey, message, length);

            // Si no hay callback registrado, loggear pero no auto-aceptar
            if (_friendRequestCallback == null)
            {
                Logger.Log.Warning("[MESSENGER] Friend request received but no callback registered. " +
                    "Request from {Logger.SafeKeyThumb(publicKey)} will be ignored.");
            }
        }

        // Handler para FriendConnectionStatusCallback de IFriendConnection
        // Firma: void(int friendNumber, FriendConnectionStatus status, object userData)
        private void OnFriendConnectionStatusChanged(int friendNumber, FriendConnectionStatus status, object userData)
        {
            if (!_friends.TryGetValue(friendNumber, out var friend))
                return;

            var oldStatus = friend.Status;
            ToxConnectionStatus newToxStatus;

            switch (status)
            {
                case FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED:
                    newToxStatus = ToxConnectionStatus.Udp;
                    friend.LastOnline = _monoTime.GetSeconds();
                    break;
                case FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING:
                    newToxStatus = ToxConnectionStatus.None;
                    break;
                default:
                    newToxStatus = ToxConnectionStatus.None;
                    break;
            }

            friend.Status = newToxStatus;

            if (oldStatus != newToxStatus)
            {
                Logger.Log.Info($"[MESSENGER] Friend {friendNumber} connection status: {oldStatus} -> {newToxStatus}");
                _friendToxConnectionStatusCallback?.Invoke(friendNumber, newToxStatus);
            }
        }

        // Handler para FriendConnectionDataCallback de IFriendConnection
        // Firma: void(int friendNumber, byte[] data, object userData)
        private void OnFriendDataReceived(int friendNumber, byte[] data, object userData)
        {
            if (data == null || data.Length < 1) return;

            byte packetId = data[0];

            switch (packetId)
            {
                case 0x40: // Mensaje normal
                case 0x41: // Acción
                    HandleFriendMessage(friendNumber, data);
                    break;
                case PacketIdFriendName:
                    HandleFriendName(friendNumber, data);
                    break;
                case PacketIdFriendStatusMessage:
                    HandleFriendStatusMessage(friendNumber, data);
                    break;
                case PacketIdFriendUserStatus:
                    HandleFriendUserStatus(friendNumber, data);
                    break;
                default:
                    Logger.Log.Debug($"[MESSENGER] Unknown friend packet type: {packetId:X2}");
                    break;
            }
        }

        private void HandleFriendMessage(int friendNumber, byte[] data)
        {
            if (data.Length < 5) return;

            var messageType = data[0] == 0x41 ? ToxMessageType.Action : ToxMessageType.Normal;
            var messageId = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(1, 4));
            var message = data.AsSpan(5).ToArray();

            Logger.Log.Debug($"[MESSENGER] Received message {messageId} from friend {friendNumber}");
            _friendMessageCallback?.Invoke(friendNumber, messageType, message, (uint)message.Length);
        }

        private void HandleFriendName(int friendNumber, byte[] data)
        {
            if (data.Length < 1) return;

            var name = data.AsSpan(1).ToArray();

            if (_friends.TryGetValue(friendNumber, out var friend))
            {
                friend.Name = name;
                Logger.Log.Info($"[MESSENGER] Friend {friendNumber} name changed");
                _friendNameCallback?.Invoke(friendNumber, name, (uint)name.Length);
            }
        }

        private void HandleFriendStatusMessage(int friendNumber, byte[] data)
        {
            if (data.Length < 1) return;

            var message = data.AsSpan(1).ToArray();

            if (_friends.TryGetValue(friendNumber, out var friend))
            {
                friend.StatusMessage = message;
                Logger.Log.Info($"[MESSENGER] Friend {friendNumber} status message changed");
                _friendStatusMessageCallback?.Invoke(friendNumber, message, (uint)message.Length);
            }
        }

        private void HandleFriendUserStatus(int friendNumber, byte[] data)
        {
            if (data.Length < 1) return;

            var status = (ToxUserStatus)data[0];

            if (_friends.TryGetValue(friendNumber, out var friend))
            {
                friend.UserStatus = status;
                Logger.Log.Info($"[MESSENGER] Friend {friendNumber} user status: {status}");
                _friendStatusCallback?.Invoke(friendNumber, status);
            }
        }

        private void HandleNetCryptoFriendRequest(IPEndPoint source, byte[] data, int length)
        {
            if (length < 5) return;

            var publicKey = _netCrypto.GetPublicKeyForEndpoint(source);
            if (publicKey == null) return;

            var nospam = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(1, 4));
            var message = data.AsSpan(5).ToArray();

            Logger.Log.Info($"[MESSENGER] Friend request via NetCrypto from {Logger.SafeKeyThumb(publicKey)}");

            // Llamar al handler interno con todos los parámetros requeridos
            OnFriendRequestReceivedInternal(this, publicKey, message, (uint)message.Length, null);
        }

        #endregion

        #region Métodos Privados - Utilidades

        private void UpdateConnectionStatus()
        {
            var now = _monoTime.GetSeconds();
            if (now - _lastConnectionStatusCheck < 1) return;

            _lastConnectionStatusCheck = now;

            var newStatus = _dht.IsConnected ? ToxConnectionStatus.Udp : ToxConnectionStatus.None;

            if (_selfConnectionStatus != newStatus)
            {
                _selfConnectionStatus = newStatus;
                Logger.Log.Info($"[MESSENGER] Self connection status: {newStatus}");
                _selfConnectionStatusCallback?.Invoke(newStatus);
            }
        }

        /// <summary>
        /// Actualiza el checksum de la dirección Tox.
        /// CORRECCIÓN: Implementa algoritmo correcto según especificación Tox.
        /// 
        /// El checksum se calcula sobre: public_key (32 bytes) + nospam (4 bytes) = 36 bytes
        /// Algoritmo: Suma de palabras de 16 bits en complemento a uno, luego ~resultado
        /// </summary>
        private void UpdateChecksum()
        {
            _checksum = CalculateAddressChecksum(_selfPublicKey, _nospam);
        }

        /// <summary>
        /// Calcula el checksum de una dirección Tox.
        /// </summary>
        /// <param name="publicKey">Clave pública de 32 bytes</param>
        /// <param name="nospam">Valor nospam de 4 bytes</param>
        /// <returns>Checksum de 16 bits</returns>
        private static ushort CalculateAddressChecksum(byte[] publicKey, uint nospam)
        {
            if (publicKey == null || publicKey.Length != ToxPublicKeySize)
                throw new ArgumentException("Invalid public key");

            // Crear buffer de 36 bytes: pk[32] + nospam[4]
            var data = new byte[ToxPublicKeySize + sizeof(uint)];
            Buffer.BlockCopy(publicKey, 0, data, 0, ToxPublicKeySize);
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(ToxPublicKeySize), nospam);

            return CalculateOnesComplementSum(data);
        }

        /// <summary>
        /// Calcula suma de palabras de 16 bits en complemento a uno.
        /// Algoritmo estándar usado en checksums de red (similar a IP checksum).
        /// </summary>
        private static ushort CalculateOnesComplementSum(byte[] data)
        {
            uint sum = 0;

            // Sumar palabras de 16 bits
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                ushort word = (ushort)((data[i] << 8) | data[i + 1]);
                sum += word;
            }

            // Si hay byte impar final, agregarlo
            if (data.Length % 2 == 1)
            {
                sum += (uint)(data[data.Length - 1] << 8);
            }

            // Sumar acarreos (fold 32-bit sum to 16 bits)
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // Complemento a uno (inversión de bits)
            return (ushort)~sum;
        }

        /// <summary>
        /// Verifica el checksum de una dirección Tox.
        /// CORRECCIÓN: Usa algoritmo correcto de validación.
        /// </summary>
        private static bool VerifyAddressChecksum(ReadOnlySpan<byte> address)
        {
            if (address.Length != ToxAddressSize) return false;

            // Extraer componentes
            var publicKey = address.Slice(0, ToxPublicKeySize);
            var nospam = BinaryPrimitives.ReadUInt32BigEndian(address.Slice(ToxPublicKeySize, sizeof(uint)));
            var storedChecksum = BinaryPrimitives.ReadUInt16BigEndian(address.Slice(ToxPublicKeySize + sizeof(uint), sizeof(ushort)));

            // Calcular checksum esperado
            var calculatedChecksum = CalculateAddressChecksum(publicKey.ToArray(), nospam);

            return storedChecksum == calculatedChecksum;
        }

        private void SendFriendRequest(Friend friend, byte[] message, uint length)
        {
            var requestData = new byte[4 + length];
            BinaryPrimitives.WriteUInt32BigEndian(requestData.AsSpan(0, 4), friend.Nospam);

            if (length > 0)
                Buffer.BlockCopy(message, 0, requestData, 4, (int)length);

            _friendConnection.SendData(friend.FriendNumber, requestData);
        }

        private void BroadcastToFriends(byte packetId, byte[] data)
        {
            var packet = new byte[1 + data.Length];
            packet[0] = packetId;
            data.CopyTo(packet.AsSpan(1));

            foreach (var kvp in _friends)
            {
                if (kvp.Value.Status != ToxConnectionStatus.None)
                {
                    _friendConnection.SendData(kvp.Key, packet);
                }
            }
        }

        private uint GenerateMessageId() => (uint)Interlocked.Increment(ref _nextFriendNumber);

        private byte[] SerializeFriends()
        {
            using var ms = new System.IO.MemoryStream();

            foreach (var kvp in _friends)
            {
                var friend = kvp.Value;

                var friendData = new System.IO.MemoryStream();

                var numberBytes = BitConverter.GetBytes(friend.FriendNumber);
                friendData.Write(numberBytes);

                friendData.Write(friend.PublicKey);
                friendData.WriteByte((byte)friend.Status);

                var nameLenBytes = BitConverter.GetBytes((ushort)friend.Name.Length);
                friendData.Write(nameLenBytes);
                friendData.Write(friend.Name);

                var statusLenBytes = BitConverter.GetBytes((ushort)friend.StatusMessage.Length);
                friendData.Write(statusLenBytes);
                friendData.Write(friend.StatusMessage);

                var data = friendData.ToArray();
                ms.Write(BitConverter.GetBytes(data.Length));
                ms.Write(data);
            }

            return ms.ToArray();
        }

        private void DeserializeFriends(ReadOnlySpan<byte> data)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                if (data.Length - offset < 4) break;

                int friendDataLen = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                offset += 4;

                if (data.Length - offset < friendDataLen) break;
                var friendData = data.Slice(offset, friendDataLen);
                offset += friendDataLen;

                try
                {
                    int fOffset = 0;
                    var friendNumber = BinaryPrimitives.ReadInt32LittleEndian(friendData.Slice(fOffset, 4));
                    fOffset += 4;

                    var publicKey = friendData.Slice(fOffset, ToxPublicKeySize).ToArray();
                    fOffset += ToxPublicKeySize;

                    var status = (ToxConnectionStatus)friendData[fOffset++];

                    var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(friendData.Slice(fOffset, 2));
                    fOffset += 2;
                    var name = friendData.Slice(fOffset, nameLen).ToArray();
                    fOffset += nameLen;

                    var statusMsgLen = BinaryPrimitives.ReadUInt16LittleEndian(friendData.Slice(fOffset, 2));
                    fOffset += 2;
                    var statusMsg = friendData.Slice(fOffset, statusMsgLen).ToArray();

                    if (AddFriendNoRequest(publicKey, out _))
                    {
                        if (_friends.TryGetValue(friendNumber, out var friend))
                        {
                            friend.Name = name;
                            friend.StatusMessage = statusMsg;
                            friend.Status = status;
                        }
                    }
                }
                catch { /* Ignorar amigos corruptos */ }
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _isRunning = false;

            _friendRequestCallback = null;
            _friendMessageCallback = null;
            _friendNameCallback = null;
            _friendStatusMessageCallback = null;
            _friendToxConnectionStatusCallback = null;
            _friendStatusCallback = null;
            _selfConnectionStatusCallback = null;

            foreach (var friendNumber in _friends.Keys.ToArray())
            {
                DeleteFriend(friendNumber);
            }

            CryptographicOperations.ZeroMemory(_selfSecretKey);

            Logger.Log.Info("[MESSENGER] Disposed");
        }

        #endregion
    }

    #region Clases Auxiliares

    /// <summary>
    /// Opciones de configuración para el Messenger.
    /// </summary>
    public class MessengerOptions
    {
        public bool Ipv6Enabled { get; set; } = true;
        public bool UdpEnabled { get; set; } = true;
        public bool HolePunchingEnabled { get; set; } = true;
        public bool TcpEnabled { get; set; } = true;
        public ushort PortRangeStart { get; set; } = 33445;
        public ushort PortRangeEnd { get; set; } = 33545;
        public byte[] SavedData { get; set; }
    }

    /// <summary>
    /// Representa un amigo en la lista del messenger.
    /// </summary>
    public class Friend
    {
        public int FriendNumber { get; set; }
        public byte[] PublicKey { get; set; }
        public uint Nospam { get; set; }
        public ToxConnectionStatus Status { get; set; }
        public ToxUserStatus UserStatus { get; set; }
        public byte[] Name { get; set; }
        public byte[] StatusMessage { get; set; }
        public ulong LastOnline { get; set; }
        public bool FriendRequestSent { get; set; }
        public bool FriendRequestReceived { get; set; }
        public byte[] FriendRequestMessage { get; set; }
    }

    #endregion
}