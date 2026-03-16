// ToxCore.Internal.cs - Implementación Interna del Cliente Tox
// Propósito: Contener toda la lógica de implementación, separada de la API pública
// Equivalente a: tox.c + tox_api.c + tox_private.c (consolidado)

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Toxcore;
using Toxcore.Core;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.Onion;
using Toxcore.Core.Abstractions.TCP;
using Toxcore.Events;
using CoreAddError = Toxcore.Core.Abstractions.ToxFriendAddError;
using CoreMessageType = Toxcore.Core.Abstractions.ToxMessageType;
using CoreSendError = Toxcore.Core.Abstractions.ToxFriendSendMessageError;
// Alias para resolver conflictos de nombres entre ToxCore y ToxCore.Core.Abstractions
using CoreStatus = Toxcore.Core.Abstractions.ToxConnectionStatus;
using CoreUserStatus = Toxcore.Core.Abstractions.ToxUserStatus;

namespace Toxcore.Internal
{
    /// <summary>
    /// Implementación principal de ITox. Contiene toda la lógica interna.
    /// </summary>
    public sealed class ToxInternal : ITox
    {
        // === Dependencias Inyectadas ===
        private readonly IMessenger _messenger;
        private readonly IOnionClient _onionClient;
        private readonly IOnionAnnounce _onionAnnounce;
        private readonly IDht _dht;
        private readonly INetworkCore _networkCore;
        private readonly ITCPConnection _tcpConnection;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;
        private readonly MonoTime _monoTime;
        private readonly IToxEventDispatcher _eventDispatcher;
        private readonly ToxEventBridge _eventBridge;

        // === Estado ===
        private bool _disposed;
        private bool _isRunning;
        private readonly object _iterateLock = new();
        private readonly bool _ownsMessenger;

        // === Componentes Internos ===
        private readonly ToxSelfManager _selfManager;
        private readonly ToxFriendManager _friendManager;
        private readonly ToxNetworkManager _networkManager;

        public ToxOptions Options { get; }

        public ToxInternal(ToxOptions options,
            IMessenger messenger,
            IOnionClient onionClient,
            IOnionAnnounce onionAnnounce,
            IDht dht,
            INetworkCore networkCore,
            ITCPConnection tcpConnection,
            IFriendConnection friendConnection,
            IFriendRequests friendRequests,
            MonoTime monoTime,
            IToxEventDispatcher eventDispatcher = null)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options));
            _messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));
            _onionClient = onionClient ?? throw new ArgumentNullException(nameof(onionClient));
            _onionAnnounce = onionAnnounce ?? throw new ArgumentNullException(nameof(onionAnnounce));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _networkCore = networkCore ?? throw new ArgumentNullException(nameof(networkCore));
            _tcpConnection = tcpConnection ?? throw new ArgumentNullException(nameof(tcpConnection));
            _friendConnection = friendConnection ?? throw new ArgumentNullException(nameof(friendConnection));
            _friendRequests = friendRequests ?? throw new ArgumentNullException(nameof(friendRequests));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));

            _eventDispatcher = eventDispatcher ?? new ToxEventDispatcher();
            _eventBridge = new ToxEventBridge(_eventDispatcher);

            _selfManager = new ToxSelfManager(_messenger);
            _friendManager = new ToxFriendManager(_messenger, _friendConnection, _friendRequests, _eventDispatcher);
            _networkManager = new ToxNetworkManager(Options, _messenger, _dht, _onionClient, _networkCore, _tcpConnection);

            RegisterMessengerCallbacks();

            if (Options.SavedData != null && Options.SavedData.Length > 0)
            {
                LoadSaveData(Options.SavedData);
            }

            _friendRequests.Init(_friendConnection);
            _isRunning = true;

            Logger.Log.Info("[TOX-INTERNAL] Instance created successfully");
        }

        #region ITox Implementation - Propiedades

        public bool IsConnected => _messenger.SelfConnectionStatus != CoreStatus.None;

        public byte[] SelfPublicKey
        {
            get
            {
                var key = _messenger.SelfPublicKey;
                if (key.IsEmpty) return Array.Empty<byte>();
                var array = new byte[key.Length];
                key.CopyTo(array);
                return array;
            }
        }

        public byte[] SelfAddress => _messenger.SelfAddress;
        public int FriendCount => _messenger.FriendCount;

        #endregion

        #region ITox Implementation - Ciclo de Vida

        public uint GetIterationInterval() => _messenger.GetIterationInterval();

        public void Iterate()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ToxInternal));

            lock (_iterateLock)
            {
                if (!_isRunning) return;

                try
                {
                    _monoTime.Update();
                    _networkCore.Poll();
                    _dht.DoDht();
                    _onionClient.DoOnionClient();
                    _onionAnnounce.DoOnionAnnounce();
                    _friendConnection.DoFriendConnections();
                    _messenger.Iterate();
                    _tcpConnection.DoTcp();

                    // Procesar eventos pendientes
                    _eventDispatcher.DispatchEvents();
                }
                catch (Exception ex)
                {
                    Logger.Log.ErrorF("[TOX-INTERNAL] Iterate error: {0}", ex.Message);
                }
            }
        }

        #endregion

        #region ITox Implementation - Perfil

        public bool SetSelfName(string name) => _selfManager.SetName(name);
        public string GetSelfName() => _selfManager.GetName();
        public bool SetSelfStatusMessage(string message) => _selfManager.SetStatusMessage(message);
        public string GetSelfStatusMessage() => _selfManager.GetStatusMessage();
        public void SetSelfStatus(ToxUserStatus status) => _selfManager.SetStatus((CoreUserStatus)status);
        public ToxUserStatus GetSelfStatus() => (ToxUserStatus)_selfManager.GetStatus();
        public void SetSelfNospam(uint nospam) => _selfManager.SetNospam(nospam);
        public uint GetSelfNospam() => _selfManager.GetNospam();

        #endregion

        #region ITox Implementation - Amigos

        public ToxFriendAddError AddFriend(byte[] address, string message, out int friendNumber) =>
            (ToxFriendAddError)_friendManager.Add(address, message, out friendNumber);

        public ToxFriendAddError AddFriendNoRequest(byte[] publicKey, out int friendNumber) =>
            (ToxFriendAddError)_friendManager.AddNoRequest(publicKey, out friendNumber);

        public bool DeleteFriend(int friendNumber) => _friendManager.Delete(friendNumber);
        public int GetFriendByPublicKey(byte[] publicKey) => _messenger.GetFriendByPublicKey(publicKey);
        public bool GetFriendPublicKey(int friendNumber, out byte[] publicKey) => _messenger.GetFriendPublicKey(friendNumber, out publicKey);
        public bool FriendExists(int friendNumber) => _messenger.FriendExists(friendNumber);
        public ToxConnectionStatus GetFriendConnectionStatus(int friendNumber) => (ToxConnectionStatus)_messenger.GetFriendConnectionStatus(friendNumber);
        public IReadOnlyList<int> GetFriendList() => _friendManager.GetList();

        public string GetFriendName(int friendNumber) => _friendManager.GetName(friendNumber);
        public string GetFriendStatusMessage(int friendNumber) => _friendManager.GetStatusMessage(friendNumber);
        public ToxUserStatus GetFriendStatus(int friendNumber) => (ToxUserStatus)_messenger.GetFriendStatus(friendNumber);
        public ulong GetFriendLastOnline(int friendNumber) => _messenger.GetFriendLastOnline(friendNumber);

        #endregion

        #region ITox Implementation - Mensajería

        public ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType type, string message, out uint messageId) =>
            (ToxFriendSendMessageError)_friendManager.SendMessage(friendNumber, (CoreMessageType)type, message, out messageId);

        public bool SetTyping(int friendNumber, bool isTyping) =>
            _friendManager.SetTyping(friendNumber, isTyping);

        public bool GetFriendTyping(int friendNumber) =>
            _friendManager.GetTypingStatus(friendNumber);

        #endregion

        #region ITox Implementation - Networking

        public bool Bootstrap(string address, ushort port, byte[] publicKey) =>
            _networkManager.Bootstrap(address, port, publicKey);

        public bool AddTcpRelay(string address, ushort port, byte[] publicKey) =>
            _networkManager.AddTcpRelay(address, port, publicKey);

        public ushort GetUdpPort() => _networkManager.GetUdpPort();
        public ushort GetTcpPort() => _networkManager.GetTcpPort();

        #endregion

        #region ITox Implementation - Persistencia

        public byte[] GetSaveData()
        {
            var size = _messenger.GetSaveDataSize();
            var data = new byte[size];
            _messenger.GetSaveData(data);
            return data;
        }

        public bool LoadSaveData(byte[] data) =>
            data != null && data.Length > 0 && _messenger.LoadSaveData(data);

        #endregion

        #region ITox Implementation - Eventos

        // Los eventos se delegan al ToxEventBridge, que los expone públicamente
        public event EventHandler<ToxFriendRequestEventArgs> OnFriendRequest
        {
            add => _eventBridge.OnFriendRequest += value;
            remove => _eventBridge.OnFriendRequest -= value;
        }

        public event EventHandler<ToxFriendMessageEventArgs> OnFriendMessage
        {
            add => _eventBridge.OnFriendMessage += value;
            remove => _eventBridge.OnFriendMessage -= value;
        }

        public event EventHandler<ToxFriendNameChangeEventArgs> OnFriendNameChange
        {
            add => _eventBridge.OnFriendNameChange += value;
            remove => _eventBridge.OnFriendNameChange -= value;
        }

        public event EventHandler<ToxFriendStatusMessageChangeEventArgs> OnFriendStatusMessageChange
        {
            add => _eventBridge.OnFriendStatusMessageChange += value;
            remove => _eventBridge.OnFriendStatusMessageChange -= value;
        }

        public event EventHandler<ToxFriendStatusChangeEventArgs> OnFriendStatusChange
        {
            add => _eventBridge.OnFriendStatusChange += value;
            remove => _eventBridge.OnFriendStatusChange -= value;
        }

        public event EventHandler<ToxFriendConnectionStatusChangeEventArgs> OnFriendConnectionStatusChange
        {
            add => _eventBridge.OnFriendConnectionStatusChange += value;
            remove => _eventBridge.OnFriendConnectionStatusChange -= value;
        }

        public event EventHandler<ToxSelfConnectionStatusChangeEventArgs> OnSelfConnectionStatusChange
        {
            add => _eventBridge.OnSelfConnectionStatusChange += value;
            remove => _eventBridge.OnSelfConnectionStatusChange -= value;
        }

        public event EventHandler<ToxFriendTypingEventArgs> OnFriendTyping
        {
            add => _eventBridge.OnFriendTyping += value;
            remove => _eventBridge.OnFriendTyping -= value;
        }

        #endregion

        #region Registro de Callbacks Internos

        private void RegisterMessengerCallbacks()
        {
            _messenger.SetFriendRequestCallback(OnMessengerFriendRequest);
            _messenger.SetFriendMessageCallback(OnMessengerFriendMessage);
            _messenger.SetFriendNameCallback(OnMessengerFriendNameChange);
            _messenger.SetFriendStatusMessageCallback(OnMessengerFriendStatusMessageChange);
            _messenger.SetFriendStatusCallback(OnMessengerFriendStatusChange);
            _messenger.SetFriendToxConnectionStatusCallback(OnMessengerFriendConnectionStatusChange);
            _messenger.SetSelfConnectionStatusCallback(OnMessengerSelfConnectionStatusChange);
        }

        // Callbacks con firmas exactas según los delegates de Core.Abstractions
        private void OnMessengerFriendRequest(byte[] publicKey, byte[] message, uint length)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendRequestEvent(publicKey, message, length));
        }

        private void OnMessengerFriendMessage(int friendNumber, CoreMessageType type, byte[] message, uint length)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendMessageEvent(friendNumber, (ToxMessageType)type, message, length, 0));
        }

        private void OnMessengerFriendNameChange(int friendNumber, byte[] name, uint length)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendNameChangeEvent(friendNumber, name, length));
        }

        private void OnMessengerFriendStatusMessageChange(int friendNumber, byte[] message, uint length)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendStatusMessageChangeEvent(friendNumber, message, length));
        }

        private void OnMessengerFriendStatusChange(int friendNumber, CoreUserStatus status)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendStatusChangeEvent(friendNumber, (ToxUserStatus)status));
        }

        private void OnMessengerFriendConnectionStatusChange(int friendNumber, CoreStatus status)
        {
            _eventDispatcher.EnqueueEvent(new InternalFriendConnectionStatusChangeEvent(friendNumber, (ToxConnectionStatus)status));
        }

        private void OnMessengerSelfConnectionStatusChange(CoreStatus status)
        {
            _eventDispatcher.EnqueueEvent(new InternalSelfConnectionStatusChangeEvent((ToxConnectionStatus)status));
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _isRunning = false;

            _eventBridge?.Dispose();
            _eventDispatcher?.Dispose();
            _networkManager?.Dispose();
            _friendManager?.Dispose();
            _selfManager?.Dispose();

            if (_ownsMessenger)
            {
                _messenger?.Dispose();
            }

            _tcpConnection?.Dispose();
            _friendConnection?.Dispose();
            _friendRequests?.Dispose();
            _onionClient?.Dispose();
            _onionAnnounce?.Dispose();
            _dht?.Dispose();
            _networkCore?.Dispose();
            _monoTime?.Dispose();

            Logger.Log.Info("[TOX-INTERNAL] Instance disposed");
        }

        #endregion
    }

    #region Componentes Internos

    /// <summary>
    /// Gestión del perfil de usuario.
    /// </summary>
    internal sealed class ToxSelfManager : IDisposable
    {
        private readonly IMessenger _messenger;

        public ToxSelfManager(IMessenger messenger)
        {
            _messenger = messenger;
        }

        public bool SetName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            var bytes = Encoding.UTF8.GetBytes(name);
            if (bytes.Length > 128) return false;
            return _messenger.SetSelfName(bytes, (uint)bytes.Length);
        }

        public string GetName()
        {
            var bytes = _messenger.GetSelfName();
            return bytes != null ? Encoding.UTF8.GetString(bytes) : string.Empty;
        }

        public bool SetStatusMessage(string message)
        {
            if (message == null) message = string.Empty;
            var bytes = Encoding.UTF8.GetBytes(message);
            if (bytes.Length > 1007) return false;
            return _messenger.SetSelfStatusMessage(bytes, (uint)bytes.Length);
        }

        public string GetStatusMessage()
        {
            var bytes = _messenger.GetSelfStatusMessage();
            return bytes != null ? Encoding.UTF8.GetString(bytes) : string.Empty;
        }

        public void SetStatus(CoreUserStatus status) => _messenger.SetSelfStatus(status);
        public CoreUserStatus GetStatus() => _messenger.GetSelfStatus();
        public void SetNospam(uint nospam) => _messenger.SetSelfNospam(nospam);
        public uint GetNospam() => _messenger.GetSelfNospam();

        public void Dispose() { }
    }

    /// <summary>
    /// Gestión de amigos con thread-safety.
    /// </summary>
    internal sealed class ToxFriendManager : IDisposable
    {
        private readonly IMessenger _messenger;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;
        private readonly IToxEventDispatcher _eventDispatcher;
        private readonly ConcurrentDictionary<int, FriendTypingState> _typingStates = new();

        public ToxFriendManager(IMessenger messenger, IFriendConnection friendConnection,
            IFriendRequests friendRequests, IToxEventDispatcher eventDispatcher)
        {
            _messenger = messenger;
            _friendConnection = friendConnection;
            _friendRequests = friendRequests;
            _eventDispatcher = eventDispatcher;
        }

        public CoreAddError Add(byte[] address, string message, out int friendNumber)
        {
            friendNumber = -1;
            if (address == null || address.Length != 38)
                return CoreAddError.BadChecksum;

            if (!ToxAddressUtils.IsValidAddress(address))
                return CoreAddError.BadChecksum;

            var msgBytes = string.IsNullOrEmpty(message) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(message);
            if (msgBytes.Length > 1016)
                return CoreAddError.TooLong;

            var result = _messenger.AddFriend(address, msgBytes, (uint)msgBytes.Length, out friendNumber);
            return result;
        }

        public CoreAddError AddNoRequest(byte[] publicKey, out int friendNumber)
        {
            friendNumber = -1;
            if (publicKey == null || publicKey.Length != 32)
                return CoreAddError.BadChecksum;

            var selfKey = _messenger.SelfPublicKey;
            if (selfKey.SequenceEqual(publicKey))
                return CoreAddError.OwnKey;

            var success = _messenger.AddFriendNoRequest(publicKey, out friendNumber);
            return success ? CoreAddError.Ok : CoreAddError.Malloc;
        }

        public bool Delete(int friendNumber)
        {
            _friendConnection.KillConnection(friendNumber);
            _typingStates.TryRemove(friendNumber, out _);
            return _messenger.DeleteFriend(friendNumber);
        }

        public IReadOnlyList<int> GetList()
        {
            return _messenger.GetFriendList()
                .Where(f => _messenger.FriendExists(f))
                .ToArray();
        }

        public string GetName(int friendNumber)
        {
            if (!_messenger.GetFriendName(friendNumber, out var bytes)) return null;
            return bytes != null ? Encoding.UTF8.GetString(bytes) : string.Empty;
        }

        public string GetStatusMessage(int friendNumber)
        {
            if (!_messenger.GetFriendStatusMessage(friendNumber, out var bytes)) return null;
            return bytes != null ? Encoding.UTF8.GetString(bytes) : string.Empty;
        }

        public CoreSendError SendMessage(int friendNumber, CoreMessageType type, string message, out uint messageId)
        {
            messageId = 0;
            if (string.IsNullOrEmpty(message)) return CoreSendError.Empty;
            if (!_messenger.FriendExists(friendNumber)) return CoreSendError.FriendNotFound;

            var bytes = Encoding.UTF8.GetBytes(message);
            if (bytes.Length > 1372)
                return CoreSendError.TooLong;

            if (_messenger.GetFriendConnectionStatus(friendNumber) == CoreStatus.None)
                return CoreSendError.FriendNotConnected;

            var result = _messenger.SendMessage(friendNumber, type, bytes, (uint)bytes.Length, out messageId);
            return result;
        }

        public bool SetTyping(int friendNumber, bool isTyping)
        {
            if (!_messenger.FriendExists(friendNumber))
                return false;

            if (_messenger.GetFriendConnectionStatus(friendNumber) == CoreStatus.None)
                return false;

            try
            {
                var packet = new byte[2];
                packet[0] = 0x42; // Typing Indicator
                packet[1] = (byte)(isTyping ? 1 : 0);

                var result = _friendConnection.SendData(friendNumber, packet);

                if (result > 0)
                {
                    UpdateTypingStatus(friendNumber, isTyping);
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX-FRIEND] Error setting typing status: {ex.Message}");
                return false;
            }
        }

        public bool GetTypingStatus(int friendNumber)
        {
            if (_typingStates.TryGetValue(friendNumber, out var state))
            {
                // Expirar después de 10 segundos
                if (DateTime.UtcNow - state.LastUpdate > TimeSpan.FromSeconds(10))
                {
                    _typingStates.TryRemove(friendNumber, out _);
                    return false;
                }
                return state.IsTyping;
            }
            return false;
        }

        public void UpdateTypingStatus(int friendNumber, bool isTyping)
        {
            _typingStates[friendNumber] = new FriendTypingState
            {
                IsTyping = isTyping,
                LastUpdate = DateTime.UtcNow
            };
        }

        public void ProcessTypingIndicator(int friendNumber, bool isTyping)
        {
            UpdateTypingStatus(friendNumber, isTyping);
            _eventDispatcher.EnqueueEvent(new InternalFriendTypingEvent(friendNumber, isTyping));
        }

        public void Dispose()
        {
            _typingStates.Clear();
        }

        private class FriendTypingState
        {
            public bool IsTyping { get; set; }
            public DateTime LastUpdate { get; set; }
        }
    }

    /// <summary>
    /// Gestión de networking.
    /// </summary>
    internal sealed class ToxNetworkManager : IDisposable
    {
        private readonly ToxOptions _options;
        private readonly IMessenger _messenger;
        private readonly IDht _dht;
        private readonly IOnionClient _onionClient;
        private readonly INetworkCore _networkCore;
        private readonly ITCPConnection _tcpConnection;
        private readonly List<(string host, ushort port, byte[] key)> _tcpRelays = new();

        public ToxNetworkManager(ToxOptions options, IMessenger messenger, IDht dht,
            IOnionClient onionClient, INetworkCore networkCore, ITCPConnection tcpConnection)
        {
            _options = options;
            _messenger = messenger;
            _dht = dht;
            _onionClient = onionClient;
            _networkCore = networkCore;
            _tcpConnection = tcpConnection;
        }

        public bool Bootstrap(string address, ushort port, byte[] publicKey)
        {
            if (string.IsNullOrEmpty(address) || publicKey == null || publicKey.Length != 32)
                return false;

            if (_options.UdpEnabled)
            {
                var result = _messenger.Bootstrap(address, port, publicKey);
                if (result)
                {
                    Logger.Log.Info($"[TOX-NETWORK] UDP bootstrap successful to {address}:{port}");
                    return true;
                }
            }

            return BootstrapTcp(address, port, publicKey);
        }

        public bool AddTcpRelay(string address, ushort port, byte[] publicKey)
        {
            if (string.IsNullOrEmpty(address) || publicKey == null || publicKey.Length != 32)
                return false;

            if (!TryResolve(address, port, out var endpoint))
                return false;

            lock (_tcpRelays)
            {
                _tcpRelays.Add((address, port, (byte[])publicKey.Clone()));
            }

            return _messenger.AddTcpRelay(address, port, publicKey);
        }

        public ushort GetUdpPort()
        {
            try
            {
                if (_dht is IUDPPortProvider udpProvider)
                    return udpProvider.LocalPort;

                if (_networkCore is IUDPPortProvider udpProvider2)
                    return udpProvider2.LocalPort;

                return _options.StartPort;
            }
            catch (Exception ex)
            {
                Logger.Log.Debug($"[TOX-NETWORK] Could not get UDP port: {ex.Message}");
                return 0;
            }
        }

        public ushort GetTcpPort()
        {
            try
            {
                if (_tcpConnection is ITCPPortProvider tcpProvider)
                    return tcpProvider.ListeningPort ?? 0;
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.Debug($"[TOX-NETWORK] Could not get TCP port: {ex.Message}");
                return 0;
            }
        }

        private bool BootstrapTcp(string address, ushort port, byte[] publicKey)
        {
            try
            {
                if (!TryResolve(address, port, out var endpoint))
                    return false;

                Logger.Log.Info($"[TOX-NETWORK] Attempting TCP bootstrap to {endpoint}");

                if (_messenger.AddTcpRelay(address, port, publicKey))
                {
                    Logger.Log.Info($"[TOX-NETWORK] Added bootstrap node as TCP relay");
                    _messenger.Reconnect();
                    return true;
                }

                return TryDirectTcpBootstrap(endpoint, publicKey);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF("[TOX-NETWORK] TCP bootstrap error: {0}", ex.Message);
                return false;
            }
        }

        private bool TryDirectTcpBootstrap(IPEndPoint endpoint, byte[] publicKey)
        {
            try
            {
                lock (_tcpRelays)
                {
                    _tcpRelays.Add((endpoint.Address.ToString(), (ushort)endpoint.Port, (byte[])publicKey.Clone()));
                }

                Logger.Log.Warning($"[TOX-NETWORK] Direct TCP bootstrap queued for retry: {endpoint}");
                return TryOnionBootstrap(publicKey, endpoint);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX-NETWORK] Direct TCP bootstrap failed: {ex.Message}");
                return false;
            }
        }

        private bool TryOnionBootstrap(byte[] publicKey, IPEndPoint expectedEndpoint)
        {
            try
            {
                if (_onionClient?.CreatePath(out int pathId) != true)
                    return false;

                using var ms = new System.IO.MemoryStream();
                ms.WriteByte(0xF0); // Bootstrap Request
                ms.Write(publicKey, 0, publicKey.Length);

                var selfData = _messenger.SelfAddress;
                ms.Write(selfData, 0, Math.Min(selfData.Length, 38));

                var bootstrapData = ms.ToArray();

                bool sent = _onionClient.SendData(pathId, publicKey, bootstrapData);

                if (sent)
                {
                    Logger.Log.Info($"[TOX-NETWORK] Sent onion bootstrap request via path {pathId}");

                    Task.Run(async () =>
                    {
                        await Task.Delay(30000);
                        _onionClient.KillPath(pathId);
                    });

                    return true;
                }

                _onionClient.KillPath(pathId);
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX-NETWORK] Onion bootstrap failed: {ex.Message}");
                return false;
            }
        }

        private bool TryResolve(string host, ushort port, out IPEndPoint endpoint)
        {
            endpoint = null;
            try
            {
                var family = _options.Ipv6Enabled ?
                    System.Net.Sockets.AddressFamily.InterNetworkV6 :
                    System.Net.Sockets.AddressFamily.InterNetwork;

                var addresses = System.Net.Dns.GetHostAddresses(host);
                foreach (var addr in addresses)
                {
                    if (addr.AddressFamily == family ||
                        (family == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                         addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
                    {
                        endpoint = new IPEndPoint(addr, port);
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            lock (_tcpRelays)
            {
                foreach (var relay in _tcpRelays)
                {
                    CryptographicOperations.ZeroMemory(relay.key);
                }
                _tcpRelays.Clear();
            }
        }
    }

    #endregion

    #region Utilidades

    internal static class ToxAddressUtils
    {
        public const int AddressSize = 38;
        public const int PublicKeySize = 32;
        public const int NospamSize = 4;
        public const int ChecksumSize = 2;

        public static bool IsValidAddress(ReadOnlySpan<byte> address)
        {
            if (address.Length != AddressSize) return false;

            var nospamKey = address.Slice(0, PublicKeySize + NospamSize);
            var checksum = BinaryPrimitives.ReadUInt16BigEndian(
                address.Slice(PublicKeySize + NospamSize, ChecksumSize));

            var calculated = CalculateChecksum(nospamKey);
            return checksum == calculated;
        }

        // CORREGIDO: Algoritmo Ones' Complement según especificación Tox
        public static ushort CalculateChecksum(ReadOnlySpan<byte> data)
        {
            uint sum = 0;

            // Sumar palabras de 16 bits big-endian
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                ushort word = (ushort)((data[i] << 8) | data[i + 1]);
                sum += word;
            }

            // Byte impar final
            if (data.Length % 2 == 1)
                sum += (uint)(data[data.Length - 1] << 8);

            // Fold carry bits
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);

            return (ushort)~sum; // Ones' complement
        }
    }

    #endregion
}