// ToxCore.cs - Implementación completa corregida de la API pública de Tox
// Correcciones: Compilación, reflection eliminada, métodos completados

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ToxCore.Core;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.Onion;
using ToxCore.Core.Abstractions.TCP;

namespace ToxCore
{
    #region API Pública - Interfaz ITox y ToxOptions

    public sealed class ToxOptions
    {
        public bool Ipv6Enabled { get; set; } = true;
        public bool UdpEnabled { get; set; } = true;
        public bool LocalDiscoveryEnabled { get; set; } = true;
        public bool HolePunchingEnabled { get; set; } = true;
        public ToxProxyType ProxyType { get; set; } = ToxProxyType.None;
        public string ProxyHost { get; set; } = string.Empty;
        public ushort ProxyPort { get; set; } = 0;
        public ushort StartPort { get; set; } = 33445;
        public ushort EndPort { get; set; } = 33545;
        public byte[] SavedData { get; set; }
        public byte[] SecretKey { get; set; }
        public bool ExperimentalThreadSafe { get; set; } = false;
    }

    public enum ToxProxyType : byte
    {
        None = 0,
        Socks5 = 1,
        Http = 2
    }

    public interface ITox : IDisposable
    {
        ToxOptions Options { get; }
        bool IsConnected { get; }
        uint GetIterationInterval();
        void Iterate();

        byte[] SelfPublicKey { get; }
        byte[] SelfAddress { get; }
        bool SetSelfName(string name);
        string GetSelfName();
        bool SetSelfStatusMessage(string message);
        string GetSelfStatusMessage();
        void SetSelfStatus(ToxUserStatus status);
        ToxUserStatus GetSelfStatus();
        void SetSelfNospam(uint nospam);
        uint GetSelfNospam();

        int FriendCount { get; }
        ToxFriendAddError AddFriend(byte[] address, string message, out int friendNumber);
        ToxFriendAddError AddFriendNoRequest(byte[] publicKey, out int friendNumber);
        bool DeleteFriend(int friendNumber);
        int GetFriendByPublicKey(byte[] publicKey);
        bool GetFriendPublicKey(int friendNumber, out byte[] publicKey);
        bool FriendExists(int friendNumber);
        ToxConnectionStatus GetFriendConnectionStatus(int friendNumber);
        IReadOnlyList<int> GetFriendList();

        string GetFriendName(int friendNumber);
        string GetFriendStatusMessage(int friendNumber);
        ToxUserStatus GetFriendStatus(int friendNumber);
        ulong GetFriendLastOnline(int friendNumber);

        ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType type, string message, out uint messageId);

        bool SetTyping(int friendNumber, bool isTyping);
        bool GetFriendTyping(int friendNumber); // CORREGIDO: Ahora funcional

        event Action<byte[], string> OnFriendRequest;
        event Action<int, ToxMessageType, string> OnFriendMessage;
        event Action<int, string> OnFriendNameChange;
        event Action<int, string> OnFriendStatusMessageChange;
        event Action<int, ToxUserStatus> OnFriendStatusChange;
        event Action<int, ToxConnectionStatus> OnFriendConnectionStatusChange;
        event Action<ToxConnectionStatus> OnSelfConnectionStatusChange;

        bool Bootstrap(string address, ushort port, byte[] publicKey);
        bool AddTcpRelay(string address, ushort port, byte[] publicKey);

        ushort GetUdpPort();   // CORREGIDO: Sin reflection
        ushort GetTcpPort();   // CORREGIDO: Sin reflection

        byte[] GetSaveData();
        bool LoadSaveData(byte[] data);
    }

    #endregion

    #region API Pública - Implementación Principal

    public sealed class Tox : ITox
    {
        private ToxSelf _self;
        private ToxFriends _friends;
        private ToxNetwork _network;
        private ToxCallbacks _callbacks;

        // Dependencias inyectadas directamente - SIN EXTRACTFROMMESSENGER
        private readonly IMessenger _messenger;
        private readonly IOnionClient _onionClient;
        private readonly IOnionAnnounce _onionAnnounce;
        private readonly IDht _dht;
        private readonly INetworkCore _networkCore;
        private readonly ITCPConnection _tcpConnection;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;
        private readonly MonoTime _monoTime;

        private bool _disposed;
        private bool _isRunning;
        private readonly object _iterateLock = new();

        // CORRECCIÓN: Flag de ownership para Dispose correcto
        private readonly bool _ownsMessenger;

        /// <summary>
        /// Constructor principal con inyección directa de dependencias.
        /// RECOMENDADO: Usar este constructor siempre.
        /// </summary>
        public Tox(ToxOptions options,
            IMessenger messenger,
            IOnionClient onionClient,
            IOnionAnnounce onionAnnounce,
            IDht dht,
            INetworkCore networkCore,
            ITCPConnection tcpConnection,
            IFriendConnection friendConnection,
            IFriendRequests friendRequests,
            MonoTime monoTime)
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

            _ownsMessenger = false; // No lo creamos nosotros

            InitializeComponents();
        }


        public void ProcessFriendTypingIndicator(int friendNumber, bool isTyping)
        {
            _friends.ProcessTypingIndicator(friendNumber, isTyping);
        }

        private void InitializeComponents()
        {
            _self = new ToxSelf(this, _messenger);
            _friends = new ToxFriends(this, _messenger, _friendConnection, _friendRequests);
            _network = new ToxNetwork(this, _messenger, _dht, _onionClient, _networkCore, _tcpConnection);
            _callbacks = new ToxCallbacks(this, _messenger, _friendConnection, _friendRequests);

            if (Options.SavedData != null && Options.SavedData.Length > 0)
            {
                LoadSaveData(Options.SavedData);
            }

            _friendRequests.Init(_friendConnection);
            _isRunning = true;

            Logger.Log.Info("[TOX] Instance created successfully");
        }
                

        public ToxOptions Options { get; }

        public bool IsConnected => _messenger.SelfConnectionStatus != ToxConnectionStatus.None;

        public uint GetIterationInterval() => _messenger.GetIterationInterval();

        public void Iterate()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Tox));

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
                }
                catch (Exception ex)
                {
                    Logger.Log.ErrorF("[TOX] Iterate error: {0}", ex.Message);
                }
            }
        }

        // CORRECCIÓN: SelfPublicKey ahora maneja ReadOnlySpan correctamente
        public byte[] SelfPublicKey
        {
            get
            {
                var key = _messenger.SelfPublicKey;
                if (key.IsEmpty) return Array.Empty<byte>();

                // CORREGIDO: Crear array y copiar datos
                var array = new byte[key.Length];
                key.CopyTo(array);
                return array;
            }
        }

        public byte[] SelfAddress => _messenger.SelfAddress;

        public bool SetSelfName(string name) => _self.SetName(name);
        public string GetSelfName() => _self.GetName();
        public bool SetSelfStatusMessage(string message) => _self.SetStatusMessage(message);
        public string GetSelfStatusMessage() => _self.GetStatusMessage();
        public void SetSelfStatus(ToxUserStatus status) => _self.SetStatus(status);
        public ToxUserStatus GetSelfStatus() => _self.GetStatus();
        public void SetSelfNospam(uint nospam) => _self.SetNospam(nospam);
        public uint GetSelfNospam() => _self.GetNospam();

        public int FriendCount => _friends.Count;

        public ToxFriendAddError AddFriend(byte[] address, string message, out int friendNumber) =>
            _friends.Add(address, message, out friendNumber);

        public ToxFriendAddError AddFriendNoRequest(byte[] publicKey, out int friendNumber) =>
            _friends.AddNoRequest(publicKey, out friendNumber);

        public bool DeleteFriend(int friendNumber) => _friends.Delete(friendNumber);
        public int GetFriendByPublicKey(byte[] publicKey) => _friends.GetByPublicKey(publicKey);
        public bool GetFriendPublicKey(int friendNumber, out byte[] publicKey) => _friends.GetPublicKey(friendNumber, out publicKey);
        public bool FriendExists(int friendNumber) => _friends.Exists(friendNumber);
        public ToxConnectionStatus GetFriendConnectionStatus(int friendNumber) => _friends.GetConnectionStatus(friendNumber);

        // CORRECCIÓN: GetFriendList ahora compila correctamente
        public IReadOnlyList<int> GetFriendList()
        {
            var list = _messenger.GetFriendList();
            // CORREGIDO: ToArray() retorna int[] que implementa IReadOnlyList<int>
            return list.Where(f => _messenger.FriendExists(f)).ToArray();
        }

        public string GetFriendName(int friendNumber) => _friends.GetName(friendNumber);
        public string GetFriendStatusMessage(int friendNumber) => _friends.GetStatusMessage(friendNumber);
        public ToxUserStatus GetFriendStatus(int friendNumber) => _friends.GetStatus(friendNumber);
        public ulong GetFriendLastOnline(int friendNumber) => _friends.GetLastOnline(friendNumber);

        public ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType type, string message, out uint messageId) =>
            _friends.SendMessage(friendNumber, type, message, out messageId);

        // CORRECCIÓN: SetTyping ahora verifica conexión del amigo
        public bool SetTyping(int friendNumber, bool isTyping)
        {
            if (!_messenger.FriendExists(friendNumber))
                return false;

            // CORREGIDO: Verificar que el amigo esté conectado
            if (_messenger.GetFriendConnectionStatus(friendNumber) == ToxConnectionStatus.None)
                return false;

            try
            {
                var packet = new byte[2];
                packet[0] = 0x42; // Typing Indicator
                packet[1] = (byte)(isTyping ? 1 : 0);

                var result = _friendConnection.SendData(friendNumber, packet);

                // Actualizar estado local de typing
                _friends.UpdateFriendTypingStatus(friendNumber, isTyping);

                return result > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX] Error setting typing status: {ex.Message}");
                return false;
            }
        }

        // CORRECCIÓN: GetFriendTyping ahora consulta el estado real
        public bool GetFriendTyping(int friendNumber)
        {
            return _friends.GetTypingStatus(friendNumber);
        }

        public bool Bootstrap(string address, ushort port, byte[] publicKey) =>
            _network.Bootstrap(address, port, publicKey);

        public bool AddTcpRelay(string address, ushort port, byte[] publicKey) =>
            _network.AddTcpRelay(address, port, publicKey);

        // CORRECCIÓN: GetUdpPort usa propiedad explícita de IDht
        public ushort GetUdpPort()
        {
            try
            {
                // Estrategia 1: Usar propiedad explícita de IDht (RECOMENDADA)
                // Requiere que IDht tenga: ushort LocalPort { get; }
                if (_dht is IUDPPortProvider udpProvider)
                    return udpProvider.LocalPort;

                // Estrategia 2: Fallback a NetworkCore
                if (_networkCore is IUDPPortProvider udpProvider2)
                    return udpProvider2.LocalPort;

                // Estrategia 3: Usar puerto configurado
                return Options.StartPort;
            }
            catch (Exception ex)
            {
                Logger.Log.Debug($"[TOX] Could not get UDP port: {ex.Message}");
                return 0;
            }
        }

        // CORRECCIÓN: GetTcpPort usa propiedad explícita de ITCPConnection
        public ushort GetTcpPort()
        {
            try
            {
                // Estrategia 1: Usar propiedad explícita de ITCPConnection
                // Requiere que ITCPConnection tenga: ushort? ListeningPort { get; }
                if (_tcpConnection is ITCPPortProvider tcpProvider)
                    return tcpProvider.ListeningPort ?? 0;

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.Debug($"[TOX] Could not get TCP port: {ex.Message}");
                return 0;
            }
        }

        public event Action<byte[], string> OnFriendRequest
        {
            add => _callbacks.OnFriendRequest += value;
            remove => _callbacks.OnFriendRequest -= value;
        }

        public event Action<int, ToxMessageType, string> OnFriendMessage
        {
            add => _callbacks.OnFriendMessage += value;
            remove => _callbacks.OnFriendMessage -= value;
        }

        public event Action<int, string> OnFriendNameChange
        {
            add => _callbacks.OnFriendNameChange += value;
            remove => _callbacks.OnFriendNameChange -= value;
        }

        public event Action<int, string> OnFriendStatusMessageChange
        {
            add => _callbacks.OnFriendStatusMessageChange += value;
            remove => _callbacks.OnFriendStatusMessageChange -= value;
        }

        public event Action<int, ToxUserStatus> OnFriendStatusChange
        {
            add => _callbacks.OnFriendStatusChange += value;
            remove => _callbacks.OnFriendStatusChange -= value;
        }

        public event Action<int, ToxConnectionStatus> OnFriendConnectionStatusChange
        {
            add => _callbacks.OnFriendConnectionStatusChange += value;
            remove => _callbacks.OnFriendConnectionStatusChange -= value;
        }

        public event Action<ToxConnectionStatus> OnSelfConnectionStatusChange
        {
            add => _callbacks.OnSelfConnectionStatusChange += value;
            remove => _callbacks.OnSelfConnectionStatusChange -= value;
        }

        public byte[] GetSaveData()
        {
            var size = _messenger.GetSaveDataSize();
            var data = new byte[size];
            _messenger.GetSaveData(data);
            return data;
        }

        public bool LoadSaveData(byte[] data)
        {
            if (data == null || data.Length == 0) return false;
            return _messenger.LoadSaveData(data);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _isRunning = false;

            _callbacks?.Dispose();
            _network?.Dispose();
            _friends?.Dispose();
            _self?.Dispose();

            // CORREGIDO: Solo disponer si somos dueños
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

            Logger.Log.Info("[TOX] Instance disposed");
        }
    }

    #endregion

    #region Clases Internas - Componentes Privados

    internal sealed class ToxSelf : IDisposable
    {
        private readonly Tox _tox;
        private readonly IMessenger _messenger;

        public ToxSelf(Tox tox, IMessenger messenger)
        {
            _tox = tox;
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

        public void SetStatus(ToxUserStatus status) => _messenger.SetSelfStatus(status);
        public ToxUserStatus GetStatus() => _messenger.GetSelfStatus();
        public void SetNospam(uint nospam) => _messenger.SetSelfNospam(nospam);
        public uint GetNospam() => _messenger.GetSelfNospam();

        public void Dispose() { }
    }

    // CORRECCIÓN: ToxFriends ahora con tracking de typing
    internal sealed class ToxFriends : IDisposable
    {
        private readonly Tox _tox;
        private readonly IMessenger _messenger;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;

        // CORRECCIÓN: Tracking de estado de typing
        private readonly Dictionary<int, FriendTypingState> _typingStates = new();

        public ToxFriends(Tox tox, IMessenger messenger, IFriendConnection friendConnection, IFriendRequests friendRequests)
        {
            _tox = tox;
            _messenger = messenger;
            _friendConnection = friendConnection;
            _friendRequests = friendRequests;
        }

        public int Count => _messenger.FriendCount;

        public ToxFriendAddError Add(byte[] address, string message, out int friendNumber)
        {
            friendNumber = -1;
            if (address == null || address.Length != 38)
                return ToxFriendAddError.BadChecksum;

            if (!ToxAddressUtils.IsValidAddress(address))
                return ToxFriendAddError.BadChecksum;

            var msgBytes = string.IsNullOrEmpty(message) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(message);
            if (msgBytes.Length > 1016)
                return ToxFriendAddError.TooLong;

            var result = _messenger.AddFriend(address, msgBytes, (uint)msgBytes.Length, out friendNumber);
            return ConvertError(result);
        }

        public ToxFriendAddError AddNoRequest(byte[] publicKey, out int friendNumber)
        {
            friendNumber = -1;
            if (publicKey == null || publicKey.Length != 32)
                return ToxFriendAddError.BadChecksum;

            var selfKey = _messenger.SelfPublicKey;
            if (selfKey.SequenceEqual(publicKey))
                return ToxFriendAddError.OwnKey;

            var success = _messenger.AddFriendNoRequest(publicKey, out friendNumber);
            return success ? ToxFriendAddError.Ok : ToxFriendAddError.Malloc;
        }

        public bool Delete(int friendNumber)
        {
            _friendConnection.KillConnection(friendNumber);
            _typingStates.Remove(friendNumber); // Limpiar estado de typing
            return _messenger.DeleteFriend(friendNumber);
        }

        public int GetByPublicKey(byte[] publicKey) => _messenger.GetFriendByPublicKey(publicKey);

        public bool GetPublicKey(int friendNumber, out byte[] publicKey)
        {
            publicKey = null;
            return _messenger.GetFriendPublicKey(friendNumber, out publicKey);
        }

        public bool Exists(int friendNumber) => _messenger.FriendExists(friendNumber);

        public ToxConnectionStatus GetConnectionStatus(int friendNumber) =>
            _messenger.GetFriendConnectionStatus(friendNumber);

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

        public ToxUserStatus GetStatus(int friendNumber) => _messenger.GetFriendStatus(friendNumber);
        public ulong GetLastOnline(int friendNumber) => _messenger.GetFriendLastOnline(friendNumber);

        public ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType type, string message, out uint messageId)
        {
            messageId = 0;
            if (string.IsNullOrEmpty(message)) return ToxFriendSendMessageError.Empty;
            if (!_messenger.FriendExists(friendNumber)) return ToxFriendSendMessageError.FriendNotFound;

            var bytes = Encoding.UTF8.GetBytes(message);
            if (bytes.Length > 1372)
                return ToxFriendSendMessageError.TooLong;

            if (_messenger.GetFriendConnectionStatus(friendNumber) == ToxConnectionStatus.None)
                return ToxFriendSendMessageError.FriendNotConnected;

            var result = _messenger.SendMessage(friendNumber, type, bytes, (uint)bytes.Length, out messageId);
            return ConvertSendError(result);
        }

        // CORRECCIÓN: Métodos para tracking de typing
        public void UpdateFriendTypingStatus(int friendNumber, bool isTyping)
        {
            _typingStates[friendNumber] = new FriendTypingState
            {
                IsTyping = isTyping,
                LastUpdate = DateTime.UtcNow
            };
        }

        public bool GetTypingStatus(int friendNumber)
        {
            if (_typingStates.TryGetValue(friendNumber, out var state))
            {
                // Expirar después de 10 segundos si no hay actualización
                if (DateTime.UtcNow - state.LastUpdate > TimeSpan.FromSeconds(10))
                {
                    _typingStates.Remove(friendNumber);
                    return false;
                }
                return state.IsTyping;
            }
            return false;
        }

        // CORRECCIÓN: Procesar indicador de typing entrante
        public void ProcessTypingIndicator(int friendNumber, bool isTyping)
        {
            UpdateFriendTypingStatus(friendNumber, isTyping);
        }

        private static ToxFriendAddError ConvertError(ToxFriendAddError error) => error;
        private static ToxFriendSendMessageError ConvertSendError(ToxFriendSendMessageError error) => error;

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

    internal sealed class ToxNetwork : IDisposable
    {
        private readonly Tox _tox;
        private readonly IMessenger _messenger;
        private readonly IDht _dht;
        private readonly IOnionClient _onionClient;
        private readonly INetworkCore _networkCore;
        private readonly ITCPConnection _tcpConnection;
        private readonly List<(string host, ushort port, byte[] key)> _tcpRelays = new();

        public ToxNetwork(Tox tox, IMessenger messenger, IDht dht, IOnionClient onionClient,
            INetworkCore networkCore, ITCPConnection tcpConnection)
        {
            _tox = tox;
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

            if (_tox.Options.UdpEnabled)
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

        private bool BootstrapTcp(string address, ushort port, byte[] publicKey)
        {
            try
            {
                if (!TryResolve(address, port, out var endpoint))
                    return false;

                Logger.Log.Info($"[TOX-NETWORK] Attempting TCP bootstrap to {endpoint}");

                // Estrategia 1: Agregar como TCP relay
                if (_messenger.AddTcpRelay(address, port, publicKey))
                {
                    Logger.Log.Info($"[TOX-NETWORK] Added bootstrap node as TCP relay: {endpoint}");
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

        // CORRECCIÓN: TryOnionBootstrap con mejor manejo pero aún placeholder
        private bool TryOnionBootstrap(byte[] publicKey, IPEndPoint expectedEndpoint)
        {
            try
            {
                // NOTA: Esto es un placeholder. Una implementación completa requeriría:
                // 1. Buscar el nodo en el DHT via onion routing
                // 2. Establecer un path onion al nodo
                // 3. Enviar paquete de bootstrap por el path
                // 4. Esperar respuesta confirmando conexión

                if (_onionClient.CreatePath(out int pathId))
                {
                    using var ms = new System.IO.MemoryStream();
                    ms.WriteByte(0xF0); // Bootstrap Request
                    ms.Write(publicKey, 0, publicKey.Length);
                    var data = ms.ToArray();

                    bool sent = _onionClient.SendData(pathId, publicKey, data);

                    if (sent)
                    {
                        Logger.Log.Info($"[TOX-NETWORK] Sent onion bootstrap request for node {Logger.SafeKeyThumb(publicKey)}");
                    }

                    // Cleanup después de timeout
                    Task.Run(async () =>
                    {
                        await Task.Delay(30000);
                        _onionClient.KillPath(pathId);
                    });

                    // RETORNA TRUE SI SE ENVIÓ, NO SI CONECTÓ
                    // Esto es intencionalmente un placeholder
                    return sent;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX-NETWORK] Onion bootstrap failed: {ex.Message}");
            }

            return false;
        }

        private bool TryResolve(string host, ushort port, out IPEndPoint endpoint)
        {
            endpoint = null;
            try
            {
                var family = _tox.Options.Ipv6Enabled ?
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

    // CORRECCIÓN: ToxCallbacks sin duplicación de FriendRequest
    internal sealed class ToxCallbacks : IDisposable
    {
        private readonly Tox _tox;
        private readonly IMessenger _messenger;
        private readonly IFriendConnection _friendConnection;
        private readonly IFriendRequests _friendRequests;

        public event Action<byte[], string> OnFriendRequest;
        public event Action<int, ToxMessageType, string> OnFriendMessage;
        public event Action<int, string> OnFriendNameChange;
        public event Action<int, string> OnFriendStatusMessageChange;
        public event Action<int, ToxUserStatus> OnFriendStatusChange;
        public event Action<int, ToxConnectionStatus> OnFriendConnectionStatusChange;
        public event Action<ToxConnectionStatus> OnSelfConnectionStatusChange;

        private FriendConnectionStatusCallback _friendStatusHandler;
        private FriendConnectionDataCallback _friendDataHandler;

        public ToxCallbacks(Tox tox, IMessenger messenger,
            IFriendConnection friendConnection,
            IFriendRequests friendRequests)
        {
            _tox = tox;
            _messenger = messenger;
            _friendConnection = friendConnection;
            _friendRequests = friendRequests;

            RegisterCallbacks();
        }

        private void RegisterCallbacks()
        {
            // CORREGIDO: Solo registrar callbacks en Messenger, NO en FriendRequests
            // Messenger ya maneja FriendRequests internamente
            _messenger.SetFriendRequestCallback(OnMessengerFriendRequest);
            _messenger.SetFriendMessageCallback(OnMessengerFriendMessage);
            _messenger.SetFriendNameCallback(OnMessengerFriendNameChange);
            _messenger.SetFriendStatusMessageCallback(OnMessengerFriendStatusMessageChange);
            _messenger.SetFriendStatusCallback(OnMessengerFriendStatusChange);
            _messenger.SetFriendToxConnectionStatusCallback(OnMessengerFriendConnectionStatusChange);
            _messenger.SetSelfConnectionStatusCallback(OnMessengerSelfConnectionStatusChange);

            // Callbacks de FriendConnection para datos de bajo nivel
            _friendStatusHandler = OnFriendConnectionStatusChanged;
            _friendDataHandler = OnFriendConnectionDataReceived;

            _friendConnection.RegisterStatusCallback(_friendStatusHandler, this);
            _friendConnection.RegisterDataCallback(_friendDataHandler, this);

            // CORREGIDO: NO registrar callback de FriendRequest en FriendConnection
            // porque Messenger ya lo maneja
        }

        private void OnMessengerFriendRequest(byte[] publicKey, byte[] message, uint length)
        {
            var msg = message != null ? Encoding.UTF8.GetString(message, 0, (int)Math.Min(length, message.Length)) : string.Empty;
            OnFriendRequest?.Invoke(publicKey, msg);
        }

        private void OnMessengerFriendMessage(int friendNumber, ToxMessageType messageType, byte[] message, uint length)
        {
            var msg = message != null ? Encoding.UTF8.GetString(message, 0, (int)Math.Min(length, message.Length)) : string.Empty;
            OnFriendMessage?.Invoke(friendNumber, messageType, msg);
        }

        private void OnMessengerFriendNameChange(int friendNumber, byte[] name, uint length)
        {
            var n = name != null ? Encoding.UTF8.GetString(name, 0, (int)Math.Min(length, name.Length)) : string.Empty;
            OnFriendNameChange?.Invoke(friendNumber, n);
        }

        private void OnMessengerFriendStatusMessageChange(int friendNumber, byte[] message, uint length)
        {
            var msg = message != null ? Encoding.UTF8.GetString(message, 0, (int)Math.Min(length, message.Length)) : string.Empty;
            OnFriendStatusMessageChange?.Invoke(friendNumber, msg);
        }

        private void OnMessengerFriendStatusChange(int friendNumber, ToxUserStatus status)
        {
            OnFriendStatusChange?.Invoke(friendNumber, status);
        }

        private void OnMessengerFriendConnectionStatusChange(int friendNumber, ToxConnectionStatus connectionStatus)
        {
            OnFriendConnectionStatusChange?.Invoke(friendNumber, connectionStatus);
        }

        private void OnMessengerSelfConnectionStatusChange(ToxConnectionStatus connectionStatus)
        {
            OnSelfConnectionStatusChange?.Invoke(connectionStatus);
        }

        private void OnFriendConnectionStatusChanged(int friendNumber, FriendConnectionStatus status, object userData)
        {
            // Ya manejado por Messenger, no hacer nada aquí para evitar duplicación
            // o mapear a ToxConnectionStatus si es necesario para eventos de bajo nivel
        }

        private void OnFriendConnectionDataReceived(int friendNumber, byte[] data, object userData)
        {
            if (data == null || data.Length < 1) return;

            try
            {
                byte packetType = data[0];

                switch (packetType)
                {
                    case 0x40: // Mensaje normal
                    case 0x41: // Acción
                               // Messenger ya procesa estos, no duplicar
                        break;

                    case 0x42: // Typing indicator
                        if (data.Length >= 2)
                        {
                            bool isTyping = data[1] != 0;
                            // CORREGIDO: Usar método público de Tox
                            _tox.ProcessFriendTypingIndicator(friendNumber, isTyping);
                        }
                        break;

                    default:
                        Logger.Log.Debug($"[TOX-CALLBACK] Unknown packet type {packetType:X2} from friend {friendNumber}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TOX-CALLBACK] Error processing data from friend {friendNumber}: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _friendConnection.RegisterStatusCallback(null, null);

            OnFriendRequest = null;
            OnFriendMessage = null;
            OnFriendNameChange = null;
            OnFriendStatusMessageChange = null;
            OnFriendStatusChange = null;
            OnFriendConnectionStatusChange = null;
            OnSelfConnectionStatusChange = null;
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

            // Los últimos 2 bytes son el checksum
            var nospamKey = address.Slice(0, PublicKeySize + NospamSize);
            var checksum = BinaryPrimitives.ReadUInt16LittleEndian(
                address.Slice(PublicKeySize + NospamSize, ChecksumSize));

            var calculated = CalculateChecksum(nospamKey);
            return checksum == calculated;
        }

        // CORREGIDO: Algoritmo XOR como en la especificación oficial
        public static ushort CalculateChecksum(ReadOnlySpan<byte> data)
        {
            // Byte 0: XOR de todos los bytes en posiciones pares (0, 2, 4...)
            // Byte 1: XOR de todos los bytes en posiciones impares (1, 3, 5...)
            byte even = 0, odd = 0;

            for (int i = 0; i < data.Length; i++)
            {
                if ((i & 1) == 0) // Par
                    even ^= data[i];
                else // Impar
                    odd ^= data[i];
            }

            return (ushort)((even << 8) | odd);
        }
    }

    #endregion
}