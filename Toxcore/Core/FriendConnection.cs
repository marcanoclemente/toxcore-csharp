using Sodium;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ToxCore.Core;

namespace ToxCore.Core
{
    /// <summary>
    /// Estados de conexión de amigos compatibles con toxcore
    /// </summary>
    public enum FriendConnectionStatus
    {
        FRIENDCONN_STATUS_NONE,
        FRIENDCONN_STATUS_CONNECTING,
        FRIENDCONN_STATUS_CONNECTED,
        FRIENDCONN_STATUS_DISCONNECTED
    }

    public enum FriendUserStatus
    {
        TOX_USER_STATUS_NONE,
        TOX_USER_STATUS_AWAY,
        TOX_USER_STATUS_BUSY
    }


    /// <summary>
    /// Información de un amigo individual
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public class Friend
    {
        public int FriendNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        public FriendConnectionStatus ConnectionStatus;
        public FriendUserStatus UserStatus;
        public long LastSeen;
        public bool IsOnline;
        public int PingId;
        public long LastPingSent;
        public long LastPingReceived; // ✅ NUEVO
        public ToxConnection ConnectionType; // ✅ NUEVO - UDP/TCP/None
        public int FailedPings; // ✅ NUEVO - contador de pings fallidos

        public Friend(int friendNumber, byte[] publicKey)
        {
            FriendNumber = friendNumber;
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
            ConnectionStatus = FriendConnectionStatus.FRIENDCONN_STATUS_NONE;
            UserStatus = FriendUserStatus.TOX_USER_STATUS_NONE;
            LastSeen = 0;
            IsOnline = false;
            PingId = 0;
            LastPingSent = 0;
            LastPingReceived = 0; // ✅ NUEVO
            ConnectionType = ToxConnection.TOX_CONNECTION_NONE; // ✅ NUEVO
            FailedPings = 0; // ✅ NUEVO
        }
    }

    /// <summary>
    /// Callbacks para eventos de amigos
    /// </summary>
    public class FriendCallbacks
    {
        public Action<int, FriendConnectionStatus> OnConnectionStatusChanged;
        public Action<int, byte[], int> OnMessageReceived;
        public Action<int, string> OnNameChanged;
        public Action<int, string> OnStatusMessageChanged;
        public Action<int, FriendUserStatus> OnUserStatusChanged;
        public Action<byte[], string> OnFriendRequest; // ✅ NUEVO - solicitudes de amistad
    }

    /// <summary>
    /// Implementación completa de Friend Connection compatible con toxcore
    /// </summary>
    public class FriendConnection
    {
        private const string LOG_TAG = "FRIEND";
        private long _lastLogTime = 0;

        public const int MAX_DATA_SIZE = 1372; // Tamaño máximo de mensaje en toxcore
        public const int CRYPTO_NONCE_SIZE = 24;
        public const int CRYPTO_MAC_SIZE = 16;

        public const int MAX_FRIEND_COUNT = 500;
        public const int FRIEND_CONNECTION_TIMEOUT = 60000;
        public const int FRIEND_PING_INTERVAL = 30000;

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public FriendCallbacks Callbacks { get; private set; }

        private readonly List<Friend> _friends;
        private readonly object _friendsLock = new object();
        private DHT _dht;
        private Onion _onion;
        private TCP_Client _tcpClient;
        private int _lastFriendNumber;
        private long _lastMaintenanceTime;

        public int FriendCount
        {
            get
            {
                lock (_friendsLock)
                {
                    return _friends.Count;
                }
            }
        }

        public int OnlineFriends
        {
            get
            {
                lock (_friendsLock)
                {
                    return _friends.Count(f => f.IsOnline);
                }
            }
        }

        public FriendConnection(byte[] selfPublicKey, byte[] selfSecretKey, DHT dht, Onion onion)
        {
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            _friends = new List<Friend>();
            _dht = dht;
            _onion = onion;
            _tcpClient = new TCP_Client(selfPublicKey, selfSecretKey);
            _lastFriendNumber = 0;
            _lastMaintenanceTime = DateTime.UtcNow.Ticks;
            Callbacks = new FriendCallbacks();
            Logger.Log.InfoF($"[{LOG_TAG}] FriendConnection inicializado");
        }


        /// <summary>
        /// GetFriendConnectionStatus - Determina estado REAL de conexión como en Messenger.c
        /// </summary>
        public ToxConnection GetFriendConnectionStatus(int friendNumber)
        {
            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                if (friend.PublicKey == null) return ToxConnection.TOX_CONNECTION_NONE;

                long currentTime = DateTime.UtcNow.Ticks;
                long timeSinceLastSeen = (currentTime - friend.LastSeen) / TimeSpan.TicksPerMillisecond;
                long timeSinceLastPingResponse = (currentTime - friend.LastPingReceived) / TimeSpan.TicksPerMillisecond;

                // Si no hemos visto actividad reciente, está desconectado
                if (timeSinceLastSeen > FRIEND_CONNECTION_TIMEOUT)
                {
                    return ToxConnection.TOX_CONNECTION_NONE;
                }

                // Si recibimos pong recientemente, está conectado via UDP (óptimo)
                if (timeSinceLastPingResponse < Messenger.PING_TIMEOUT)
                {
                    return ToxConnection.TOX_CONNECTION_UDP;
                }

                // Si hemos visto actividad pero no pongs recientes, podría ser TCP
                if (timeSinceLastSeen < FRIEND_CONNECTION_TIMEOUT)
                {
                    return ToxConnection.TOX_CONNECTION_TCP;
                }

                return ToxConnection.TOX_CONNECTION_NONE;
            }
        }

        /// <summary>
        /// SendPingToFriend - Envía ping REAL y monitorea respuesta
        /// </summary>
        public int SendPingToFriend(int friendNumber)
        {
            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                    if (friend.PublicKey == null) return -1;

                    long currentTime = DateTime.UtcNow.Ticks;

                    // Verificar que no estamos spameando pings
                    long timeSinceLastPing = (currentTime - friend.LastPingSent) / TimeSpan.TicksPerMillisecond;
                    if (timeSinceLastPing < Messenger.PING_INTERVAL / 2) // Esperar al menos 15 segundos
                    {
                        return -1;
                    }

                    // Crear ping real con ID único
                    byte[] pingPacket = CreateRealPingPacket(friend.PingId);
                    if (pingPacket == null) return -1;

                    // Enviar ping encriptado
                    int sent = m_send_message(friendNumber, pingPacket, pingPacket.Length);
                    if (sent > 0)
                    {
                        // Actualizar estado del friend
                        friend.LastPingSent = currentTime;
                        friend.PingId++; // Incrementar para próximo ping
                        UpdateFriendInList(friend);

                        Logger.Log.TraceF($"[{LOG_TAG}] Ping enviado a friend {friendNumber} (ID: {friend.PingId})");
                        return sent;
                    }

                    return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando ping: {ex.Message}");
                return -1;
            }
        }


        /// <summary>
        /// CreateRealPingPacket - Crea ping REAL con timestamp e ID
        /// </summary>
        private byte[] CreateRealPingPacket(int pingId)
        {
            try
            {
                // Payload del ping: [0x10][ping_id(4)][timestamp(8)]
                byte[] pingData = new byte[1 + 4 + 8];
                pingData[0] = 0x10; // PING type

                // Ping ID (4 bytes)
                byte[] idBytes = BitConverter.GetBytes(pingId);
                Buffer.BlockCopy(idBytes, 0, pingData, 1, 4);

                // Timestamp actual (8 bytes)
                byte[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                Buffer.BlockCopy(timestamp, 0, pingData, 5, 8);

                return pingData;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando ping packet: {ex.Message}");
                return null;
            }
        }


        /// <summary>
        /// HandleRealPongResponse - Procesa respuesta PONG real
        /// </summary>
        private int HandlePongResponse(int friendNumber, byte[] packet, int length)
        {
            if (length < 1 + 4 + 8) return -1; // [0x11][ping_id][timestamp]

            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                    if (friend.PublicKey == null) return -1;

                    // Extraer ping ID (bytes 1-4)
                    int receivedPingId = BitConverter.ToInt32(packet, 1);

                    // Extraer timestamp (bytes 5-12) - podríamos calcular RTT aquí
                    long pingTimestamp = BitConverter.ToInt64(packet, 5);

                    long currentTime = DateTime.UtcNow.Ticks;

                    // Actualizar estado del friend
                    friend.LastPingReceived = currentTime;
                    friend.LastSeen = currentTime;
                    friend.FailedPings = 0; // Resetear contador de fallos
                    friend.ConnectionType = ToxConnection.TOX_CONNECTION_UDP; // Conexión directa

                    UpdateFriendInList(friend);

                    Logger.Log.TraceF($"[{LOG_TAG}] Pong recibido de friend {friendNumber} (ID: {receivedPingId})");
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando pong: {ex.Message}");
                return -1;
            }
        }


        /// <summary>
        /// CheckConnectionStatusChanges - Monitorea cambios de estado REAL
        /// </summary>
        private void CheckConnectionStatusChanges()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;
                List<(int friendNumber, ToxConnection newStatus)> statusChanges = new List<(int, ToxConnection)>();

                lock (_friendsLock)
                {
                    foreach (var friend in _friends)
                    {
                        if (friend.PublicKey == null) continue;

                        ToxConnection currentStatus = friend.ConnectionType;
                        ToxConnection newStatus = GetFriendConnectionStatus(friend.FriendNumber);

                        // Si el estado cambió, registrar para callback
                        if (currentStatus != newStatus)
                        {
                            statusChanges.Add((friend.FriendNumber, newStatus));

                            // Actualizar friend con nuevo estado
                            var updatedFriend = friend;
                            updatedFriend.ConnectionType = newStatus;
                            updatedFriend.IsOnline = (newStatus != ToxConnection.TOX_CONNECTION_NONE);
                            UpdateFriendInList(updatedFriend);
                        }

                        // Si estamos desconectados, incrementar contador de pings fallidos
                        if (newStatus == ToxConnection.TOX_CONNECTION_NONE)
                        {
                            var updatedFriend = friend;
                            updatedFriend.FailedPings++;
                            UpdateFriendInList(updatedFriend);
                        }
                    }
                }

                // Disparar callbacks fuera del lock
                foreach (var change in statusChanges)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Estado de friend {change.friendNumber} cambió: {change.newStatus}");
                    // Aquí iría: Callbacks.OnConnectionStatusChanged?.Invoke(change.friendNumber, change.newStatus);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error verificando cambios de estado: {ex.Message}");
            }
        }


        /// <summary>
        /// UpdateFriendInList - Actualiza friend en la lista de forma segura
        /// </summary>
        private void UpdateFriendInList(Friend updatedFriend)
        {
            lock (_friendsLock)
            {
                for (int i = 0; i < _friends.Count; i++)
                {
                    if (_friends[i].FriendNumber == updatedFriend.FriendNumber)
                    {
                        _friends[i] = updatedFriend;
                        break;
                    }
                }
            }
        }


        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// m_addfriend - Agregar amigo por clave pública
        /// </summary>
        public int m_addfriend(byte[] public_key)
        {
            Logger.Log.InfoF($"[{LOG_TAG}] Agregando nuevo amigo [PK: {BitConverter.ToString(public_key, 0, 8).Replace("-", "")}...]");

            if (public_key == null || public_key.Length != 32) return -1;

            try
            {
                lock (_friendsLock)
                {
                    // Verificar si el amigo ya existe
                    var existingFriend = _friends.Find(f => ByteArraysEqual(public_key, f.PublicKey));
                    if (existingFriend.PublicKey != null)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Amigo ya existe: {existingFriend.FriendNumber}");
                        return -1;
                    }

                    // Verificar límite de amigos
                    if (_friends.Count >= MAX_FRIEND_COUNT) return -1;

                    // Crear nuevo amigo
                    var newFriend = new Friend(_lastFriendNumber++, public_key);
                    _friends.Add(newFriend);

                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo amigo agregado: {newFriend.FriendNumber} [Total: {_friends.Count}]");

                    // Intentar conectar inmediatamente
                    friendconn_connect(newFriend.FriendNumber);

                    return newFriend.FriendNumber;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error agregando amigo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// m_delfriend - Eliminar amigo
        /// </summary>
        public int m_delfriend(int friend_number)
        {
            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null) return -1;

                    // Cerrar conexiones activas
                    friendconn_kill(friend_number);

                    _friends.Remove(friend);
                    return 0;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// m_send_message - Enviar mensaje a amigo
        /// </summary>
        public int m_send_message(int friend_number, byte[] message, int length)
        {
            Logger.Log.DebugF($"[{LOG_TAG}] Enviando mensaje a amigo {friend_number} - Tamaño: {length} bytes");

            if (message == null || length > 1372) return -1;

            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null || !friend.IsOnline)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Amigo {friend_number} no disponible para envío");
                        return -1;
                    }

                    // Crear paquete de mensaje ENCRIPTADO - pasar friend_number
                    byte[] packet = CreateMessagePacket(message, length, friend_number); // ← Agregar parámetro
                    if (packet == null) return -1;

                    // Enviar a través de Onion Routing
                    int sent = _onion.onion_send_1(packet, packet.Length, friend.PublicKey);
                    if (sent > 0)
                    {
                        friend.LastSeen = DateTime.UtcNow.Ticks;
                        Logger.Log.TraceF($"[{LOG_TAG}] Mensaje enviado a amigo {friend_number}: {sent} bytes");
                        return sent;
                    }

                    Logger.Log.WarningF($"[{LOG_TAG}] Falló envío a amigo {friend_number}");
                    return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando mensaje: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// m_set_status - Establecer estado de usuario
        /// </summary>
        public int m_set_status(FriendUserStatus status)
        {
            try
            {
                // Notificar a todos los amigos conectados
                lock (_friendsLock)
                {
                    foreach (var friend in _friends)
                    {
                        if (friend.IsOnline)
                        {
                            byte[] statusPacket = CreateStatusPacket(status);
                            _onion.onion_send_1(statusPacket, statusPacket.Length, friend.PublicKey);
                        }
                    }
                }
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// m_set_status_message - Establecer mensaje de estado
        /// </summary>
        public int m_set_status_message(string message)
        {
            if (message == null || message.Length > 1007) return -1; // MAX_STATUSMESSAGE_LENGTH

            try
            {
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);

                lock (_friendsLock)
                {
                    foreach (var friend in _friends)
                    {
                        if (friend.IsOnline)
                        {
                            byte[] statusMessagePacket = CreateStatusMessagePacket(messageBytes, messageBytes.Length);
                            _onion.onion_send_1(statusMessagePacket, statusMessagePacket.Length, friend.PublicKey);
                        }
                    }
                }
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== GESTIÓN DE CONEXIONES ====================

        /// <summary>
        /// friendconn_connect - Conectar a amigo
        /// </summary>
        public int friendconn_connect(int friend_number)
        {
            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null) return -1;

                    // Buscar amigo en DHT
                    var closestNodes = _dht.GetClosestNodes(friend.PublicKey, 8);
                    if (closestNodes.Count == 0) return -1;

                    // Enviar solicitud de conexión a través de Onion
                    byte[] connectPacket = CreateConnectPacket();
                    int sent = _onion.onion_send_1(connectPacket, connectPacket.Length, friend.PublicKey);

                    if (sent > 0)
                    {
                        UpdateFriendStatus(friend_number, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTING);
                        friend.LastSeen = DateTime.UtcNow.Ticks;
                        return 0;
                    }

                    return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// friendconn_kill - Desconectar amigo
        /// </summary>
        public int friendconn_kill(int friend_number)
        {
            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null) return -1;

                    // Enviar paquete de desconexión
                    byte[] disconnectPacket = CreateDisconnectPacket();
                    _onion.onion_send_1(disconnectPacket, disconnectPacket.Length, friend.PublicKey);

                    UpdateFriendStatus(friend_number, FriendConnectionStatus.FRIENDCONN_STATUS_DISCONNECTED);
                    return 0;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// friend_new_connection - Nueva conexión entrante
        /// </summary>
        public int friend_new_connection(int friend_number)
        {
            Logger.Log.InfoF($"[{LOG_TAG}] Nueva conexión con amigo {friend_number}");

            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null) return -1;

                    UpdateFriendStatus(friend_number, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED);
                    friend.IsOnline = true;
                    friend.LastSeen = DateTime.UtcNow.Ticks;

                    // Notificar callback
                    Callbacks.OnConnectionStatusChanged?.Invoke(friend_number, FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED);

                    Logger.Log.InfoF($"[{LOG_TAG}] Amigo {friend_number} conectado [Online: {_friends.Count(f => f.IsOnline)}]");
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en nueva conexión: {ex.Message}");
                return -1;
            }
        }

        // ==================== MANEJO DE PAQUETES ====================

        /// <summary>
        /// handle_packet - Manejar paquete entrante de amigo
        /// </summary>
        public int handle_packet(int friend_number, byte[] packet, int length)
        {
            if (packet == null || length < 1) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x10: // Ping
                        return HandlePingPacket(friend_number, packet, length);
                    case 0x11: // Pong
                        return HandlePongPacket(friend_number, packet, length);
                    case 0x20: // Message
                        return HandleMessagePacket(friend_number, packet, length);
                    case 0x30: // Connection request
                        return HandleConnectionPacket(friend_number, packet, length);
                    case 0x31: // Disconnection
                        return HandleDisconnectionPacket(friend_number, packet, length);
                    case 0x40: // Status update
                        return HandleStatusPacket(friend_number, packet, length);
                    case 0x41: // Status message
                        return HandleStatusMessagePacket(friend_number, packet, length);
                    default:
                        return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// m_handle_packet - ACTUALIZADO para usar procesamiento REAL
        /// </summary>
        public int m_handle_packet(int friendcon_id, byte[] data, int length)
        {
            // Este método ahora delega al sistema real de procesamiento
            // Necesitamos obtener la public key del friend primero
            byte[] friendPublicKey = GetFriendPublicKey(friendcon_id);
            if (friendPublicKey == null) return -1;

            return HandleFriendPacket(data, length, friendPublicKey);
        }

        /// <summary>
        /// GetFriendPublicKey - Obtiene public key de un friend por número
        /// </summary>
        private byte[] GetFriendPublicKey(int friendNumber)
        {
            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                return friend.PublicKey;
            }
        }

        /// <summary>
        /// HandleFriendRequest - Procesa solicitudes de amistad REALES
        /// Como en Messenger.c - friendreq_handle()
        /// </summary>
        public int HandleFriendRequest(byte[] publicKey, string message)
        {
            try
            {
                if (publicKey == null || publicKey.Length != 32)
                    return -1;

                Logger.Log.InfoF($"[{LOG_TAG}] Solicitud de amistad recibida: '{message}'");

                // Verificar si ya es nuestro amigo
                if (FindFriendNumberByPublicKey(publicKey) != -1)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Solicitud de amistad de friend ya existente");
                    return -1;
                }

                // Disparar callback de solicitud de amistad
                Callbacks.OnFriendRequest?.Invoke(publicKey, message);

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando solicitud de amistad: {ex.Message}");
                return -1;
            }
        }

        // ==================== FUNCIONES DE CREACIÓN DE PAQUETES ====================

        private byte[] CreateMessagePacket(byte[] message, int length, int friendNumber) // ← Agregar friendNumber como parámetro
        {
            try
            {
                // Obtener la shared key real para este amigo
                byte[] sharedKey = GetFriendSharedKey(friendNumber);

                if (sharedKey == null)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No shared key para friend {friendNumber}");
                    return null;
                }

                // Nonce para encriptación
                byte[] nonce = RandomBytes.Generate(CryptoBox.CRYPTO_NONCE_SIZE);

                // Encriptar como en Messenger.c - encrypt_data_symmetric
                byte[] encrypted = new byte[length + CryptoBox.CRYPTO_MAC_SIZE];

                // Usar Sodium para encriptación simétrica
                byte[] cipherText = SecretBox.Create(message, nonce, sharedKey);
                if (cipherText == null || cipherText.Length != encrypted.Length)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Falló encriptación para friend {friendNumber}");
                    return null;
                }

                Buffer.BlockCopy(cipherText, 0, encrypted, 0, encrypted.Length);

                // Paquete real: [nonce(24)][encrypted_data]
                byte[] packet = new byte[CryptoBox.CRYPTO_NONCE_SIZE + encrypted.Length];
                Buffer.BlockCopy(nonce, 0, packet, 0, CryptoBox.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encrypted, 0, packet, CryptoBox.CRYPTO_NONCE_SIZE, encrypted.Length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete mensaje: {ex.Message}");
                return null;
            }
        }

        private byte[] GetFriendSharedKey(int friendNumber)
        {
            // Basado en Messenger.c - get_friend_shared_key
            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                if (friend?.PublicKey == null) return null;

                // Calcular shared key usando crypto_box_beforenm (versión corregida)
                byte[] sharedKey = CryptoBox.BeforeNm(friend.PublicKey, SelfSecretKey);

                return sharedKey; // Ya retorna null si falla
            }
        }


        private byte[] CreateConnectPacket()
        {
            byte[] packet = new byte[33];
            packet[0] = 0x30; // Connection request type
            Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);
            return packet;
        }

        private byte[] CreateDisconnectPacket()
        {
            return new byte[] { 0x31 }; // Disconnection type
        }

        private byte[] CreateStatusPacket(FriendUserStatus status)
        {
            byte[] packet = new byte[2];
            packet[0] = 0x40; // Status type
            packet[1] = (byte)status;
            return packet;
        }

        private byte[] CreateStatusMessagePacket(byte[] message, int length)
        {
            byte[] packet = new byte[1 + length];
            packet[0] = 0x41; // Status message type
            Buffer.BlockCopy(message, 0, packet, 1, length);
            return packet;
        }

        private byte[] CreatePingPacket(int pingId)
        {
            byte[] packet = new byte[5];
            packet[0] = 0x10; // Ping type
            byte[] idBytes = BitConverter.GetBytes(pingId);
            Buffer.BlockCopy(idBytes, 0, packet, 1, 4);
            return packet;
        }

        private byte[] CreatePongPacket(int pingId)
        {
            byte[] packet = new byte[5];
            packet[0] = 0x11; // Pong type
            byte[] idBytes = BitConverter.GetBytes(pingId);
            Buffer.BlockCopy(idBytes, 0, packet, 1, 4);
            return packet;
        }

        // ==================== MANEJADORES DE PAQUETES ====================

        private int HandlePingPacket(int friend_number, byte[] packet, int length)
        {
            if (length != 5) return -1;

            // Extraer ID del ping
            int pingId = BitConverter.ToInt32(packet, 1);

            // Enviar pong de respuesta
            byte[] pongPacket = CreatePongPacket(pingId);
            return m_send_message(friend_number, pongPacket, pongPacket.Length);
        }

        /// <summary>
        /// HandlePongPacket - ACTUALIZADO para usar gestión real
        /// </summary>
        private int HandlePongPacket(int friend_number, byte[] packet, int length)
        {
            // Usar el nuevo sistema real de pong
            return HandlePongResponse(friend_number, packet, length);
        }

        private int HandleMessagePacket(int friend_number, byte[] packet, int length)
        {
            if (length < 2) return -1;

            byte[] message = new byte[length - 1];
            Buffer.BlockCopy(packet, 1, message, 0, length - 1);

            // Notificar callback
            Callbacks.OnMessageReceived?.Invoke(friend_number, message, message.Length);

            return 0;
        }

        private int HandleConnectionPacket(int friend_number, byte[] packet, int length)
        {
            if (length != 33) return -1;

            // Verificar clave pública
            byte[] senderPublicKey = new byte[32];
            Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friend_number);
                if (friend.PublicKey != null && ByteArraysEqual(senderPublicKey, friend.PublicKey))
                {
                    // Aceptar conexión
                    friend_new_connection(friend_number);

                    // Enviar confirmación
                    byte[] connectPacket = CreateConnectPacket();
                    return m_send_message(friend_number, connectPacket, connectPacket.Length);
                }
            }

            return -1;
        }

        private int HandleDisconnectionPacket(int friend_number, byte[] packet, int length)
        {
            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friend_number);
                if (friend.PublicKey != null)
                {
                    UpdateFriendStatus(friend_number, FriendConnectionStatus.FRIENDCONN_STATUS_DISCONNECTED);
                    friend.IsOnline = false;
                }
            }
            return 0;
        }

        private int HandleStatusPacket(int friend_number, byte[] packet, int length)
        {
            if (length != 2) return -1;

            FriendUserStatus status = (FriendUserStatus)packet[1];

            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friend_number);
                if (friend.PublicKey != null)
                {
                    friend.UserStatus = status;
                    Callbacks.OnUserStatusChanged?.Invoke(friend_number, status);
                }
            }
            return 0;
        }

        private int HandleStatusMessagePacket(int friend_number, byte[] packet, int length)
        {
            if (length < 2) return -1;

            byte[] messageBytes = new byte[length - 1];
            Buffer.BlockCopy(packet, 1, messageBytes, 0, length - 1);
            string statusMessage = System.Text.Encoding.UTF8.GetString(messageBytes);

            Callbacks.OnStatusMessageChanged?.Invoke(friend_number, statusMessage);
            return 0;
        }

        /// <summary>
        /// HandleFriendPacket - Procesa paquetes encriptados de amigos REALES
        /// Como en Messenger.c - handle_packet()
        /// </summary>
        public int HandleFriendPacket(byte[] packet, int length, byte[] publicKey)
        {
            if (packet == null || length < CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE + 1)
                return -1;

            try
            {
                // 1. Buscar el friend por public key
                int friendNumber = FindFriendNumberByPublicKey(publicKey);
                if (friendNumber == -1)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Paquete de friend desconocido: {BitConverter.ToString(publicKey, 0, 8).Replace("-", "")}...");
                    return -1;
                }

                // 2. Obtener shared key para este friend
                byte[] sharedKey = GetFriendSharedKey(friendNumber);
                if (sharedKey == null)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No shared key para friend {friendNumber}");
                    return -1;
                }

                // 3. Extraer nonce (primeros 24 bytes)
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                Buffer.BlockCopy(packet, 0, nonce, 0, CRYPTO_NONCE_SIZE);

                // 4. Extraer datos encriptados (resto)
                int encryptedLength = length - CRYPTO_NONCE_SIZE;
                byte[] encrypted = new byte[encryptedLength];
                Buffer.BlockCopy(packet, CRYPTO_NONCE_SIZE, encrypted, 0, encryptedLength);

                // 5. Decryptar usando crypto_secretbox_open
                byte[] decrypted = SecretBox.Open(encrypted, nonce, sharedKey);
                if (decrypted == null || decrypted.Length < 1)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Falló decryptación para friend {friendNumber}");
                    return -1;
                }

                // 6. Procesar el paquete decryptado
                return ProcessDecryptedFriendPacket(friendNumber, decrypted, decrypted.Length);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleFriendPacket: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// FindFriendNumberByPublicKey - Encuentra friend number por public key
        /// </summary>
        private int FindFriendNumberByPublicKey(byte[] publicKey)
        {
            lock (_friendsLock)
            {
                var friend = _friends.Find(f => ByteArraysEqual(f.PublicKey, publicKey));
                return friend.PublicKey != null ? friend.FriendNumber : -1;
            }
        }

        /// <summary>
        /// ProcessDecryptedFriendPacket - Procesa paquetes decryptados de amigos
        /// Como en Messenger.c - handle_packet()
        /// </summary>
        private int ProcessDecryptedFriendPacket(int friendNumber, byte[] decrypted, int length)
        {
            if (decrypted == null || length < 1) return -1;

            byte packetType = decrypted[0];

            // Actualizar last seen - el friend está activo
            UpdateFriendLastSeen(friendNumber);

            switch (packetType)
            {
                case 0x10: // Ping
                    return HandlePingPacket(friendNumber, decrypted, length); // ← CAMBIADO

                case 0x11: // Pong
                    return HandlePongResponse(friendNumber, decrypted, length);

                case 0x20: // Message
                    return HandleRealMessagePacket(friendNumber, decrypted, length);

                case 0x30: // Connection request
                    return HandleRealConnectionPacket(friendNumber, decrypted, length);

                case 0x31: // Disconnection
                    return HandleDisconnectionPacket(friendNumber, decrypted, length); // ← CAMBIADO

                case 0x40: // Status update
                    return HandleStatusPacket(friendNumber, decrypted, length); // ← CAMBIADO

                case 0x41: // Status message
                    return HandleStatusMessagePacket(friendNumber, decrypted, length); // ← CAMBIADO

                default:
                    Logger.Log.DebugF($"[{LOG_TAG}] Tipo de paquete friend desconocido: 0x{packetType:X2}");
                    return -1;
            }
        }

        /// <summary>
        /// HandleRealMessagePacket - Procesa mensajes REALES de amigos
        /// </summary>
        private int HandleRealMessagePacket(int friendNumber, byte[] packet, int length)
        {
            if (length < 2) return -1; // [type][message_data...]

            try
            {
                // Extraer datos del mensaje (bytes 1 hasta el final)
                byte[] messageData = new byte[length - 1];
                Buffer.BlockCopy(packet, 1, messageData, 0, length - 1);

                // Convertir a string (asumiendo UTF-8 como en toxcore)
                string message = System.Text.Encoding.UTF8.GetString(messageData);

                // Determinar tipo de mensaje (normal o acción)
                ToxMessageType messageType = ToxMessageType.TOX_MESSAGE_TYPE_NORMAL;

                Logger.Log.InfoF($"[{LOG_TAG}] Mensaje recibido de friend {friendNumber}: '{message}'");

                // Disparar callback de mensaje recibido
                Callbacks.OnMessageReceived?.Invoke(friendNumber, messageData, messageData.Length);

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando mensaje: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// HandleRealConnectionPacket - Procesa solicitudes de conexión REALES
        /// </summary>
        private int HandleRealConnectionPacket(int friendNumber, byte[] packet, int length)
        {
            if (length != 1 + 32) return -1; // [0x30][public_key(32)]

            try
            {
                // Extraer public key del solicitante
                byte[] senderPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friendNumber);
                    if (friend.PublicKey != null && ByteArraysEqual(senderPublicKey, friend.PublicKey))
                    {
                        // Aceptar conexión - friend se conectó exitosamente
                        friend_new_connection(friendNumber);

                        // Enviar confirmación de conexión
                        byte[] connectPacket = CreateRealConnectionPacket();
                        return m_send_message(friendNumber, connectPacket, connectPacket.Length);
                    }
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando conexión: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// CreateRealConnectionPacket - Crea paquete de conexión REAL
        /// </summary>
        private byte[] CreateRealConnectionPacket()
        {
            try
            {
                // Payload: [0x30][nuestra_public_key(32)]
                byte[] packet = new byte[1 + 32];
                packet[0] = 0x30; // Connection type
                Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete conexión: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// UpdateFriendLastSeen - Actualiza last seen de un friend
        /// </summary>
        private void UpdateFriendLastSeen(int friendNumber)
        {
            lock (_friendsLock)
            {
                for (int i = 0; i < _friends.Count; i++)
                {
                    if (_friends[i].FriendNumber == friendNumber)
                    {
                        var friend = _friends[i];
                        friend.LastSeen = DateTime.UtcNow.Ticks;
                        friend.IsOnline = true;
                        friend.ConnectionType = ToxConnection.TOX_CONNECTION_UDP;
                        _friends[i] = friend;
                        break;
                    }
                }
            }
        }




        // ==================== FUNCIONES AUXILIARES ====================

        private void UpdateFriendStatus(int friend_number, FriendConnectionStatus status)
        {
            lock (_friendsLock)
            {
                for (int i = 0; i < _friends.Count; i++)
                {
                    if (_friends[i].FriendNumber == friend_number)
                    {
                        var friend = _friends[i];
                        friend.ConnectionStatus = status;
                        friend.IsOnline = (status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED);
                        _friends[i] = friend;
                        break;
                    }
                }
            }
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        /// <summary>
        /// Do_periodic_work - ACTUALIZADO con gestión real de conexión
        /// </summary>
        public void Do_periodic_work()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;

                lock (_friendsLock)
                {
                    for (int i = 0; i < _friends.Count; i++)
                    {
                        var friend = _friends[i];

                        // Enviar ping a amigos que necesiten actualización de estado
                        if (friend.IsOnline && (currentTime - friend.LastPingSent) > TimeSpan.TicksPerMillisecond * Messenger.PING_INTERVAL)
                        {
                            SendPingToFriend(friend.FriendNumber);
                        }

                        // Verificar timeouts reales
                        if (friend.IsOnline && (currentTime - friend.LastSeen) > TimeSpan.TicksPerMillisecond * FRIEND_CONNECTION_TIMEOUT)
                        {
                            var updatedFriend = friend;
                            updatedFriend.IsOnline = false;
                            updatedFriend.ConnectionType = ToxConnection.TOX_CONNECTION_NONE;
                            _friends[i] = updatedFriend;

                            Logger.Log.InfoF($"[{LOG_TAG}] Friend {friend.FriendNumber} desconectado por timeout");
                        }
                    }
                }

                // Verificar cambios de estado
                CheckConnectionStatusChanges();

                if ((currentTime - _lastLogTime) > TimeSpan.TicksPerSecond * 60)
                {
                    int onlineCount = _friends.Count(f => f.IsOnline);
                    Logger.Log.DebugF($"[{LOG_TAG}] Estadísticas - Amigos: {_friends.Count}, Online: {onlineCount}");
                    _lastLogTime = currentTime;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico: {ex.Message}");
            }
        }

        /// <summary>
        /// Get_friend - Obtener información de amigo
        /// </summary>
        public Friend? Get_friend(int friend_number)
        {
            lock (_friendsLock)
            {
                return _friends.Find(f => f.FriendNumber == friend_number);
            }
        }

        /// <summary>
        /// Get_friend_list - Obtener lista de amigos
        /// </summary>
        public List<Friend> Get_friend_list()
        {
            lock (_friendsLock)
            {
                return new List<Friend>(_friends);
            }
        }
    }
}