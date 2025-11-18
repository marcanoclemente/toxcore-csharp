using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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
    public struct Friend
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
    }

    /// <summary>
    /// Implementación completa de Friend Connection compatible con toxcore
    /// </summary>
    public class FriendConnection
    {
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
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// m_addfriend - Agregar amigo por clave pública
        /// </summary>
        public int m_addfriend(byte[] public_key)
        {
            if (public_key == null || public_key.Length != 32) return -1;

            try
            {
                lock (_friendsLock)
                {
                    // Verificar si el amigo ya existe
                    var existingFriend = _friends.Find(f => ByteArraysEqual(public_key, f.PublicKey));
                    if (existingFriend.PublicKey != null) return -1;

                    // Verificar límite de amigos
                    if (_friends.Count >= MAX_FRIEND_COUNT) return -1;

                    // Crear nuevo amigo
                    var newFriend = new Friend(_lastFriendNumber++, public_key);
                    _friends.Add(newFriend);

                    // Intentar conectar inmediatamente
                    friendconn_connect(newFriend.FriendNumber);

                    return newFriend.FriendNumber;
                }
            }
            catch (Exception)
            {
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
            if (message == null || length > 1372) return -1; // MAX_MESSAGE_LENGTH en toxcore

            try
            {
                lock (_friendsLock)
                {
                    var friend = _friends.Find(f => f.FriendNumber == friend_number);
                    if (friend.PublicKey == null || !friend.IsOnline) return -1;

                    // Crear paquete de mensaje
                    byte[] packet = CreateMessagePacket(message, length);
                    if (packet == null) return -1;

                    // Enviar a través de Onion Routing
                    int sent = _onion.onion_send_1(packet, packet.Length, friend.PublicKey);
                    if (sent > 0)
                    {
                        friend.LastSeen = DateTime.UtcNow.Ticks;
                        return sent;
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

                    return 0;
                }
            }
            catch (Exception)
            {
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
        /// m_handle_packet - Manejar paquete desde capa de red
        /// </summary>
        public int m_handle_packet(int friendcon_id, byte[] data, int length)
        {
            return handle_packet(friendcon_id, data, length);
        }

        // ==================== FUNCIONES DE CREACIÓN DE PAQUETES ====================

        private byte[] CreateMessagePacket(byte[] message, int length)
        {
            byte[] packet = new byte[1 + length];
            packet[0] = 0x20; // Message type
            Buffer.BlockCopy(message, 0, packet, 1, length);
            return packet;
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

        private int HandlePongPacket(int friend_number, byte[] packet, int length)
        {
            if (length != 5) return -1;

            lock (_friendsLock)
            {
                var friend = _friends.Find(f => f.FriendNumber == friend_number);
                if (friend.PublicKey != null)
                {
                    friend.LastSeen = DateTime.UtcNow.Ticks;
                    friend.IsOnline = true;
                }
            }
            return 0;
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
        /// Do_periodic_work - Mantenimiento de conexiones de amigos
        /// </summary>
        public void Do_periodic_work()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            lock (_friendsLock)
            {
                // CORREGIDO: Usar for loop en lugar de foreach para modificar elementos
                for (int i = 0; i < _friends.Count; i++)
                {
                    var friend = _friends[i];

                    // Enviar ping a amigos conectados
                    if (friend.IsOnline && (currentTime - friend.LastPingSent) > TimeSpan.TicksPerMillisecond * FRIEND_PING_INTERVAL)
                    {
                        byte[] pingPacket = CreatePingPacket(friend.PingId);

                        // Enviar ping
                        m_send_message(friend.FriendNumber, pingPacket, pingPacket.Length);

                        // Actualizar friend con nuevo estado
                        var updatedFriend = friend;
                        updatedFriend.PingId++; // Incrementar aquí, no en la llamada
                        updatedFriend.LastPingSent = currentTime;
                        _friends[i] = updatedFriend;
                    }

                    // Verificar timeouts
                    if (friend.IsOnline && (currentTime - friend.LastSeen) > TimeSpan.TicksPerMillisecond * FRIEND_CONNECTION_TIMEOUT)
                    {
                        UpdateFriendStatus(friend.FriendNumber, FriendConnectionStatus.FRIENDCONN_STATUS_DISCONNECTED);
                    }
                }
            }

            // Ejecutar mantenimiento cada 30 segundos
            if ((currentTime - _lastMaintenanceTime) > TimeSpan.TicksPerSecond * 30)
            {
                _lastMaintenanceTime = currentTime;
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