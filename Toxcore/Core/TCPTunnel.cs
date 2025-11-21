using Sodium;
using System.Net.Sockets;

namespace ToxCore.Core
{
    /// <summary>
    /// Estados de conexión TCP tunneling
    /// </summary>
    public enum TCPTunnelStatus
    {
        TCP_TUNNEL_STATUS_DISCONNECTED,
        TCP_TUNNEL_STATUS_CONNECTING,
        TCP_TUNNEL_STATUS_CONNECTED,
        TCP_TUNNEL_STATUS_FORWARDING,
        TCP_TUNNEL_STATUS_ERROR
    }

    /// <summary>
    /// Tipos de paquetes TCP tunneling
    /// </summary>
    public enum TCPTunnelPacketType
    {
        TCP_TUNNEL_PACKET_CONNECT_REQUEST = 0x10,
        TCP_TUNNEL_PACKET_CONNECT_RESPONSE = 0x11,
        TCP_TUNNEL_PACKET_DATA = 0x12,
        TCP_TUNNEL_PACKET_DISCONNECT = 0x13,
        TCP_TUNNEL_PACKET_PING = 0x14,
        TCP_TUNNEL_PACKET_PONG = 0x15
    }

    /// <summary>
    /// Conexión de tunneling TCP
    /// </summary>
    public class TCPTunnelConnection
    {
        public int ConnectionId { get; set; }
        public int FriendNumber { get; set; }
        public TCPTunnelStatus Status { get; set; }
        public Socket LocalSocket { get; set; }
        public IPPort RemoteEndPoint { get; set; }
        public byte[] SessionKey { get; set; }
        public long LastActivity { get; set; }
        public int BytesSent { get; set; }
        public int BytesReceived { get; set; }
        public bool IsInitiator { get; set; }

        // Buffer management
        private readonly byte[] _receiveBuffer;
        private int _receiveBufferOffset;

        public TCPTunnelConnection(int connectionId, int friendNumber)
        {
            ConnectionId = connectionId;
            FriendNumber = friendNumber;
            Status = TCPTunnelStatus.TCP_TUNNEL_STATUS_DISCONNECTED;
            _receiveBuffer = new byte[16 * 1024]; // 16KB buffer
            _receiveBufferOffset = 0;
            SessionKey = new byte[32];
            LastActivity = DateTime.UtcNow.Ticks;
        }

        public void AppendData(byte[] data, int offset, int count)
        {
            if (_receiveBufferOffset + count <= _receiveBuffer.Length)
            {
                Buffer.BlockCopy(data, offset, _receiveBuffer, _receiveBufferOffset, count);
                _receiveBufferOffset += count;
            }
        }

        public byte[] GetBufferedData()
        {
            byte[] data = new byte[_receiveBufferOffset];
            Buffer.BlockCopy(_receiveBuffer, 0, data, 0, _receiveBufferOffset);
            _receiveBufferOffset = 0;
            return data;
        }

        public bool HasBufferedData => _receiveBufferOffset > 0;
    }

    /// <summary>
    /// Sistema principal de TCP Tunneling
    /// </summary>
    public class TCPTunnel : IDisposable
    {
        private const string LOG_TAG = "TCP_TUNNEL";

        // Constantes de configuración
        private const int MAX_TUNNEL_CONNECTIONS = 10;
        private const int TUNNEL_CONNECTION_TIMEOUT = 30000; // 30 segundos
        private const int TUNNEL_PING_INTERVAL = 15000; // 15 segundos
        private const int MAX_PACKET_SIZE = 1372; // Tamaño máximo de paquete Tox

        private readonly Messenger _messenger;
        private readonly Dictionary<int, TCPTunnelConnection> _connections;
        private readonly object _connectionsLock = new object();
        private int _lastConnectionId;
        private bool _isRunning;
        private Thread _tunnelThread;
        private CancellationTokenSource _cancellationTokenSource;

        // Estadísticas
        public int TotalConnections => _connections.Count;
        public int ActiveConnections
        {
            get
            {
                lock (_connectionsLock)
                {
                    return _connections.Values.Count(c =>
                        c.Status == TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTED ||
                        c.Status == TCPTunnelStatus.TCP_TUNNEL_STATUS_FORWARDING);
                }
            }
        }

        public TCPTunnel(Messenger messenger)
        {
            _messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));
            _connections = new Dictionary<int, TCPTunnelConnection>();
            _lastConnectionId = 0;
            _cancellationTokenSource = new CancellationTokenSource();

            Logger.Log.Info($"[{LOG_TAG}] TCP Tunneling inicializado");
        }

        /// <summary>
        /// Iniciar servicio de tunneling
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] TCP Tunneling ya está ejecutándose");
                return true;
            }

            try
            {
                _isRunning = true;
                _cancellationTokenSource = new CancellationTokenSource();

                // Iniciar hilo de mantenimiento
                _tunnelThread = new Thread(TunnelWorker);
                _tunnelThread.IsBackground = true;
                _tunnelThread.Name = "TCPTunnel-Worker";
                _tunnelThread.Start();

                Logger.Log.Info($"[{LOG_TAG}] Servicio TCP Tunneling iniciado");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando TCP Tunneling: {ex.Message}");
                _isRunning = false;
                return false;
            }
        }

        /// <summary>
        /// Detener servicio de tunneling
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _isRunning = false;
                _cancellationTokenSource?.Cancel();

                // Cerrar todas las conexiones
                lock (_connectionsLock)
                {
                    foreach (var connection in _connections.Values)
                    {
                        CloseConnection(connection);
                    }
                    _connections.Clear();
                }

                _tunnelThread?.Join(2000);

                Logger.Log.Info($"[{LOG_TAG}] Servicio TCP Tunneling detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo TCP Tunneling: {ex.Message}");
            }
        }

        // ==================== API PÚBLICA ====================

        /// <summary>
        /// Iniciar conexión de tunneling a un amigo
        /// </summary>
        public int StartTunnel(int friendNumber, IPPort remoteEndPoint)
        {
            if (!_isRunning)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede iniciar tunnel - Servicio no iniciado");
                return -1;
            }

            try
            {
                int connectionId = _lastConnectionId++;
                var connection = new TCPTunnelConnection(connectionId, friendNumber)
                {
                    RemoteEndPoint = remoteEndPoint,
                    Status = TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTING,
                    IsInitiator = true,
                    LastActivity = DateTime.UtcNow.Ticks
                };

                // Generar session key
                RandomBytes.Generate(connection.SessionKey);

                lock (_connectionsLock)
                {
                    if (_connections.Count >= MAX_TUNNEL_CONNECTIONS)
                    {
                        Logger.Log.Warning($"[{LOG_TAG}] Límite de conexiones de tunnel alcanzado");
                        return -1;
                    }
                    _connections[connectionId] = connection;
                }

                // Enviar solicitud de conexión
                if (SendConnectRequest(connection))
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Tunnel iniciado a friend {friendNumber} -> {remoteEndPoint}");
                    return connectionId;
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando tunnel: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Enviar datos a través del tunnel
        /// </summary>
        public int SendTunnelData(int connectionId, byte[] data, int length)
        {
            if (!_isRunning) return -1;

            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection) ||
                        connection.Status != TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTED)
                    {
                        return -1;
                    }
                }

                // Encriptar datos
                byte[] encryptedData = EncryptTunnelData(connection, data, length);
                if (encryptedData == null) return -1;

                // Crear paquete de datos
                byte[] packet = CreateDataPacket(connectionId, encryptedData);
                if (packet == null) return -1;

                // Enviar a través de messenger
                int sent = _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
                if (sent > 0)
                {
                    connection.BytesSent += length;
                    connection.LastActivity = DateTime.UtcNow.Ticks;
                }

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando datos por tunnel: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Cerrar conexión de tunnel
        /// </summary>
        public bool CloseTunnel(int connectionId)
        {
            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection))
                    {
                        return false;
                    }
                }

                // Enviar paquete de desconexión
                SendDisconnectPacket(connection);

                // Cerrar conexión local
                CloseConnection(connection);

                lock (_connectionsLock)
                {
                    _connections.Remove(connectionId);
                }

                Logger.Log.InfoF($"[{LOG_TAG}] Tunnel {connectionId} cerrado");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error cerrando tunnel: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Manejar paquetes de tunneling entrantes
        /// </summary>
        public int HandleTunnelPacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 5) return -1;

            try
            {
                byte packetType = packet[0];
                int connectionId = BitConverter.ToInt32(packet, 1);

                switch (packetType)
                {
                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_CONNECT_REQUEST:
                        return HandleConnectRequest(friendNumber, connectionId, packet, length);

                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_CONNECT_RESPONSE:
                        return HandleConnectResponse(connectionId, packet, length);

                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_DATA:
                        return HandleDataPacket(connectionId, packet, length);

                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_DISCONNECT:
                        return HandleDisconnectPacket(connectionId);

                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_PING:
                        return HandlePingPacket(connectionId);

                    case (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_PONG:
                        return HandlePongPacket(connectionId);

                    default:
                        Logger.Log.WarningF($"[{LOG_TAG}] Tipo de paquete tunnel desconocido: 0x{packetType:X2}");
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete tunnel: {ex.Message}");
                return -1;
            }
        }

        // ==================== MANEJADORES DE PAQUETES ====================

        private int HandleConnectRequest(int friendNumber, int connectionId, byte[] packet, int length)
        {
            if (length < 37) return -1; // type(1) + connectionId(4) + sessionKey(32)

            try
            {
                // Extraer session key
                byte[] sessionKey = new byte[32];
                Buffer.BlockCopy(packet, 5, sessionKey, 0, 32);

                // Extraer endpoint remoto (si está presente)
                IPPort remoteEndPoint = new IPPort();
                if (length > 37)
                {
                    // El paquete incluye información del endpoint
                    // Esto sería para conexiones de forwarding
                }

                lock (_connectionsLock)
                {
                    // Verificar si ya existe la conexión
                    if (_connections.ContainsKey(connectionId))
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Conexión tunnel {connectionId} ya existe");
                        return -1;
                    }

                    // Crear nueva conexión
                    var connection = new TCPTunnelConnection(connectionId, friendNumber)
                    {
                        Status = TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTING,
                        SessionKey = sessionKey,
                        IsInitiator = false,
                        LastActivity = DateTime.UtcNow.Ticks
                    };

                    _connections[connectionId] = connection;
                }

                // Enviar respuesta de conexión
                SendConnectResponse(connectionId);

                Logger.Log.InfoF($"[{LOG_TAG}] Solicitud de tunnel recibida de friend {friendNumber} (ID: {connectionId})");

                // Aquí se podría disparar un callback para notificar la nueva conexión
                // OnTunnelConnectionRequest?.Invoke(connectionId, friendNumber, remoteEndPoint);

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando solicitud de conexión: {ex.Message}");
                return -1;
            }
        }

        private int HandleConnectResponse(int connectionId, byte[] packet, int length)
        {
            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection))
                    {
                        return -1;
                    }
                }

                connection.Status = TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTED;
                connection.LastActivity = DateTime.UtcNow.Ticks;

                Logger.Log.InfoF($"[{LOG_TAG}] Conexión tunnel {connectionId} establecida");

                // Aquí se podría disparar un callback
                // OnTunnelConnected?.Invoke(connectionId);

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando respuesta de conexión: {ex.Message}");
                return -1;
            }
        }

        private int HandleDataPacket(int connectionId, byte[] packet, int length)
        {
            if (length < 5) return -1;

            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection) ||
                        connection.Status != TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTED)
                    {
                        return -1;
                    }
                }

                // Extraer datos encriptados
                int encryptedDataLength = length - 5;
                byte[] encryptedData = new byte[encryptedDataLength];
                Buffer.BlockCopy(packet, 5, encryptedData, 0, encryptedDataLength);

                // Desencriptar datos
                byte[] decryptedData = DecryptTunnelData(connection, encryptedData);
                if (decryptedData == null) return -1;

                connection.BytesReceived += decryptedData.Length;
                connection.LastActivity = DateTime.UtcNow.Ticks;

                // Almacenar datos en buffer
                connection.AppendData(decryptedData, 0, decryptedData.Length);

                Logger.Log.TraceF($"[{LOG_TAG}] Datos recibidos por tunnel {connectionId}: {decryptedData.Length} bytes");

                // Aquí se podría disparar un callback
                // OnTunnelDataReceived?.Invoke(connectionId, decryptedData);

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete de datos: {ex.Message}");
                return -1;
            }
        }

        private int HandleDisconnectPacket(int connectionId)
        {
            try
            {
                Logger.Log.InfoF($"[{LOG_TAG}] Desconexión recibida para tunnel {connectionId}");

                CloseTunnel(connectionId);
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete de desconexión: {ex.Message}");
                return -1;
            }
        }

        private int HandlePingPacket(int connectionId)
        {
            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection))
                    {
                        return -1;
                    }
                }

                // Enviar pong de respuesta
                SendPongPacket(connection);

                connection.LastActivity = DateTime.UtcNow.Ticks;
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando ping: {ex.Message}");
                return -1;
            }
        }

        private int HandlePongPacket(int connectionId)
        {
            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection))
                    {
                        return -1;
                    }
                }

                connection.LastActivity = DateTime.UtcNow.Ticks;
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando pong: {ex.Message}");
                return -1;
            }
        }

        // ==================== CREACIÓN DE PAQUETES ====================

        private bool SendConnectRequest(TCPTunnelConnection connection)
        {
            try
            {
                byte[] packet = new byte[37]; // type(1) + connectionId(4) + sessionKey(32)
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_CONNECT_REQUEST;
                Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);
                Buffer.BlockCopy(connection.SessionKey, 0, packet, 5, 32);

                int sent = _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando solicitud de conexión: {ex.Message}");
                return false;
            }
        }

        private bool SendConnectResponse(int connectionId)
        {
            try
            {
                TCPTunnelConnection connection;
                lock (_connectionsLock)
                {
                    if (!_connections.TryGetValue(connectionId, out connection))
                    {
                        return false;
                    }
                }

                byte[] packet = new byte[5];
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_CONNECT_RESPONSE;
                Buffer.BlockCopy(BitConverter.GetBytes(connectionId), 0, packet, 1, 4);

                int sent = _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando respuesta de conexión: {ex.Message}");
                return false;
            }
        }

        private byte[] CreateDataPacket(int connectionId, byte[] encryptedData)
        {
            try
            {
                byte[] packet = new byte[5 + encryptedData.Length];
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_DATA;
                Buffer.BlockCopy(BitConverter.GetBytes(connectionId), 0, packet, 1, 4);
                Buffer.BlockCopy(encryptedData, 0, packet, 5, encryptedData.Length);
                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete de datos: {ex.Message}");
                return null;
            }
        }

        private void SendDisconnectPacket(TCPTunnelConnection connection)
        {
            try
            {
                byte[] packet = new byte[5];
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_DISCONNECT;
                Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);

                _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando paquete de desconexión: {ex.Message}");
            }
        }

        private void SendPingPacket(TCPTunnelConnection connection)
        {
            try
            {
                byte[] packet = new byte[5];
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_PING;
                Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);

                _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando ping: {ex.Message}");
            }
        }

        private void SendPongPacket(TCPTunnelConnection connection)
        {
            try
            {
                byte[] packet = new byte[5];
                packet[0] = (byte)TCPTunnelPacketType.TCP_TUNNEL_PACKET_PONG;
                Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);

                _messenger.FriendConn.m_send_message(connection.FriendNumber, packet, packet.Length);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando pong: {ex.Message}");
            }
        }

        // ==================== CIFRADO/DESCIFRADO ====================

        private byte[] EncryptTunnelData(TCPTunnelConnection connection, byte[] data, int length)
        {
            try
            {
                // Usar session key para encriptación simétrica
                byte[] nonce = RandomBytes.Generate(24);
                byte[] encrypted = SecretBox.Create(
                    data.AsSpan(0, length).ToArray(),
                    nonce,
                    connection.SessionKey
                );

                if (encrypted == null) return null;

                // Combinar nonce + datos encriptados
                byte[] result = new byte[24 + encrypted.Length];
                Buffer.BlockCopy(nonce, 0, result, 0, 24);
                Buffer.BlockCopy(encrypted, 0, result, 24, encrypted.Length);

                return result;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error encriptando datos de tunnel: {ex.Message}");
                return null;
            }
        }

        private byte[] DecryptTunnelData(TCPTunnelConnection connection, byte[] encryptedData)
        {
            try
            {
                if (encryptedData.Length < 24) return null;

                // Extraer nonce y datos encriptados
                byte[] nonce = new byte[24];
                byte[] data = new byte[encryptedData.Length - 24];

                Buffer.BlockCopy(encryptedData, 0, nonce, 0, 24);
                Buffer.BlockCopy(encryptedData, 24, data, 0, data.Length);

                // Desencriptar
                byte[] decrypted = SecretBox.Open(data, nonce, connection.SessionKey);
                return decrypted;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error desencriptando datos de tunnel: {ex.Message}");
                return null;
            }
        }

        // ==================== GESTIÓN DE CONEXIONES ====================

        private void CloseConnection(TCPTunnelConnection connection)
        {
            try
            {
                connection.Status = TCPTunnelStatus.TCP_TUNNEL_STATUS_DISCONNECTED;

                if (connection.LocalSocket != null)
                {
                    connection.LocalSocket.Close();
                    connection.LocalSocket = null;
                }

                Logger.Log.DebugF($"[{LOG_TAG}] Conexión tunnel {connection.ConnectionId} cerrada localmente");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error cerrando conexión local: {ex.Message}");
            }
        }

        // ==================== WORKER PRINCIPAL ====================

        private void TunnelWorker()
        {
            Logger.Log.Debug($"[{LOG_TAG}] Hilo TCP Tunneling iniciado");

            while (_isRunning && !_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    MaintainConnections();
                    Thread.Sleep(1000); // Ejecutar cada segundo
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] Error en worker: {ex.Message}");
                    }
                }
            }

            Logger.Log.Debug($"[{LOG_TAG}] Hilo TCP Tunneling finalizado");
        }

        private void MaintainConnections()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            List<int> connectionsToRemove = new List<int>();

            lock (_connectionsLock)
            {
                foreach (var kvp in _connections)
                {
                    var connection = kvp.Value;
                    long timeSinceActivity = (currentTime - connection.LastActivity) / TimeSpan.TicksPerMillisecond;

                    // Verificar timeout
                    if (timeSinceActivity > TUNNEL_CONNECTION_TIMEOUT)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Timeout en conexión tunnel {connection.ConnectionId}");
                        connectionsToRemove.Add(connection.ConnectionId);
                        continue;
                    }

                    // Enviar ping periódico para conexiones activas
                    if (connection.Status == TCPTunnelStatus.TCP_TUNNEL_STATUS_CONNECTED &&
                        timeSinceActivity > TUNNEL_PING_INTERVAL)
                    {
                        SendPingPacket(connection);
                    }
                }

                // Remover conexiones timeout
                foreach (int connectionId in connectionsToRemove)
                {
                    _connections.Remove(connectionId);
                }
            }

            if (connectionsToRemove.Count > 0)
            {
                Logger.Log.InfoF($"[{LOG_TAG}] {connectionsToRemove.Count} conexiones tunnel removidas por timeout");
            }
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource?.Dispose();
        }
    }
}
