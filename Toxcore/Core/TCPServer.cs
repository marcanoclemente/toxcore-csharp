using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Servidor TCP compatible con TCP_server.c de toxcore
    /// </summary>
    public class TCP_Server
    {
        public const int TCP_MAX_CONNECTIONS = 10;
        public const int TCP_BACKLOG_SIZE = 5;
        public const int TCP_PACKET_MAX_SIZE = 2048;

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public Socket ListenerSocket { get; private set; }
        public bool IsRunning { get; private set; }

        private readonly List<TCP_Connection> _connections;
        private readonly object _connectionsLock = new object();
        private int _lastConnectionID;

        private readonly List<TcpClient> _activeConnections = new List<TcpClient>();
        private DateTime _lastConnectionCleanup = DateTime.UtcNow;

        public int ConnectionCount
        {
            get
            {
                lock (_connectionsLock)
                {
                    return _connections.Count;
                }
            }
        }

        public int ActiveConnections
        {
            get
            {
                lock (_connectionsLock)
                {
                    return _connections.Count(c => c.Status == TCP_Status.TCP_STATUS_CONFIRMED);
                }
            }
        }

        public TCP_Server(byte[] selfPublicKey, byte[] selfSecretKey)
        {
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            _connections = new List<TCP_Connection>();
            _lastConnectionID = 0;
            IsRunning = false;
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// tcp_listen - Compatible con TCP_server.c
        /// </summary>
        public int tcp_listen(IPPort ipp)
        {
            if (IsRunning) return -1;

            try
            {
                ListenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                ListenerSocket.Blocking = false;
                ListenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                IPEndPoint localEndPoint = new IPEndPoint(ipp.IP.ToIPAddress(), ipp.Port);
                ListenerSocket.Bind(localEndPoint);
                ListenerSocket.Listen(TCP_BACKLOG_SIZE);

                IsRunning = true;
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_accept - Compatible con TCP_server.c
        /// </summary>
        public int tcp_accept(out TCP_Connection connection)
        {
            connection = new TCP_Connection();

            if (!IsRunning || ListenerSocket == null) return -1;

            try
            {
                if (ListenerSocket.Poll(0, SelectMode.SelectRead))
                {
                    Socket clientSocket = ListenerSocket.Accept();
                    clientSocket.Blocking = false;

                    IPEndPoint remoteEndPoint = (IPEndPoint)clientSocket.RemoteEndPoint;
                    IPPort ipp = new IPPort(new IP(remoteEndPoint.Address), (ushort)remoteEndPoint.Port);

                    connection = new TCP_Connection(clientSocket, ipp, null, _lastConnectionID++);
                    connection.Status = TCP_Status.TCP_STATUS_UNCONFIRMED;

                    lock (_connectionsLock)
                    {
                        if (_connections.Count < TCP_MAX_CONNECTIONS)
                        {
                            _connections.Add(connection);
                            return 0;
                        }
                        else
                        {
                            clientSocket.Close();
                            return -1;
                        }
                    }
                }
                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_send_packet - Compatible con TCP_server.c
        /// </summary>
        public int tcp_send_packet(TCP_Connection conn, byte[] data, int length)
        {
            if (!IsRunning || data == null || length > TCP_PACKET_MAX_SIZE) return -1;

            try
            {
                lock (_connectionsLock)
                {
                    var connection = _connections.Find(c => c.ConnectionID == conn.ConnectionID);
                    if (connection.Socket == null || !connection.Socket.Connected) return -1;

                    // Encriptar datos para transmisión segura
                    byte[] nonce = RandomBytes.Generate(24);
                    byte[] encrypted = CryptoBox.Encrypt(data, nonce, connection.PublicKey, SelfSecretKey);

                    if (encrypted == null) return -1;

                    // Crear paquete: nonce + datos encriptados
                    byte[] packet = new byte[24 + encrypted.Length];
                    Buffer.BlockCopy(nonce, 0, packet, 0, 24);
                    Buffer.BlockCopy(encrypted, 0, packet, 24, encrypted.Length);

                    int sent = connection.Socket.Send(packet);
                    if (sent > 0)
                    {
                        connection.LastActivity = DateTime.UtcNow.Ticks;
                    }
                    return sent;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_recv_packet - Recepción de paquete del cliente
        /// </summary>
        public int tcp_recv_packet(TCP_Connection conn, byte[] buffer, int length)
        {
            if (!IsRunning || buffer == null) return -1;

            try
            {
                lock (_connectionsLock)
                {
                    var connection = _connections.Find(c => c.ConnectionID == conn.ConnectionID);
                    if (connection.Socket == null || !connection.Socket.Connected) return -1;

                    if (connection.Socket.Available > 0)
                    {
                        byte[] tempBuffer = new byte[TCP_PACKET_MAX_SIZE];
                        int received = connection.Socket.Receive(tempBuffer);

                        if (received >= 24)
                        {
                            // Extraer nonce y datos encriptados
                            byte[] nonce = new byte[24];
                            Buffer.BlockCopy(tempBuffer, 0, nonce, 0, 24);

                            byte[] encrypted = new byte[received - 24];
                            Buffer.BlockCopy(tempBuffer, 24, encrypted, 0, received - 24);

                            // Desencriptar datos
                            byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, connection.PublicKey, SelfSecretKey);

                            if (decrypted != null && decrypted.Length <= length)
                            {
                                Buffer.BlockCopy(decrypted, 0, buffer, 0, decrypted.Length);
                                connection.LastActivity = DateTime.UtcNow.Ticks;
                                return decrypted.Length;
                            }
                        }
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
        /// tcp_close_connection - Cerrar conexión específica
        /// </summary>
        public int tcp_close_connection(TCP_Connection conn)
        {
            try
            {
                lock (_connectionsLock)
                {
                    var connection = _connections.Find(c => c.ConnectionID == conn.ConnectionID);
                    if (connection.Socket != null)
                    {
                        connection.Socket.Shutdown(SocketShutdown.Both);
                        connection.Socket.Close();
                        connection.Status = TCP_Status.TCP_STATUS_DISCONNECTED;
                        _connections.Remove(connection);
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
        /// tcp_bind - Bind a puerto específico
        /// </summary>
        public int tcp_bind(IPPort ipp)
        {
            return tcp_listen(ipp);
        }

        // ==================== FUNCIONES DE GESTIÓN ====================

        /// <summary>
        /// tcp_handle_connection - Manejar handshake y estado de conexión
        /// </summary>
        public int tcp_handle_connection(TCP_Connection conn)
        {
            try
            {
                lock (_connectionsLock)
                {
                    var connection = _connections.Find(c => c.ConnectionID == conn.ConnectionID);
                    if (connection.Socket == null || !connection.Socket.Connected) return -1;

                    // Procesar handshake si está en estado no confirmado
                    if (connection.Status == TCP_Status.TCP_STATUS_UNCONFIRMED)
                    {
                        byte[] handshakeBuffer = new byte[64];
                        int received = tcp_recv_packet(connection, handshakeBuffer, handshakeBuffer.Length);

                        if (received >= 32)
                        {
                            // Extraer clave pública del cliente
                            byte[] clientPublicKey = new byte[32];
                            Buffer.BlockCopy(handshakeBuffer, 0, clientPublicKey, 0, 32);
                            connection.PublicKey = clientPublicKey;
                            connection.Status = TCP_Status.TCP_STATUS_CONFIRMED;
                            return 0;
                        }
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
        /// Start - Iniciar servidor (alias de tcp_listen)
        /// </summary>
        public int Start(IPPort ipp)
        {
            return tcp_listen(ipp);
        }

        /// <summary>
        /// Stop - Detener servidor
        /// </summary>
        public int Stop()
        {
            if (!IsRunning) return -1;

            try
            {
                IsRunning = false;

                lock (_connectionsLock)
                {
                    foreach (var connection in _connections)
                    {
                        if (connection.Socket != null && connection.Socket.Connected)
                        {
                            connection.Socket.Shutdown(SocketShutdown.Both);
                            connection.Socket.Close();
                        }
                    }
                    _connections.Clear();
                }

                if (ListenerSocket != null)
                {
                    ListenerSocket.Close();
                    ListenerSocket = null;
                }

                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

       
        /// <summary>
        /// Do_periodic_work - Mantenimiento del servidor
        /// </summary>
        public void Do_periodic_work()
        {
            if (!IsRunning) return;

            long currentTime = DateTime.UtcNow.Ticks;

            lock (_connectionsLock)
            {
                // Limpiar conexiones desconectadas o timeout
                for (int i = _connections.Count - 1; i >= 0; i--)
                {
                    var connection = _connections[i];

                    bool shouldRemove = false;

                    if (connection.Socket == null || !connection.Socket.Connected)
                    {
                        shouldRemove = true;
                    }
                    else if ((currentTime - connection.LastActivity) > TimeSpan.TicksPerMillisecond * 30000)
                    {
                        shouldRemove = true;
                    }

                    if (shouldRemove)
                    {
                        if (connection.Socket != null)
                        {
                            connection.Socket.Close();
                        }
                        _connections.RemoveAt(i);
                    }
                }
            }
        }

        /// <summary>
        /// Get_connections - Obtener lista de conexiones activas
        /// </summary>
        public List<TCP_Connection> Get_connections()
        {
            lock (_connectionsLock)
            {
                return new List<TCP_Connection>(_connections);
            }
        }
    }
}