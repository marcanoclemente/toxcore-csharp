using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Estado de conexión TCP compatible con toxcore
    /// </summary>
    public enum TCP_Status
    {
        TCP_STATUS_NO_STATUS,
        TCP_STATUS_CONNECTING,
        TCP_STATUS_UNCONFIRMED,
        TCP_STATUS_CONFIRMED,
        TCP_STATUS_DISCONNECTED
    }

    /// <summary>
    /// Conexión TCP individual
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TCP_Connection
    {
        public Socket Socket;
        public IPPort RemoteEndPoint;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        public TCP_Status Status;
        public long LastActivity;
        public int ConnectionID;

        public TCP_Connection(Socket socket, IPPort remote, byte[] publicKey, int id)
        {
            Socket = socket;
            RemoteEndPoint = remote;
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
            Status = TCP_Status.TCP_STATUS_CONNECTING;
            LastActivity = DateTime.UtcNow.Ticks;
            ConnectionID = id;
        }
    }

    /// <summary>
    /// Cliente TCP compatible con TCP_client.c de toxcore
    /// </summary>
    public class TCP_Client
    {
        private const string LOG_TAG = "TCP_Client";

        public const int TCP_PACKET_MAX_SIZE = 2048;
        public const int TCP_HANDSHAKE_TIMEOUT = 10000;
        public const int TCP_CONNECTION_TIMEOUT = 30000;

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public TCP_Connection Connection { get; private set; }
        public bool IsConnected => Connection.Socket != null && Connection.Socket.Connected;

        private int _lastConnectionID;
        private long _lastKeepAliveSent;

        public TCP_Client(byte[] selfPublicKey, byte[] selfSecretKey)
        {
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            Connection = new TCP_Connection();
            _lastConnectionID = 0;
            _lastKeepAliveSent = 0;
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// tcp_connect - Compatible con TCP_client.c
        /// </summary>
        public int tcp_connect(IPPort ipp, byte[] public_key)
        {
            if (IsConnected) return -1;

            try
            {
                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Blocking = false;

                IPEndPoint endPoint = new IPEndPoint(ipp.IP.ToIPAddress(), ipp.Port);

                // Conexión asíncrona
                IAsyncResult result = socket.BeginConnect(endPoint, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(5000, true);

                if (success && socket.Connected)
                {
                    socket.EndConnect(result);

                    // CORREGIDO: Crear nueva instancia en lugar de modificar propiedades
                    Connection = new TCP_Connection(socket, ipp, public_key, _lastConnectionID++);

                    // Iniciar handshake criptográfico
                    return tcp_handshake(public_key);
                }
                else
                {
                    socket.Close();
                    return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_send_data - Compatible con TCP_client.c
        /// </summary>
        public int tcp_send_data(byte[] data, int length)
        {
            if (!IsConnected || Connection.Status != TCP_Status.TCP_STATUS_CONFIRMED) return -1;
            if (data == null || length > TCP_PACKET_MAX_SIZE) return -1;

            try
            {
                // Encriptar datos para transmisión segura
                byte[] nonce = RandomBytes.Generate(24);
                byte[] encrypted = CryptoBox.Encrypt(data, nonce, Connection.PublicKey, SelfSecretKey);

                if (encrypted == null) return -1;

                // Crear paquete: nonce + datos encriptados
                byte[] packet = new byte[24 + encrypted.Length];
                Buffer.BlockCopy(nonce, 0, packet, 0, 24);
                Buffer.BlockCopy(encrypted, 0, packet, 24, encrypted.Length);

                int sent = Connection.Socket.Send(packet);
                if (sent > 0)
                {
                    // CORREGIDO: Actualizar LastActivity creando nueva instancia
                    Connection = new TCP_Connection(
                        Connection.Socket,
                        Connection.RemoteEndPoint,
                        Connection.PublicKey,
                        Connection.ConnectionID)
                    {
                        Status = Connection.Status,
                        LastActivity = DateTime.UtcNow.Ticks
                    };
                }
                return sent;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_recv_data - Compatible con TCP_client.c
        /// </summary>
        public int tcp_recv_data(byte[] buffer, int length)
        {
            if (!IsConnected || buffer == null) return -1;

            try
            {
                if (Connection.Socket.Available > 0)
                {
                    byte[] tempBuffer = new byte[TCP_PACKET_MAX_SIZE];
                    int received = Connection.Socket.Receive(tempBuffer);

                    if (received >= 24)
                    {
                        // Extraer nonce y datos encriptados
                        byte[] nonce = new byte[24];
                        Buffer.BlockCopy(tempBuffer, 0, nonce, 0, 24);

                        byte[] encrypted = new byte[received - 24];
                        Buffer.BlockCopy(tempBuffer, 24, encrypted, 0, received - 24);

                        // Desencriptar datos
                        byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, Connection.PublicKey, SelfSecretKey);

                        if (decrypted != null && decrypted.Length <= length)
                        {
                            Buffer.BlockCopy(decrypted, 0, buffer, 0, decrypted.Length);

                            // CORREGIDO: Actualizar LastActivity
                            Connection = new TCP_Connection(
                                Connection.Socket,
                                Connection.RemoteEndPoint,
                                Connection.PublicKey,
                                Connection.ConnectionID)
                            {
                                Status = Connection.Status,
                                LastActivity = DateTime.UtcNow.Ticks
                            };

                            return decrypted.Length;
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
        /// tcp_disconnect - Compatible con TCP_client.c
        /// </summary>
        public int tcp_disconnect()
        {
            if (!IsConnected) return -1;

            try
            {
                Connection.Socket.Shutdown(SocketShutdown.Both);
                Connection.Socket.Close();

                // CORREGIDO: Crear nueva instancia desconectada
                Connection = new TCP_Connection();
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== FUNCIONES AUXILIARES ====================

        /// <summary>
        /// tcp_handshake - Handshake criptográfico
        /// </summary>
        private int tcp_handshake(byte[] public_key)
        {
            try
            {
                // Enviar handshake inicial - pasar public_key
                byte[] handshake = CreateHandshakePacket(public_key); // ← Agregar parámetro
                int sent = Connection.Socket.Send(handshake);

                if (sent > 0)
                {
                    // Actualizar estado
                    Connection = new TCP_Connection(
                        Connection.Socket,
                        Connection.RemoteEndPoint,
                        Connection.PublicKey,
                        Connection.ConnectionID)
                    {
                        Status = TCP_Status.TCP_STATUS_CONFIRMED,
                        LastActivity = DateTime.UtcNow.Ticks
                    };

                    return 0;
                }

                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_write_packet - Envío de paquete raw
        /// </summary>
        public int tcp_write_packet(byte[] data, int length)
        {
            if (!IsConnected) return -1;

            try
            {
                int sent = Connection.Socket.Send(data, length, SocketFlags.None);
                if (sent > 0)
                {
                    // CORREGIDO: Actualizar LastActivity
                    Connection = new TCP_Connection(
                        Connection.Socket,
                        Connection.RemoteEndPoint,
                        Connection.PublicKey,
                        Connection.ConnectionID)
                    {
                        Status = Connection.Status,
                        LastActivity = DateTime.UtcNow.Ticks
                    };
                }
                return sent;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_read_packet - Recepción de paquete raw
        /// </summary>
        public int tcp_read_packet(byte[] buffer, int length)
        {
            if (!IsConnected || buffer == null) return -1;

            try
            {
                if (Connection.Socket.Available > 0)
                {
                    int received = Connection.Socket.Receive(buffer, Math.Min(length, buffer.Length), SocketFlags.None);
                    if (received > 0)
                    {
                        // CORREGIDO: Actualizar LastActivity
                        Connection = new TCP_Connection(
                            Connection.Socket,
                            Connection.RemoteEndPoint,
                            Connection.PublicKey,
                            Connection.ConnectionID)
                        {
                            Status = Connection.Status,
                            LastActivity = DateTime.UtcNow.Ticks
                        };
                    }
                    return received;
                }
                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        private byte[] CreateHandshakePacket(byte[] public_key) // ← Agregar parámetro public_key
        {
            try
            {
                // Basado en TCP_client.c - send_tcp_handshake
                byte[] packet = new byte[CryptoBox.CRYPTO_PUBLIC_KEY_SIZE + CryptoBox.CRYPTO_NONCE_SIZE + CryptoBox.CRYPTO_MAC_SIZE];

                // 1. Nuestra clave pública
                Buffer.BlockCopy(SelfPublicKey, 0, packet, 0, CryptoBox.CRYPTO_PUBLIC_KEY_SIZE);

                // 2. Nonce aleatorio
                byte[] nonce = RandomBytes.Generate(CryptoBox.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(nonce, 0, packet, CryptoBox.CRYPTO_PUBLIC_KEY_SIZE, CryptoBox.CRYPTO_NONCE_SIZE);

                // 3. Encriptar con la clave pública del destino
                byte[] temp = new byte[CryptoBox.CRYPTO_PUBLIC_KEY_SIZE + CryptoBox.CRYPTO_NONCE_SIZE];
                Buffer.BlockCopy(SelfPublicKey, 0, temp, 0, CryptoBox.CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(nonce, 0, temp, CryptoBox.CRYPTO_PUBLIC_KEY_SIZE, CryptoBox.CRYPTO_NONCE_SIZE);

                byte[] encrypted = CryptoBox.Encrypt(temp, nonce, public_key, SelfSecretKey);
                if (encrypted == null) return null;

                // 4. El paquete final es la data encriptada
                return encrypted;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando handshake TCP: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// tcp_set_nodelay - Configurar Nagle algorithm
        /// </summary>
        public int tcp_set_nodelay(bool nodelay)
        {
            if (!IsConnected) return -1;

            try
            {
                Connection.Socket.NoDelay = nodelay;
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tcp_set_keepalive - Configurar keep-alive
        /// </summary>
        public int tcp_set_keepalive(bool keepalive)
        {
            if (!IsConnected) return -1;

            try
            {
                // Configuración básica de keep-alive
                byte[] keepAlive = BitConverter.GetBytes(keepalive ? 1U : 0U);
                Connection.Socket.IOControl(IOControlCode.KeepAliveValues, keepAlive, null);
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// Do_periodic_work - Mantenimiento de conexión
        /// </summary>
        public void Do_periodic_work()
        {
            if (!IsConnected) return;

            long currentTime = DateTime.UtcNow.Ticks;

            // Verificar timeout
            if ((currentTime - Connection.LastActivity) > TimeSpan.TicksPerMillisecond * TCP_CONNECTION_TIMEOUT)
            {
                tcp_disconnect();
                return;
            }

            // Enviar keep-alive periódicamente
            if ((currentTime - _lastKeepAliveSent) > TimeSpan.TicksPerSecond * 30)
            {
                byte[] keepAlivePacket = new byte[] { 0x00 }; // Packet keep-alive
                tcp_write_packet(keepAlivePacket, 1);
                _lastKeepAliveSent = currentTime;
            }
        }
    }
}