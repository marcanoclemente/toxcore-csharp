using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Estructuras para direcciones de red compatibles con C
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP4
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Data;

        public IP4(byte[] data)
        {
            if (data == null || data.Length != 4)
                throw new ArgumentException("IP4 must be 4 bytes");
            Data = new byte[4];
            Buffer.BlockCopy(data, 0, Data, 0, 4);
        }

        public IP4(string ipString)
        {
            if (IPAddress.TryParse(ipString, out IPAddress address) && address.AddressFamily == AddressFamily.InterNetwork)
            {
                Data = address.GetAddressBytes();
            }
            else
            {
                throw new ArgumentException("Invalid IPv4 address");
            }
        }

        public override string ToString()
        {
            return $"{Data[0]}.{Data[1]}.{Data[2]}.{Data[3]}";
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Data;

        public IP6(byte[] data)
        {
            if (data == null || data.Length != 16)
                throw new ArgumentException("IP6 must be 16 bytes");
            Data = new byte[16];
            Buffer.BlockCopy(data, 0, Data, 0, 16);
        }

        public IP6(string ipString)
        {
            if (IPAddress.TryParse(ipString, out IPAddress address) && address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Data = address.GetAddressBytes();
            }
            else
            {
                throw new ArgumentException("Invalid IPv6 address");
            }
        }

        public override string ToString()
        {
            return new IPAddress(Data).ToString();
        }
    }

    /// <summary>
    /// Dirección IP (IPv4 o IPv6)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Data;
        public byte IsIPv6; // 0 = IPv4, 1 = IPv6

        public IP(IP4 ip4)
        {
            Data = new byte[16];
            Buffer.BlockCopy(ip4.Data, 0, Data, 0, 4);
            IsIPv6 = 0;
        }

        public IP(IP6 ip6)
        {
            Data = new byte[16];
            Buffer.BlockCopy(ip6.Data, 0, Data, 0, 16);
            IsIPv6 = 1;
        }

        public IP(IPAddress address)
        {
            Data = new byte[16];
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                Buffer.BlockCopy(bytes, 0, Data, 0, 4);
                IsIPv6 = 0;
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] bytes = address.GetAddressBytes();
                Buffer.BlockCopy(bytes, 0, Data, 0, 16);
                IsIPv6 = 1;
            }
            else
            {
                throw new ArgumentException("Unsupported address family");
            }
        }

        public IPAddress ToIPAddress()
        {
            if (IsIPv6 == 0)
            {
                byte[] ip4Bytes = new byte[4];
                Buffer.BlockCopy(Data, 0, ip4Bytes, 0, 4);
                return new IPAddress(ip4Bytes);
            }
            else
            {
                return new IPAddress(Data);
            }
        }

        public override string ToString()
        {
            return ToIPAddress().ToString();
        }
    }

    /// <summary>
    /// Par IP + Puerto
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IPPort
    {
        public IP IP;
        public ushort Port;

        public IPPort(IP ip, ushort port)
        {
            IP = ip;
            Port = port;
        }

        public IPPort(IPAddress ip, ushort port)
        {
            IP = new IP(ip);
            Port = port;
        }

        public override string ToString()
        {
            return $"{IP}:{Port}";
        }
    }

    /// <summary>
    /// Funciones básicas de networking compatibles con toxcore C
    /// </summary>
    public static class Network
    {
        public const int IP4_SIZE = 4;
        public const int IP6_SIZE = 16;
        public const int IP_PORT_SIZE = 18;
        public const int SOCKET_ERROR = -1;

        // Gestión de sockets activos para compatibilidad con C
        private static readonly List<Socket> _activeSockets = new List<Socket>();
        private static readonly object _socketListLock = new object();

        // ==================== COMPATIBILIDAD CON C ORIGINAL ====================

        /// <summary>
        /// new_socket - Compatible con C original
        /// </summary>
        public static int new_socket(int domain, int type, int protocol)
        {
            try
            {
                AddressFamily af = (domain == 2) ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                SocketType st = (type == 2) ? SocketType.Dgram : SocketType.Stream;
                ProtocolType pt = (protocol == 17) ? ProtocolType.Udp : ProtocolType.Tcp;

                Socket socket = new Socket(af, st, pt);

                // Configuraciones esenciales
                socket.Blocking = false;

                if (st == SocketType.Dgram)
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                    if (af == AddressFamily.InterNetworkV6)
                    {
                        socket.DualMode = true;
                    }
                }

                lock (_socketListLock)
                {
                    _activeSockets.Add(socket);
                    return _activeSockets.Count - 1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// socket_bind - Compatible con C original
        /// </summary>
        public static int socket_bind(int sock, IPPort ip_port)
        {
            if (!IsValidSocket(sock)) return -1;

            try
            {
                Socket socket = _activeSockets[sock];
                IPEndPoint endpoint = new IPEndPoint(ip_port.IP.ToIPAddress(), ip_port.Port);
                socket.Bind(endpoint);
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// socket_send - Compatible con C original
        /// </summary>
        public static int socket_send(int sock, byte[] data, int length, IPPort ip_port)
        {
            if (!IsValidSocket(sock)) return -1;

            try
            {
                Socket socket = _activeSockets[sock];
                IPEndPoint endpoint = new IPEndPoint(ip_port.IP.ToIPAddress(), ip_port.Port);
                return socket.SendTo(data, 0, length, SocketFlags.None, endpoint);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// socket_recv - Compatible con C original
        /// </summary>
        public static int socket_recv(int sock, byte[] buffer, ref IPPort ip_port)
        {
            if (!IsValidSocket(sock)) return -1;

            try
            {
                Socket socket = _activeSockets[sock];
                EndPoint tempEndpoint = new IPEndPoint(IPAddress.Any, 0);

                int received = socket.ReceiveFrom(buffer, ref tempEndpoint);

                if (tempEndpoint is IPEndPoint iep)
                {
                    ip_port.IP = new IP(iep.Address);
                    ip_port.Port = (ushort)iep.Port;
                }

                return received;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// kill_socket - Compatible con C original
        /// </summary>
        public static int kill_socket(int sock)
        {
            if (!IsValidSocket(sock)) return -1;

            try
            {
                Socket socket = _activeSockets[sock];
                socket.Close();

                lock (_socketListLock)
                {
                    _activeSockets[sock] = null;
                }
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// get_ip - Compatible con C original
        /// </summary>
        public static int get_ip(string ip_str, ref IP ip)
        {
            try
            {
                IPAddress addr = Resolve(ip_str);
                ip = new IP(addr);
                return 0;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// socket_get_address - Compatible con C original
        /// </summary>
        public static int socket_get_address(int sock, ref IP ip, ref ushort port)
        {
            if (!IsValidSocket(sock)) return -1;

            try
            {
                Socket socket = _activeSockets[sock];
                if (socket.LocalEndPoint is IPEndPoint localEndPoint)
                {
                    ip = new IP(localEndPoint.Address);
                    port = (ushort)localEndPoint.Port;
                    return 0;
                }
                return -1;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== FUNCIONES AUXILIARES MODERNAS ====================

        /// <summary>
        /// Crea un socket UDP
        /// </summary>
        public static Socket CreateUDPSocket(AddressFamily family = AddressFamily.InterNetwork)
        {
            var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            ConfigureSocketForP2P(socket);
            return socket;
        }

        /// <summary>
        /// Configura socket para optimizar performance P2P
        /// </summary>
        public static void ConfigureSocketForP2P(Socket socket)
        {
            try
            {
                socket.Blocking = false;
                socket.ReceiveBufferSize = 65536;
                socket.SendBufferSize = 65536;
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    socket.DualMode = true;
                }
            }
            catch
            {
                // Configuración fallida silenciosamente
            }
        }

        /// <summary>
        /// Enlaza un socket a un puerto específico
        /// </summary>
        public static bool BindSocket(Socket socket, ushort port, AddressFamily family = AddressFamily.InterNetwork)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            try
            {
                IPEndPoint endPoint = family == AddressFamily.InterNetworkV6
                    ? new IPEndPoint(IPAddress.IPv6Any, port)
                    : new IPEndPoint(IPAddress.Any, port);
                socket.Bind(endPoint);
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        /// <summary>
        /// Envía datos a través de un socket UDP
        /// </summary>
        public static int SendTo(Socket socket, byte[] data, IPPort destination)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (data == null) throw new ArgumentNullException(nameof(data));
            try
            {
                IPEndPoint endPoint = new IPEndPoint(destination.IP.ToIPAddress(), destination.Port);
                return socket.SendTo(data, endPoint);
            }
            catch (SocketException)
            {
                return SOCKET_ERROR;
            }
        }

        /// <summary>
        /// Recibe datos de un socket UDP
        /// </summary>
        public static int RecvFrom(Socket socket, byte[] buffer, out IPPort source)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));

            try
            {
                EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
                int received = socket.ReceiveFrom(buffer, ref remoteEP);

                IPEndPoint ipEndPoint = (IPEndPoint)remoteEP;
                source = new IPPort(ipEndPoint.Address, (ushort)ipEndPoint.Port);

                return received;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                source = default;
                return -1;
            }
            catch (SocketException)
            {
                source = default;
                return SOCKET_ERROR;
            }
        }

        /// <summary>
        /// Convierte bytes a IPPort (versión segura sin punteros)
        /// </summary>
        public static bool BytesToIPPort(ref IPPort ipp, byte[] ip, byte ipFamily, ushort port)
        {
            try
            {
                if (ipFamily == 0) // IPv4
                {
                    if (ip.Length < IP4_SIZE) return false;
                    IP4 ip4 = new IP4(new byte[] { ip[0], ip[1], ip[2], ip[3] });
                    ipp = new IPPort(new IP(ip4), port);
                }
                else // IPv6
                {
                    if (ip.Length < IP6_SIZE) return false;
                    byte[] ip6Bytes = new byte[IP6_SIZE];
                    Buffer.BlockCopy(ip, 0, ip6Bytes, 0, IP6_SIZE);
                    IP6 ip6 = new IP6(ip6Bytes);
                    ipp = new IPPort(new IP(ip6), port);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Convierte un hostname a dirección IP
        /// </summary>
        public static IPAddress Resolve(string hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                throw new ArgumentNullException(nameof(hostname));

            try
            {
                IPAddress[] addresses = Dns.GetHostAddresses(hostname);
                if (addresses.Length == 0)
                    throw new SocketException((int)SocketError.HostNotFound);

                // Preferir IPv4 para compatibilidad
                foreach (IPAddress addr in addresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork)
                        return addr;
                }

                // Si no hay IPv4, usar el primero disponible
                return addresses[0];
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to resolve hostname: {hostname}", ex);
            }
        }

        /// <summary>
        /// Obtiene la IP local del socket
        /// </summary>
        public static IPAddress GetLocalIP(Socket socket)
        {
            if (socket == null) throw new ArgumentNullException(nameof(socket));
            if (socket.LocalEndPoint is IPEndPoint localEndPoint)
            {
                return localEndPoint.Address;
            }
            return IPAddress.None;
        }

        /// <summary>
        /// Cierra un socket de forma segura
        /// </summary>
        public static void CloseSocket(Socket socket)
        {
            if (socket == null) return;

            try
            {
                socket.Close();
            }
            catch
            {
                // Ignorar errores al cerrar
            }
        }

        // ==================== FUNCIONES INTERNAS ====================

        private static bool IsValidSocket(int sock)
        {
            lock (_socketListLock)
            {
                return sock >= 0 && sock < _activeSockets.Count && _activeSockets[sock] != null;
            }
        }

        /// <summary>
        /// Limpia todos los sockets activos
        /// </summary>
        public static void Cleanup()
        {
            lock (_socketListLock)
            {
                foreach (var socket in _activeSockets)
                {
                    socket?.Close();
                }
                _activeSockets.Clear();
            }
        }

        // ==================== FUNCIONES DE PRUEBA ====================

        /// <summary>
        /// Test básico de funcionalidades de red
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de Network...");

                // Test 1: Resolución de DNS
                IPAddress localhost = Resolve("localhost");
                if (localhost == null)
                {
                    Console.WriteLine("     ❌ Test 1 falló: Resolución de localhost");
                    return false;
                }
                Console.WriteLine("     ✅ Test 1 - Resolución DNS: PASÓ");

                // Test 2: Creación de estructuras IP
                IP4 ip4 = new IP4("127.0.0.1");
                IP6 ip6 = new IP6("::1");

                if (ip4.ToString() != "127.0.0.1")
                {
                    Console.WriteLine("     ❌ Test 2 falló: IP4 string conversion");
                    return false;
                }
                Console.WriteLine("     ✅ Test 2 - Estructuras IP: PASÓ");

                // Test 3: IPPort
                IP ipFrom4 = new IP(ip4);
                IPPort ipport = new IPPort(ipFrom4, 33445);
                if (ipport.Port != 33445)
                {
                    Console.WriteLine("     ❌ Test 3 falló: IPPort port");
                    return false;
                }
                Console.WriteLine("     ✅ Test 3 - IPPort: PASÓ");

                // Test 4: API compatible con C
                int sock = new_socket(2, 2, 17); // IPv4, DGRAM, UDP
                if (sock == -1)
                {
                    Console.WriteLine("     ❌ Test 4 falló: new_socket");
                    return false;
                }
                Console.WriteLine("     ✅ Test 4 - new_socket: PASÓ");

                // Test 5: socket_bind
                IPPort bindAddr = new IPPort(new IP(IPAddress.Loopback), 0);
                int bindResult = socket_bind(sock, bindAddr);
                if (bindResult == -1)
                {
                    Console.WriteLine("     ❌ Test 5 falló: socket_bind");
                    kill_socket(sock);
                    return false;
                }
                Console.WriteLine("     ✅ Test 5 - socket_bind: PASÓ");

                kill_socket(sock);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test: {ex.Message}");
                return false;
            }
        }
    }
}