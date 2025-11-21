using System.Net;
using System.Net.Sockets;
using ToxCore.Core;

namespace ToxCore.Networking
{
    /// <summary>
    /// Tipos de proxy soportados
    /// </summary>
    public enum ProxyType
    {
        PROXY_TYPE_NONE = 0,
        PROXY_TYPE_HTTP = 1,
        PROXY_TYPE_SOCKS5 = 2
    }

    /// <summary>
    /// Estrategias de hole punching
    /// </summary>
    public enum HolePunchStrategy
    {
        UDP_HOLE_PUNCH = 0,
        TCP_HOLE_PUNCH = 1,
        ICMP_HOLE_PUNCH = 2,
        RELAY_FALLBACK = 3
    }

    /// <summary>
    /// Información de configuración de proxy
    /// </summary>
    public class ProxyConfig
    {
        public ProxyType Type { get; set; }
        public string Host { get; set; }
        public ushort Port { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool Enabled { get; set; }

        public ProxyConfig()
        {
            Type = ProxyType.PROXY_TYPE_NONE;
            Enabled = false;
        }
    }

    /// <summary>
    /// Información de sesión de hole punching
    /// </summary>
    public class HolePunchSession
    {
        public IPPort Target { get; set; }
        public HolePunchStrategy Strategy { get; set; }
        public long StartTime { get; set; }
        public int Attempts { get; set; }
        public bool Success { get; set; }
        public int TimeoutMs { get; set; }
        public List<IPPort> CandidatePorts { get; set; }

        public HolePunchSession(IPPort target, HolePunchStrategy strategy)
        {
            Target = target;
            Strategy = strategy;
            StartTime = DateTime.UtcNow.Ticks;
            Attempts = 0;
            Success = false;
            TimeoutMs = 10000; // 10 segundos
            CandidatePorts = new List<IPPort>();
        }
    }

    /// <summary>
    /// Información de conexión TCP relay
    /// </summary>
    public class RelayConnection
    {
        public int FriendNumber { get; set; }
        public IPPort RelayServer { get; set; }
        public Socket RelaySocket { get; set; }
        public bool IsConnected { get; set; }
        public long LastActivity { get; set; }
        public int RelayId { get; set; }

        public RelayConnection(int friendNumber, IPPort relayServer)
        {
            FriendNumber = friendNumber;
            RelayServer = relayServer;
            IsConnected = false;
            LastActivity = DateTime.UtcNow.Ticks;
            RelayId = new Random().Next();
        }
    }

    /// <summary>
    /// Módulo de Networking Avanzado para Tox
    /// </summary>
    public class AdvancedNetworking : IDisposable
    {
        private const string LOG_TAG = "ADV_NET";

        // Constantes de configuración
        private const int MAX_HOLE_PUNCH_ATTEMPTS = 5;
        private const int HOLE_PUNCH_TIMEOUT_MS = 10000;
        private const int RELAY_CONNECTION_TIMEOUT_MS = 30000;
        private const int PORT_RANGE_START = 33445;
        private const int PORT_RANGE_END = 33545;

        // Componentes
        private readonly Core.Tox _tox;
        private readonly ProxyConfig _proxyConfig;
        private readonly List<HolePunchSession> _activePunchSessions;
        private readonly Dictionary<int, RelayConnection> _relayConnections;
        private readonly Dictionary<IPPort, long> _natMappings;
        private readonly object _sessionsLock = new object();
        private readonly object _relaysLock = new object();
        private bool _isRunning;
        private Thread _networkingThread;
        private CancellationTokenSource _cancellationTokenSource;

        // Servidores STUN para detección NAT
        private readonly string[] _stunServers = {
            "stun.l.google.com:19302",
            "stun1.l.google.com:19302",
            "stun2.l.google.com:19302",
            "stun3.l.google.com:19302",
            "stun4.l.google.com:19302"
        };

        // Servidores relay de respaldo
        private readonly IPPort[] _relayServers = {
            new IPPort(new IP(IPAddress.Parse("144.217.167.73")), 33445),
            new IPPort(new IP(IPAddress.Parse("108.61.165.198")), 33445),
            new IPPort(new IP(IPAddress.Parse("51.15.43.205")), 33445)
        };

        public ProxyConfig Proxy => _proxyConfig;
        public bool IsRunning => _isRunning;

        public AdvancedNetworking(Core.Tox tox)
        {
            _tox = tox ?? throw new ArgumentNullException(nameof(tox));
            _proxyConfig = new ProxyConfig();
            _activePunchSessions = new List<HolePunchSession>();
            _relayConnections = new Dictionary<int, RelayConnection>();
            _natMappings = new Dictionary<IPPort, long>();
            _cancellationTokenSource = new CancellationTokenSource();

            Logger.Log.Info($"[{LOG_TAG}] Advanced Networking inicializado");
        }

        /// <summary>
        /// Iniciar servicio de networking avanzado
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Advanced Networking ya está ejecutándose");
                return true;
            }

            try
            {
                _isRunning = true;
                _cancellationTokenSource = new CancellationTokenSource();

                // Iniciar hilo de networking
                _networkingThread = new Thread(NetworkingWorker);
                _networkingThread.IsBackground = true;
                _networkingThread.Name = "AdvancedNetworking-Worker";
                _networkingThread.Start();

                // Iniciar detección NAT
                Task.Run(() => DetectNatType());

                Logger.Log.Info($"[{LOG_TAG}] Servicio Advanced Networking iniciado");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando Advanced Networking: {ex.Message}");
                _isRunning = false;
                return false;
            }
        }

        /// <summary>
        /// Detener servicio de networking avanzado
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _isRunning = false;
                _cancellationTokenSource?.Cancel();

                lock (_sessionsLock)
                {
                    _activePunchSessions.Clear();
                }

                lock (_relaysLock)
                {
                    foreach (var relay in _relayConnections.Values)
                    {
                        relay.RelaySocket?.Close();
                    }
                    _relayConnections.Clear();
                }

                _networkingThread?.Join(2000);

                Logger.Log.Info($"[{LOG_TAG}] Servicio Advanced Networking detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo Advanced Networking: {ex.Message}");
            }
        }

        // ==================== HOLE PUNCHING ====================

        /// <summary>
        /// Iniciar hole punching a un objetivo
        /// </summary>
        public bool StartHolePunching(IPPort target, HolePunchStrategy strategy = HolePunchStrategy.UDP_HOLE_PUNCH)
        {
            try
            {
                var session = new HolePunchSession(target, strategy);

                // Generar puertos candidatos
                GenerateCandidatePorts(session);

                lock (_sessionsLock)
                {
                    _activePunchSessions.Add(session);
                }

                Logger.Log.InfoF($"[{LOG_TAG}] Iniciando hole punching a {target} - Estrategia: {strategy}");

                // Iniciar proceso asíncrono
                Task.Run(() => ExecuteHolePunch(session));

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando hole punching: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Ejecutar proceso de hole punching
        /// </summary>
        private async Task ExecuteHolePunch(HolePunchSession session)
        {
            try
            {
                while (session.Attempts < MAX_HOLE_PUNCH_ATTEMPTS &&
                       !session.Success &&
                       _isRunning)
                {
                    session.Attempts++;

                    Logger.Log.DebugF($"[{LOG_TAG}] Intento {session.Attempts} de hole punching a {session.Target}");

                    bool success = false;

                    switch (session.Strategy)
                    {
                        case HolePunchStrategy.UDP_HOLE_PUNCH:
                            success = await ExecuteUdpHolePunch(session);
                            break;
                        case HolePunchStrategy.TCP_HOLE_PUNCH:
                            success = await ExecuteTcpHolePunch(session);
                            break;
                        case HolePunchStrategy.RELAY_FALLBACK:
                            success = await ExecuteRelayFallback(session);
                            break;
                    }

                    if (success)
                    {
                        session.Success = true;
                        Logger.Log.InfoF($"[{LOG_TAG}] Hole punching exitoso a {session.Target} después de {session.Attempts} intentos");
                        break;
                    }

                    // Esperar antes del siguiente intento
                    if (session.Attempts < MAX_HOLE_PUNCH_ATTEMPTS)
                    {
                        await Task.Delay(1000);
                    }
                }

                if (!session.Success)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Hole punching falló después de {session.Attempts} intentos");
                    // Intentar con relay como último recurso
                    await ExecuteRelayFallback(session);
                }

                // Limpiar sesión
                lock (_sessionsLock)
                {
                    _activePunchSessions.Remove(session);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en proceso de hole punching: {ex.Message}");
            }
        }

        /// <summary>
        /// Hole punching UDP (el más común para Tox) - VERSIÓN CORREGIDA
        /// </summary>
        private async Task<bool> ExecuteUdpHolePunch(HolePunchSession session)
        {
            try
            {
                using (var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    // ✅ CORRECCIÓN: Configurar socket correctamente
                    udpSocket.Blocking = false;
                    udpSocket.ReceiveTimeout = 1000;
                    udpSocket.SendTimeout = 1000;

                    // Bind a puerto aleatorio
                    int localPort = new Random().Next(PORT_RANGE_START, PORT_RANGE_END);
                    var localEP = new IPEndPoint(IPAddress.Any, localPort);

                    try
                    {
                        udpSocket.Bind(localEP);
                    }
                    catch (SocketException)
                    {
                        // Si el puerto está ocupado, usar puerto efímero
                        udpSocket.Bind(new IPEndPoint(IPAddress.Any, 0));
                    }

                    // ✅ CORRECCIÓN: Usar LINQ para crear tasks
                    var tasks = session.CandidatePorts
                        .Select(candidate => TestUdpConnectivity(udpSocket, candidate))
                        .ToList();

                    // ✅ CORRECCIÓN: Esperar todas las tasks con timeout
                    var timeoutTask = Task.Delay(HOLE_PUNCH_TIMEOUT_MS);
                    var completedTask = await Task.WhenAny(Task.WhenAll(tasks), timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        Logger.Log.DebugF($"[{LOG_TAG}] Timeout en hole punching UDP");
                        return false;
                    }

                    var results = await Task.WhenAll(tasks);
                    return results.Any(r => r);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en UDP hole punch: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Test de conectividad UDP - VERSIÓN CORREGIDA
        /// </summary>
        private async Task<bool> TestUdpConnectivity(Socket socket, IPPort target)
        {
            try
            {
                // Crear paquete de prueba
                byte[] testPacket = CreateHolePunchPacket();
                var remoteEP = new IPEndPoint(target.IP.ToIPAddress(), target.Port);

                // Enviar múltiples paquetes (NATs pueden requerir múltiples intentos)
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        // ✅ CORRECCIÓN: Usar SendTo de forma asíncrona
                        var sendTask = Task.Run(() => socket.SendTo(testPacket, remoteEP));
                        if (await Task.WhenAny(sendTask, Task.Delay(1000)) == sendTask)
                        {
                            int sent = sendTask.Result;
                            if (sent > 0)
                            {
                                // Esperar respuesta breve
                                await Task.Delay(100);

                                // Verificar si hay datos de respuesta usando Poll
                                if (socket.Poll(100000, SelectMode.SelectRead)) // 100ms timeout
                                {
                                    byte[] buffer = new byte[1024];
                                    EndPoint tempEP = new IPEndPoint(IPAddress.Any, 0);

                                    var receiveTask = Task.Run(() => socket.ReceiveFrom(buffer, ref tempEP));
                                    if (await Task.WhenAny(receiveTask, Task.Delay(500)) == receiveTask)
                                    {
                                        int received = receiveTask.Result;
                                        if (received > 0 && IsValidHolePunchResponse(buffer, received))
                                        {
                                            Logger.Log.DebugF($"[{LOG_TAG}] Conexión UDP establecida con {target}");
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (SocketException) { /* Timeout esperado */ }
                    catch (ObjectDisposedException) { /* Socket cerrado */ }

                    await Task.Delay(200);
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] Test UDP falló para {target}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Hole punching TCP (para conexiones TCP relay)
        /// </summary>
        private async Task<bool> ExecuteTcpHolePunch(HolePunchSession session)
        {
            try
            {
                // TCP hole punching es más complejo - requiere coordinación
                // Por simplicidad, intentamos conexiones simultáneas
                var tasks = session.CandidatePorts.Select(candidate =>
                    AttemptTcpConnection(candidate)).ToList();

                var results = await Task.WhenAll(tasks);
                return results.Any(r => r);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en TCP hole punch: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> AttemptTcpConnection(IPPort target)
        {
            try
            {
                using (var tcpClient = new TcpClient())
                {
                    tcpClient.SendTimeout = 2000;
                    tcpClient.ReceiveTimeout = 2000;

                    // ✅ CORRECCIÓN: Usar ConnectAsync correctamente
                    var connectTask = tcpClient.ConnectAsync(target.IP.ToIPAddress(), target.Port);
                    var timeoutTask = Task.Delay(3000);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    if (completedTask == connectTask && !connectTask.IsFaulted && tcpClient.Connected)
                    {
                        Logger.Log.DebugF($"[{LOG_TAG}] Conexión TCP establecida con {target}");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] Conexión TCP falló para {target}: {ex.Message}");
            }

            return false;
        }

        // ==================== PROXY SUPPORT ====================

        /// <summary>
        /// Configurar proxy
        /// </summary>
        public bool SetProxy(ProxyType type, string host, ushort port, string username = null, string password = null)
        {
            try
            {
                _proxyConfig.Type = type;
                _proxyConfig.Host = host;
                _proxyConfig.Port = port;
                _proxyConfig.Username = username;
                _proxyConfig.Password = password;
                _proxyConfig.Enabled = true;

                Logger.Log.InfoF($"[{LOG_TAG}] Proxy configurado: {type}://{host}:{port}");

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error configurando proxy: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Conectar a través de proxy
        /// </summary>
        public async Task<Socket> ConnectThroughProxy(IPPort target)
        {
            if (!_proxyConfig.Enabled)
                return await DirectConnect(target);

            try
            {
                switch (_proxyConfig.Type)
                {
                    case ProxyType.PROXY_TYPE_HTTP:
                        return await ConnectThroughHttpProxy(target);
                    case ProxyType.PROXY_TYPE_SOCKS5:
                        return await ConnectThroughSocks5Proxy(target);
                    default:
                        return await DirectConnect(target);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error conectando through proxy: {ex.Message}");
                return await DirectConnect(target); // Fallback a conexión directa
            }
        }

        /// <summary>
        /// Conexión a través de proxy HTTP
        /// </summary>
        private async Task<Socket> ConnectThroughHttpProxy(IPPort target)
        {
            var proxySocket = await DirectConnect(new IPPort(new IP(IPAddress.Parse(_proxyConfig.Host)), _proxyConfig.Port));
            if (proxySocket == null) return null;

            try
            {
                // Enviar comando CONNECT HTTP
                string connectCommand = $"CONNECT {target.IP}:{target.Port} HTTP/1.1\r\nHost: {target.IP}:{target.Port}\r\n\r\n";
                byte[] commandBytes = System.Text.Encoding.ASCII.GetBytes(connectCommand);

                await proxySocket.SendAsync(new ArraySegment<byte>(commandBytes), SocketFlags.None);

                // Leer respuesta
                byte[] buffer = new byte[1024];
                int received = await proxySocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);
                string response = System.Text.Encoding.ASCII.GetString(buffer, 0, received);

                if (response.StartsWith("HTTP/1.1 200") || response.StartsWith("HTTP/1.0 200"))
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Conexión HTTP proxy establecida a {target}");
                    return proxySocket;
                }
                else
                {
                    proxySocket.Close();
                    return null;
                }
            }
            catch
            {
                proxySocket?.Close();
                throw;
            }
        }

        /// <summary>
        /// Conexión a través de proxy SOCKS5
        /// </summary>
        private async Task<Socket> ConnectThroughSocks5Proxy(IPPort target)
        {
            var proxySocket = await DirectConnect(new IPPort(new IP(IPAddress.Parse(_proxyConfig.Host)), _proxyConfig.Port));
            if (proxySocket == null) return null;

            try
            {
                // Handshake SOCKS5
                byte[] handshake = new byte[] { 0x05, 0x01, 0x00 }; // VER, NMETHODS, NO AUTH
                await proxySocket.SendAsync(new ArraySegment<byte>(handshake), SocketFlags.None);

                byte[] handshakeResponse = new byte[2];
                await proxySocket.ReceiveAsync(new ArraySegment<byte>(handshakeResponse), SocketFlags.None);

                if (handshakeResponse[0] != 0x05 || handshakeResponse[1] != 0x00)
                {
                    proxySocket.Close();
                    return null;
                }

                // Comando CONNECT
                byte[] connectRequest = CreateSocks5ConnectRequest(target);
                await proxySocket.SendAsync(new ArraySegment<byte>(connectRequest), SocketFlags.None);

                byte[] connectResponse = new byte[10];
                await proxySocket.ReceiveAsync(new ArraySegment<byte>(connectResponse), SocketFlags.None);

                if (connectResponse[1] == 0x00) // Success
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Conexión SOCKS5 proxy establecida a {target}");
                    return proxySocket;
                }
                else
                {
                    proxySocket.Close();
                    return null;
                }
            }
            catch
            {
                proxySocket?.Close();
                throw;
            }
        }

        // ==================== TCP RELAY FALLBACK ====================

        /// <summary>
        /// Fallback a conexión relay
        /// </summary>
        private async Task<bool> ExecuteRelayFallback(HolePunchSession session)
        {
            try
            {
                Logger.Log.InfoF($"[{LOG_TAG}] Intentando conexión relay para {session.Target}");

                // Buscar servidor relay disponible
                foreach (var relayServer in _relayServers)
                {
                    var relaySocket = await ConnectThroughProxy(relayServer);
                    if (relaySocket != null && relaySocket.Connected)
                    {
                        // Establecer conexión relay
                        var relayConn = new RelayConnection(-1, relayServer) // -1 indica conexión temporal
                        {
                            RelaySocket = relaySocket,
                            IsConnected = true
                        };

                        lock (_relaysLock)
                        {
                            _relayConnections[relayConn.RelayId] = relayConn;
                        }

                        Logger.Log.InfoF($"[{LOG_TAG}] Conexión relay establecida a través de {relayServer}");
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en relay fallback: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enviar datos a través de relay
        /// </summary>
        public async Task<int> SendThroughRelay(int relayId, byte[] data, IPPort ultimateTarget)
        {
            try
            {
                lock (_relaysLock)
                {
                    if (_relayConnections.TryGetValue(relayId, out var relayConn) &&
                        relayConn.IsConnected &&
                        relayConn.RelaySocket.Connected)
                    {
                        // Encapsular datos con información de destino
                        byte[] relayPacket = CreateRelayPacket(data, ultimateTarget);
                        return relayConn.RelaySocket.Send(relayPacket);
                    }
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando through relay: {ex.Message}");
                return -1;
            }
        }

        // ==================== NAT DETECTION ====================

        /// <summary>
        /// Detectar tipo de NAT
        /// </summary>
        private async Task DetectNatType()
        {
            try
            {
                Logger.Log.Info($"[{LOG_TAG}] Iniciando detección de tipo NAT...");

                using (var udpClient = new UdpClient())
                {
                    udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

                    foreach (var stunServer in _stunServers)
                    {
                        try
                        {
                            var serverParts = stunServer.Split(':');
                            string host = serverParts[0];
                            int port = int.Parse(serverParts[1]);

                            var stunResult = await ExecuteStunRequest(udpClient, host, port);
                            if (stunResult != null)
                            {
                                Logger.Log.InfoF($"[{LOG_TAG}] NAT Detection: {stunResult.NatType} - Mapped: {stunResult.MappedAddress}");

                                // Guardar mapping NAT
                                _natMappings[stunResult.MappedAddress] = DateTime.UtcNow.Ticks;
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Log.DebugF($"[{LOG_TAG}] STUN server {stunServer} falló: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en detección NAT: {ex.Message}");
            }
        }

        // ==================== MÉTODOS AUXILIARES ====================

        private void GenerateCandidatePorts(HolePunchSession session)
        {
            // Puertos comunes para Tox
            int[] commonPorts = { 33445, 3389, 3390, 3391, 443, 80, 8080 };

            foreach (int port in commonPorts)
            {
                session.CandidatePorts.Add(new IPPort(session.Target.IP, (ushort)port));
            }

            // Algunos puertos aleatorios en rango común
            var random = new Random();
            for (int i = 0; i < 5; i++)
            {
                int randomPort = random.Next(10000, 60000);
                session.CandidatePorts.Add(new IPPort(session.Target.IP, (ushort)randomPort));
            }
        }

        private byte[] CreateHolePunchPacket()
        {
            // Paquete de prueba para hole punching
            byte[] packet = new byte[32];
            packet[0] = 0x20; // HOLE_PUNCH type
            Buffer.BlockCopy(BitConverter.GetBytes(DateTime.UtcNow.Ticks), 0, packet, 1, 8);
            RandomBytes.Generate(packet, 9, 23); // Random data
            return packet;
        }

        private bool IsValidHolePunchResponse(byte[] data, int length)
        {
            return length >= 9 && data[0] == 0x21; // HOLE_PUNCH_RESPONSE type
        }

        private byte[] CreateSocks5ConnectRequest(IPPort target)
        {
            byte[] request = new byte[10];
            request[0] = 0x05; // VER
            request[1] = 0x01; // CMD CONNECT
            request[2] = 0x00; // RSV
            request[3] = 0x01; // ATYP IPv4

            byte[] ipBytes = target.IP.ToIPAddress().GetAddressBytes();
            Buffer.BlockCopy(ipBytes, 0, request, 4, 4);

            byte[] portBytes = BitConverter.GetBytes((ushort)target.Port);
            Array.Reverse(portBytes); // Big-endian
            Buffer.BlockCopy(portBytes, 0, request, 8, 2);

            return request;
        }

        private byte[] CreateRelayPacket(byte[] data, IPPort target)
        {
            byte[] packet = new byte[22 + data.Length]; // header + IPv4 + port + data
            packet[0] = 0x30; // RELAY type

            // Dirección de destino
            byte[] ipBytes = target.IP.ToIPAddress().GetAddressBytes();
            Buffer.BlockCopy(ipBytes, 0, packet, 1, 4);

            Buffer.BlockCopy(BitConverter.GetBytes(target.Port), 0, packet, 5, 2);

            // Datos
            Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, packet, 7, 4);
            Buffer.BlockCopy(data, 0, packet, 11, data.Length);

            return packet;
        }

        private async Task<Socket> DirectConnect(IPPort target)
        {
            try
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.Blocking = false;

                await socket.ConnectAsync(target.IP.ToIPAddress(), target.Port);
                return socket;
            }
            catch (Exception ex)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] Conexión directa falló a {target}: {ex.Message}");
                return null;
            }
        }

        private async Task<StunResult> ExecuteStunRequest(UdpClient udpClient, string host, int port)
        {
            // Implementación básica de cliente STUN
            // En producción, usar una librería STUN completa
            try
            {
                var stunMessage = CreateStunBindingRequest();
                var sendTask = udpClient.SendAsync(stunMessage, stunMessage.Length, host, port);

                // ✅ CORRECCIÓN: Esperar envío
                await sendTask;

                var receiveTask = udpClient.ReceiveAsync();
                var timeoutTask = Task.Delay(5000);

                var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

                if (completedTask == receiveTask)
                {
                    var result = receiveTask.Result;
                    return ParseStunResponse(result.Buffer);
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] STUN request falló: {ex.Message}");
                return null;
            }
        }

        private byte[] CreateStunBindingRequest()
        {
            // STUN Binding Request simplificado
            byte[] request = new byte[20];
            request[0] = 0x00; // STUN method
            request[1] = 0x01; // Binding Request
            request[2] = 0x00; // Message length
            request[3] = 0x00;
            RandomBytes.Generate(request, 4, 16); // Transaction ID
            return request;
        }

        private StunResult ParseStunResponse(byte[] response)
        {
            // Parseo básico de respuesta STUN
            if (response.Length < 20) return null;

            return new StunResult
            {
                NatType = "Cone NAT", // Simplificado
                MappedAddress = new IPPort(new IP(IPAddress.Loopback), 33445) // Placeholder
            };
        }

        // ==================== WORKER PRINCIPAL ====================

        private void NetworkingWorker()
        {
            Logger.Log.Debug($"[{LOG_TAG}] Hilo Advanced Networking iniciado");

            while (_isRunning && !_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    MaintainRelayConnections();
                    CleanupExpiredMappings();
                    Thread.Sleep(5000); // Ejecutar cada 5 segundos
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] Error en worker: {ex.Message}");
                    }
                }
            }

            Logger.Log.Debug($"[{LOG_TAG}] Hilo Advanced Networking finalizado");
        }

        private void MaintainRelayConnections()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            List<int> relaysToRemove = new List<int>();

            lock (_relaysLock)
            {
                foreach (var kvp in _relayConnections)
                {
                    var relay = kvp.Value;
                    long timeSinceActivity = (currentTime - relay.LastActivity) / TimeSpan.TicksPerMillisecond;

                    if (timeSinceActivity > RELAY_CONNECTION_TIMEOUT_MS ||
                        !relay.RelaySocket.Connected)
                    {
                        relaysToRemove.Add(kvp.Key);
                        relay.RelaySocket?.Close();
                    }
                }

                foreach (int relayId in relaysToRemove)
                {
                    _relayConnections.Remove(relayId);
                }
            }

            if (relaysToRemove.Count > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {relaysToRemove.Count} conexiones relay removidas");
            }
        }

        private void CleanupExpiredMappings()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            List<IPPort> mappingsToRemove = new List<IPPort>();

            foreach (var kvp in _natMappings)
            {
                long timeSinceUpdate = (currentTime - kvp.Value) / TimeSpan.TicksPerMillisecond;
                if (timeSinceUpdate > 3600000) // 1 hora
                {
                    mappingsToRemove.Add(kvp.Key);
                }
            }

            foreach (var mapping in mappingsToRemove)
            {
                _natMappings.Remove(mapping);
            }
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource?.Dispose();
        }
    }

    // ==================== CLASES AUXILIARES ====================

    public class StunResult
    {
        public string NatType { get; set; }
        public IPPort MappedAddress { get; set; }
        public IPPort ServerAddress { get; set; }
    }
}