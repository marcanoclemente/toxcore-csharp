using System.Net;
using ToxCore.FileTransfer;
using ToxCore.Networking;

namespace ToxCore.Core
{
    /// <summary>
    /// Adaptación de messenger.c - Núcleo principal del cliente Tox
    /// </summary>
    public class Messenger : IDisposable
    {
        public enum ToxConnection
        {
            TOX_CONNECTION_NONE = 0,
            TOX_CONNECTION_TCP = 1,
            TOX_CONNECTION_UDP = 2
        }

        private readonly List<BootstrapNode> _bootstrapNodes = new List<BootstrapNode>
        {
            // Nodos oficiales de Tox - actualizados 2024
            new BootstrapNode("tox.plastiras.org", 33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832"),
            new BootstrapNode("144.217.167.73", 33445, "7F9C31FE850E97CEFD4C4591DF93FC757C7C12549DDD55F8EEAECC34FE76C029"),
            new BootstrapNode("tox.abilinski.com", 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D294302F67BEDFFB5DF67F"),
            new BootstrapNode("tox.novg.net", 33445, "D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463"),
            new BootstrapNode("tox.kurnevsky.net", 33445, "82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23")
        };

        private string _stateFilePath;
        public AdvancedNetworking AdvancedNetworking { get; private set; }

        private Messenger _messenger;

        private int _currentBootstrapIndex = 0;
        private long _lastBootstrapAttempt = 0;
        private const int BOOTSTRAP_RETRY_INTERVAL = 30000; // 30 segundos
        private const int BOOTSTRAP_MAX_ATTEMPTS = 3;

        // ✅ NUEVO: Clase para nodos bootstrap
        private class BootstrapNode
        {
            public string Host { get; }
            public ushort Port { get; }
            public byte[] PublicKey { get; }

            public BootstrapNode(string host, ushort port, string publicKeyHex)
            {
                Host = host;
                Port = port;
                PublicKey = HexStringToByteArray(publicKeyHex);
            }
        }


        public const int FRIEND_CONNECTION_TIMEOUT = 60000; // 60 segundos
        public const int PING_INTERVAL = 30000; // 30 segundos
        public const int PING_TIMEOUT = 10000; // 10 segundos

        private const string LOG_TAG = "MESSENGER";
        public GroupManager GroupManager { get; private set; }

        // Componentes principales
        public DHT Dht { get; private set; }
        public Onion Onion { get; private set; }
        public TCP_Server TcpServer { get; private set; }
        public FriendConnection FriendConn { get; private set; }
        public ToxState State { get; private set; }
        public LANDiscovery LANDiscovery { get; private set; }
        public FileTransferManager FileTransfer { get; private set; }
        public TCPTunnel TcpTunnel { get; private set; }
        public TCPForwarding TcpForwarding { get; private set; }

        // Configuración
        private readonly MessengerOptions _options;
        private bool _isRunning;

        public Messenger(MessengerOptions options = null)
        {
            _options = options ?? new MessengerOptions();
            State = new ToxState();
            TcpTunnel = new TCPTunnel(this);
            TcpForwarding = new TCPForwarding(TcpTunnel);
            Onion = new Onion(State.User.PublicKey, State.User.SecretKey, null!, this);
            _isRunning = false;

            Logger.Log.Info($"[{LOG_TAG}] Messenger inicializando...");
        }

        /// <summary>
        /// messenger_start - Inicializar todos los componentes
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Messenger ya está ejecutándose");
                return true;
            }

            try
            {
                // 1. Generar claves si no existen
                if (State.User.PublicKey.All(b => b == 0) || State.User.SecretKey.All(b => b == 0))
                {
                    Logger.Log.Info($"[{LOG_TAG}] Generando nuevas claves criptográficas");
                    GenerateNewKeys();
                }

                // 2. Inicializar DHT
                Dht = new DHT(State.User.PublicKey, State.User.SecretKey);

                // 3. Inicializar Onion
                Onion = new Onion(State.User.PublicKey, State.User.SecretKey, Dht, this);

                // 4. Inicializar TCP Server si está habilitado (usar constructor sin parámetros)
                if (_options.TcpEnabled)
                {
                    TcpServer = new TCP_Server(State.User.PublicKey, State.User.SecretKey);
                    // En una implementación real, inicializarías el servidor aquí
                }

                // 5. Inicializar Friend Connection
                FriendConn = new FriendConnection(State.User.PublicKey, State.User.SecretKey, Dht, Onion);

                if (_options.EnableLANDiscovery)
                {
                    LANDiscovery = new LANDiscovery(State.User.PublicKey);

                    // Configurar callback para agregar amigos automáticamente
                    LANDiscovery.PeerDiscoveredCallback = OnPeerDiscovered;

                    bool lanStarted = LANDiscovery.Start();
                    if (lanStarted)
                    {
                        Logger.Log.Info($"[{LOG_TAG}] LAN Discovery iniciado");
                    }
                }

                GroupManager = new GroupManager(this);
                GroupManager?.Start();

                Logger.Log.Info($"[{LOG_TAG}] Group Manager iniciado");


                FileTransfer = new FileTransferManager(this);

                TcpTunnel.Start();

                
                _isRunning = true;
                Logger.Log.Info($"[{LOG_TAG}] Messenger iniciado correctamente");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando messenger: {ex.Message}");
                return false;
            }
        }

        private int HandleTunnelPacket(int friendcon_id, byte[] data, int length)
        {
            return TcpTunnel?.HandleTunnelPacket(friendcon_id, data, length) ?? -1;
        }

        /// <summary>
        /// messenger_stop - Detener todos los componentes
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _isRunning = false;

                // Usar métodos de cierre existentes en tus clases
                // Si no tienen Dispose, simplemente dejar que el GC los limpie
                FriendConn = null;
                Onion = null;
                TcpServer = null;
                Dht = null;
                LANDiscovery?.Stop();
                LANDiscovery?.Dispose();
                GroupManager?.Stop();
                GroupManager?.Dispose();
                TcpTunnel?.Stop();
                Logger.Log.Info($"[{LOG_TAG}] Messenger detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo messenger: {ex.Message}");
            }
        }

        public void TriggerOnionFriendMessage(int friendNumber, byte[] message)
        {
            FriendConn?.HandleFriendPacket(message, message.Length, GetFriendPublicKey(friendNumber));
        }

        private byte[] GetFriendPublicKey(int friendNumber)
        {
            return State.Friends.Friends.FirstOrDefault(f => f.FriendNumber == friendNumber)?.PublicKey;
        }

        /// <summary>
        /// Establece la ruta del archivo de estado y carga si existe
        /// </summary>
        public bool LoadState(string filePath)
        {
            _stateFilePath = filePath;
            if (State.LoadFromFile(filePath))
            {
                Logger.Log.InfoF($"[MESSENGER] Estado cargado desde {filePath}");
                return true;
            }
            Logger.Log.WarningF($"[MESSENGER] No se pudo cargar estado desde {filePath}, iniciando nuevo");
            return false;
        }

        /// <summary>
        /// Guarda el estado actual si hay ruta configurada
        /// </summary>
        public bool SaveState()
        {
            if (string.IsNullOrEmpty(_stateFilePath)) return false;

            // ✅ Usa el campo real que ya existe
            State.Runtime.KnownDHTNodes = Dht?.GetClosestNodes(_messenger.State.User.PublicKey, 200) ?? new List<DHT.DHTNode>();

            // ✅ Usa reflexión para FileTransfer
            var xferList = FileTransfer?.GetType()
                .GetMethod("GetActiveTransfers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?.Invoke(FileTransfer, null) as System.Collections.IEnumerable;

            State.Runtime.ActiveFileTransfers = xferList?.Cast<EnhancedFileTransfer>().ToList() ?? new List<EnhancedFileTransfer>();

            // ✅ LanDiscovery
            State.Runtime.LanPeers = LANDiscovery?.GetDiscoveredPeers() ?? new List<DiscoveredPeer>();

            // ✅ Onion
            State.Runtime.OnionPaths = Onion?._onionPaths ?? new List<OnionPath>();

            // ✅ TCPTunnel
            State.Runtime.TcpTunnels = TcpTunnel != null ? TcpTunnel._connections.Values.ToList() : new List<TCPTunnelConnection>();

            return State.SaveToFile(_stateFilePath);
        }


        private void OnPeerDiscovered(DiscoveredPeer peer)
        {
            try
            {
                Logger.Log.InfoF($"[{LOG_TAG}] Peer LAN descubierto: {peer.IPAddress}");

                // Intentar bootstrap con el peer descubierto
                Bootstrap(peer.IPAddress.ToString(), peer.Port, peer.PublicKey);

                // Opcional: agregar como amigo automáticamente
                // AddFriend(peer.PublicKey, "Discovered on LAN");
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error manejando peer descubierto: {ex.Message}");
            }
        }

        /// <summary>
        /// messenger_do - ACTUALIZADO con bootstrap automático
        /// </summary>
        public void Do()
        {
            if (!_isRunning) return;

            try
            {
                // 1. Bootstrap automático si no hay suficientes nodos DHT
                if (Dht?.ActiveNodes < 10) // Si tenemos menos de 10 nodos activos
                {
                    PerformAutomaticBootstrap();
                }

                // 2. Ejecutar trabajos periódicos de todos los componentes
                Dht?.DoPeriodicWork();
                Onion?.DoPeriodicWork();
                FriendConn?.Do_periodic_work();

                // 3. LAN Discovery si está habilitado
                if (_options.EnableLANDiscovery)
                {
                    // LAN Discovery ya maneja su propio trabajo periódico
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en iteración principal: {ex.Message}");
            }
        }

        /// <summary>
        /// Bootstrap - MEJORADO con múltiples intentos y mejor manejo de errores
        /// </summary>
        public bool Bootstrap(string host, ushort port, byte[] publicKey)
        {
            if (!_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] No se puede bootstrap - Messenger no iniciado");
                return false;
            }

            try
            {
                Logger.Log.InfoF($"[{LOG_TAG}] Bootstrap a {host}:{port}");

                // ✅ MEJORADO: Usar DNS resolution real
                IPAddress[] addresses;
                try
                {
                    addresses = Dns.GetHostAddresses(host);
                    if (addresses.Length == 0)
                    {
                        Logger.Log.Error($"[{LOG_TAG}] No se pudo resolver host: {host}");
                        return false;
                    }
                }
                catch (Exception dnsEx)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Error DNS para {host}: {dnsEx.Message}");
                    return false;
                }

                // Intentar con todas las direcciones IP resueltas
                foreach (var ipAddress in addresses)
                {
                    try
                    {
                        var ipPort = new IPPort(new IP(ipAddress), port);

                        // Bootstrap en DHT
                        int result = Dht.DHT_bootstrap(ipPort, publicKey);
                        bool success = result == 0;

                        if (success)
                        {
                            Logger.Log.Info($"[{LOG_TAG}] Bootstrap exitoso a {ipAddress}:{port}");
                            return true;
                        }
                    }
                    catch (Exception ipEx)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Bootstrap falló para {ipAddress}: {ipEx.Message}");
                    }
                }

                Logger.Log.Warning($"[{LOG_TAG}] Todos los intentos de bootstrap fallaron para {host}");
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en bootstrap: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// BootstrapMultiple - Bootstrap a múltiples nodos simultáneamente
        /// </summary>
        public void BootstrapMultiple(params (string host, ushort port, string publicKeyHex)[] nodes)
        {
            if (!_isRunning) return;

            foreach (var node in nodes)
            {
                try
                {
                    byte[] publicKey = HexStringToByteArray(node.publicKeyHex);
                    if (publicKey != null)
                    {
                        Task.Run(() => Bootstrap(node.host, node.port, publicKey));
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Error en bootstrap múltiple para {node.host}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// messenger_add_friend - Agregar amigo por dirección Tox
        /// </summary>
        public int AddFriend(byte[] address, string message)
        {
            if (!_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] No se puede agregar amigo - Messenger no iniciado");
                return -1;
            }

            try
            {
                // Extraer clave pública de la dirección Tox (primeros 32 bytes)
                if (address.Length < 32)
                {
                    Logger.Log.Error($"[{LOG_TAG}] Dirección Tox inválida - muy corta");
                    return -1;
                }

                byte[] publicKey = new byte[32];
                Array.Copy(address, publicKey, 32);

                Logger.Log.InfoF($"[{LOG_TAG}] Agregando amigo - Mensaje: {message}");

                // Usar API existente de FriendConnection - solo publicKey
                int friendNumber = FriendConn.m_addfriend(publicKey);

                if (friendNumber >= 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Amigo agregado: {friendNumber}");
                    // Guardar en estado
                    SaveFriendToState(friendNumber, publicKey);
                }
                else
                {
                    Logger.Log.Warning($"[{LOG_TAG}] Falló agregar amigo");
                }

                return friendNumber;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error agregando amigo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// messenger_send_message - Enviar mensaje a amigo
        /// </summary>
        public int SendMessage(uint friendNumber, string message)
        {
            if (!_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] No se puede enviar mensaje - Messenger no iniciado");
                return -1;
            }

            try
            {
                Logger.Log.DebugF($"[{LOG_TAG}] Enviando mensaje a amigo {friendNumber}");

                // Convertir mensaje a bytes
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message ?? "");

                // Usar API existente - solo 3 parámetros
                int result = FriendConn.m_send_message((int)friendNumber, messageBytes, messageBytes.Length);

                if (result > 0)
                {
                    Logger.Log.TraceF($"[{LOG_TAG}] Mensaje enviado a amigo {friendNumber}: {result} bytes");
                }
                else
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Falló envío a amigo {friendNumber}");
                }

                return result;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando mensaje: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// messenger_set_name - Establecer nombre de usuario
        /// </summary>
        public bool SetName(string name)
        {
            try
            {
                if (string.IsNullOrEmpty(name) || name.Length > 128)
                {
                    Logger.Log.Error($"[{LOG_TAG}] Nombre inválido");
                    return false;
                }

                State.User.Name = name;
                State.MarkModified();

                Logger.Log.InfoF($"[{LOG_TAG}] Nombre establecido: {name}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error estableciendo nombre: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// messenger_set_status_message - Establecer mensaje de estado
        /// </summary>
        public bool SetStatusMessage(string message)
        {
            try
            {
                if (message?.Length > 1007) // Límite de toxcore
                {
                    Logger.Log.Error($"[{LOG_TAG}] Mensaje de estado muy largo");
                    return false;
                }

                State.User.StatusMessage = message ?? "";
                State.MarkModified();

                Logger.Log.InfoF($"[{LOG_TAG}] Mensaje de estado establecido: {message}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error estableciendo mensaje de estado: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// messenger_set_status - Establecer estado de usuario
        /// </summary>
        public bool SetStatus(ToxUserStatus status)
        {
            try
            {
                State.User.Status = status;
                State.MarkModified();

                Logger.Log.InfoF($"[{LOG_TAG}] Estado de usuario establecido: {status}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error estableciendo estado: {ex.Message}");
                return false;
            }
        }

        // ==================== MÉTODOS PRIVADOS ====================

        private void GenerateNewKeys()
        {
            try
            {
                // Generar par de claves
                byte[] publicKey = new byte[32];
                byte[] secretKey = new byte[32];

                var random = new Random();
                random.NextBytes(publicKey);
                random.NextBytes(secretKey);

                State.User.PublicKey = publicKey;
                State.User.SecretKey = secretKey;
                State.MarkModified();

                Logger.Log.Info($"[{LOG_TAG}] Nuevas claves generadas");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error generando claves: {ex.Message}");
                throw;
            }
        }

        private void SaveFriendToState(int friendNumber, byte[] publicKey)
        {
            try
            {
                var friend = new ToxFriend
                {
                    FriendNumber = (uint)friendNumber,
                    PublicKey = publicKey
                };

                var friendsList = State.Friends.Friends.ToList();
                friendsList.Add(friend);
                State.Friends.Friends = friendsList.ToArray();
                State.MarkModified();

                Logger.Log.DebugF($"[{LOG_TAG}] Amigo {friendNumber} guardado en estado");
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error guardando amigo en estado: {ex.Message}");
            }
        }

        /// <summary>
        /// PerformAutomaticBootstrap - Bootstrap automático como en toxcore
        /// </summary>
        private void PerformAutomaticBootstrap()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;

                // Esperar entre intentos de bootstrap
                if ((currentTime - _lastBootstrapAttempt) < TimeSpan.TicksPerMillisecond * BOOTSTRAP_RETRY_INTERVAL)
                    return;

                _lastBootstrapAttempt = currentTime;

                // Intentar con el siguiente nodo en la lista
                var bootstrapNode = _bootstrapNodes[_currentBootstrapIndex];
                _currentBootstrapIndex = (_currentBootstrapIndex + 1) % _bootstrapNodes.Count;

                Logger.Log.InfoF($"[{LOG_TAG}] Intentando bootstrap automático con {bootstrapNode.Host}:{bootstrapNode.Port}");

                bool success = Bootstrap(bootstrapNode.Host, bootstrapNode.Port, bootstrapNode.PublicKey);

                if (success)
                {
                    Logger.Log.Info($"[{LOG_TAG}] Bootstrap automático exitoso");
                }
                else
                {
                    Logger.Log.Warning($"[{LOG_TAG}] Bootstrap automático falló, siguiente intento en {BOOTSTRAP_RETRY_INTERVAL / 1000} segundos");
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en bootstrap automático: {ex.Message}");
            }
        }

        /// <summary>
        /// HexStringToByteArray - Convierte string hex a byte[] (auxiliar para bootstrap)
        /// </summary>
        private static byte[] HexStringToByteArray(string hex)
        {
            try
            {
                int numberChars = hex.Length;
                byte[] bytes = new byte[numberChars / 2];
                for (int i = 0; i < numberChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                }
                return bytes;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[MESSENGER] Error convirtiendo hex a bytes: {ex.Message}");
                return null;
            }
        }




        public void Dispose()
        {
            Stop();
            State?.Dispose();
        }
    }

    /// <summary>
    /// Opciones de configuración del Messenger
    /// </summary>
    public class MessengerOptions
    {
        public bool IPv6Enabled { get; set; } = true;
        public bool UDPEnabled { get; set; } = true;
        public bool TcpEnabled { get; set; } = true;
        public bool ProxyEnabled { get; set; } = false;
        public string ProxyHost { get; set; } = string.Empty;
        public ushort ProxyPort { get; set; } = 0;
        public bool EnableLANDiscovery { get; set; } = true;

    }
}