using System;
using System.Collections.Generic;
using System.Linq;

namespace ToxCore.Core
{
    /// <summary>
    /// Adaptación de messenger.c - Núcleo principal del cliente Tox
    /// </summary>
    public class Messenger : IDisposable
    {
        private const string LOG_TAG = "MESSENGER";
        public GroupManager GroupManager { get; private set; }

        // Componentes principales
        public DHT Dht { get; private set; }
        public Onion Onion { get; private set; }
        public TCP_Server TcpServer { get; private set; }
        public FriendConnection FriendConn { get; private set; }
        public ToxState State { get; private set; }
        public LANDiscovery LANDiscovery { get; private set; }

        // Configuración
        private readonly MessengerOptions _options;
        private bool _isRunning;

        public Messenger(MessengerOptions options = null)
        {
            _options = options ?? new MessengerOptions();
            State = new ToxState();
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
                Onion = new Onion(State.User.PublicKey, State.User.SecretKey);

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
                GroupManager.Start();

                Logger.Log.Info($"[{LOG_TAG}] Group Manager iniciado");


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
                Logger.Log.Info($"[{LOG_TAG}] Messenger detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo messenger: {ex.Message}");
            }
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
        /// messenger_do - Ejecutar iteración principal (equivalente a do_messenger)
        /// </summary>
        public void Do()
        {
            if (!_isRunning) return;

            try
            {
                // Ejecutar trabajos periódicos de todos los componentes
                Dht?.DoPeriodicWork();
                Onion?.DoPeriodicWork();
                FriendConn?.Do_periodic_work();
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en iteración principal: {ex.Message}");
            }
        }

        /// <summary>
        /// messenger_bootstrap - Conectar a la red Tox
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

                // Usar el método de red existente para crear IPPort
                var ipPort = new IPPort();
                bool ipSuccess = Network.BytesToIPPort(ref ipPort, System.Text.Encoding.UTF8.GetBytes(host), 0, port);

                if (!ipSuccess)
                {
                    Logger.Log.Error($"[{LOG_TAG}] No se pudo resolver host: {host}");
                    return false;
                }

                // Bootstrap en DHT - usar método existente
                int result = Dht.DHT_bootstrap(ipPort, publicKey);
                bool success = result == 0;

                if (success)
                {
                    Logger.Log.Info($"[{LOG_TAG}] Bootstrap exitoso a {host}:{port}");
                }
                else
                {
                    Logger.Log.Warning($"[{LOG_TAG}] Bootstrap falló a {host}:{port}");
                }

                return success;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en bootstrap: {ex.Message}");
                return false;
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