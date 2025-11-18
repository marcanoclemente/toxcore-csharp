using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    // ==================== ENUMERACIONES FALTANTES ====================

    public enum ToxProxyType
    {
        None = 0,
        HTTP = 1,
        SOCKS5 = 2
    }

    public enum ToxConnectionStatus
    {
        NONE = 0,
        TCP = 1,
        UDP = 2
    }

    public enum ToxUserStatus
    {
        NONE = 0,
        AWAY = 1,
        BUSY = 2
    }

    /// <summary>
    /// Opciones de configuración de Tox compatibles con toxcore
    /// </summary>
    public class ToxOptions
    {
        public bool IPv6Enabled { get; set; } = true;
        public bool UDPEnabled { get; set; } = true;
        public bool LocalDiscoveryEnabled { get; set; } = false;
        public bool ProxyEnabled { get; set; } = false;
        public ToxProxyType ProxyType { get; set; } = ToxProxyType.None;
        public string ProxyHost { get; set; } = "";
        public ushort ProxyPort { get; set; } = 0;
        public int StartPort { get; set; } = 0;
        public int EndPort { get; set; } = 0;
        public int TCPPort { get; set; } = 0;
        public byte[] SavedData { get; set; } = null;
    }

    /// <summary>
    /// Callbacks para eventos de Tox
    /// </summary>
    public class ToxCallbacks
    {
        public Action<ToxConnectionStatus> OnSelfConnectionStatus;
        public Action<int, ToxConnectionStatus> OnFriendConnectionStatus;
        public Action<int, string> OnFriendMessage;
        public Action<int, byte[], int> OnFriendData;
        public Action<int, string> OnFriendName;
        public Action<int, string> OnFriendStatusMessage;
        public Action<int, ToxUserStatus> OnFriendStatus;
        public Action<int, byte[]> OnFriendRequest;
        public Action<int> OnFriendAdded;
        public Action<int> OnFriendRemoved;
    }

    /// <summary>
    /// Cliente Tox principal que integra todos los módulos
    /// </summary>
    public class Tox : IDisposable
    {
        public const string TOX_VERSION = "1.2.5";
        public const int TOX_ADDRESS_SIZE = 38;
        public const int TOX_MAX_NAME_LENGTH = 128;
        public const int TOX_MAX_STATUS_MESSAGE_LENGTH = 1007;
        public const int TOX_MAX_MESSAGE_LENGTH = 1372;
        public const int TOX_MAX_FILENAME_LENGTH = 255;

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public string SelfName { get; private set; }
        public string SelfStatusMessage { get; private set; }
        public ToxUserStatus SelfStatus { get; private set; }
        public ToxConnectionStatus ConnectionStatus { get; private set; }
        public ToxCallbacks Callbacks { get; private set; }

        // Módulos integrados
        private DHT _dht;
        private Onion _onion;
        private FriendConnection _friendConn;
        private TCP_Server _tcpServer;
        private bool _isRunning;
        private long _lastIterationTime;

        public string Address => GetAddress();
        public int FriendCount => _friendConn?.FriendCount ?? 0;
        public int OnlineFriendCount => _friendConn?.OnlineFriends ?? 0;

        public Tox(ToxOptions options = null)
        {
            options ??= new ToxOptions();

            // Generar claves criptográficas
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            RandomBytes.Generate(SelfPublicKey);
            RandomBytes.Generate(SelfSecretKey);

            // Inicializar módulos
            _dht = new DHT(SelfPublicKey, SelfSecretKey);
            _onion = new Onion(SelfPublicKey, SelfSecretKey);
            _friendConn = new FriendConnection(SelfPublicKey, SelfSecretKey, _dht, _onion);

            // Configurar servidor TCP si se especifica puerto
            if (options.TCPPort > 0)
            {
                _tcpServer = new TCP_Server(SelfPublicKey, SelfSecretKey);
            }

            // Configurar callbacks
            Callbacks = new ToxCallbacks();
            SetupCallbacks();

            // Estado inicial
            SelfName = "Tox User";
            SelfStatusMessage = "";
            SelfStatus = ToxUserStatus.NONE;
            ConnectionStatus = ToxConnectionStatus.NONE;
            _isRunning = false;
            _lastIterationTime = 0;

            // Cargar datos guardados si existen
            if (options.SavedData != null)
            {
                LoadFromSaveData(options.SavedData);
            }
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// tox_new - Crear nueva instancia de Tox (equivalente a tox_new)
        /// </summary>
        public static Tox tox_new(ToxOptions options)
        {
            return new Tox(options);
        }

        /// <summary>
        /// tox_iteration_interval - Obtener intervalo de iteración
        /// </summary>
        public uint tox_iteration_interval()
        {
            return 50; // 50ms como en toxcore original
        }

        /// <summary>
        /// tox_iterate - Ejecutar iteración principal (equivalente a tox_iterate)
        /// </summary>
        public void tox_iterate()
        {
            if (!_isRunning) return;

            long currentTime = DateTime.UtcNow.Ticks;

            try
            {
                _dht.DoPeriodicWork();
                _onion.DoPeriodicWork();
                _friendConn.Do_periodic_work();
                _tcpServer?.Do_periodic_work();

                // Actualizar estado de conexión
                UpdateConnectionStatus();

                // Procesar paquetes de red
                ProcessNetworkPackets();

                _lastIterationTime = currentTime;
            }
            catch (Exception)
            {
                // Silenciar errores en iteración
            }
        }

        /// <summary>
        /// tox_self_get_connection_status - Obtener estado de conexión
        /// </summary>
        public ToxConnectionStatus tox_self_get_connection_status()
        {
            return ConnectionStatus;
        }

        /// <summary>
        /// tox_bootstrap - Conectar a la red Tox
        /// </summary>
        public bool tox_bootstrap(string host, ushort port, byte[] public_key)
        {
            if (public_key == null || public_key.Length != 32) return false;

            try
            {
                var ip = new IP(Network.Resolve(host));
                var ipp = new IPPort(ip, port);

                // Bootstrap DHT
                int result = _dht.DHT_bootstrap(ipp, public_key);
                if (result == 0)
                {
                    // Iniciar servicios
                    _onion.Start();
                    _isRunning = true;
                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_add_tcp_relay - Agregar relay TCP
        /// </summary>
        public bool tox_add_tcp_relay(string host, ushort port, byte[] public_key)
        {
            if (public_key == null || public_key.Length != 32) return false;

            try
            {
                var ip = new IP(Network.Resolve(host));
                var ipp = new IPPort(ip, port);

                // CORREGIDO: Usar onion_add_node en lugar de AddNode
                _onion.onion_add_node(public_key, ipp);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // ==================== GESTIÓN DE PERFIL ====================

        /// <summary>
        /// tox_self_set_name - Establecer nombre de usuario
        /// </summary>
        public bool tox_self_set_name(string name)
        {
            if (name == null || name.Length > TOX_MAX_NAME_LENGTH) return false;

            try
            {
                SelfName = name;
                // CORREGIDO: Convertir FriendUserStatus a ToxUserStatus
                _friendConn.m_set_status_message(name);
                Callbacks.OnFriendName?.Invoke(-1, name); // -1 indica self
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_self_get_name - Obtener nombre de usuario
        /// </summary>
        public string tox_self_get_name()
        {
            return SelfName;
        }

        /// <summary>
        /// tox_self_set_status_message - Establecer mensaje de estado
        /// </summary>
        public bool tox_self_set_status_message(string message)
        {
            if (message == null || message.Length > TOX_MAX_STATUS_MESSAGE_LENGTH) return false;

            try
            {
                SelfStatusMessage = message;
                _friendConn.m_set_status_message(message);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_self_get_status_message - Obtener mensaje de estado
        /// </summary>
        public string tox_self_get_status_message()
        {
            return SelfStatusMessage;
        }

        /// <summary>
        /// tox_self_set_status - Establecer estado de usuario
        /// </summary>
        public bool tox_self_set_status(ToxUserStatus status)
        {
            try
            {
                SelfStatus = status;
                // CORREGIDO: Convertir ToxUserStatus a FriendUserStatus
                _friendConn.m_set_status((FriendUserStatus)status);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_self_get_status - Obtener estado de usuario
        /// </summary>
        public ToxUserStatus tox_self_get_status()
        {
            return SelfStatus;
        }

        /// <summary>
        /// tox_self_get_address - Obtener dirección Tox
        /// </summary>
        public byte[] tox_self_get_address()
        {
            byte[] address = new byte[TOX_ADDRESS_SIZE];

            // Formato: public_key (32 bytes) + nosave (1 byte) + checksum (4 bytes)
            Buffer.BlockCopy(SelfPublicKey, 0, address, 0, 32);
            address[32] = 0x00; // nosave

            // Calcular checksum (simplificado)
            byte[] checksum = CalculateAddressChecksum(SelfPublicKey);
            Buffer.BlockCopy(checksum, 0, address, 33, 4);

            return address;
        }

        /// <summary>
        /// tox_self_get_public_key - Obtener clave pública
        /// </summary>
        public byte[] tox_self_get_public_key()
        {
            byte[] key = new byte[32];
            Buffer.BlockCopy(SelfPublicKey, 0, key, 0, 32);
            return key;
        }

        /// <summary>
        /// tox_self_get_secret_key - Obtener clave secreta
        /// </summary>
        public byte[] tox_self_get_secret_key()
        {
            byte[] key = new byte[32];
            Buffer.BlockCopy(SelfSecretKey, 0, key, 0, 32);
            return key;
        }

        // ==================== GESTIÓN DE AMIGOS ====================

        /// <summary>
        /// tox_friend_add - Agregar amigo por dirección
        /// </summary>
        public int tox_friend_add(byte[] address, string message)
        {
            if (address == null || address.Length != TOX_ADDRESS_SIZE) return -1;
            if (message == null || message.Length == 0) return -1;

            try
            {
                // Extraer clave pública de la dirección
                byte[] publicKey = new byte[32];
                Buffer.BlockCopy(address, 0, publicKey, 0, 32);

                // Agregar amigo
                int friendNumber = _friendConn.m_addfriend(publicKey);
                if (friendNumber >= 0)
                {
                    Callbacks.OnFriendAdded?.Invoke(friendNumber);
                }

                return friendNumber;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tox_friend_add_norequest - Agregar amigo por clave pública
        /// </summary>
        public int tox_friend_add_norequest(byte[] public_key)
        {
            if (public_key == null || public_key.Length != 32) return -1;

            try
            {
                int friendNumber = _friendConn.m_addfriend(public_key);
                if (friendNumber >= 0)
                {
                    Callbacks.OnFriendAdded?.Invoke(friendNumber);
                }
                return friendNumber;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tox_friend_delete - Eliminar amigo
        /// </summary>
        public bool tox_friend_delete(int friend_number)
        {
            try
            {
                int result = _friendConn.m_delfriend(friend_number);
                if (result == 0)
                {
                    Callbacks.OnFriendRemoved?.Invoke(friend_number);
                    return true;
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_friend_send_message - Enviar mensaje a amigo
        /// </summary>
        public int tox_friend_send_message(int friend_number, string message)
        {
            if (message == null || message.Length > TOX_MAX_MESSAGE_LENGTH) return -1;

            try
            {
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
                return _friendConn.m_send_message(friend_number, messageBytes, messageBytes.Length);
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// tox_friend_send_data - Enviar datos a amigo
        /// </summary>
        public int tox_friend_send_data(int friend_number, byte[] data, int length)
        {
            if (data == null || length > TOX_MAX_MESSAGE_LENGTH) return -1;

            try
            {
                return _friendConn.m_send_message(friend_number, data, length);
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== INFORMACIÓN DE AMIGOS ====================

        /// <summary>
        /// tox_friend_get_public_key - Obtener clave pública de amigo
        /// </summary>
        public bool tox_friend_get_public_key(int friend_number, byte[] public_key)
        {
            if (public_key == null || public_key.Length != 32) return false;

            try
            {
                var friend = _friendConn.Get_friend(friend_number);
                if (friend?.PublicKey != null)
                {
                    Buffer.BlockCopy(friend.Value.PublicKey, 0, public_key, 0, 32);
                    return true;
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// tox_friend_get_connection_status - Obtener estado de conexión de amigo
        /// </summary>
        public ToxConnectionStatus tox_friend_get_connection_status(int friend_number)
        {
            try
            {
                var friend = _friendConn.Get_friend(friend_number);
                if (friend?.IsOnline == true)
                {
                    return ToxConnectionStatus.TCP;
                }
                return ToxConnectionStatus.NONE;
            }
            catch (Exception)
            {
                return ToxConnectionStatus.NONE;
            }
        }

        /// <summary>
        /// tox_friend_get_last_online - Obtener última vez online de amigo
        /// </summary>
        public ulong tox_friend_get_last_online(int friend_number)
        {
            try
            {
                var friend = _friendConn.Get_friend(friend_number);
                if (friend?.LastSeen != null)
                {
                    return (ulong)friend.Value.LastSeen;
                }
                return 0;
            }
            catch (Exception)
            {
                return 0;
            }
        }

        // ==================== FUNCIONES AUXILIARES ====================

        private void SetupCallbacks()
        {
            _friendConn.Callbacks.OnConnectionStatusChanged = (friendNum, status) =>
            {
                var toxStatus = status == FriendConnectionStatus.FRIENDCONN_STATUS_CONNECTED
                    ? ToxConnectionStatus.TCP
                    : ToxConnectionStatus.NONE;

                if (friendNum >= 0)
                {
                    Callbacks.OnFriendConnectionStatus?.Invoke(friendNum, toxStatus);
                }
            };

            _friendConn.Callbacks.OnMessageReceived = (friendNum, data, length) =>
            {
                string message = System.Text.Encoding.UTF8.GetString(data, 0, length);
                Callbacks.OnFriendMessage?.Invoke(friendNum, message);
                Callbacks.OnFriendData?.Invoke(friendNum, data, length);
            };

            _friendConn.Callbacks.OnUserStatusChanged = (friendNum, status) =>
            {
                Callbacks.OnFriendStatus?.Invoke(friendNum, (ToxUserStatus)status);
            };
        }

        private void UpdateConnectionStatus()
        {
            var oldStatus = ConnectionStatus;

            // Determinar estado basado en nodos DHT y Onion
            if (_dht.ActiveNodes > 2 && _onion.ActivePaths > 0)
            {
                ConnectionStatus = ToxConnectionStatus.TCP;
            }
            else if (_dht.ActiveNodes > 0)
            {
                ConnectionStatus = ToxConnectionStatus.UDP;
            }
            else
            {
                ConnectionStatus = ToxConnectionStatus.NONE;
            }

            // Notificar cambio de estado
            if (oldStatus != ConnectionStatus)
            {
                Callbacks.OnSelfConnectionStatus?.Invoke(ConnectionStatus);
            }
        }

        private void ProcessNetworkPackets()
        {
            // En una implementación completa, aquí se procesarían
            // los paquetes de red entrantes de todos los módulos
        }

        private byte[] CalculateAddressChecksum(byte[] publicKey)
        {
            // Checksum simplificado para pruebas
            // En toxcore real usa SHA256
            byte[] checksum = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                checksum[i] = (byte)(publicKey[i] ^ publicKey[i + 28]);
            }
            return checksum;
        }

        private void LoadFromSaveData(byte[] savedData)
        {
            // Implementación básica de carga de datos guardados
            // En una implementación completa, esto cargaría el estado completo
            try
            {
                // Simular carga de datos
                if (savedData.Length > 0)
                {
                    // Aquí iría la lógica real de deserialización
                }
            }
            catch (Exception)
            {
                // Silenciar errores de carga
            }
        }

        /// <summary>
        /// Get_save_data - Obtener datos para guardar estado
        /// </summary>
        public byte[] Get_save_data()
        {
            // Implementación básica de guardado
            // En una implementación completa, esto serializaría el estado completo
            try
            {
                // Datos mínimos para pruebas
                byte[] saveData = new byte[100];
                Buffer.BlockCopy(SelfPublicKey, 0, saveData, 0, 32);
                Buffer.BlockCopy(SelfSecretKey, 0, saveData, 32, 32);
                return saveData;
            }
            catch (Exception)
            {
                return new byte[0];
            }
        }

        /// <summary>
        /// GetAddress - Obtener dirección Tox (formateada)
        /// </summary>
        public string GetAddress()
        {
            byte[] address = tox_self_get_address();
            return BitConverter.ToString(address).Replace("-", "").ToUpper();
        }

        // ==================== DISPOSABLE PATTERN ====================

        private bool _disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _isRunning = false;
                    _friendConn?.Do_periodic_work(); // Última iteración
                    _onion?.Close();
                    _dht?.Close();
                    _tcpServer?.Stop();
                }
                _disposed = true;
            }
        }

        ~Tox()
        {
            Dispose(false);
        }
    }
}