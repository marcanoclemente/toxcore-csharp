using System;
using System.Collections.Generic;
using System.Linq;
using ToxCore.FileTransfer;

namespace ToxCore.Core
{
    /// <summary>
    /// Cliente Tox principal - Adaptación de tox.c/tox.h con API pública completa
    /// </summary>
    public class Tox : IDisposable
    {
        private const string LOG_TAG = "TOX";

        // Componentes principales
        private Messenger _messenger;
        private ToxOptions _options;
        private bool _isRunning;


        // Callbacks de la API pública (equivalente a tox.h callbacks)
        public delegate void FriendRequestCallback(Tox tox, byte[] publicKey, string message, object userData);
        public delegate void FriendMessageCallback(Tox tox, uint friendNumber, ToxMessageType type, string message, object userData);
        public delegate void FriendConnectionStatusCallback(Tox tox, uint friendNumber, ToxConnection connectionStatus, object userData);
        public delegate void FriendNameCallback(Tox tox, uint friendNumber, string name, object userData);
        public delegate void FriendStatusMessageCallback(Tox tox, uint friendNumber, string message, object userData);
        public delegate void FriendStatusCallback(Tox tox, uint friendNumber, ToxUserStatus status, object userData);
        public delegate void FriendReadReceiptCallback(Tox tox, uint friendNumber, uint messageId, object userData);
        public delegate void SelfConnectionStatusCallback(Tox tox, ToxConnection connectionStatus, object userData);

        // Eventos para callbacks (más idiomático en C#)
        public event FriendRequestCallback OnFriendRequest;
        public event FriendMessageCallback OnFriendMessage;
        public event FriendConnectionStatusCallback OnFriendConnectionStatus;
        public event FriendNameCallback OnFriendName;
        public event FriendStatusMessageCallback OnFriendStatusMessage;
        public event FriendStatusCallback OnFriendStatus;
        public event FriendReadReceiptCallback OnFriendReadReceipt;
        public event SelfConnectionStatusCallback OnSelfConnectionStatus;

        // Constantes de la API pública (de tox.h)
        public const int TOX_ADDRESS_SIZE = 38;
        public const int TOX_PUBLIC_KEY_SIZE = 32;
        public const int TOX_SECRET_KEY_SIZE = 32;
        public const int TOX_NOSPAM_SIZE = 4;
        public const int TOX_MAX_NAME_LENGTH = 128;
        public const int TOX_MAX_STATUS_MESSAGE_LENGTH = 1007;
        public const int TOX_MAX_FRIEND_REQUEST_LENGTH = 1016;
        public const int TOX_MAX_MESSAGE_LENGTH = 1372;

        public Tox(ToxOptions options = null)
        {
            _options = options ?? new ToxOptions();
            _isRunning = false;

            Logger.Log.Info($"[{LOG_TAG}] Cliente Tox inicializado");
        }

        // ==================== API PÚBLICA PRINCIPAL (tox.h) ====================

        /// <summary>
        /// tox_self_get_address - Obtener dirección Tox pública
        /// </summary>
        public string GetAddress()
        {
            if (_messenger?.State?.User?.PublicKey == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede obtener address - Estado no inicializado");
                return string.Empty;
            }

            try
            {
                byte[] publicKey = _messenger.State.User.PublicKey;
                byte[] nospam = _messenger.State.User.Nospam ?? new byte[4];

                // 1. Primero crear address sin checksum: public_key (32) + nospam (4)
                byte[] addressWithoutChecksum = new byte[TOX_PUBLIC_KEY_SIZE + TOX_NOSPAM_SIZE];
                Buffer.BlockCopy(publicKey, 0, addressWithoutChecksum, 0, TOX_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(nospam, 0, addressWithoutChecksum, TOX_PUBLIC_KEY_SIZE, TOX_NOSPAM_SIZE);

                // 2. Calcular checksum (2 bytes) como en toxcore - crypto_sha256
                byte[] checksum = CalculateToxAddressChecksum(addressWithoutChecksum);

                // 3. Combinar todo: public_key (32) + nospam (4) + checksum (2) = 38 bytes
                byte[] fullAddress = new byte[TOX_ADDRESS_SIZE];
                Buffer.BlockCopy(addressWithoutChecksum, 0, fullAddress, 0, addressWithoutChecksum.Length);
                Buffer.BlockCopy(checksum, 0, fullAddress, addressWithoutChecksum.Length, 2);

                // Convertir a hexadecimal (76 caracteres)
                return BitConverter.ToString(fullAddress).Replace("-", "").ToUpper();
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error obteniendo address: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// CalculateToxAddressChecksum - Como en toxcore (basado en SHA256)
        /// </summary>
        private byte[] CalculateToxAddressChecksum(byte[] addressWithoutChecksum)
        {
            try
            {
                // En toxcore, el checksum son los primeros 2 bytes del SHA256 hash
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(addressWithoutChecksum);

                    // Tomar primeros 2 bytes del hash como checksum
                    byte[] checksum = new byte[2];
                    Buffer.BlockCopy(hash, 0, checksum, 0, 2);

                    return checksum;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error calculando checksum: {ex.Message}");
                return new byte[2]; // Checksum por defecto (ceros)
            }
        }


        /// <summary>
        /// ValidateToxAddress - Verifica que un ID Tox sea válido (checksum correcto)
        /// </summary>
        public bool ValidateToxAddress(string toxAddress)
        {
            if (string.IsNullOrEmpty(toxAddress) || toxAddress.Length != 76) // 38 bytes * 2 caracteres hex
                return false;

            try
            {
                // Convertir hex string a bytes
                byte[] addressBytes = HexStringToByteArray(toxAddress);
                if (addressBytes.Length != TOX_ADDRESS_SIZE)
                    return false;

                // Separar components
                byte[] addressWithoutChecksum = new byte[TOX_PUBLIC_KEY_SIZE + TOX_NOSPAM_SIZE];
                byte[] receivedChecksum = new byte[2];

                Buffer.BlockCopy(addressBytes, 0, addressWithoutChecksum, 0, addressWithoutChecksum.Length);
                Buffer.BlockCopy(addressBytes, addressWithoutChecksum.Length, receivedChecksum, 0, 2);

                // Calcular checksum esperado
                byte[] calculatedChecksum = CalculateToxAddressChecksum(addressWithoutChecksum);

                // ✅ CORREGIDO: Comparar manualmente los 2 bytes del checksum
                return receivedChecksum[0] == calculatedChecksum[0] &&
                       receivedChecksum[1] == calculatedChecksum[1];
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error validando address: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// HexStringToByteArray - Convierte string hexadecimal a byte[] (robusto)
        /// </summary>
        private static byte[] HexStringToByteArray(string hex)
        {
            try
            {
                if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
                    return null;

                byte[] bytes = new byte[hex.Length / 2];
                for (int i = 0; i < hex.Length; i += 2)
                {
                    string hexByte = hex.Substring(i, 2);
                    bytes[i / 2] = Convert.ToByte(hexByte, 16);
                }
                return bytes;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[TOX] Error convirtiendo hex a bytes: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// tox_self_get_public_key - Obtener clave pública
        /// </summary>
        public byte[] GetPublicKey()
        {
            return _messenger?.State?.User?.PublicKey?.ToArray() ?? new byte[TOX_PUBLIC_KEY_SIZE];
        }

        /// <summary>
        /// tox_self_get_secret_key - Obtener clave secreta
        /// </summary>
        public byte[] GetSecretKey()
        {
            return _messenger?.State?.User?.SecretKey?.ToArray() ?? new byte[TOX_SECRET_KEY_SIZE];
        }

        /// <summary>
        /// tox_self_set_name - Establecer nombre de usuario
        /// </summary>
        public bool tox_self_set_name(string name)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede establecer nombre - Messenger no inicializado");
                return false;
            }

            return _messenger.SetName(name);
        }

        /// <summary>
        /// tox_self_get_name - Obtener nombre de usuario
        /// </summary>
        public string tox_self_get_name()
        {
            return _messenger?.State?.User?.Name ?? string.Empty;
        }

        /// <summary>
        /// tox_self_set_status_message - Establecer mensaje de estado
        /// </summary>
        public bool tox_self_set_status_message(string message)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede establecer estado - Messenger no inicializado");
                return false;
            }

            return _messenger.SetStatusMessage(message);
        }

        /// <summary>
        /// tox_self_get_status_message - Obtener mensaje de estado
        /// </summary>
        public string tox_self_get_status_message()
        {
            return _messenger?.State?.User?.StatusMessage ?? string.Empty;
        }

        /// <summary>
        /// tox_self_set_status - Establecer estado de usuario
        /// </summary>
        public bool tox_self_set_status(ToxUserStatus status)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede establecer estado - Messenger no inicializado");
                return false;
            }

            return _messenger.SetStatus(status);
        }

        /// <summary>
        /// tox_self_get_status - Obtener estado de usuario
        /// </summary>
        public ToxUserStatus tox_self_get_status()
        {
            return _messenger?.State?.User?.Status ?? ToxUserStatus.NONE;
        }

        /// <summary>
        /// tox_bootstrap - Conectar a la red Tox
        /// </summary>
        public bool tox_bootstrap(string host, ushort port, byte[] public_key)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede bootstrap - Messenger no inicializado");
                return false;
            }

            return _messenger.Bootstrap(host, port, public_key);
        }

        /// <summary>
        /// tox_friend_add - ACTUALIZADO para validar formato de address
        /// </summary>
        public int tox_friend_add(byte[] address, string message)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede agregar amigo - Messenger no inicializado");
                return -1;
            }

            // Convertir address bytes a string hex para validación
            string addressHex = BitConverter.ToString(address).Replace("-", "").ToUpper();

            if (!ValidateToxAddress(addressHex))
            {
                Logger.Log.Error($"[{LOG_TAG}] Dirección Tox inválida - checksum incorrecto");
                return -1;
            }

            if (address.Length < TOX_PUBLIC_KEY_SIZE)
            {
                Logger.Log.Error($"[{LOG_TAG}] Dirección Tox inválida - muy corta");
                return -1;
            }

            // Extraer clave pública (primeros 32 bytes del address)
            byte[] publicKey = new byte[TOX_PUBLIC_KEY_SIZE];
            Array.Copy(address, publicKey, TOX_PUBLIC_KEY_SIZE);

            Logger.Log.InfoF($"[{LOG_TAG}] Agregando amigo - Mensaje: {message}");

            int friendNumber = _messenger.AddFriend(publicKey, message);

            if (friendNumber >= 0)
            {
                Logger.Log.InfoF($"[{LOG_TAG}] Amigo agregado: {friendNumber}");
            }
            else
            {
                Logger.Log.Warning($"[{LOG_TAG}] Falló agregar amigo");
            }

            return friendNumber;
        }

        /// <summary>
        /// tox_friend_add_norequest - Agregar amigo solo con clave pública (sin enviar solicitud)
        /// </summary>
        public int tox_friend_add_norequest(byte[] publicKey)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede agregar amigo - Messenger no inicializado");
                return -1;
            }

            if (publicKey == null || publicKey.Length != TOX_PUBLIC_KEY_SIZE)
            {
                Logger.Log.Error($"[{LOG_TAG}] Clave pública inválida");
                return -1;
            }

            // Crear dirección ficticia con nospam cero
            byte[] address = new byte[TOX_ADDRESS_SIZE];
            Buffer.BlockCopy(publicKey, 0, address, 0, TOX_PUBLIC_KEY_SIZE);
            // Los últimos 6 bytes (nospam + checksum) se dejan en cero

            return _messenger.AddFriend(publicKey, string.Empty);
        }

        /// <summary>
        /// tox_friend_send_message - Enviar mensaje a amigo
        /// </summary>
        public int tox_friend_send_message(uint friendNumber, ToxMessageType type, string message)
        {
            if (_messenger == null)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede enviar mensaje - Messenger no inicializado");
                return -1;
            }

            if (string.IsNullOrEmpty(message))
            {
                Logger.Log.Error($"[{LOG_TAG}] Mensaje vacío");
                return -1;
            }

            if (message.Length > TOX_MAX_MESSAGE_LENGTH)
            {
                Logger.Log.Error($"[{LOG_TAG}] Mensaje demasiado largo");
                return -1;
            }

            return _messenger.SendMessage(friendNumber, message);
        }

        /// <summary>
        /// tox_self_get_friend_list - Obtener lista de números de amigos
        /// </summary>
        public uint[] tox_self_get_friend_list()
        {
            if (_messenger?.State?.Friends?.Friends == null)
                return Array.Empty<uint>();

            return _messenger.State.Friends.Friends
                .Where(f => f != null)
                .Select(f => f.FriendNumber)
                .ToArray();
        }

        /// <summary>
        /// tox_friend_get_public_key - Obtener clave pública de amigo
        /// </summary>
        public byte[] tox_friend_get_public_key(uint friendNumber)
        {
            var friend = GetFriend(friendNumber);
            return friend?.PublicKey?.ToArray() ?? new byte[TOX_PUBLIC_KEY_SIZE];
        }

        /// <summary>
        /// tox_friend_get_connection_status - Obtener estado de conexión de amigo
        /// </summary>
        public ToxConnection tox_friend_get_connection_status(uint friendNumber)
        {
            var friend = GetFriend(friendNumber);
            // En esta implementación básica, asumimos que si el amigo existe está conectado
            return friend != null ? ToxConnection.TOX_CONNECTION_UDP : ToxConnection.TOX_CONNECTION_NONE;
        }

        /// <summary>
        /// tox_friend_get_last_online - Obtener última vez que el amigo estuvo online
        /// </summary>
        public ulong tox_friend_get_last_online(uint friendNumber)
        {
            // En esta implementación, devolvemos el timestamp actual
            return (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>
        /// tox_self_get_connection_status - Obtener estado de conexión propio
        /// </summary>
        public ToxConnection tox_self_get_connection_status()
        {
            return _messenger != null ? ToxConnection.TOX_CONNECTION_UDP : ToxConnection.TOX_CONNECTION_NONE;
        }

        /// <summary>
        /// tox_iterate - Ejecutar iteración principal
        /// </summary>
        public void tox_iterate()
        {
            _messenger?.Do();
        }

        // ==================== PROPIEDADES ADICIONALES ====================

        /// <summary>
        /// Número total de amigos
        /// </summary>
        public int FriendCount
        {
            get
            {
                return _messenger?.State?.Friends?.Friends?.Length ?? 0;
            }
        }

        /// <summary>
        /// Número de amigos conectados
        /// </summary>
        public int OnlineFriendCount
        {
            get
            {
                // Implementación simplificada - todos los amigos están "conectados"
                return FriendCount;
            }
        }

        /// <summary>
        /// Instancia del Messenger interno (para acceso avanzado)
        /// </summary>
        public Messenger Messenger => _messenger;

        // ==================== MÉTODOS DE CONTROL ====================

        /// <summary>
        /// Iniciar cliente Tox
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Cliente Tox ya está ejecutándose");
                return true;
            }

            try
            {
                // Convertir ToxOptions a MessengerOptions
                var messengerOptions = new MessengerOptions
                {
                    IPv6Enabled = _options.IPv6Enabled,
                    UDPEnabled = _options.UDPEnabled,
                    TcpEnabled = true, // Habilitar TCP por defecto
                    EnableLANDiscovery = _options.EnableLANDiscovery
                };

                _messenger = new Messenger(messengerOptions);

                // Configurar LAN Discovery si está habilitado
                if (_options.EnableLANDiscovery && _messenger.LANDiscovery != null)
                {
                    _messenger.LANDiscovery.PeerDiscoveredCallback = (peer) =>
                    {
                        Logger.Log.InfoF($"[{LOG_TAG}] Peer descubierto via LAN: {peer.IPAddress}");
                        // Opcional: agregar automáticamente como amigo
                        // tox_friend_add_norequest(peer.PublicKey);
                    };
                }

                bool started = _messenger.Start();

                if (started)
                {
                    _isRunning = true;
                    Logger.Log.Info($"[{LOG_TAG}] Cliente Tox iniciado correctamente");
                }

                return started;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando cliente Tox: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Detener cliente Tox
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _messenger?.Stop();
                _isRunning = false;
                Logger.Log.Info($"[{LOG_TAG}] Cliente Tox detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo cliente Tox: {ex.Message}");
            }
        }

        // ==================== MÉTODOS PRIVADOS ====================

        private ToxFriend GetFriend(uint friendNumber)
        {
            return _messenger?.State?.Friends?.Friends?
                .FirstOrDefault(f => f.FriendNumber == friendNumber);
        }

        private void TriggerFriendRequest(byte[] publicKey, string message)
        {
            OnFriendRequest?.Invoke(this, publicKey, message, null);
        }

        private void TriggerFriendMessage(uint friendNumber, ToxMessageType type, string message)
        {
            OnFriendMessage?.Invoke(this, friendNumber, type, message, null);
        }

        private void TriggerFriendConnectionStatus(uint friendNumber, ToxConnection status)
        {
            OnFriendConnectionStatus?.Invoke(this, friendNumber, status, null);
        }

        public int FileSend(int friendNumber, FileKind kind, long fileSize, string fileName, byte[] fileId = null)
        {
            return _messenger?.FileTransfer?.FileSend(friendNumber, kind, fileSize, fileName, fileId) ?? -1;
        }

        public bool FileSendChunk(int friendNumber, int fileNumber, long position, byte[] data, int length)
        {
            return _messenger?.FileTransfer?.FileSendChunk(friendNumber, fileNumber, position, data, length) ?? false;
        }

        public bool FileControl(int friendNumber, int fileNumber, int control)
        {
            return _messenger?.FileTransfer?.FileControl(friendNumber, fileNumber, control) ?? false;
        }

        // Callbacks para archivos
        public event FileTransferCallbacks.FileReceiveCallback OnFileReceive;
        public event FileTransferCallbacks.FileChunkRequestCallback OnFileChunkRequest;
        public event FileTransferCallbacks.FileChunkReceivedCallback OnFileChunkReceived;
        public event FileTransferCallbacks.FileTransferStatusChangedCallback OnFileTransferStatusChanged;


        public void Dispose()
        {
            Stop();
            _messenger?.Dispose();
        }
    }

    // ==================== ENUMS Y ESTRUCTURAS ====================

    /// <summary>
    /// Estados de conexión (de tox.h)
    /// </summary>
    public enum ToxConnection
    {
        TOX_CONNECTION_NONE = 0,
        TOX_CONNECTION_TCP = 1,
        TOX_CONNECTION_UDP = 2
    }

    /// <summary>
    /// Tipos de mensaje (de tox.h)
    /// </summary>
    public enum ToxMessageType
    {
        TOX_MESSAGE_TYPE_NORMAL = 0,
        TOX_MESSAGE_TYPE_ACTION = 1
    }

    /// <summary>
    /// Opciones para crear instancia Tox
    /// </summary>
    public class ToxOptions
    {
        public bool IPv6Enabled { get; set; } = true;
        public bool UDPEnabled { get; set; } = true;
        public bool ProxyEnabled { get; set; } = false;
        public ToxProxyType ProxyType { get; set; } = ToxProxyType.TOX_PROXY_TYPE_NONE;
        public string ProxyHost { get; set; } = string.Empty;
        public ushort ProxyPort { get; set; } = 0;
        public ushort StartPort { get; set; } = 0;
        public ushort EndPort { get; set; } = 0;
        public uint TCPPort { get; set; } = 0;
        public byte[] SavedData { get; set; } = null;
        public bool EnableLANDiscovery { get; set; } = true;
    }

    /// <summary>
    /// Tipos de proxy (de tox.h)
    /// </summary>
    public enum ToxProxyType
    {
        TOX_PROXY_TYPE_NONE = 0,
        TOX_PROXY_TYPE_HTTP = 1,
        TOX_PROXY_TYPE_SOCKS5 = 2
    }
}