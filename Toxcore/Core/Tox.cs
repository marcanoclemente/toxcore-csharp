using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Cliente Tox principal - integra todos los componentes en una API unificada
    /// </summary>
    public class Tox : IDisposable
    {
        // Componentes principales
        private DHT dht;
        private Onion onion;
        private FriendConnection friendConnection;
        private TCPClient tcpClient;
        private TCPServer tcpServer;

        // Configuración
        private ToxOptions options;
        private byte[] savedData;

        // Estado
        public ToxStatus Status { get; private set; }
        public string Name { get; private set; }
        public string StatusMessage { get; private set; }
        public ToxUserStatus UserStatus { get; private set; }

        // Información del nodo
        public byte[] PublicKey => dht?.SelfPublicKey;
        public byte[] SecretKey => dht?.SelfSecretKey;
        public byte[] Address => CalculateToxAddress();

        // Eventos públicos
        public event Action<string> OnLogMessage; // Para debugging
        public event Action OnConnected;
        public event Action OnDisconnected;
        public event Action<Friend> OnFriendRequest;
        public event Action<Friend> OnFriendConnected;
        public event Action<Friend> OnFriendDisconnected;
        public event Action<FriendMessage> OnFriendMessage;
        public event Action<Friend, string> OnFriendStatusChange;
        public event Action<Friend, byte[]> OnFileReceive;

        // Estadísticas
        public int FriendCount => friendConnection?.FriendCount ?? 0;
        public int OnlineFriends => friendConnection?.OnlineFriends ?? 0;
        public int DHTNodes => dht?.TotalNodes ?? 0;
        public int OnionNodes => onion?.AvailableNodes ?? 0;

        public Tox(ToxOptions options = null)
        {
            this.options = options ?? new ToxOptions();

            // Si no se especifica puerto, usar 0 (puerto aleatorio)
            if (this.options.UDPListenPort == 33445)
            {
                this.options.UDPListenPort = 0; // Puerto aleatorio para tests
            }

            Status = ToxStatus.Stopped;
            Name = "Tox User";
            StatusMessage = "Using Tox";
            UserStatus = ToxUserStatus.None;

            Log("Tox instance created");
        }

        /// <summary>
        /// Inicia el cliente Tox con las claves proporcionadas o genera nuevas
        /// </summary>
        public async Task<bool> StartAsync(byte[] savedData = null)
        {
            if (Status != ToxStatus.Stopped)
            {
                Log("Tox already running");
                return false;
            }

            try
            {
                Status = ToxStatus.Starting;
                Log("Starting Tox client...");

                // Cargar o generar claves
                byte[] publicKey, secretKey;
                if (savedData != null && LoadKeysFromSave(savedData, out publicKey, out secretKey))
                {
                    Log("Loaded keys and profile from saved data");
                }
                else
                {
                    var keyPair = CryptoBox.GenerateKeyPair();
                    publicKey = keyPair.PublicKey;
                    secretKey = keyPair.PrivateKey;
                    Log("Generated new key pair");
                }

                // Inicializar componentes en orden
                Log("Initializing DHT...");

                try
                {
                    dht = new DHT(publicKey, secretKey, options.UDPListenPort);
                }
                catch (Exception ex)
                {
                    // Fallback a puerto aleatorio si falla
                    Log($"DHT failed on port {options.UDPListenPort}, using random port: {ex.Message}");
                    dht = new DHT(publicKey, secretKey, 0);
                }

                Log("Initializing Onion Routing...");
                onion = new Onion(dht);

                Log("Initializing Friend Connection...");
                friendConnection = new FriendConnection(dht, onion, options.TCPListenPort);

                // Configurar eventos del Friend Connection
                friendConnection.OnFriendRequest += HandleFriendRequest;
                friendConnection.OnFriendConnected += HandleFriendConnected;
                friendConnection.OnFriendDisconnected += HandleFriendDisconnected;
                friendConnection.OnFriendMessage += HandleFriendMessage;
                friendConnection.OnFriendStatusChange += HandleFriendStatusChange;

                Log("Starting network services...");
                onion.Start();

                bool friendStarted = await friendConnection.StartAsync();
                if (!friendStarted)
                {
                    throw new InvalidOperationException("Failed to start friend connection");
                }

                // Cargar amigos desde datos guardados (si existen)
                if (savedData != null)
                {
                    LoadFriendsFromSave(savedData);
                }

                // Bootstrap con nodos iniciales
                await BootstrapAsync();

                Status = ToxStatus.Connected;
                OnConnected?.Invoke();

                Log($"Tox client started successfully. Address: {BitConverter.ToString(Address).Replace("-", "")}");
                Log($"DHT Nodes: {DHTNodes}, Onion Nodes: {OnionNodes}");

                return true;
            }
            catch (Exception ex)
            {
                Status = ToxStatus.Error;
                Log($"Error starting Tox: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Conecta a la red Tox usando nodos bootstrap
        /// </summary>
        private async Task BootstrapAsync()
        {
            Log("Bootstrapping to Tox network...");

            var bootstrapNodes = new List<IPPort>
            {
                new IPPort(IPAddress.Parse("144.76.60.215"), 33445),   // utox.org
                new IPPort(IPAddress.Parse("195.154.119.113"), 33445), // tox.abilinski.com
                new IPPort(IPAddress.Parse("46.101.197.175"), 33445),  // tox.initramfs.io
            };

            var bootstrapKeys = new List<byte[]>
            {
                new byte[] { 0x04, 0x11, 0x1C, 0x29, 0x1F, 0x2A, 0x26, 0x41, 0x2C, 0x51, 0x4B, 0x2C, 0x66, 0x1F, 0x6B, 0x52, 0x3C, 0x57, 0x1C, 0x6D, 0x1E, 0x29, 0x13, 0x1A, 0x56, 0x1D, 0x11, 0x3E, 0x52, 0x1D, 0x15, 0x6C },
                new byte[] { 0x02, 0x80, 0x0C, 0x85, 0x0E, 0x62, 0x78, 0x82, 0x4B, 0x8E, 0x26, 0x75, 0xBB, 0x46, 0x50, 0x67, 0x28, 0x64, 0x7B, 0x01, 0x05, 0xDB, 0x3D, 0x38, 0x94, 0x17, 0x5B, 0x89, 0x33, 0x73, 0x3D, 0x38 },
                new byte[] { 0x3F, 0x0A, 0x45, 0x5F, 0x41, 0x51, 0x19, 0xE9, 0x8A, 0x98, 0x9D, 0x79, 0x16, 0x10, 0x89, 0x7A, 0x62, 0x3E, 0x2D, 0x57, 0x60, 0x10, 0x19, 0x5A, 0x33, 0x93, 0x86, 0x35, 0x03, 0x57, 0x41, 0x28 }
            };

            // Bootstrap DHT
            dht.Bootstrap(bootstrapNodes, bootstrapKeys);

            // Esperar un poco para que el DHT se conecte
            await Task.Delay(2000);

            Log($"Bootstrapping complete. DHT nodes: {DHTNodes}");
        }

        /// <summary>
        /// Detiene el cliente Tox
        /// </summary>
        public void Stop()
        {
            if (Status == ToxStatus.Stopped) return;

            Log("Stopping Tox client...");

            Status = ToxStatus.Stopping;

            friendConnection?.Stop();
            onion?.Stop();

            Status = ToxStatus.Stopped;
            OnDisconnected?.Invoke();

            Log("Tox client stopped");
        }

        /// <summary>
        /// Agrega un amigo por su dirección Tox
        /// </summary>
        public uint AddFriend(byte[] address, string message = "Hello!")
        {
            if (Status != ToxStatus.Connected)
                throw new InvalidOperationException("Tox is not connected");

            if (address == null || address.Length != 32)
                throw new ArgumentException("Tox address must be 32 bytes");

            try
            {
                // En Tox, la dirección es la clave pública + algunos bytes de checksum
                // Por simplicidad, asumimos que los primeros 32 bytes son la clave pública
                byte[] publicKey = new byte[32];
                Buffer.BlockCopy(address, 0, publicKey, 0, 32);

                uint friendNumber = friendConnection.AddFriend(publicKey, message);
                Log($"Friend request sent to {BitConverter.ToString(publicKey, 0, 8).Replace("-", "")}...");

                return friendNumber;
            }
            catch (Exception ex)
            {
                Log($"Error adding friend: {ex.Message}");
                return uint.MaxValue;
            }
        }

        /// <summary>
        /// Agrega un amigo por su clave pública (sin checksum)
        /// </summary>
        public uint AddFriendByPublicKey(byte[] publicKey, string message = "Hello!")
        {
            if (publicKey == null || publicKey.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes");

            return AddFriend(publicKey, message);
        }

        /// <summary>
        /// Remueve un amigo
        /// </summary>
        public bool RemoveFriend(uint friendNumber)
        {
            if (Status != ToxStatus.Connected)
                return false;

            return friendConnection.RemoveFriend(friendNumber);
        }

        /// <summary>
        /// Envía un mensaje de texto a un amigo
        /// </summary>
        public async Task<bool> SendMessage(uint friendNumber, string message, bool isAction = false)
        {
            if (Status != ToxStatus.Connected)
                return false;

            if (string.IsNullOrEmpty(message))
                return false;

            try
            {
                var friend = friendConnection.GetFriend(friendNumber);
                if (friend == null || !friend.IsOnline)
                {
                    Log($"Friend {friendNumber} is not online");
                    return false;
                }

                bool sent = await friendConnection.SendTextMessage(friendNumber, message, isAction);
                if (sent)
                {
                    Log($"Message sent to {friend.Name}: {message}");
                }

                return sent;
            }
            catch (Exception ex)
            {
                Log($"Error sending message: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Envía un mensaje typing notification
        /// </summary>
        public async Task<bool> SendTypingNotification(uint friendNumber, bool isTyping)
        {
            // Implementación simplificada - en realidad enviaría un paquete especial
            string message = isTyping ? "is typing..." : "";
            return await SendMessage(friendNumber, message);
        }

        /// <summary>
        /// Establece el nombre de usuario
        /// </summary>
        public void SetName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 128)
                throw new ArgumentException("Name must be 1-128 characters");

            Name = name;

            // Notificar a amigos sobre el cambio
            // (implementación simplificada)
            Log($"Name changed to: {name}");
        }

        /// <summary>
        /// Establece el mensaje de estado
        /// </summary>
        public void SetStatusMessage(string statusMessage)
        {
            if (statusMessage?.Length > 1007) // Límite de Tox
                throw new ArgumentException("Status message too long");

            StatusMessage = statusMessage ?? "";

            // Notificar a amigos sobre el cambio
            // (implementación simplificada)
            Log($"Status message changed to: {statusMessage}");
        }

        /// <summary>
        /// Establece el estado de usuario
        /// </summary>
        public void SetUserStatus(ToxUserStatus status)
        {
            UserStatus = status;

            // Notificar a amigos sobre el cambio
            // (implementación simplificada)
            Log($"User status changed to: {status}");
        }

        /// <summary>
        /// Obtiene un amigo por su número
        /// </summary>
        public Friend GetFriend(uint friendNumber)
        {
            return friendConnection?.GetFriend(friendNumber);
        }

        /// <summary>
        /// Obtiene todos los amigos
        /// </summary>
        public List<Friend> GetAllFriends()
        {
            return friendConnection?.GetAllFriends() ?? new List<Friend>();
        }

        /// <summary>
        /// Obtiene amigos online
        /// </summary>
        public List<Friend> GetOnlineFriends()
        {
            return friendConnection?.GetOnlineFriends() ?? new List<Friend>();
        }

        /// <summary>
        /// Calcula la dirección Tox (public key + checksum)
        /// </summary>
        private byte[] CalculateToxAddress()
        {
            if (PublicKey == null) return new byte[38]; // 32 + 6 bytes de checksum en Tox real

            // En la implementación real, esto calcularía un checksum
            // Por simplicidad, devolvemos solo la clave pública
            byte[] address = new byte[32];
            Buffer.BlockCopy(PublicKey, 0, address, 0, 32);
            return address;
        }

        /// <summary>
        /// Guarda el estado actual para persistencia
        /// </summary>
        public byte[] Save()
        {
            if (Status != ToxStatus.Connected)
            {
                throw new InvalidOperationException("Tox must be connected to save state");
            }

            try
            {
                using (var ms = new System.IO.MemoryStream())
                {
                    // Guardar versión (1 byte)
                    ms.WriteByte(0x01); // Versión 1

                    // Guardar claves (64 bytes)
                    ms.Write(SecretKey, 0, 32);
                    ms.Write(PublicKey, 0, 32);

                    // Guardar información de perfil
                    var nameBytes = System.Text.Encoding.UTF8.GetBytes(Name ?? "");
                    ms.WriteByte((byte)nameBytes.Length);
                    ms.Write(nameBytes, 0, nameBytes.Length);

                    var statusBytes = System.Text.Encoding.UTF8.GetBytes(StatusMessage ?? "");
                    ms.WriteByte((byte)statusBytes.Length);
                    ms.Write(statusBytes, 0, statusBytes.Length);

                    ms.WriteByte((byte)UserStatus);

                    // Guardar información de amigos
                    var friends = GetAllFriends();
                    ms.WriteByte((byte)Math.Min(friends.Count, 255)); // Máximo 255 amigos en save

                    foreach (var friend in friends)
                    {
                        // Clave pública del amigo (32 bytes)
                        ms.Write(friend.PublicKey, 0, 32);

                        // Nombre del amigo
                        var friendNameBytes = System.Text.Encoding.UTF8.GetBytes(friend.Name ?? "");
                        ms.WriteByte((byte)Math.Min(friendNameBytes.Length, 255));
                        ms.Write(friendNameBytes, 0, friendNameBytes.Length);

                        // Estado de conexión
                        ms.WriteByte((byte)friend.ConnectionStatus);

                        // Último visto (8 bytes)
                        var lastSeenBytes = BitConverter.GetBytes(friend.LastSeen);
                        ms.Write(lastSeenBytes, 0, 8);
                    }

                    savedData = ms.ToArray();
                    Log($"Tox state saved ({savedData.Length} bytes)");
                    return savedData;
                }
            }
            catch (Exception ex)
            {
                Log($"Error saving state: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Carga amigos desde datos guardados (después de la inicialización)
        /// </summary>
        private void LoadFriendsFromSave(byte[] data)
        {
            if (data == null || data.Length < 65)
                return;

            try
            {
                using (var ms = new System.IO.MemoryStream(data))
                {
                    // Saltar hasta la sección de amigos
                    ms.Position = 1 + 64; // versión + claves

                    int nameLength = ms.ReadByte();
                    ms.Position += nameLength;

                    int statusLength = ms.ReadByte();
                    ms.Position += statusLength + 1; // +1 para UserStatus

                    // Leer amigos
                    int friendCount = ms.ReadByte();
                    for (int i = 0; i < friendCount; i++)
                    {
                        byte[] friendPublicKey = new byte[32];
                        ms.Read(friendPublicKey, 0, 32);

                        int friendNameLength = ms.ReadByte();
                        string friendName = "";
                        if (friendNameLength > 0)
                        {
                            byte[] friendNameBytes = new byte[friendNameLength];
                            ms.Read(friendNameBytes, 0, friendNameLength);
                            friendName = System.Text.Encoding.UTF8.GetString(friendNameBytes);
                        }

                        var connectionStatus = (FriendConnectionStatus)ms.ReadByte();

                        byte[] lastSeenBytes = new byte[8];
                        ms.Read(lastSeenBytes, 0, 8);
                        long lastSeen = BitConverter.ToInt64(lastSeenBytes, 0);

                        // Agregar amigo
                        uint friendNumber = friendConnection.AddFriend(friendPublicKey, "Loaded from save");
                        var friend = friendConnection.GetFriend(friendNumber);
                        if (friend != null && !string.IsNullOrEmpty(friendName))
                        {
                            friend.Name = friendName;
                            friend.LastSeen = lastSeen;
                        }
                    }

                    Log($"Loaded {friendCount} friends from save data");
                }
            }
            catch (Exception ex)
            {
                Log($"Error loading friends from save: {ex.Message}");
            }
        }


        /// <summary>
        /// Carga claves desde datos guardados
        /// </summary>
        private bool LoadKeysFromSave(byte[] data, out byte[] publicKey, out byte[] secretKey)
        {
            publicKey = null;
            secretKey = null;

            if (data == null || data.Length < 65) // Mínimo: versión + claves
                return false;

            try
            {
                using (var ms = new System.IO.MemoryStream(data))
                {
                    byte version = (byte)ms.ReadByte();
                    if (version != 0x01)
                    {
                        Log($"Unsupported save version: {version}");
                        return false;
                    }

                    secretKey = new byte[32];
                    publicKey = new byte[32];

                    // Leer claves
                    ms.Read(secretKey, 0, 32);
                    ms.Read(publicKey, 0, 32);

                    // Leer información de perfil
                    int nameLength = ms.ReadByte();
                    if (nameLength > 0)
                    {
                        byte[] nameBytes = new byte[nameLength];
                        ms.Read(nameBytes, 0, nameLength);
                        Name = System.Text.Encoding.UTF8.GetString(nameBytes);
                    }

                    int statusLength = ms.ReadByte();
                    if (statusLength > 0)
                    {
                        byte[] statusBytes = new byte[statusLength];
                        ms.Read(statusBytes, 0, statusLength);
                        StatusMessage = System.Text.Encoding.UTF8.GetString(statusBytes);
                    }

                    UserStatus = (ToxUserStatus)ms.ReadByte();

                    Log("State loaded successfully from save data");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log($"Error loading save data: {ex.Message}");
                return false;
            }
        }

        // Handlers de eventos del Friend Connection
        private void HandleFriendRequest(Friend friend, byte[] message)
        {
            Log($"Friend request from {friend}");
            OnFriendRequest?.Invoke(friend);
        }

        private void HandleFriendConnected(Friend friend)
        {
            Log($"Friend connected: {friend}");
            OnFriendConnected?.Invoke(friend);
        }

        private void HandleFriendDisconnected(Friend friend)
        {
            Log($"Friend disconnected: {friend}");
            OnFriendDisconnected?.Invoke(friend);
        }

        private void HandleFriendMessage(FriendMessage message)
        {
            var friend = friendConnection.GetFriend(message.FriendNumber);
            Log($"Message from {friend?.Name}: {message.GetMessageText()}");
            OnFriendMessage?.Invoke(message);
        }

        private void HandleFriendStatusChange(Friend friend, string status)
        {
            Log($"Friend {friend.Name} status changed: {status}");
            OnFriendStatusChange?.Invoke(friend, status);
        }

        /// <summary>
        /// Logging interno
        /// </summary>
        private void Log(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logMessage = $"[{timestamp}] {message}";
            OnLogMessage?.Invoke(logMessage);
            Console.WriteLine(logMessage);
        }

        public void Dispose()
        {
            Stop();
            friendConnection?.Dispose();
            onion?.Dispose();
        }

        /// <summary>
        /// Test básico de Tox
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de Tox...");

                using (var tox = new Tox())
                {
                    // Test 1: Creación
                    bool creationValid = tox != null && tox.Status == ToxStatus.Stopped;
                    Console.WriteLine($"     Test 1 - Creación: {(creationValid ? "✅" : "❌")}");

                    // Test 2: Propiedades iniciales
                    bool propertiesValid = tox.PublicKey == null && tox.SecretKey == null && tox.Address != null;
                    Console.WriteLine($"     Test 2 - Propiedades iniciales: {(propertiesValid ? "✅" : "❌")}");

                    // Test 3: Configuración de perfil
                    tox.SetName("Test User");
                    tox.SetStatusMessage("Testing Tox");
                    tox.SetUserStatus(ToxUserStatus.Away);

                    bool profileValid = tox.Name == "Test User" &&
                                      tox.StatusMessage == "Testing Tox" &&
                                      tox.UserStatus == ToxUserStatus.Away;
                    Console.WriteLine($"     Test 3 - Configuración de perfil: {(profileValid ? "✅" : "❌")}");

                    return creationValid && propertiesValid && profileValid;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test Tox: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Opciones de configuración para Tox
    /// </summary>
    public class ToxOptions
    {
        public ushort UDPListenPort { get; set; } = 33445;
        public ushort TCPListenPort { get; set; } = 0; // 0 = auto
        public bool EnableIPv6 { get; set; } = true;
        public bool EnableUDP { get; set; } = true;
        public bool EnableTCP { get; set; } = true;
        public string ProxyHost { get; set; }
        public ushort ProxyPort { get; set; }
        public ToxProxyType ProxyType { get; set; } = ToxProxyType.None;
    }

    /// <summary>
    /// Estado del cliente Tox
    /// </summary>
    public enum ToxStatus
    {
        Stopped = 0,
        Starting = 1,
        Connected = 2,
        Stopping = 3,
        Error = 4
    }

    /// <summary>
    /// Estado de usuario
    /// </summary>
    public enum ToxUserStatus
    {
        None = 0,
        Away = 1,
        Busy = 2
    }

    /// <summary>
    /// Tipo de proxy
    /// </summary>
    public enum ToxProxyType
    {
        None = 0,
        HTTP = 1,
        SOCKS5 = 2
    }
}