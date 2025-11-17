using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Estado de conexión con un amigo
    /// </summary>
    public enum FriendConnectionStatus
    {
        None = 0,
        Connecting = 1,
        Connected = 2,
        Disconnected = 3,
        Error = 4
    }

    /// <summary>
    /// Información de un amigo en la red Tox
    /// </summary>
    public class Friend
    {
        public byte[] PublicKey { get; set; } // 32 bytes
        public string Name { get; set; }
        public string StatusMessage { get; set; }
        public FriendConnectionStatus ConnectionStatus { get; set; }
        public IPPort DirectAddress { get; set; }
        public List<IPPort> RelayAddresses { get; set; }
        public long LastSeen { get; set; }
        public bool IsOnline => ConnectionStatus == FriendConnectionStatus.Connected;
        public uint FriendNumber { get; set; }

        public Friend(byte[] publicKey)
        {
            PublicKey = new byte[32];
            Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            ConnectionStatus = FriendConnectionStatus.None;
            RelayAddresses = new List<IPPort>();
            LastSeen = DateTime.UtcNow.Ticks;
        }

        public override string ToString()
        {
            return $"{Name ?? "Unknown"} [PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...] - {ConnectionStatus}";
        }
    }

    /// <summary>
    /// Mensaje entre amigos
    /// </summary>
    public class FriendMessage
    {
        public uint FriendNumber { get; set; }
        public byte[] Message { get; set; }
        public long Timestamp { get; set; }
        public bool IsAction { get; set; } // /me actions

        public FriendMessage(uint friendNumber, byte[] message)
        {
            FriendNumber = friendNumber;
            Message = message;
            Timestamp = DateTime.UtcNow.Ticks;
        }

        public string GetMessageText()
        {
            return System.Text.Encoding.UTF8.GetString(Message);
        }
    }

    /// <summary>
    /// Gestión de conexiones con amigos - integra DHT, Onion y TCP
    /// </summary>
    public class FriendConnection : IDisposable
    {
        private const int FRIEND_REQUEST_TIMEOUT = 30000; // 30 segundos
        private const int FRIEND_PING_INTERVAL = 60000; // 60 segundos
        private const int MAX_FRIENDS = 1000;

        private DHT dht;
        private Onion onion;
        private TCPClient tcpClient;
        private TCPServer tcpServer;

        private Dictionary<uint, Friend> friends;
        private Dictionary<byte[], uint> publicKeyToFriendNumber;
        private uint nextFriendNumber;

        private Timer pingTimer;
        private object friendsLock = new object();

        public int FriendCount => friends.Count;
        public int OnlineFriends => GetOnlineFriends().Count;
        public bool IsRunning { get; private set; }

        // Eventos
        public event Action<Friend> OnFriendConnected;
        public event Action<Friend> OnFriendDisconnected;
        public event Action<FriendMessage> OnFriendMessage;
        public event Action<Friend, string> OnFriendStatusChange;
        public event Action<Friend, byte[]> OnFriendRequest;

        public FriendConnection(DHT dhtInstance, Onion onionInstance, ushort tcpPort = 0)
        {
            dht = dhtInstance ?? throw new ArgumentNullException(nameof(dhtInstance));
            onion = onionInstance ?? throw new ArgumentNullException(nameof(onionInstance));

            friends = new Dictionary<uint, Friend>();
            publicKeyToFriendNumber = new Dictionary<byte[], uint>(new ByteArrayComparer());
            nextFriendNumber = 0;

            // Inicializar cliente TCP
            tcpClient = new TCPClient();
            tcpClient.OnDataReceived += HandleTCPData;
            tcpClient.OnConnected += HandleTCPConnected;
            tcpClient.OnDisconnected += HandleTCPDisconnected;

            // Inicializar servidor TCP
            tcpServer = new TCPServer();
            tcpServer.OnClientConnected += HandleTCPClientConnected;
            tcpServer.OnClientDataReceived += HandleTCPClientData;
            tcpServer.OnClientDisconnected += HandleTCPClientDisconnected;

            IsRunning = false;
        }

        /// <summary>
        /// Inicia el servicio de conexiones con amigos
        /// </summary>
        public async Task<bool> StartAsync()
        {
            if (IsRunning) return true;

            try
            {
                // Iniciar servidor TCP
                bool serverStarted = await tcpServer.StartAsync(0);
                if (!serverStarted) return false;

                IsRunning = true;

                // Iniciar timer de ping
                pingTimer = new Timer(PingFriends, null, 0, FRIEND_PING_INTERVAL);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting friend connection: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Detiene el servicio de conexiones con amigos
        /// </summary>
        public void Stop()
        {
            IsRunning = false;
            pingTimer?.Dispose();
            pingTimer = null;

            tcpServer.Stop();
            tcpClient.Disconnect();
        }

        /// <summary>
        /// Agrega un amigo por su clave pública
        /// </summary>
        public uint AddFriend(byte[] publicKey, string message = "Hello!")
        {
            if (publicKey == null || publicKey.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes");

            lock (friendsLock)
            {
                // Verificar si el amigo ya existe
                if (publicKeyToFriendNumber.ContainsKey(publicKey))
                {
                    return publicKeyToFriendNumber[publicKey];
                }

                if (friends.Count >= MAX_FRIENDS)
                    throw new InvalidOperationException("Maximum friends limit reached");

                uint friendNumber = nextFriendNumber++;
                var friend = new Friend(publicKey)
                {
                    FriendNumber = friendNumber,
                    Name = $"Friend_{friendNumber}",
                    ConnectionStatus = FriendConnectionStatus.Connecting
                };

                friends[friendNumber] = friend;
                publicKeyToFriendNumber[publicKey] = friendNumber;

                // Intentar conectar inmediatamente
                Task.Run(() => ConnectToFriend(friend, message));

                return friendNumber;
            }
        }

        /// <summary>
        /// Remueve un amigo
        /// </summary>
        public bool RemoveFriend(uint friendNumber)
        {
            lock (friendsLock)
            {
                if (friends.TryGetValue(friendNumber, out Friend friend))
                {
                    friends.Remove(friendNumber);
                    publicKeyToFriendNumber.Remove(friend.PublicKey);

                    if (friend.IsOnline)
                    {
                        OnFriendDisconnected?.Invoke(friend);
                    }

                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Obtiene un amigo por su número
        /// </summary>
        public Friend GetFriend(uint friendNumber)
        {
            lock (friendsLock)
            {
                return friends.TryGetValue(friendNumber, out Friend friend) ? friend : null;
            }
        }

        /// <summary>
        /// Obtiene un amigo por su clave pública
        /// </summary>
        public Friend GetFriendByPublicKey(byte[] publicKey)
        {
            lock (friendsLock)
            {
                return publicKeyToFriendNumber.TryGetValue(publicKey, out uint friendNumber)
                    ? friends[friendNumber]
                    : null;
            }
        }

        /// <summary>
        /// Intenta conectar con un amigo usando múltiples métodos
        /// </summary>
        private async Task ConnectToFriend(Friend friend, string message)
        {
            try
            {
                Console.WriteLine($"Attempting to connect to friend {friend}");

                // Método 1: Buscar en DHT
                var closestNodes = dht.FindClosestNodes(friend.PublicKey);
                foreach (var node in closestNodes)
                {
                    if (CryptoVerify.Verify32(node.PublicKey, friend.PublicKey))
                    {
                        friend.DirectAddress = node.IPPort;
                        break;
                    }
                }

                // Método 2: Usar Onion Routing si no hay dirección directa
                if (friend.DirectAddress.IP.Data == null && onion.AvailableNodes > 0)
                {
                    await ConnectViaOnion(friend, message);
                }
                // Método 3: Conexión TCP directa
                else if (friend.DirectAddress.IP.Data != null)
                {
                    await ConnectViaTCP(friend, message);
                }

                // Actualizar estado
                if (friend.ConnectionStatus != FriendConnectionStatus.Connected)
                {
                    friend.ConnectionStatus = FriendConnectionStatus.Error;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to friend {friend}: {ex.Message}");
                friend.ConnectionStatus = FriendConnectionStatus.Error;
            }
        }

        /// <summary>
        /// Conecta a un amigo via Onion Routing
        /// </summary>
        private async Task ConnectViaOnion(Friend friend, string message)
        {
            try
            {
                var path = onion.CreateOnionPath();
                var connectPacket = CreateFriendRequestPacket(message);
                var onionPacket = onion.Encapsulate(connectPacket, path);

                // Enviar solicitud de amistad via onion
                bool sent = onion.SendOnionPacket(onionPacket, new IPPort(IPAddress.Any, 0));
                if (sent)
                {
                    friend.ConnectionStatus = FriendConnectionStatus.Connecting;
                    Console.WriteLine($"Friend request sent to {friend} via onion routing");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in onion connection to {friend}: {ex.Message}");
            }
        }

        /// <summary>
        /// Conecta a un amigo via TCP directo
        /// </summary>
        private async Task ConnectViaTCP(Friend friend, string message)
        {
            try
            {
                if (await tcpClient.ConnectAsync(friend.DirectAddress))
                {
                    // Enviar solicitud de amistad
                    var requestPacket = CreateFriendRequestPacket(message);
                    await tcpClient.SendAsync(requestPacket);

                    friend.ConnectionStatus = FriendConnectionStatus.Connecting;
                    Console.WriteLine($"Friend request sent to {friend} via TCP");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in TCP connection to {friend}: {ex.Message}");
            }
        }

        /// <summary>
        /// Crea un paquete de solicitud de amistad
        /// </summary>
        private byte[] CreateFriendRequestPacket(string message)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                // Tipo: Friend request (0x10)
                ms.WriteByte(0x10);

                // Nuestra clave pública
                ms.Write(dht.SelfPublicKey, 0, 32);

                // Mensaje
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
                ms.WriteByte((byte)messageBytes.Length);
                ms.Write(messageBytes, 0, messageBytes.Length);

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Envía un mensaje a un amigo
        /// </summary>
        public async Task<bool> SendMessage(uint friendNumber, byte[] message, bool isAction = false)
        {
            var friend = GetFriend(friendNumber);
            if (friend == null || !friend.IsOnline)
                return false;

            try
            {
                var messagePacket = CreateMessagePacket(message, isAction);

                if (friend.DirectAddress.IP.Data != null && tcpClient.IsConnected)
                {
                    return await tcpClient.SendAsync(messagePacket);
                }
                else if (onion.AvailableNodes > 0)
                {
                    var path = onion.CreateOnionPath();
                    var onionPacket = onion.Encapsulate(messagePacket, path);
                    return onion.SendOnionPacket(onionPacket, friend.DirectAddress);
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending message to friend {friendNumber}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Envía un mensaje de texto a un amigo
        /// </summary>
        public async Task<bool> SendTextMessage(uint friendNumber, string text, bool isAction = false)
        {
            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(text);
            return await SendMessage(friendNumber, messageBytes, isAction);
        }

        /// <summary>
        /// Crea un paquete de mensaje
        /// </summary>
        private byte[] CreateMessagePacket(byte[] message, bool isAction)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                // Tipo: Message (0x20) o Action (0x21)
                ms.WriteByte(isAction ? (byte)0x21 : (byte)0x20);

                // Longitud del mensaje (2 bytes)
                ms.WriteByte((byte)((message.Length >> 8) & 0xFF));
                ms.WriteByte((byte)(message.Length & 0xFF));

                // Mensaje
                ms.Write(message, 0, message.Length);

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Maneja datos recibidos via TCP
        /// </summary>
        private void HandleTCPData(byte[] data)
        {
            if (data == null || data.Length == 0) return;

            try
            {
                byte packetType = data[0];
                ProcessFriendPacket(packetType, data, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling TCP data: {ex.Message}");
            }
        }

        /// <summary>
        /// Maneja datos recibidos de clientes TCP
        /// </summary>
        private void HandleTCPClientData(TCPClientConnection client, byte[] data)
        {
            if (data == null || data.Length == 0) return;

            try
            {
                byte packetType = data[0];
                ProcessFriendPacket(packetType, data, client);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling TCP client data: {ex.Message}");
            }
        }

        /// <summary>
        /// Procesa paquetes de amigos
        /// </summary>
        private void ProcessFriendPacket(byte packetType, byte[] data, TCPClientConnection client)
        {
            switch (packetType)
            {
                case 0x10: // Friend request
                    HandleFriendRequest(data, client);
                    break;
                case 0x11: // Friend response
                    HandleFriendResponse(data);
                    break;
                case 0x20: // Message
                case 0x21: // Action
                    HandleFriendMessage(data, packetType == 0x21);
                    break;
                case 0x30: // Ping
                    HandlePing(data);
                    break;
                case 0x31: // Pong
                    HandlePong(data);
                    break;
            }
        }

        /// <summary>
        /// Maneja solicitud de amistad
        /// </summary>
        private void HandleFriendRequest(byte[] data, TCPClientConnection client)
        {
            if (data.Length < 34) return;

            try
            {
                byte[] friendPublicKey = new byte[32];
                Buffer.BlockCopy(data, 1, friendPublicKey, 0, 32);

                int messageLength = data[33];
                string message = System.Text.Encoding.UTF8.GetString(data, 34, messageLength);

                var friend = GetFriendByPublicKey(friendPublicKey);
                if (friend == null)
                {
                    // Nuevo amigo - agregar
                    uint friendNumber = AddFriend(friendPublicKey);
                    friend = GetFriend(friendNumber);

                    if (client != null)
                    {
                        friend.DirectAddress = client.RemoteEndPoint;
                    }

                    OnFriendRequest?.Invoke(friend, System.Text.Encoding.UTF8.GetBytes(message));
                }

                // Enviar respuesta de amistad
                SendFriendResponse(friend);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling friend request: {ex.Message}");
            }
        }

        /// <summary>
        /// Maneja respuesta de amistad
        /// </summary>
        private void HandleFriendResponse(byte[] data)
        {
            if (data.Length < 33) return;

            byte[] friendPublicKey = new byte[32];
            Buffer.BlockCopy(data, 1, friendPublicKey, 0, 32);

            var friend = GetFriendByPublicKey(friendPublicKey);
            if (friend != null)
            {
                friend.ConnectionStatus = FriendConnectionStatus.Connected;
                friend.LastSeen = DateTime.UtcNow.Ticks;

                OnFriendConnected?.Invoke(friend);
                Console.WriteLine($"Friend connected: {friend}");
            }
        }

        /// <summary>
        /// Maneja mensaje de amigo
        /// </summary>
        private void HandleFriendMessage(byte[] data, bool isAction)
        {
            if (data.Length < 4) return;

            // Asumimos que el mensaje viene de un amigo conocido
            // En implementación real, verificaríamos la clave pública
            ushort messageLength = (ushort)((data[1] << 8) | data[2]);
            if (data.Length < 3 + messageLength) return;

            byte[] messageData = new byte[messageLength];
            Buffer.BlockCopy(data, 3, messageData, 0, messageLength);

            // Por simplicidad, usamos friend number 0 para mensajes entrantes
            // En implementación real, buscaríamos el friend number por la conexión
            var message = new FriendMessage(0, messageData) { IsAction = isAction };
            OnFriendMessage?.Invoke(message);
        }

        /// <summary>
        /// Envía respuesta de amistad
        /// </summary>
        private async void SendFriendResponse(Friend friend)
        {
            try
            {
                using (var ms = new System.IO.MemoryStream())
                {
                    // Tipo: Friend response (0x11)
                    ms.WriteByte(0x11);

                    // Nuestra clave pública
                    ms.Write(dht.SelfPublicKey, 0, 32);

                    byte[] responsePacket = ms.ToArray();

                    if (friend.DirectAddress.IP.Data != null)
                    {
                        await tcpClient.SendAsync(responsePacket);
                    }
                    else if (onion.AvailableNodes > 0)
                    {
                        var path = onion.CreateOnionPath();
                        var onionPacket = onion.Encapsulate(responsePacket, path);
                        onion.SendOnionPacket(onionPacket, friend.DirectAddress);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending friend response: {ex.Message}");
            }
        }

        /// <summary>
        /// Maneja eventos de conexión TCP
        /// </summary>
        private void HandleTCPConnected()
        {
            Console.WriteLine("TCP connection established");
        }

        private void HandleTCPDisconnected()
        {
            Console.WriteLine("TCP connection lost");
        }

        private void HandleTCPClientConnected(TCPClientConnection client)
        {
            Console.WriteLine($"TCP client connected: {client.RemoteEndPoint}");
        }

        private void HandleTCPClientDisconnected(TCPClientConnection client)
        {
            Console.WriteLine($"TCP client disconnected: {client.RemoteEndPoint}");
        }

        /// <summary>
        /// Hace ping a los amigos para mantener conexiones activas
        /// </summary>
        private void PingFriends(object state)
        {
            if (!IsRunning) return;

            lock (friendsLock)
            {
                foreach (var friend in friends.Values)
                {
                    if (friend.IsOnline)
                    {
                        // Enviar ping para mantener conexión activa
                        SendPing(friend);
                    }
                    else if (friend.ConnectionStatus == FriendConnectionStatus.Connecting)
                    {
                        // Reintentar conexión
                        Task.Run(() => ConnectToFriend(friend, "Ping"));
                    }
                }
            }
        }

        private void SendPing(Friend friend)
        {
            // Implementación simplificada de ping
            try
            {
                byte[] pingPacket = new byte[] { 0x30 }; // Ping packet
                if (friend.DirectAddress.IP.Data != null && tcpClient.IsConnected)
                {
                    tcpClient.SendAsync(pingPacket);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending ping to {friend}: {ex.Message}");
            }
        }

        private void HandlePing(byte[] data)
        {
            // Responder con pong
            byte[] pongPacket = new byte[] { 0x31 }; // Pong packet
            tcpClient.SendAsync(pongPacket);
        }

        private void HandlePong(byte[] data)
        {
            // Actualizar último visto del amigo
            // (implementación simplificada)
        }

        /// <summary>
        /// Obtiene lista de amigos online
        /// </summary>
        public List<Friend> GetOnlineFriends()
        {
            lock (friendsLock)
            {
                var onlineFriends = new List<Friend>();
                foreach (var friend in friends.Values)
                {
                    if (friend.IsOnline)
                    {
                        onlineFriends.Add(friend);
                    }
                }
                return onlineFriends;
            }
        }

        /// <summary>
        /// Obtiene lista de todos los amigos
        /// </summary>
        public List<Friend> GetAllFriends()
        {
            lock (friendsLock)
            {
                return new List<Friend>(friends.Values);
            }
        }

        public void Dispose()
        {
            Stop();
            tcpClient?.Dispose();
            tcpServer?.Dispose();
            pingTimer?.Dispose();
        }

        /// <summary>
        /// Comparador de arrays de bytes para Dictionary
        /// </summary>
        private class ByteArrayComparer : IEqualityComparer<byte[]>
        {
            public bool Equals(byte[] x, byte[] y)
            {
                if (x == null || y == null) return x == y;
                if (x.Length != y.Length) return false;
                for (int i = 0; i < x.Length; i++)
                {
                    if (x[i] != y[i]) return false;
                }
                return true;
            }

            public int GetHashCode(byte[] obj)
            {
                if (obj == null) return 0;
                int hash = 17;
                foreach (byte b in obj)
                {
                    hash = hash * 31 + b;
                }
                return hash;
            }
        }

        /// <summary>
        /// Test básico de Friend Connection
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de FriendConnection...");

                // Crear componentes base
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                using (var friendConn = new FriendConnection(dht, onion))
                {
                    // Test 1: Creación
                    bool creationValid = friendConn != null && friendConn.FriendCount == 0;
                    Console.WriteLine($"     Test 1 - Creación: {(creationValid ? "✅" : "❌")}");

                    // Test 2: Inicio
                    bool startValid = friendConn.StartAsync().Wait(1000) && friendConn.IsRunning;
                    Console.WriteLine($"     Test 2 - Inicio: {(startValid ? "✅" : "❌")}");

                    // Test 3: Agregar amigo
                    var testPublicKey = RandomBytes.Generate(32);
                    uint friendNumber = friendConn.AddFriend(testPublicKey, "Test request");
                    bool addFriendValid = friendNumber != uint.MaxValue && friendConn.FriendCount == 1;
                    Console.WriteLine($"     Test 3 - Agregar amigo: {(addFriendValid ? "✅" : "❌")}");

                    // Test 4: Obtener amigo
                    var friend = friendConn.GetFriend(friendNumber);
                    bool getFriendValid = friend != null && CryptoVerify.Verify32(friend.PublicKey, testPublicKey);
                    Console.WriteLine($"     Test 4 - Obtener amigo: {(getFriendValid ? "✅" : "❌")}");

                    // Test 5: Remover amigo
                    bool removeValid = friendConn.RemoveFriend(friendNumber) && friendConn.FriendCount == 0;
                    Console.WriteLine($"     Test 5 - Remover amigo: {(removeValid ? "✅" : "❌")}");

                    friendConn.Stop();
                    return creationValid && startValid && addFriendValid && getFriendValid && removeValid;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test FriendConnection: {ex.Message}");
                return false;
            }
        }
    }
}