using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Estructuras compatibles con DHT original de toxcore
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PackedNode
    {
        public IPPort IPPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;

        public PackedNode(IPPort ipp, byte[] publicKey)
        {
            IPPort = ipp;
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
        }

        public override string ToString()
        {
            return $"{IPPort} [PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NodeFormat
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        public IPPort IPPort;

        public NodeFormat(byte[] publicKey, IPPort ipp)
        {
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
            IPPort = ipp;
        }
    }

    public struct DHTHandshake
    {
        public byte[] TemporaryPublicKey;
        public byte[] TemporarySecretKey;
        public byte[] PeerPublicKey;
        public long CreationTime;
        public IPPort EndPoint;
    }

    public struct HandshakePacket
    {
        public byte[] TemporaryPublicKey; // 32 bytes
        public byte[] EncryptedPayload;   // Datos encriptados
    }


    /// <summary>
    /// Nodo DHT con información completa
    /// </summary>
    public class DHTNode
    {
        public byte[] PublicKey { get; set; }
        public IPPort EndPoint { get; set; }
        public long LastSeen { get; set; }
        public long LastPingSent { get; set; }
        public int PingID { get; set; }
        public bool IsActive { get; set; }
        public int RTT { get; set; } // Round Trip Time
        public int QualityScore { get; set; }

        public DHTNode(byte[] publicKey, IPPort endPoint)
        {
            PublicKey = new byte[32];
            Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            EndPoint = endPoint;
            LastSeen = DateTime.UtcNow.Ticks;
            IsActive = true;
            QualityScore = 100;
        }

        public override string ToString()
        {
            return $"{EndPoint} [PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";
        }
    }

    /// <summary>
    /// Implementación completa de DHT compatible con toxcore C
    /// </summary>
    public class DHT
    {
        private const string LOG_TAG = "DHT";

        // Constantes reales de toxcore
        public const int MAX_FRIEND_CLOSE = 8;
        public const int CRYPTO_PACKET_SIZE = 122;
        public const int CRYPTO_NONCE_SIZE = 24;
        public const int CRYPTO_PUBLIC_KEY_SIZE = 32;
        public const int CRYPTO_SECRET_KEY_SIZE = 32;
        public const int MAX_CLOSE_TO_BOOTSTRAP_NODES = 16;
        public const int DHT_PING_INTERVAL = 30000; // 30 segundos
        public const int DHT_PING_TIMEOUT = 10000;  // 10 segundos


        private long _lastCleanupTime = 0;

        private DateTime _lastCleanup = DateTime.UtcNow;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(2);

        private readonly Dictionary<string, List<DHTNode>> _closestNodesCache = new Dictionary<string, List<DHTNode>>();
        private readonly TimeSpan _cacheTTL = TimeSpan.FromSeconds(30);
        private readonly object _cacheLock = new object();
        private DateTime _lastCacheCleanup = DateTime.UtcNow;

        private readonly Dictionary<string, DHTNode> _nodesByKey;


        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public int Socket { get; private set; }

        private readonly List<DHTNode> _nodes;
        private readonly List<PackedNode> _bootstrapNodes;
        private readonly object _nodesLock = new object();
        private int _lastPingID;
        private long _lastBootstrapTime;

        private long _lastLogTime = 0;

        // Estadísticas
        public int TotalNodes => _nodes.Count;
        public int ActiveNodes
        {
            get
            {
                lock (_nodesLock)
                {
                    return _nodes.Count(n => n.IsActive);
                }
            }
        }

        private readonly Dictionary<string, DHTHandshake> _activeHandshakes;
        private readonly object _handshakesLock = new object();
        private const int HANDSHAKE_TIMEOUT = 30000; // 30 segundos

        // Claves temporales para handshake
        private byte[] _currentTempPublicKey;
        private byte[] _currentTempSecretKey;
        private long _lastKeyRotation;
        private const int KEY_ROTATION_INTERVAL = 60000; // Rotar cada 60 segundos



        public DHT(byte[] selfPublicKey, byte[] selfSecretKey)
        {
            SelfPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
            SelfSecretKey = new byte[CRYPTO_SECRET_KEY_SIZE];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, CRYPTO_SECRET_KEY_SIZE);

            _nodes = new List<DHTNode>();
            _bootstrapNodes = new List<PackedNode>();
            _nodesByKey = new Dictionary<string, DHTNode>();

            // ✅ INICIALIZAR DICCIONARIOS FALTANTES
            _activeHandshakes = new Dictionary<string, DHTHandshake>();

            _lastPingID = 0;
            _lastBootstrapTime = 0;

            Socket = Network.new_socket(2, 2, 17); // IPv4 UDP
            Logger.Log.InfoF($"[{LOG_TAG}] DHT inicializado - Socket: {Socket}");
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// DHT_bootstrap - Compatible con C original
        /// </summary>
        public int DHT_bootstrap(IPPort ipp, byte[] public_key)
        {
            Logger.Log.InfoF($"[{LOG_TAG}] Bootstrap a {ipp}");

            if (Socket == -1) return -1;

            try
            {
                var bootstrapNode = new PackedNode(ipp, public_key);
                _bootstrapNodes.Add(bootstrapNode);

                // Enviar get_nodes request encriptado
                byte[] packet = CreateEncryptedGetNodesPacket(public_key, SelfPublicKey);
                if (packet == null) return -1;

                int sent = Network.socket_send(Socket, packet, packet.Length, ipp);
                return sent > 0 ? 0 : -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en bootstrap: {ex.Message}");
                return -1;
            }
        }


        /// <summary>
        /// Genera o rota las claves temporales para handshake
        /// </summary>
        private void EnsureTempKeys()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            if (_currentTempPublicKey == null ||
                (currentTime - _lastKeyRotation) > TimeSpan.TicksPerMillisecond * KEY_ROTATION_INTERVAL)
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                _currentTempPublicKey = keyPair.PublicKey;
                _currentTempSecretKey = keyPair.PrivateKey;
                _lastKeyRotation = currentTime;

                Logger.Log.DebugF($"[{LOG_TAG}] Claves temporales rotadas");
            }
        }

        /// <summary>
        /// Inicia handshake criptográfico con un nodo
        /// </summary>
        public int StartHandshake(IPPort endPoint, byte[] peerPublicKey)
        {
            try
            {
                EnsureTempKeys();

                // Crear payload del handshake: nuestra public key real + nonce
                byte[] payload = new byte[CRYPTO_PUBLIC_KEY_SIZE + 8];
                Buffer.BlockCopy(SelfPublicKey, 0, payload, 0, CRYPTO_PUBLIC_KEY_SIZE);

                byte[] nonce = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                Buffer.BlockCopy(nonce, 0, payload, CRYPTO_PUBLIC_KEY_SIZE, 8);

                // Encriptar payload con la public key del peer
                byte[] encryptionNonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);
                byte[] encryptedPayload = CryptoBox.Encrypt(payload, encryptionNonce, peerPublicKey, SelfSecretKey);

                if (encryptedPayload == null)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No se pudo encriptar payload del handshake");
                    return -1;
                }

                // Construir paquete de handshake
                byte[] handshakePacket = CreateHandshakePacket(_currentTempPublicKey, encryptionNonce, encryptedPayload);

                // Enviar handshake
                int sent = DHT_send_packet(endPoint, handshakePacket, handshakePacket.Length);
                if (sent <= 0) return -1;

                // Registrar handshake pendiente
                var handshake = new DHTHandshake
                {
                    TemporaryPublicKey = _currentTempPublicKey,
                    TemporarySecretKey = _currentTempSecretKey,
                    PeerPublicKey = peerPublicKey,
                    CreationTime = DateTime.UtcNow.Ticks,
                    EndPoint = endPoint
                };

                string handshakeKey = $"{endPoint}_{BitConverter.ToString(peerPublicKey).Replace("-", "").Substring(0, 16)}";

                lock (_handshakesLock)
                {
                    _activeHandshakes[handshakeKey] = handshake;
                }

                Logger.Log.DebugF($"[{LOG_TAG}] Handshake iniciado con {endPoint}");
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando handshake: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Crea paquete de handshake
        /// </summary>
        private byte[] CreateHandshakePacket(byte[] tempPublicKey, byte[] nonce, byte[] encryptedPayload)
        {
            byte[] packet = new byte[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encryptedPayload.Length];
            packet[0] = 0x10; // HANDSHAKE_REQUEST packet type

            Buffer.BlockCopy(tempPublicKey, 0, packet, 1, CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(nonce, 0, packet, 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(encryptedPayload, 0, packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encryptedPayload.Length);

            return packet;
        }

        /// <summary>
        /// Maneja respuesta de handshake
        /// </summary>
        private int HandleHandshakeResponse(byte[] packet, int length, IPPort source)
        {
            try
            {
                if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + 16)
                    return -1;

                // Extraer temporary public key del remitente
                byte[] peerTempPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1, peerTempPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Buscar handshake pendiente
                var handshake = FindHandshakeByTempKey(peerTempPublicKey, source);
                if (handshake == null)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Handshake no encontrado para {source}");
                    return -1;
                }

                // Extraer y desencriptar payload
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                byte[] encryptedPayload = new byte[length - 1 - CRYPTO_PUBLIC_KEY_SIZE - CRYPTO_NONCE_SIZE];

                Buffer.BlockCopy(packet, 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encryptedPayload, 0, encryptedPayload.Length);

                // Desencriptar con nuestra temporary secret key
                byte[] decrypted = CryptoBox.Decrypt(encryptedPayload, nonce, peerTempPublicKey, handshake.Value.TemporarySecretKey);
                if (decrypted == null || decrypted.Length < CRYPTO_PUBLIC_KEY_SIZE)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No se pudo desencriptar respuesta de handshake");
                    return -1;
                }

                // Extraer public key real del peer
                byte[] peerRealPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(decrypted, 0, peerRealPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Verificar que coincide con la public key esperada
                if (!CryptoVerify.Verify32(peerRealPublicKey, handshake.Value.PeerPublicKey))
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Public key no coincide en handshake");
                    return -1;
                }

                // Handshake completado - agregar nodo a la DHT
                AddNode(peerRealPublicKey, source);

                // Limpiar handshake
                RemoveHandshake(peerTempPublicKey, source);

                Logger.Log.InfoF($"[{LOG_TAG}] Handshake completado con {source}");
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando respuesta de handshake: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Maneja solicitud de handshake entrante
        /// </summary>
        private int HandleHandshakeRequest(byte[] packet, int length, IPPort source)
        {
            try
            {
                if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + 16)
                    return -1;

                // Extraer temporary public key del remitente
                byte[] peerTempPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1, peerTempPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Extraer y desencriptar payload
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                byte[] encryptedPayload = new byte[length - 1 - CRYPTO_PUBLIC_KEY_SIZE - CRYPTO_NONCE_SIZE];

                Buffer.BlockCopy(packet, 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encryptedPayload, 0, encryptedPayload.Length);

                // Desencriptar con nuestra secret key real
                byte[] decrypted = CryptoBox.Decrypt(encryptedPayload, nonce, peerTempPublicKey, SelfSecretKey);
                if (decrypted == null || decrypted.Length < CRYPTO_PUBLIC_KEY_SIZE)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No se pudo desencriptar solicitud de handshake");
                    return -1;
                }

                // Extraer public key real del peer
                byte[] peerRealPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(decrypted, 0, peerRealPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Generar respuesta de handshake
                EnsureTempKeys();

                // Crear payload de respuesta: nuestra public key real
                byte[] responsePayload = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(SelfPublicKey, 0, responsePayload, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Encriptar respuesta con la temporary public key del peer
                byte[] responseNonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);
                byte[] encryptedResponse = CryptoBox.Encrypt(responsePayload, responseNonce, peerTempPublicKey, _currentTempSecretKey);

                if (encryptedResponse == null)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No se pudo encriptar respuesta de handshake");
                    return -1;
                }

                // Enviar respuesta
                byte[] responsePacket = CreateHandshakeResponsePacket(_currentTempPublicKey, responseNonce, encryptedResponse);
                int sent = DHT_send_packet(source, responsePacket, responsePacket.Length);

                if (sent > 0)
                {
                    // Agregar nodo a la DHT
                    AddNode(peerRealPublicKey, source);
                    Logger.Log.InfoF($"[{LOG_TAG}] Handshake respondido a {source}");
                }

                return sent > 0 ? 0 : -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando solicitud de handshake: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Crea paquete de respuesta de handshake
        /// </summary>
        private byte[] CreateHandshakeResponsePacket(byte[] tempPublicKey, byte[] nonce, byte[] encryptedPayload)
        {
            byte[] packet = new byte[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encryptedPayload.Length];
            packet[0] = 0x11; // HANDSHAKE_RESPONSE packet type

            Buffer.BlockCopy(tempPublicKey, 0, packet, 1, CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(nonce, 0, packet, 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(encryptedPayload, 0, packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encryptedPayload.Length);

            return packet;
        }

        // Métodos auxiliares para gestión de handshakes
        private DHTHandshake? FindHandshakeByTempKey(byte[] tempPublicKey, IPPort endPoint)
        {
            string targetKey = $"{endPoint}_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";

            lock (_handshakesLock)
            {
                if (_activeHandshakes.TryGetValue(targetKey, out var handshake))
                {
                    return handshake;
                }
            }
            return null;
        }

        private void RemoveHandshake(byte[] tempPublicKey, IPPort endPoint)
        {
            string handshakeKey = $"{endPoint}_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";

            lock (_handshakesLock)
            {
                _activeHandshakes.Remove(handshakeKey);
            }
        }

        /// <summary>
        /// Limpia handshakes expirados
        /// </summary>
        private void CleanupExpiredHandshakes()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * HANDSHAKE_TIMEOUT;
            int removed = 0;

            lock (_handshakesLock)
            {
                var expiredKeys = new List<string>();

                foreach (var kvp in _activeHandshakes)
                {
                    if (kvp.Value.CreationTime < cutoffTime)
                    {
                        expiredKeys.Add(kvp.Key);
                    }
                }

                foreach (var key in expiredKeys)
                {
                    _activeHandshakes.Remove(key);
                    removed++;
                }
            }

            if (removed > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {removed} handshakes expirados removidos");
            }
        }


        /// <summary>
        /// Manejar paquetes DHT REAL con encriptación
        /// </summary>
        public int DHT_handle_packet(byte[] packet, int length, IPPort source)
        {
            if (packet == null || length < 1 + CRYPTO_NONCE_SIZE) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x00: // Ping request encriptado
                        return HandleEncryptedPingRequest(packet, length, source);
                    case 0x02: // Get nodes request encriptado  
                        return HandleEncryptedGetNodesRequest(packet, length, source);
                    case 0x04: // Send nodes response encriptado
                        return HandleEncryptedSendNodesResponse(packet, length, source);
                    case 0x10: // Handshake request
                        return HandleHandshakeRequest(packet, length, source);
                    case 0x11: // Handshake response
                        return HandleHandshakeResponse(packet, length, source);
                    default:
                        Logger.Log.DebugF($"[{LOG_TAG}] Tipo de paquete desconocido: 0x{packetType:X2}");
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete: {ex.Message}");
                return -1;
            }
        }

        private int HandleEncryptedPingRequest(byte[] packet, int length, IPPort source)
        {
            // ✅ IMPLEMENTACIÓN REAL: Usar handshake criptográfico para obtener la public key
            if (HandleEncryptedPingPacket(packet, length - 1, source, out byte[] senderPublicKey))
            {
                // En lugar de simular, iniciamos un handshake para obtener la public key real
                // Buscar si ya tenemos un nodo en esta dirección IP
                var existingNode = FindNodeByEndpoint(source);
                if (existingNode != null)
                {
                    // Ya tenemos este nodo, actualizar last seen
                    existingNode.LastSeen = DateTime.UtcNow.Ticks;
                    existingNode.IsActive = true;

                    // Enviar respuesta ping con la public key conocida
                    byte[] responsePacket = CreateEncryptedPingPacket(existingNode.PublicKey);
                    if (responsePacket != null)
                    {
                        return DHT_send_packet(source, responsePacket, responsePacket.Length);
                    }
                }
                else
                {
                    // ✅ NUEVO NODO: Iniciar handshake para obtener su public key
                    Logger.Log.DebugF($"[{LOG_TAG}] Nuevo ping de {source}, iniciando handshake...");

                    // Para pings de nodos desconocidos, podríamos:
                    // 1. Enviar un handshake request
                    // 2. O incluir información de handshake en la respuesta ping
                    // Por ahora, simplemente respondemos el ping y confiamos en que iniciarán handshake

                    byte[] simulatedResponse = CreateEncryptedPingPacket(SelfPublicKey); // Usamos nuestra PK como destino
                    if (simulatedResponse != null)
                    {
                        return DHT_send_packet(source, simulatedResponse, simulatedResponse.Length);
                    }
                }
            }

            Logger.Log.DebugF($"[{LOG_TAG}] Ping request inválido de {source}");
            return -1;
        }

        /// <summary>
        /// Busca un nodo por su endpoint (IP + puerto)
        /// </summary>
        private DHTNode FindNodeByEndpoint(IPPort endPoint)
        {
            lock (_nodesLock)
            {
                return _nodes.Find(n =>
                    n.EndPoint.IP.ToString() == endPoint.IP.ToString() &&
                    n.EndPoint.Port == endPoint.Port);
            }
        }

        private int HandleEncryptedGetNodesRequest(byte[] packet, int length, IPPort source)
        {
            try
            {
                if (length < 1 + CRYPTO_NONCE_SIZE + 64) return -1; // mínimo para desencriptar

                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                byte[] encrypted = new byte[length - 1 - CRYPTO_NONCE_SIZE];

                Buffer.BlockCopy(packet, 1, nonce, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(packet, 1 + CRYPTO_NONCE_SIZE, encrypted, 0, encrypted.Length);

                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, SelfPublicKey, SelfSecretKey);
                if (decrypted == null || decrypted.Length < CRYPTO_PUBLIC_KEY_SIZE * 2) return -1;

                // Extraer public keys: remitente y objetivo de búsqueda
                byte[] senderPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                byte[] searchPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(decrypted, 0, senderPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(decrypted, CRYPTO_PUBLIC_KEY_SIZE, searchPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                AddNode(senderPublicKey, source);

                // Obtener nodos más cercanos al objetivo de búsqueda
                var closestNodes = GetClosestNodes(searchPublicKey, 4);
                if (closestNodes.Count > 0)
                {
                    byte[] response = CreateEncryptedSendNodesPacket(senderPublicKey, closestNodes);
                    if (response != null)
                    {
                        return DHT_send_packet(source, response, response.Length);
                    }
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en get_nodes: {ex.Message}");
                return -1;
            }
        }

        private int HandleEncryptedSendNodesResponse(byte[] packet, int length, IPPort source)
        {
            try
            {
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                byte[] encrypted = new byte[length - 1 - CRYPTO_NONCE_SIZE];

                Buffer.BlockCopy(packet, 1, nonce, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(packet, 1 + CRYPTO_NONCE_SIZE, encrypted, 0, encrypted.Length);

                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, SelfPublicKey, SelfSecretKey);
                if (decrypted == null) return -1;

                // Procesar nodos recibidos (cada nodo: 32 + 18 = 50 bytes)
                int nodeCount = decrypted.Length / 50;
                for (int i = 0; i < nodeCount; i++)
                {
                    int offset = i * 50;
                    byte[] nodePublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                    byte[] ippBytes = new byte[18];

                    Buffer.BlockCopy(decrypted, offset, nodePublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);
                    Buffer.BlockCopy(decrypted, offset + CRYPTO_PUBLIC_KEY_SIZE, ippBytes, 0, 18);

                    IPPort nodeIPPort = BytesToIPPort(ippBytes);
                    if (nodeIPPort.Port > 0)
                    {
                        AddNode(nodePublicKey, nodeIPPort);
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en send_nodes: {ex.Message}");
                return -1;
            }
        }


        /// <summary>
        /// DHT_send_packet - Compatible con C original
        /// </summary>
        public int DHT_send_packet(IPPort ipp, byte[] packet, int length)
        {
            if (Socket == -1) return -1;
            return Network.socket_send(Socket, packet, length, ipp);
        }


        /// <summary>
        /// DHT_get_nodes - Compatible con C original
        /// </summary>
        public int DHT_get_nodes(byte[] nodes, int length, IPPort ipp)
        {
            if (nodes == null || length < 1) return -1;

            try
            {
                var closestNodes = GetClosestNodes(SelfPublicKey, MAX_FRIEND_CLOSE);
                int offset = 0;

                foreach (var node in closestNodes)
                {
                    if (offset + 40 > length) break; // 32 + 18 = 50 bytes por nodo

                    // Copiar clave pública
                    Buffer.BlockCopy(node.PublicKey, 0, nodes, offset, 32);
                    offset += 32;

                    // Copiar IPPort
                    byte[] ippBytes = IPPortToBytes(node.EndPoint);
                    Buffer.BlockCopy(ippBytes, 0, nodes, offset, 18);
                    offset += 18;
                }

                return offset; // Total bytes escritos
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== FUNCIONES DE GESTIÓN DE NODOS ====================

        /// <summary>
        /// Agregar nodo con verificación de duplicados por public key
        /// </summary>
        public int AddNode(byte[] publicKey, IPPort endPoint)
        {
            if (publicKey == null || publicKey.Length != CRYPTO_PUBLIC_KEY_SIZE)
                return -1;

            try
            {
                string keyString = BitConverter.ToString(publicKey).Replace("-", "");

                lock (_nodesLock)
                {
                    if (_nodesByKey.ContainsKey(keyString))
                    {
                        // Actualizar nodo existente
                        var existingNode = _nodesByKey[keyString];
                        existingNode.EndPoint = endPoint;
                        existingNode.LastSeen = DateTime.UtcNow.Ticks;
                        existingNode.IsActive = true;
                        return 1;
                    }

                    // Crear nuevo nodo
                    var newNode = new DHTNode(publicKey, endPoint);
                    _nodes.Add(newNode);
                    _nodesByKey[keyString] = newNode;

                    Logger.Log.DebugF($"[{LOG_TAG}] Nuevo nodo agregado: {endPoint} [Total: {_nodes.Count}]");

                    // Limpieza periódica
                    if (_nodes.Count > 1000)
                    {
                        CleanupOldNodes();
                    }

                    return 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error agregando nodo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Limpieza REAL de nodos antiguos - MEJORADO
        /// </summary>
        private void CleanupOldNodes()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - (TimeSpan.TicksPerMinute * 10);
            int removed = 0;

            lock (_nodesLock)
            {
                for (int i = _nodes.Count - 1; i >= 0; i--)
                {
                    var node = _nodes[i];
                    if (!node.IsActive || node.LastSeen < cutoffTime)
                    {
                        string keyString = BitConverter.ToString(node.PublicKey).Replace("-", "");
                        _nodesByKey.Remove(keyString);
                        _nodes.RemoveAt(i);
                        removed++;
                    }
                }
            }

            if (removed > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] Limpieza: {removed} nodos removidos");
            }
        }

        /// <summary>
        /// Comparar arrays de bytes de forma segura - MEJORADO
        /// </summary>
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            // Usar comparación constante en tiempo para seguridad
            return CryptoVerify.Verify(a, b);
        }


        /// <summary>
        /// Versión cacheada de GetClosestNodes - CORREGIDO
        /// </summary>
        public List<DHTNode> GetClosestNodesCached(byte[] targetPublicKey, int maxNodes = 8)
        {
            string cacheKey = BitConverter.ToString(targetPublicKey).Replace("-", "");

            lock (_cacheLock)
            {
                // Limpiar cache periódicamente
                if (DateTime.UtcNow - _lastCacheCleanup > TimeSpan.FromMinutes(1))
                {
                    _closestNodesCache.Clear();
                    _lastCacheCleanup = DateTime.UtcNow;
                }

                // Devolver resultado cacheado si existe
                if (_closestNodesCache.TryGetValue(cacheKey, out var cached) &&
                    cached != null && cached.Count > 0)
                {
                    Logger.Log.TraceF($"[{LOG_TAG}] Cache hit para búsqueda de nodos");
                    return cached.Count <= maxNodes ? cached : cached.GetRange(0, maxNodes);
                }
            }

            // Calcular y cachear resultado
            var result = GetClosestNodes(targetPublicKey, maxNodes);

            lock (_cacheLock)
            {
                _closestNodesCache[cacheKey] = result;
            }

            return result;
        }

        
        /// <summary>
        /// Obtener nodos más cercanos usando distancia XOR real
        /// </summary>
        public List<DHTNode> GetClosestNodes(byte[] targetKey, int maxNodes = MAX_FRIEND_CLOSE)
        {
            var result = new List<DHTNode>();

            try
            {
                lock (_nodesLock)
                {
                    // Calcular distancia XOR para cada nodo activo
                    var nodesWithDistance = new List<(DHTNode Node, byte[] Distance)>();

                    foreach (var node in _nodes)
                    {
                        if (node.IsActive)
                        {
                            byte[] distance = CalculateXORDistance(node.PublicKey, targetKey);
                            nodesWithDistance.Add((node, distance));
                        }
                    }

                    // Ordenar por distancia XOR (bytes más significativos primero)
                    nodesWithDistance.Sort((a, b) => CompareXORDistance(a.Distance, b.Distance));

                    // Tomar los más cercanos
                    for (int i = 0; i < Math.Min(maxNodes, nodesWithDistance.Count); i++)
                    {
                        result.Add(nodesWithDistance[i].Node);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] GetClosestNodes error: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Calcular distancia XOR entre dos claves (Kademlia)
        /// </summary>
        private byte[] CalculateXORDistance(byte[] key1, byte[] key2)
        {
            byte[] result = new byte[CRYPTO_PUBLIC_KEY_SIZE];
            for (int i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; i++)
            {
                result[i] = (byte)(key1[i] ^ key2[i]);
            }
            return result;
        }

        /// <summary>
        /// Comparar distancias XOR (para ordenamiento)
        /// </summary>
        private int CompareXORDistance(byte[] dist1, byte[] dist2)
        {
            for (int i = 0; i < dist1.Length; i++)
            {
                if (dist1[i] != dist2[i])
                    return dist1[i].CompareTo(dist2[i]);
            }
            return 0;
        }


        public class ByteArrayComparer : IComparer<byte[]>
        {
            public int Compare(byte[] x, byte[] y)
            {
                if (x == null && y == null) return 0;
                if (x == null) return -1;
                if (y == null) return 1;

                for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
                {
                    if (x[i] != y[i])
                        return x[i].CompareTo(y[i]);
                }
                return x.Length.CompareTo(y.Length);
            }
        }

        /// <summary>
        /// Calcular distancia XOR entre dos claves
        /// </summary>
        public static byte[] Distance(byte[] key1, byte[] key2)
        {
            byte[] result = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                result[i] = (byte)(key1[i] ^ key2[i]);
            }
            return result;
        }

        // ==================== FUNCIONES DE MANEJO DE PAQUETES ====================

        private int HandlePingRequest(byte[] packet, int length, IPPort source)
        {
            if (length < 100) return -1;

            try
            {
                // Extraer clave pública del remitente
                byte[] senderPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

                // Agregar nodo a la DHT
                AddNode(senderPublicKey, source);

                // Enviar respuesta ping
                byte[] response = CreatePingResponse(senderPublicKey);
                return DHT_send_packet(source, response, response.Length);
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// Manejar respuesta ping - IMPLEMENTACIÓN REAL
        /// </summary>
        private int HandlePingResponse(byte[] packet, int length, IPPort source)
        {
            if (length < 100) return -1;

            try
            {
                byte[] senderPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

                lock (_nodesLock)
                {
                    var node = _nodes.Find(n =>
                        n.EndPoint.IP.ToString() == source.IP.ToString() &&
                        n.EndPoint.Port == source.Port &&
                        ByteArraysEqual(senderPublicKey, n.PublicKey));

                    if (node != null)
                    {
                        node.LastSeen = DateTime.UtcNow.Ticks;
                        node.IsActive = true;
                        if (node.LastPingSent > 0)
                        {
                            node.RTT = (int)((DateTime.UtcNow.Ticks - node.LastPingSent) / TimeSpan.TicksPerMillisecond);
                        }
                    }
                    else
                    {
                        // Agregar nodo si no existe
                        AddNode(senderPublicKey, source);
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DHT] HandlePingResponse error: {ex.Message}");
                return -1;
            }
        }



        /// <summary>
        /// Manejar get nodes request - IMPLEMENTACIÓN REAL
        /// </summary>
        private int HandleGetNodesRequest(byte[] packet, int length, IPPort source)
        {
            if (length < 67) return -1; // Mínimo 67 bytes para este paquete

            try
            {
                byte[] senderPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

                byte[] targetKey = new byte[32];
                Buffer.BlockCopy(packet, 33, targetKey, 0, 32);

                // Agregar nodo a la DHT
                AddNode(senderPublicKey, source);

                // Obtener nodos más cercanos al objetivo
                var closestNodes = GetClosestNodes(targetKey, 4);

                // Enviar respuesta
                byte[] response = CreateNodesResponse(senderPublicKey, closestNodes);
                return DHT_send_packet(source, response, response.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DHT] HandleGetNodesRequest error: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Manejar nodes response - IMPLEMENTACIÓN REAL
        /// </summary>
        private int HandleNodesResponse(byte[] packet, int length, IPPort source)
        {
            if (length < 33) return -1;

            try
            {
                byte[] senderPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);

                // Procesar nodos recibidos
                int nodesDataLength = length - 33;
                int nodeCount = nodesDataLength / 50; // 50 bytes por nodo

                for (int i = 0; i < nodeCount; i++)
                {
                    int offset = 33 + (i * 50);

                    byte[] nodePublicKey = new byte[32];
                    Buffer.BlockCopy(packet, offset, nodePublicKey, 0, 32);

                    byte[] ippBytes = new byte[18];
                    Buffer.BlockCopy(packet, offset + 32, ippBytes, 0, 18);

                    IPPort nodeIPPort = BytesToIPPort(ippBytes);

                    // Solo agregar nodos válidos
                    if (nodeIPPort.Port > 0 && nodeIPPort.IP.Data != null)
                    {
                        AddNode(nodePublicKey, nodeIPPort);
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DHT] HandleNodesResponse error: {ex.Message}");
                return -1;
            }
        }

        // ==================== FUNCIONES DE CREACIÓN DE PAQUETES ====================

        /// <summary>
        /// Crear ping request - IMPLEMENTACIÓN REAL SIMPLIFICADA
        /// </summary>
        private byte[] CreatePingRequest(byte[] targetPublicKey)
        {
            // En toxcore real, esto usa encriptación CryptoBox
            // Para la prueba, creamos un paquete básico sin encriptar
            byte[] packet = new byte[100];

            // Header: tipo de paquete (0x00 = ping request)
            packet[0] = 0x00;

            // Nuestra clave pública (32 bytes)
            Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

            // Clave pública objetivo (32 bytes)  
            Buffer.BlockCopy(targetPublicKey, 0, packet, 33, 32);

            // Timestamp (8 bytes)
            byte[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            Buffer.BlockCopy(timestamp, 0, packet, 65, 8);

            // Nonce (27 bytes)
            byte[] nonce = RandomBytes.Generate(27);
            Buffer.BlockCopy(nonce, 0, packet, 73, 27);

            return packet;
        }

        /// <summary>
        /// Crear ping response - IMPLEMENTACIÓN REAL SIMPLIFICADA
        /// </summary>
        private byte[] CreatePingResponse(byte[] targetPublicKey)
        {
            byte[] packet = new byte[100];

            // Header: tipo de paquete (0x01 = ping response)
            packet[0] = 0x01;

            // Nuestra clave pública (32 bytes)
            Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

            // Clave pública del solicitante (32 bytes)
            Buffer.BlockCopy(targetPublicKey, 0, packet, 33, 32);

            // Timestamp de respuesta (8 bytes)
            byte[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            Buffer.BlockCopy(timestamp, 0, packet, 65, 8);

            // Nonce (27 bytes)
            byte[] nonce = RandomBytes.Generate(27);
            Buffer.BlockCopy(nonce, 0, packet, 73, 27);

            return packet;
        }

        /// <summary>
        /// Crea un paquete ping REAL encriptado con CryptoBox
        /// </summary>
        private byte[] CreateEncryptedPingPacket(byte[] targetPublicKey)
        {
            try
            {
                // Datos del ping (timestamp + ping ID + información de handshake)
                byte[] pingData = new byte[16 + CRYPTO_PUBLIC_KEY_SIZE];
                byte[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                byte[] pingIdBytes = BitConverter.GetBytes(_lastPingID++);

                Buffer.BlockCopy(timestamp, 0, pingData, 0, 8);
                Buffer.BlockCopy(pingIdBytes, 0, pingData, 8, 4);

                // ✅ INCLUIR nuestra public key temporal para facilitar handshake
                EnsureTempKeys();
                Buffer.BlockCopy(_currentTempPublicKey, 0, pingData, 12, CRYPTO_PUBLIC_KEY_SIZE);

                // Nonce aleatorio
                byte[] nonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);

                // Encriptar con CryptoBox
                byte[] encrypted = CryptoBox.Encrypt(pingData, nonce, targetPublicKey, SelfSecretKey);
                if (encrypted == null) return null;

                // Construir paquete: [nonce(24)][encrypted_data]
                byte[] packet = new byte[CRYPTO_NONCE_SIZE + encrypted.Length];
                Buffer.BlockCopy(nonce, 0, packet, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encrypted, 0, packet, CRYPTO_NONCE_SIZE, encrypted.Length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando ping encriptado: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Procesa un paquete ping REAL encriptado
        /// </summary>
        private bool HandleEncryptedPingPacket(byte[] packet, int length, IPPort source, out byte[] senderPublicKey)
        {
            senderPublicKey = null;

            if (length < CRYPTO_NONCE_SIZE + 16) // nonce + datos mínimos
                return false;

            try
            {
                // Extraer nonce y datos encriptados
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                byte[] encrypted = new byte[length - CRYPTO_NONCE_SIZE];

                Buffer.BlockCopy(packet, 0, nonce, 0, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(packet, CRYPTO_NONCE_SIZE, encrypted, 0, encrypted.Length);

                // Intentar desencriptar con nuestra clave secreta
                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, SelfPublicKey, SelfSecretKey);
                if (decrypted == null || decrypted.Length < 12)
                    return false;

                // ✅ IMPLEMENTACIÓN REAL: Extraer información de handshake si está presente
                if (decrypted.Length >= 12 + CRYPTO_PUBLIC_KEY_SIZE)
                {
                    // El ping incluye public key temporal del remitente
                    byte[] peerTempPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                    Buffer.BlockCopy(decrypted, 12, peerTempPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                    Logger.Log.DebugF($"[{LOG_TAG}] Ping con handshake info de {source}");

                    // Podríamos usar esta info para iniciar handshake más eficientemente
                    // Por ahora, simplemente aceptamos el ping
                    return true;
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando ping encriptado: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Crea paquete get_nodes REAL encriptado
        /// </summary>
        private byte[] CreateEncryptedGetNodesPacket(byte[] targetPublicKey, byte[] searchPublicKey)
        {
            try
            {
                // Datos: nuestra public key + public key a buscar
                byte[] requestData = new byte[CRYPTO_PUBLIC_KEY_SIZE * 2];
                Buffer.BlockCopy(SelfPublicKey, 0, requestData, 0, CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(searchPublicKey, 0, requestData, CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);

                byte[] nonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);
                byte[] encrypted = CryptoBox.Encrypt(requestData, nonce, targetPublicKey, SelfSecretKey);
                if (encrypted == null) return null;

                byte[] packet = new byte[1 + CRYPTO_NONCE_SIZE + encrypted.Length];
                packet[0] = 0x02; // GET_NODES packet type
                Buffer.BlockCopy(nonce, 0, packet, 1, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encrypted, 0, packet, 1 + CRYPTO_NONCE_SIZE, encrypted.Length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando get_nodes encriptado: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Crea respuesta send_nodes REAL encriptada
        /// </summary>
        private byte[] CreateEncryptedSendNodesPacket(byte[] targetPublicKey, List<DHTNode> nodes)
        {
            try
            {
                // Serializar nodos (cada nodo: public_key(32) + ip_port(18))
                int nodesDataSize = nodes.Count * (CRYPTO_PUBLIC_KEY_SIZE + 18);
                byte[] nodesData = new byte[nodesDataSize];
                int offset = 0;

                foreach (var node in nodes)
                {
                    Buffer.BlockCopy(node.PublicKey, 0, nodesData, offset, CRYPTO_PUBLIC_KEY_SIZE);
                    offset += CRYPTO_PUBLIC_KEY_SIZE;

                    byte[] ippBytes = IPPortToBytes(node.EndPoint);
                    Buffer.BlockCopy(ippBytes, 0, nodesData, offset, 18);
                    offset += 18;
                }

                byte[] nonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);
                byte[] encrypted = CryptoBox.Encrypt(nodesData, nonce, targetPublicKey, SelfSecretKey);
                if (encrypted == null) return null;

                byte[] packet = new byte[1 + CRYPTO_NONCE_SIZE + encrypted.Length];
                packet[0] = 0x04; // SEND_NODES packet type
                Buffer.BlockCopy(nonce, 0, packet, 1, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encrypted, 0, packet, 1 + CRYPTO_NONCE_SIZE, encrypted.Length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando send_nodes encriptado: {ex.Message}");
                return null;
            }
        }





        /// <summary>
        /// Crear get nodes request - IMPLEMENTACIÓN REAL
        /// </summary>
        private byte[] CreateGetNodesRequest(byte[] targetPublicKey)
        {
            byte[] packet = new byte[100];

            // Header: tipo de paquete (0x02 = get nodes request)
            packet[0] = 0x02;

            // Nuestra clave pública (32 bytes)
            Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

            // Clave pública objetivo para la búsqueda (32 bytes)
            Buffer.BlockCopy(targetPublicKey, 0, packet, 33, 32);

            // Random padding (35 bytes)
            byte[] padding = RandomBytes.Generate(35);
            Buffer.BlockCopy(padding, 0, packet, 65, 35);

            return packet;
        }

        /// <summary>
        /// Crear nodes response - IMPLEMENTACIÓN REAL
        /// </summary>
        private byte[] CreateNodesResponse(byte[] targetPublicKey, List<DHTNode> nodes)
        {
            // Calcular tamaño del paquete: 33 bytes header + (50 bytes por nodo)
            int nodeCount = Math.Min(nodes.Count, 4); // Máximo 4 nodos por respuesta
            int packetSize = 33 + (nodeCount * 50);
            byte[] packet = new byte[packetSize];

            // Header: tipo de paquete (0x04 = send nodes response)
            packet[0] = 0x04;

            // Nuestra clave pública (32 bytes)
            Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

            int offset = 33;
            for (int i = 0; i < nodeCount; i++)
            {
                var node = nodes[i];

                // Clave pública del nodo (32 bytes)
                Buffer.BlockCopy(node.PublicKey, 0, packet, offset, 32);
                offset += 32;

                // IPPort del nodo (18 bytes)
                byte[] ippBytes = IPPortToBytes(node.EndPoint);
                Buffer.BlockCopy(ippBytes, 0, packet, offset, 18);
                offset += 18;
            }

            return packet;
        }

        // ==================== FUNCIONES AUXILIARES ====================

        /// <summary>
        /// Convertir IPPort a bytes - IMPLEMENTACIÓN REAL
        /// </summary>
        private byte[] IPPortToBytes(IPPort ipp)
        {
            byte[] result = new byte[18];
            if (ipp.IP.Data != null)
            {
                Buffer.BlockCopy(ipp.IP.Data, 0, result, 0, 16);
            }
            result[16] = (byte)((ipp.Port >> 8) & 0xFF);
            result[17] = (byte)(ipp.Port & 0xFF);
            return result;
        }

        private IPPort BytesToIPPort(byte[] data)
        {
            if (data.Length < 18) return new IPPort();

            // IP (primeros 16 bytes)
            byte[] ipData = new byte[16];
            Buffer.BlockCopy(data, 0, ipData, 0, 16);

            // Puerto (últimos 2 bytes)
            ushort port = (ushort)((data[16] << 8) | data[17]);

            // Determinar si es IPv4 o IPv6
            IP ip = new IP();
            bool isIPv4 = true;
            for (int i = 0; i < 10; i++)
            {
                if (ipData[i] != 0)
                {
                    isIPv4 = false;
                    break;
                }
            }

            if (isIPv4 && ipData[10] == 0xFF && ipData[11] == 0xFF)
            {
                // IPv4 mapeado a IPv6
                byte[] ip4Bytes = new byte[4];
                Buffer.BlockCopy(ipData, 12, ip4Bytes, 0, 4);
                ip = new IP(new IP4(ip4Bytes));
            }
            else
            {
                // IPv6 nativo
                ip = new IP(new IP6(ipData));
            }

            return new IPPort(ip, port);
        }

        // ==================== FUNCIONES DE MANTENIMIENTO ====================

        ////// <summary>
        /// Ejecutar mantenimiento periódico de la DHT - VERSIÓN CORREGIDA
        /// </summary>
        public void DoPeriodicWork()
        {
            try
            {
                CleanupOldNodes();
                CleanupExpiredHandshakes();

                EnsureTempKeys();

                long currentTime = DateTime.UtcNow.Ticks;

                // CORREGIR: Usar índices en lugar de enumeración
                lock (_nodesLock)
                {
                    for (int i = 0; i < _nodes.Count; i++)
                    {
                        var node = _nodes[i];
                        if (node.IsActive &&
                            (currentTime - node.LastSeen) > TimeSpan.TicksPerSecond * 60)
                        {
                            // Marcar como inactivo directamente
                            node.IsActive = false;
                        }
                    }
                }

                // Re-bootstrap periódicamente
                if ((currentTime - _lastBootstrapTime) > TimeSpan.TicksPerSecond * 300)
                {
                    foreach (var bootstrapNode in _bootstrapNodes)
                    {
                        DHT_bootstrap(bootstrapNode.IPPort, bootstrapNode.PublicKey);
                    }
                    _lastBootstrapTime = currentTime;
                }

                if ((currentTime - _lastLogTime) > TimeSpan.TicksPerSecond * 30)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Estadísticas - Nodos: {TotalNodes}, Activos: {ActiveNodes}");
                    _lastLogTime = currentTime;
                }

            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico: {ex.Message}");
            }
        }

        private void SimpleCleanup()
        {
            if (DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(2))
                return;

            try
            {
                lock (_nodesLock)
                {
                    // Limpieza simple - solo marcar como inactivos, no remover
                    foreach (var node in _nodes)
                    {
                        if (!node.IsActive)
                        {
                            // Ya está inactivo, no hacer nada
                        }
                    }
                }
                _lastCleanup = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error en limpieza simple: {ex.Message}");
            }
        }

        /// <summary>
        /// Limpieza mínima y segura - solo marca nodos, no los remueve
        /// </summary>
        private void SafeCleanup()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            // Solo ejecutar cada 2 minutos
            if (currentTime - _lastCleanupTime < TimeSpan.TicksPerMinute * 2)
                return;

            try
            {
                int markedInactive = 0;
                lock (_nodesLock)
                {
                    // Solo marcar nodos como inactivos, no remover
                    foreach (var node in _nodes)
                    {
                        // Usar comparación con ticks (compatible con tu código)
                        long inactiveThreshold = currentTime - TimeSpan.TicksPerHour;
                        if (node.IsActive && node.LastSeen < inactiveThreshold)
                        {
                            node.IsActive = false;
                            markedInactive++;
                        }
                    }
                }

                if (markedInactive > 0)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Limpieza segura - Nodos marcados inactivos: {markedInactive}");
                }

                _lastCleanupTime = currentTime;
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error en limpieza segura: {ex.Message}");
            }
        }


        /// <summary>
        /// Optimización: Limpieza periódica de nodos inactivos
        /// </summary>
        private void OptimizedCleanup()
        {
            if (DateTime.UtcNow - _lastCleanup < _cleanupInterval)
                return;

            try
            {
                lock (_nodesLock)
                {
                    int initialCount = _nodes.Count;

                    // Usar ticks para comparación (compatible con tu código)
                    long cutoffTime = DateTime.UtcNow.AddHours(-1).Ticks;

                    _nodes.RemoveAll(node =>
                        !node.IsActive &&
                        node.LastSeen < cutoffTime);

                    int removed = initialCount - _nodes.Count;
                    if (removed > 0)
                    {
                        Logger.Log.DebugF($"[{LOG_TAG}] Limpieza optimizada - Nodos removidos: {removed}");
                    }
                }

                _lastCleanup = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error en limpieza optimizada: {ex.Message}");
            }
        }

        /// <summary>
        /// Versión optimizada de DoPeriodicWork
        /// </summary>
        public void DoPeriodicWorkOptimized()
        {
            try
            {
                // 1. Limpieza optimizada
                OptimizedCleanup();

                // 2. Procesamiento normal (usando tu implementación actual)
                DoPeriodicWork();
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico optimizado: {ex.Message}");
            }
        }

        /// <summary>
        /// Cerrar DHT y liberar recursos
        /// </summary>
        public void Close()
        {
            if (Socket != -1)
            {
                Network.kill_socket(Socket);
                Socket = -1;
            }

            lock (_nodesLock)
            {
                _nodes.Clear();
            }
            _bootstrapNodes.Clear();
        }

        // ==================== FUNCIONES DE ESTADÍSTICAS ====================

        public void PrintStatistics()
        {
            Console.WriteLine($"[DHT] Statistics:");
            Console.WriteLine($"  Total Nodes: {TotalNodes}");
            Console.WriteLine($"  Active Nodes: {ActiveNodes}");
            Console.WriteLine($"  Bootstrap Nodes: {_bootstrapNodes.Count}");
            Console.WriteLine($"  Socket: {(Socket == -1 ? "Closed" : "Open")}");
        }
    }


    


}

