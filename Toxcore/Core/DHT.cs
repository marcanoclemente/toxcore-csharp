using Sodium;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación completa de Kademlia DHT compatible con toxcore C
    /// </summary>
    public class DHT
    {
        private const string LOG_TAG = "DHT";

        // ===== CONSTANTES TOXCORE REALES =====
        public const int MAX_FRIEND_CLOSE = 8;
        public const int CRYPTO_PACKET_SIZE = 122;
        public const int CRYPTO_NONCE_SIZE = 24;
        public const int CRYPTO_PUBLIC_KEY_SIZE = 32;
        public const int CRYPTO_SECRET_KEY_SIZE = 32;
        public const int MAX_CLOSE_TO_BOOTSTRAP_NODES = 16;
        public const int DHT_PING_INTERVAL = 30000; // 30 segundos
        public const int DHT_PING_TIMEOUT = 10000; // 10 segundos
        public const int CRYPTO_SYMMETRIC_KEY_SIZE = 32;
        public const int CRYPTO_MAC_SIZE = 16;
        public const int DHT_PING_SIZE = 64;
        public const int DHT_PONG_SIZE = 64;
        public const int MAX_CRYPTO_PACKET_SIZE = 1024;

        // ===== CONSTANTES KADEMLIA =====
        public const int K = 8; // K-bucket size (tamaño estándar Kademlia)
        public const int ALPHA = 3; // Paralelismo en búsquedas
        public const int BUCKET_REFRESH_INTERVAL = 900000; // 15 minutos
        public const int KEY_ROTATION_INTERVAL = 60000; // 60 segundos

        // ===== ESTRUCTURAS DE DATOS KADEMLIA =====

        /// <summary>
        /// K-Bucket real - implementación completa de Kademlia
        /// </summary>
        public class KBucket
        {
            private readonly List<DHTNode> nodes = new List<DHTNode>(K);
            private readonly object lockObj = new object();
            private DateTime lastUpdated = DateTime.UtcNow;

            public int Index { get; }
            public int Count
            {
                get
                {
                    lock (lockObj) return nodes.Count;
                }
            }

            public KBucket(int index)
            {
                Index = index;
            }

            /// <summary>
            /// Intenta añadir un nodo al K-bucket siguiendo la política Kademlia
            /// </summary>
            public bool TryAddNode(DHTNode newNode)
            {
                lock (lockObj)
                {
                    // Verificar si el nodo ya existe
                    var existing = nodes.FirstOrDefault(n => ByteArraysEqual(n.PublicKey, newNode.PublicKey));
                    if (existing != null)
                    {
                        // Mover al final (LRU - Least Recently Used)
                        nodes.Remove(existing);
                        existing.LastSeen = DateTime.UtcNow.Ticks;
                        existing.LastPingSent = 0;
                        existing.IsActive = true;
                        nodes.Add(existing);
                        lastUpdated = DateTime.UtcNow;
                        return true;
                    }

                    // Si hay espacio, añadir directamente
                    if (nodes.Count < K)
                    {
                        newNode.LastSeen = DateTime.UtcNow.Ticks;
                        nodes.Add(newNode);
                        lastUpdated = DateTime.UtcNow;
                        return true;
                    }

                    // Bucket lleno - verificar si hay nodos inactivos
                    var oldestInactive = nodes.FirstOrDefault(n => !n.IsActive ||
                        (DateTime.UtcNow.Ticks - n.LastSeen) > TimeSpan.TicksPerMinute * 15);

                    if (oldestInactive != null)
                    {
                        // Reemplazar el nodo inactivo más antiguo
                        nodes.Remove(oldestInactive);
                        newNode.LastSeen = DateTime.UtcNow.Ticks;
                        nodes.Add(newNode);
                        lastUpdated = DateTime.UtcNow;
                        return true;
                    }

                    // Todos los nodos están activos - ping al más antiguo
                    var oldest = nodes.OrderBy(n => n.LastSeen).First();
                    oldest.LastPingSent = DateTime.UtcNow.Ticks;
                    return false; // No se pudo añadir ahora
                }
            }

            /// <summary>
            /// Obtiene los nodos del bucket ordenados por LRU
            /// </summary>
            public List<DHTNode> GetNodes()
            {
                lock (lockObj)
                {
                    return nodes.OrderByDescending(n => n.LastSeen).ToList();
                }
            }

            /// <summary>
            /// Marca un nodo como inactivo si no responde
            /// </summary>
            public bool MarkNodeInactive(byte[] publicKey)
            {
                lock (lockObj)
                {
                    var node = nodes.FirstOrDefault(n => ByteArraysEqual(n.PublicKey, publicKey));
                    if (node != null)
                    {
                        node.IsActive = false;
                        return true;
                    }
                    return false;
                }
            }

            /// <summary>
            /// Limpia nodos inactivos antiguos
            /// </summary>
            public int CleanupInactiveNodes()
            {
                lock (lockObj)
                {
                    long cutoff = DateTime.UtcNow.Ticks - TimeSpan.TicksPerHour * 2;
                    int removed = nodes.RemoveAll(n => !n.IsActive && n.LastSeen < cutoff);
                    return removed;
                }
            }

            /// <summary>
            /// Verifica si necesita refresco (15 minutos sin actualización)
            /// </summary>
            public bool NeedsRefresh()
            {
                return (DateTime.UtcNow - lastUpdated) > TimeSpan.FromMilliseconds(BUCKET_REFRESH_INTERVAL);
            }
        }

        /// <summary>
        /// Tabla de routing Kademlia con 256 K-buckets
        /// </summary>
        public class KademliaRoutingTable
        {
            private readonly KBucket[] buckets = new KBucket[256];
            private readonly byte[] localId;
            private readonly object lockObj = new object();

            public KademliaRoutingTable(byte[] localId)
            {
                if (localId.Length != CRYPTO_PUBLIC_KEY_SIZE)
                    throw new ArgumentException("Local ID must be 32 bytes");

                this.localId = localId;

                for (int i = 0; i < 256; i++)
                {
                    buckets[i] = new KBucket(i);
                }
            }

            /// <summary>
            /// Calcula el índice del bucket basado en el prefix length compartido
            /// </summary>
            public int GetBucketIndex(byte[] targetId)
            {
                return KademliaDistance.GetSharedPrefixLength(localId, targetId);
            }

            /// <summary>
            /// Añade un nodo a la tabla de routing
            /// </summary>
            public bool AddNode(DHTNode node)
            {
                // No añadirnos a nosotros mismos
                if (ByteArraysEqual(node.PublicKey, localId))
                    return false;

                int bucketIndex = GetBucketIndex(node.PublicKey);

                lock (lockObj)
                {
                    return buckets[bucketIndex].TryAddNode(node);
                }
            }

            /// <summary>
            /// Encuentra los K nodos más cercanos a un ID objetivo
            /// </summary>
            public List<DHTNode> FindClosestNodes(byte[] targetId, int count = K)
            {
                var candidates = new List<DHTNode>();

                lock (lockObj)
                {
                    // Obtener nodos del bucket correspondiente
                    int targetBucket = GetBucketIndex(targetId);
                    candidates.AddRange(buckets[targetBucket].GetNodes());

                    // Si necesitamos más nodos, buscar en buckets adyacentes
                    if (candidates.Count < count)
                    {
                        for (int i = 1; i < 256 && candidates.Count < count; i++)
                        {
                            int lowerBucket = targetBucket - i;
                            int upperBucket = targetBucket + i;

                            if (lowerBucket >= 0)
                                candidates.AddRange(buckets[lowerBucket].GetNodes());
                            if (upperBucket < 256 && candidates.Count < count)
                                candidates.AddRange(buckets[upperBucket].GetNodes());
                        }
                    }
                }

                // Ordenar por distancia XOR y tomar los más cercanos
                return candidates
                    .OrderBy(n => KademliaDistance.Calculate(localId, n.PublicKey), new KademliaDistanceComparer())
                    .Take(count)
                    .ToList();
            }

            /// <summary>
            /// Obtiene todos los nodos de la tabla
            /// </summary>
            public List<DHTNode> GetAllNodes()
            {
                var allNodes = new List<DHTNode>();
                lock (lockObj)
                {
                    foreach (var bucket in buckets)
                    {
                        allNodes.AddRange(bucket.GetNodes());
                    }
                }
                return allNodes;
            }

            /// <summary>
            /// Marca un nodo como inactivo
            /// </summary>
            public bool MarkNodeInactive(byte[] publicKey)
            {
                int bucketIndex = GetBucketIndex(publicKey);
                lock (lockObj)
                {
                    return buckets[bucketIndex].MarkNodeInactive(publicKey);
                }
            }

            /// <summary>
            /// Limpieza general de buckets inactivos
            /// </summary>
            public int CleanupAllBuckets()
            {
                int totalRemoved = 0;
                lock (lockObj)
                {
                    foreach (var bucket in buckets)
                    {
                        totalRemoved += bucket.CleanupInactiveNodes();
                    }
                }
                return totalRemoved;
            }

            /// <summary>
            /// Obtiene buckets que necesitan refresco
            /// </summary>
            public List<int> GetBucketsNeedingRefresh()
            {
                var needingRefresh = new List<int>();
                lock (lockObj)
                {
                    for (int i = 0; i < 256; i++)
                    {
                        if (buckets[i].NeedsRefresh())
                        {
                            needingRefresh.Add(i);
                        }
                    }
                }
                return needingRefresh;
            }
        }

        /// <summary>
        /// Utilidades para cálculos Kademlia
        /// </summary>
        public static class KademliaDistance
        {
            /// <summary>
            /// Calcula la distancia XOR entre dos IDs
            /// </summary>
            public static byte[] Calculate(byte[] id1, byte[] id2)
            {
                if (id1.Length != id2.Length)
                    throw new ArgumentException("IDs must have same length");

                var result = new byte[id1.Length];
                for (int i = 0; i < id1.Length; i++)
                {
                    result[i] = (byte)(id1[i] ^ id2[i]);
                }
                return result;
            }

            /// <summary>
            /// Calcula la longitud del prefix compartido en bits
            /// </summary>
            public static int GetSharedPrefixLength(byte[] id1, byte[] id2)
            {
                int sharedBits = 0;
                for (int i = 0; i < id1.Length; i++)
                {
                    byte xor = (byte)(id1[i] ^ id2[i]);
                    if (xor == 0)
                    {
                        sharedBits += 8;
                    }
                    else
                    {
                        int j = 7;
                        while (j >= 0 && ((xor >> j) & 1) == 0)
                        {
                            sharedBits++;
                            j--;
                        }
                        break;
                    }
                }
                return Math.Min(sharedBits, 255); // Máximo 255 para array de 256
            }

            /// <summary>
            /// Verifica si dos nodos estarían en el mismo bucket
            /// </summary>
            public static bool InSameBucket(byte[] localId, byte[] targetId, int bucketIndex)
            {
                return GetSharedPrefixLength(localId, targetId) >= bucketIndex;
            }
        }

        /// <summary>
        /// Comparador para ordenar por distancia XOR (Kademlia)
        /// </summary>
        public class KademliaDistanceComparer : IComparer<byte[]>
        {
            public int Compare(byte[] x, byte[] y)
            {
                // Comparación bit a bit, más significativo primero
                for (int i = 0; i < x.Length; i++)
                {
                    if (x[i] != y[i])
                    {
                        // En Kademlia, menor distancia = más cercano
                        return x[i].CompareTo(y[i]);
                    }
                }
                return 0;
            }
        }

        // ===== ESTRUCTURAS COMPATIBLES CON TOXCORE ORIGINAL =====

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
            public byte[] TemporaryPublicKey;
            public byte[] EncryptedPayload;
        }

        /// <summary>
        /// Nodo DHT con información completa y métricas Kademlia
        /// </summary>
        public class DHTNode
        {
            public byte[] PublicKey { get; set; }
            public IPPort EndPoint { get; set; }
            public long LastSeen { get; set; }
            public long LastPingSent { get; set; }
            public int PingID { get; set; }
            public bool IsActive { get; set; }
            public int RTT { get; set; }
            public int QualityScore { get; set; }
            public int FailedPings { get; set; }
            public long FirstSeen { get; set; }

            public DHTNode(byte[] publicKey, IPPort endPoint)
            {
                PublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);
                EndPoint = endPoint;
                LastSeen = DateTime.UtcNow.Ticks;
                FirstSeen = DateTime.UtcNow.Ticks;
                IsActive = true;
                QualityScore = 100;
                FailedPings = 0;
            }

            public override string ToString()
            {
                return $"{EndPoint} [PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";
            }
        }

        // ===== CAMPOS PRIVADOS =====

        private readonly KademliaRoutingTable routingTable;
        private readonly Dictionary<string, DHTHandshake> activeHandshakes;
        private readonly object handshakesLock = new object();

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public int Socket { get; private set; }

        private readonly List<PackedNode> bootstrapNodes;
        private int lastPingID;
        private long lastBootstrapTime;
        private long lastMaintenanceTime;
        private long lastLogTime;

        // Claves temporales para handshake
        private byte[] currentTempPublicKey;
        private byte[] currentTempSecretKey;
        private long lastKeyRotation;

        // Estadísticas
        public int TotalNodes => routingTable.GetAllNodes().Count;
        public int ActiveNodes => routingTable.GetAllNodes().Count(n => n.IsActive);

        // ===== CONSTRUCTOR =====

        public DHT(byte[] selfPublicKey, byte[] selfSecretKey)
        {
            if (selfPublicKey?.Length != CRYPTO_PUBLIC_KEY_SIZE || selfSecretKey?.Length != CRYPTO_SECRET_KEY_SIZE)
                throw new ArgumentException("Invalid key sizes");

            SelfPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
            SelfSecretKey = new byte[CRYPTO_SECRET_KEY_SIZE];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, CRYPTO_SECRET_KEY_SIZE);

            routingTable = new KademliaRoutingTable(SelfPublicKey);
            bootstrapNodes = new List<PackedNode>();
            activeHandshakes = new Dictionary<string, DHTHandshake>();

            lastPingID = 0;
            lastBootstrapTime = 0;
            lastMaintenanceTime = 0;
            lastLogTime = 0;

            Socket = Network.new_socket(2, 2, 17); // IPv4 UDP
            Logger.Log.InfoF($"[{LOG_TAG}] DHT Kademlia inicializado - Socket: {Socket}");
        }

        // ===== MÉTODOS PÚBLICOS COMPATIBLES CON TOXCORE =====

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
                bootstrapNodes.Add(bootstrapNode);

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
        /// DHT_handle_packet - Maneja paquetes entrantes
        /// </summary>
        public int DHT_handle_packet(byte[] packet, int length, IPPort source)
        {
            if (packet == null || length < 1 + CRYPTO_PUBLIC_KEY_SIZE) return -1;

            try
            {
                byte packetType = packet[0];

                // Paquetes encriptados
                if (packetType >= 0x80)
                {
                    return HandleCryptopacket(source, packet, length, SelfPublicKey);
                }

                // Paquetes de handshake
                switch (packetType)
                {
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
                var closestNodes = routingTable.FindClosestNodes(SelfPublicKey, MAX_FRIEND_CLOSE);
                int offset = 0;

                foreach (var node in closestNodes)
                {
                    if (offset + 50 > length) break; // 32 + 18 = 50 bytes por nodo

                    // Copiar clave pública
                    Buffer.BlockCopy(node.PublicKey, 0, nodes, offset, CRYPTO_PUBLIC_KEY_SIZE);
                    offset += CRYPTO_PUBLIC_KEY_SIZE;

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

        // ===== HANDSHAKE CRIPTOGRÁFICO REAL =====

        /// <summary>
        /// Genera o rota las claves temporales para handshake
        /// </summary>
        private void EnsureTempKeys()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            if (currentTempPublicKey == null ||
                (currentTime - lastKeyRotation) > TimeSpan.TicksPerMillisecond * KEY_ROTATION_INTERVAL)
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                currentTempPublicKey = keyPair.PublicKey;
                currentTempSecretKey = keyPair.PrivateKey;
                lastKeyRotation = currentTime;

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
                byte[] handshakePacket = CreateHandshakePacket(currentTempPublicKey, encryptionNonce, encryptedPayload);

                // Enviar handshake
                int sent = DHT_send_packet(endPoint, handshakePacket, handshakePacket.Length);
                if (sent <= 0) return -1;

                // Registrar handshake pendiente
                var handshake = new DHTHandshake
                {
                    TemporaryPublicKey = currentTempPublicKey,
                    TemporarySecretKey = currentTempSecretKey,
                    PeerPublicKey = peerPublicKey,
                    CreationTime = DateTime.UtcNow.Ticks,
                    EndPoint = endPoint
                };

                string handshakeKey = $"{endPoint}_{BitConverter.ToString(peerPublicKey).Replace("-", "").Substring(0, 16)}";

                lock (handshakesLock)
                {
                    activeHandshakes[handshakeKey] = handshake;
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
                byte[] encryptedResponse = CryptoBox.Encrypt(responsePayload, responseNonce, peerTempPublicKey, currentTempSecretKey);

                if (encryptedResponse == null)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] No se pudo encriptar respuesta de handshake");
                    return -1;
                }

                // Enviar respuesta
                byte[] responsePacket = CreateHandshakeResponsePacket(currentTempPublicKey, responseNonce, encryptedResponse);
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
                if (!ByteArraysEqual(peerRealPublicKey, handshake.Value.PeerPublicKey))
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

        // ===== MANEJO DE PAQUETES ENCRIPTADOS DHT =====

        /// <summary>
        /// HandleCryptopacket - Maneja paquetes encriptados DHT reales
        /// </summary>
        public int HandleCryptopacket(IPPort source, byte[] packet, int length, byte[] publicKey)
        {
            if (packet == null || length < CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE + 1)
                return -1;

            try
            {
                // 1. Calcular shared key para decryptar
                byte[] sharedKey = new byte[CRYPTO_SYMMETRIC_KEY_SIZE];
                int keyResult = DHT_get_shared_key_recv(sharedKey, packet, SelfSecretKey);
                if (keyResult == -1) return -1;

                // 2. Extraer nonce (bytes 32-55)
                byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
                Buffer.BlockCopy(packet, CRYPTO_PUBLIC_KEY_SIZE, nonce, 0, CRYPTO_NONCE_SIZE);

                // 3. Extraer datos encriptados (resto del paquete)
                int encryptedLength = length - CRYPTO_PUBLIC_KEY_SIZE - CRYPTO_NONCE_SIZE;
                byte[] encrypted = new byte[encryptedLength];
                Buffer.BlockCopy(packet, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypted, 0, encryptedLength);

                // 4. Decryptar usando crypto_box_open_afternm
                byte[] decrypted = CryptoBox.OpenAfterNm(encrypted, nonce, sharedKey);
                if (decrypted == null) return -1;

                // 5. Procesar el paquete decryptado basado en su tipo
                return ProcessDecryptedDhtPacket(source, decrypted, decrypted.Length, publicKey);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleCryptopacket: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// ProcessDecryptedDhtPacket - Procesa paquetes DHT decryptados
        /// </summary>
        private int ProcessDecryptedDhtPacket(IPPort source, byte[] decrypted, int length, byte[] expectedPublicKey)
        {
            if (decrypted == null || length < 1) return -1;

            byte packetType = decrypted[0];

            switch (packetType)
            {
                case 0x00: // Ping request
                    return HandleDecryptedPingRequest(source, decrypted, length, expectedPublicKey);

                case 0x01: // Ping response
                    return HandleDecryptedPingResponse(source, decrypted, length, expectedPublicKey);

                case 0x02: // Get nodes request
                    return HandleDecryptedGetNodesRequest(source, decrypted, length, expectedPublicKey);

                case 0x04: // Send nodes response
                    return HandleDecryptedSendNodesResponse(source, decrypted, length, expectedPublicKey);

                default:
                    Logger.Log.DebugF($"[{LOG_TAG}] Tipo de paquete DHT desconocido: 0x{packetType:X2}");
                    return -1;
            }
        }

        /// <summary>
        /// HandleDecryptedPingRequest - Maneja ping request encriptado
        /// </summary>
        private int HandleDecryptedPingRequest(IPPort source, byte[] packet, int length, byte[] expectedPublicKey)
        {
            if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE) return -1;

            try
            {
                // Extraer public key del ping (bytes 1-32)
                byte[] senderPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Verificar que coincide con la key esperada
                if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Public key no coincide en ping request");
                    return -1;
                }

                // Agregar/actualizar nodo en la tabla Kademlia
                var node = new DHTNode(senderPublicKey, source);
                routingTable.AddNode(node);

                // Enviar pong response
                byte[] pongResponse = CreateDhtPongResponse(senderPublicKey);
                if (pongResponse != null)
                {
                    return DHT_send_packet(source, pongResponse, pongResponse.Length);
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleDecryptedPingRequest: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// HandleDecryptedPingResponse - Maneja ping response encriptado
        /// </summary>
        private int HandleDecryptedPingResponse(IPPort source, byte[] packet, int length, byte[] expectedPublicKey)
        {
            if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE) return -1;

            try
            {
                // Extraer public key del pong (bytes 1-32)
                byte[] senderPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Verificar que coincide con la key esperada
                if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Public key no coincide en ping response");
                    return -1;
                }

                // Actualizar nodo en la tabla Kademlia
                var node = new DHTNode(senderPublicKey, source);
                routingTable.AddNode(node);

                Logger.Log.DebugF($"[{LOG_TAG}] Ping response recibido de {source}");
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleDecryptedPingResponse: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// HandleDecryptedGetNodesRequest - Maneja get_nodes request encriptado
        /// </summary>
        private int HandleDecryptedGetNodesRequest(IPPort source, byte[] packet, int length, byte[] expectedPublicKey)
        {
            if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE * 2) return -1;

            try
            {
                // Extraer public key del solicitante (bytes 1-32)
                byte[] senderPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Extraer public key objetivo de búsqueda (bytes 33-64)
                byte[] targetPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 1 + CRYPTO_PUBLIC_KEY_SIZE, targetPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Verificar que la key del solicitante coincide
                if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Public key no coincide en get_nodes request");
                    return -1;
                }

                // Agregar/actualizar nodo del solicitante
                var senderNode = new DHTNode(senderPublicKey, source);
                routingTable.AddNode(senderNode);

                // Obtener los K nodos más cercanos al objetivo usando Kademlia
                var closestNodes = routingTable.FindClosestNodes(targetPublicKey, K);
                if (closestNodes.Count > 0)
                {
                    // Enviar respuesta SEND_NODES
                    byte[] nodesResponse = CreateDhtSendNodesResponse(senderPublicKey, closestNodes);
                    if (nodesResponse != null)
                    {
                        return DHT_send_packet(source, nodesResponse, nodesResponse.Length);
                    }
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleDecryptedGetNodesRequest: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// HandleDecryptedSendNodesResponse - Maneja send_nodes response encriptado
        /// </summary>
        private int HandleDecryptedSendNodesResponse(IPPort source, byte[] packet, int length, byte[] expectedPublicKey)
        {
            if (length < 1) return -1;

            try
            {
                // El payload es: [0x04] + [nodos*(public_key + ipport)]
                int nodesDataLength = length - 1;

                // Cada nodo ocupa 50 bytes (32 + 18)
                int nodeCount = nodesDataLength / 50;

                int nodesAdded = 0;
                for (int i = 0; i < nodeCount; i++)
                {
                    int offset = 1 + (i * 50);

                    // Extraer public key del nodo (32 bytes)
                    byte[] nodePublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                    Buffer.BlockCopy(packet, offset, nodePublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                    // Extraer IPPort (18 bytes)
                    byte[] ippBytes = new byte[18];
                    Buffer.BlockCopy(packet, offset + CRYPTO_PUBLIC_KEY_SIZE, ippBytes, 0, 18);

                    IPPort nodeIPPort = BytesToIPPort(ippBytes);

                    // Solo agregar nodos válidos
                    if (nodeIPPort.Port > 0 && nodeIPPort.IP.Data != null)
                    {
                        var newNode = new DHTNode(nodePublicKey, nodeIPPort);
                        routingTable.AddNode(newNode);
                        nodesAdded++;
                    }
                }

                Logger.Log.DebugF($"[{LOG_TAG}] {nodesAdded} nodos agregados desde send_nodes de {source}");
                return nodesAdded > 0 ? 0 : -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en HandleDecryptedSendNodesResponse: {ex.Message}");
                return -1;
            }
        }

        // ===== FUNCIONES DE CREACIÓN DE PAQUETES =====

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

        /// <summary>
        /// DHT_get_shared_key_recv - Calcula la shared key para decryptar paquetes entrantes
        /// </summary>
        public int DHT_get_shared_key_recv(byte[] sharedKey, byte[] packet, byte[] secretKey)
        {
            try
            {
                if (sharedKey == null || packet == null || secretKey == null)
                    return -1;

                // Extraer la public key temporal del remitente (primeros 32 bytes)
                byte[] tempPublicKey = new byte[CRYPTO_PUBLIC_KEY_SIZE];
                Buffer.BlockCopy(packet, 0, tempPublicKey, 0, CRYPTO_PUBLIC_KEY_SIZE);

                // Calcular shared key usando crypto_box_beforenm
                byte[] calculatedKey = CryptoBox.BeforeNm(tempPublicKey, secretKey);
                if (calculatedKey == null) return -1;

                Buffer.BlockCopy(calculatedKey, 0, sharedKey, 0, CRYPTO_SYMMETRIC_KEY_SIZE);
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en DHT_get_shared_key_recv: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// CreateCryptopacket - Crea paquetes encriptados DHT reales
        /// </summary>
        public byte[] CreateCryptopacket(byte[] data, int length, byte[] publicKey, byte[] secretKey)
        {
            try
            {
                if (data == null || length > MAX_CRYPTO_PACKET_SIZE)
                    return null;

                // 1. Generar keypair temporal para este paquete
                var tempKeyPair = CryptoBox.GenerateKeyPair();
                byte[] tempPublicKey = tempKeyPair.PublicKey;
                byte[] tempSecretKey = tempKeyPair.PrivateKey;

                // 2. Calcular shared key
                byte[] sharedKey = CryptoBox.BeforeNm(publicKey, tempSecretKey);
                if (sharedKey == null) return null;

                // 3. Generar nonce
                byte[] nonce = RandomBytes.Generate(CRYPTO_NONCE_SIZE);

                // 4. Encriptar datos con crypto_box_afternm
                byte[] encrypted = CryptoBox.AfterNm(data, nonce, sharedKey);
                if (encrypted == null) return null;

                // 5. Construir paquete final: [temp_public_key(32)][nonce(24)][encrypted_data]
                byte[] packet = new byte[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encrypted.Length];
                Buffer.BlockCopy(tempPublicKey, 0, packet, 0, CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(nonce, 0, packet, CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encrypted, 0, packet, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypted.Length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en CreateCryptopacket: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// CreateDhtPongResponse - Crea respuesta PONG encriptada real
        /// </summary>
        private byte[] CreateDhtPongResponse(byte[] destinationPublicKey)
        {
            try
            {
                // Crear payload PONG: [0x01][nuestra_public_key]
                byte[] pongPayload = new byte[1 + CRYPTO_PUBLIC_KEY_SIZE];
                pongPayload[0] = 0x01; // PONG type
                Buffer.BlockCopy(SelfPublicKey, 0, pongPayload, 1, CRYPTO_PUBLIC_KEY_SIZE);

                // Encriptar el pong
                return CreateCryptopacket(pongPayload, pongPayload.Length, destinationPublicKey, SelfSecretKey);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando pong response: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// CreateDhtSendNodesResponse - Crea respuesta SEND_NODES encriptada
        /// </summary>
        private byte[] CreateDhtSendNodesResponse(byte[] destinationPublicKey, List<DHTNode> nodes)
        {
            try
            {
                // Calcular tamaño del payload: [0x04] + [nodos*(public_key + ipport)]
                int nodesCount = Math.Min(nodes.Count, 4); // Máximo 4 nodos como en toxcore
                int payloadSize = 1 + (nodesCount * (CRYPTO_PUBLIC_KEY_SIZE + 18)); // 18 bytes por IPPort

                byte[] payload = new byte[payloadSize];
                payload[0] = 0x04; // SEND_NODES type

                int offset = 1;
                foreach (var node in nodes.Take(nodesCount))
                {
                    // Agregar public key del nodo (32 bytes)
                    Buffer.BlockCopy(node.PublicKey, 0, payload, offset, CRYPTO_PUBLIC_KEY_SIZE);
                    offset += CRYPTO_PUBLIC_KEY_SIZE;

                    // Agregar IPPort (18 bytes)
                    byte[] ippBytes = IPPortToBytes(node.EndPoint);
                    Buffer.BlockCopy(ippBytes, 0, payload, offset, 18);
                    offset += 18;
                }

                // Encriptar el payload
                return CreateCryptopacket(payload, payload.Length, destinationPublicKey, SelfSecretKey);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando send_nodes response: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// CreateEncryptedGetNodesPacket - Crea get_nodes request encriptado
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

        // ===== GESTIÓN DE NODOS KADEMLIA =====

        /// <summary>
        /// Agregar nodo a la tabla Kademlia
        /// </summary>
        public int AddNode(byte[] publicKey, IPPort endPoint)
        {
            if (publicKey?.Length != CRYPTO_PUBLIC_KEY_SIZE)
                return -1;

            try
            {
                var node = new DHTNode(publicKey, endPoint);
                bool added = routingTable.AddNode(node);

                if (added)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Nodo agregado a Kademlia: {endPoint}");
                }

                return added ? 0 : 1; // 0 = nuevo, 1 = actualizado
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error agregando nodo: {ex.Message}");
                return -1;
            }
        }

        // ===== FUNCIONES AUXILIARES =====

        /// <summary>
        /// IPPortToBytes - Convierte IPPort a array de bytes (18 bytes)
        /// </summary>
        private byte[] IPPortToBytes(IPPort ipp)
        {
            byte[] result = new byte[18];

            // IP (16 bytes)
            if (ipp.IP.Data != null)
            {
                Buffer.BlockCopy(ipp.IP.Data, 0, result, 0, 16);
            }

            // Puerto (2 bytes - big endian)
            result[16] = (byte)((ipp.Port >> 8) & 0xFF);
            result[17] = (byte)(ipp.Port & 0xFF);

            return result;
        }

        /// <summary>
        /// BytesToIPPort - Convierte array de bytes a IPPort
        /// </summary>
        private IPPort BytesToIPPort(byte[] data)
        {
            if (data == null || data.Length < 18)
                return new IPPort();

            try
            {
                // IP (primeros 16 bytes)
                byte[] ipData = new byte[16];
                Buffer.BlockCopy(data, 0, ipData, 0, 16);

                // Puerto (últimos 2 bytes - big endian)
                ushort port = (ushort)((data[16] << 8) | data[17]);

                // Determinar si es IPv4 o IPv6
                bool isIPv4 = true;
                for (int i = 0; i < 10; i++)
                {
                    if (ipData[i] != 0)
                    {
                        isIPv4 = false;
                        break;
                    }
                }

                IP ip;
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
            catch (Exception)
            {
                return new IPPort();
            }
        }

        /// <summary>
        /// Comparación segura de arrays de bytes
        /// </summary>
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            return CryptoVerify.Verify(a, b);
        }

        // ===== MANTENIMIENTO Y LIMPIEZA KADEMLIA =====

        /// <summary>
        /// Manejo de handshakes pendientes
        /// </summary>
        private DHTHandshake? FindHandshakeByTempKey(byte[] tempPublicKey, IPPort endPoint)
        {
            string targetKey = $"{endPoint}_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";

            lock (handshakesLock)
            {
                if (activeHandshakes.TryGetValue(targetKey, out var handshake))
                {
                    return handshake;
                }
            }
            return null;
        }

        private void RemoveHandshake(byte[] tempPublicKey, IPPort endPoint)
        {
            string handshakeKey = $"{endPoint}_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";

            lock (handshakesLock)
            {
                activeHandshakes.Remove(handshakeKey);
            }
        }

        /// <summary>
        /// Limpia handshakes expirados
        /// </summary>
        private void CleanupExpiredHandshakes()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * 30000; // 30 segundos
            int removed = 0;

            lock (handshakesLock)
            {
                var expiredKeys = new List<string>();

                foreach (var kvp in activeHandshakes)
                {
                    if (kvp.Value.CreationTime < cutoffTime)
                    {
                        expiredKeys.Add(kvp.Key);
                    }
                }

                foreach (var key in expiredKeys)
                {
                    activeHandshakes.Remove(key);
                    removed++;
                }
            }

            if (removed > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {removed} handshakes expirados removidos");
            }
        }

        /// <summary>
        /// DoPeriodicWork - Mantenimiento periódico completo Kademlia
        /// </summary>
        public void DoPeriodicWork()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;

                // 1. Limpieza de handshakes expirados
                CleanupExpiredHandshakes();

                // 2. Limpieza de buckets Kademlia
                int removed = routingTable.CleanupAllBuckets();
                if (removed > 0)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Limpieza Kademlia: {removed} nodos removidos");
                }

                // 3. Refresco de buckets que necesitan actualización
                var bucketsNeedingRefresh = routingTable.GetBucketsNeedingRefresh();
                foreach (int bucketIndex in bucketsNeedingRefresh)
                {
                    RefreshBucket(bucketIndex);
                }

                // 4. Re-bootstrap periódico
                if ((currentTime - lastBootstrapTime) > TimeSpan.TicksPerSecond * 300) // 5 minutos
                {
                    foreach (var bootstrapNode in bootstrapNodes)
                    {
                        DHT_bootstrap(bootstrapNode.IPPort, bootstrapNode.PublicKey);
                    }
                    lastBootstrapTime = currentTime;
                }

                // 5. Logging periódico
                if ((currentTime - lastLogTime) > TimeSpan.TicksPerSecond * 30) // 30 segundos
                {
                    var allNodes = routingTable.GetAllNodes();
                    int activeCount = allNodes.Count(n => n.IsActive);
                    Logger.Log.DebugF($"[{LOG_TAG}] Kademlia Stats - Total: {allNodes.Count}, Activos: {activeCount}, Buckets: {GetActiveBucketCount()}");
                    lastLogTime = currentTime;
                }

                // 6. Rotación de claves temporales
                EnsureTempKeys();

            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico Kademlia: {ex.Message}");
            }
        }

        /// <summary>
        /// Refresca un bucket Kademlia específico
        /// </summary>
        private void RefreshBucket(int bucketIndex)
        {
            try
            {
                // Generar un ID aleatorio que caiga en este bucket
                byte[] randomId = GenerateRandomIdForBucket(bucketIndex);

                // Hacer búsqueda de nodos para este ID
                var closestNodes = routingTable.FindClosestNodes(randomId, ALPHA);

                foreach (var node in closestNodes)
                {
                    // Enviar get_nodes request
                    byte[] requestPacket = CreateEncryptedGetNodesPacket(node.PublicKey, randomId);
                    if (requestPacket != null)
                    {
                        DHT_send_packet(node.EndPoint, requestPacket, requestPacket.Length);
                    }
                }

                Logger.Log.DebugF($"[{LOG_TAG}] Bucket {bucketIndex} refrescado");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error refrescando bucket {bucketIndex}: {ex.Message}");
            }
        }

        /// <summary>
        /// Genera un ID aleatorio que caiga en un bucket específico
        /// </summary>
        private byte[] GenerateRandomIdForBucket(int bucketIndex)
        {
            byte[] randomId = new byte[CRYPTO_PUBLIC_KEY_SIZE];
            RandomNumberGenerator.Fill(randomId);

            // Asegurar que el ID caiga en el bucket deseado
            if (bucketIndex > 0)
            {
                int byteIndex = bucketIndex / 8;
                int bitIndex = bucketIndex % 8;

                // Forzar el bit en la posición correcta
                if (byteIndex < randomId.Length)
                {
                    byte mask = (byte)(1 << (7 - bitIndex));
                    randomId[byteIndex] = (byte)((randomId[byteIndex] & ~mask) | mask);
                }
            }

            return randomId;
        }

        /// <summary>
        /// Obtiene el número de buckets activos
        /// </summary>
        private int GetActiveBucketCount()
        {
            int activeCount = 0;
            for (int i = 0; i < 256; i++)
            {
                if (routingTable.FindClosestNodes(SelfPublicKey, 1).Count > 0)
                {
                    activeCount++;
                }
            }
            return activeCount;
        }

        // ===== FUNCIONES DE UTILIDAD =====

        /// <summary>
        /// Obtiene nodos más cercanos (versión cacheada para compatibilidad)
        /// </summary>
        public List<DHTNode> GetClosestNodesCached(byte[] targetPublicKey, int maxNodes = 8)
        {
            return routingTable.FindClosestNodes(targetPublicKey, maxNodes);
        }

        /// <summary>
        /// Obtiene nodos más cercanos usando Kademlia
        /// </summary>
        public List<DHTNode> GetClosestNodes(byte[] targetKey, int maxNodes = MAX_FRIEND_CLOSE)
        {
            return routingTable.FindClosestNodes(targetKey, maxNodes);
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

            bootstrapNodes.Clear();
            activeHandshakes.Clear();
        }

        /// <summary>
        /// Imprime estadísticas de Kademlia
        /// </summary>
        public void PrintStatistics()
        {
            var allNodes = routingTable.GetAllNodes();
            int activeCount = allNodes.Count(n => n.IsActive);
            int bucketCount = GetActiveBucketCount();

            Console.WriteLine($"[DHT Kademlia] Statistics:");
            Console.WriteLine($" Total Nodes: {allNodes.Count}");
            Console.WriteLine($" Active Nodes: {activeCount}");
            Console.WriteLine($" Active Buckets: {bucketCount}");
            Console.WriteLine($" Bootstrap Nodes: {bootstrapNodes.Count}");
            Console.WriteLine($" Socket: {(Socket == -1 ? "Closed" : "Open")}");
        }
    }
}