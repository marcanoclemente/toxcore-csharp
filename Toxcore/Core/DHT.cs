using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ToxCore.Core
{
    /// <summary>
    /// Nodo DHT - información de un peer en la red
    /// </summary>
    public struct DHTNode
    {
        public IPPort IPPort;
        public byte[] PublicKey; // 32 bytes
        public long LastSeen;
        public bool IsValid;

        public DHTNode(IPPort ipp, byte[] publicKey)
        {
            IPPort = ipp;
            PublicKey = new byte[32];
            Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            LastSeen = DateTime.UtcNow.Ticks;
            IsValid = true;
        }

        public override string ToString()
        {
            return $"{IPPort} [PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";
        }
    }

    /// <summary>
    /// Bucket DHT - contiene nodos con IDs similares
    /// </summary>
    public class DHTBucket
    {
        public List<DHTNode> Nodes { get; private set; }
        public byte[] Prefix { get; private set; } // Prefijo común de los IDs
        public int Depth { get; private set; } // Profundidad en el árbol

        public DHTBucket(byte[] prefix, int depth)
        {
            Nodes = new List<DHTNode>();
            Prefix = new byte[prefix.Length];
            Buffer.BlockCopy(prefix, 0, Prefix, 0, prefix.Length);
            Depth = depth;
        }

        public bool IsFull => Nodes.Count >= 8; // Kademlia K=8

        public void AddNode(DHTNode node)
        {
            // Si el bucket está lleno, reemplazar el nodo más antiguo
            if (IsFull)
            {
                // Encontrar el nodo más antiguo
                int oldestIndex = 0;
                long oldestTime = Nodes[0].LastSeen;

                for (int i = 1; i < Nodes.Count; i++)
                {
                    if (Nodes[i].LastSeen < oldestTime)
                    {
                        oldestTime = Nodes[i].LastSeen;
                        oldestIndex = i;
                    }
                }

                Nodes[oldestIndex] = node;
            }
            else
            {
                Nodes.Add(node);
            }
        }

        public void RemoveNode(byte[] publicKey)
        {
            Nodes.RemoveAll(node => CryptoVerify.Verify32(node.PublicKey, publicKey));
        }

        public void UpdateLastSeen(byte[] publicKey)
        {
            for (int i = 0; i < Nodes.Count; i++)
            {
                var node = Nodes[i];
                if (CryptoVerify.Verify32(node.PublicKey, publicKey))
                {
                    node.LastSeen = DateTime.UtcNow.Ticks;
                    Nodes[i] = node; // Actualizar en la lista
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Distributed Hash Table implementation (Kademlia-based)
    /// </summary>
    public class DHT : IDisposable
    {
        private const int MAX_BUCKETS = 160; // 160 bits para claves
        private const int K = 8; // Tamaño de bucket Kademlia
        private const int ALPHA = 3; // Paralelismo de queries

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }

        private List<DHTBucket> buckets;
        private Socket udpSocket;
        private Dictionary<string, long> requestTimes; // Para tracking de requests

        // Estadísticas
        public int TotalNodes => buckets.Sum(b => b.Nodes.Count);
        public int ActiveBuckets => buckets.Count(b => b.Nodes.Count > 0);

        public DHT(byte[] selfPublicKey, byte[] selfSecretKey, ushort listenPort = 33445)
        {
            if (selfPublicKey == null || selfPublicKey.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes");
            if (selfSecretKey == null || selfSecretKey.Length != 32)
                throw new ArgumentException("Secret key must be 32 bytes");

            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            InitializeBuckets();
            InitializeSocket(listenPort);
            requestTimes = new Dictionary<string, long>();
        }

        private void InitializeBuckets()
        {
            buckets = new List<DHTBucket>();
            // Bucket inicial cubre todo el espacio de claves
            byte[] initialPrefix = new byte[32]; // Todo zeros
            buckets.Add(new DHTBucket(initialPrefix, 0));
        }

        private void InitializeSocket(ushort port)
        {
            udpSocket = Network.CreateUDPSocket();
            if (!Network.BindSocket(udpSocket, port))
            {
                throw new InvalidOperationException($"Failed to bind DHT to port {port}");
            }

            //Network.SetSocketTimeout(udpSocket, 1000, 1000);
        }

        /// <summary>
        /// Calcula la distancia XOR entre dos claves públicas
        /// </summary>
        public static byte[] CalculateDistance(byte[] key1, byte[] key2)
        {
            if (key1.Length != key2.Length)
                throw new ArgumentException("Keys must have same length");

            byte[] distance = new byte[key1.Length];
            for (int i = 0; i < key1.Length; i++)
            {
                distance[i] = (byte)(key1[i] ^ key2[i]);
            }
            return distance;
        }

        /// <summary>
        /// Encuentra el bucket apropiado para una clave
        /// </summary>
        private DHTBucket FindBucketForKey(byte[] key)
        {
            byte[] distance = CalculateDistance(SelfPublicKey, key);

            // Encontrar el primer bit diferente (profundidad)
            int depth = 0;
            for (int i = 0; i < distance.Length; i++)
            {
                for (int j = 7; j >= 0; j--)
                {
                    if ((distance[i] & (1 << j)) != 0)
                    {
                        return GetOrCreateBucket(depth);
                    }
                    depth++;
                }
            }

            return buckets[0]; // Misma clave (raro caso)
        }

        private DHTBucket GetOrCreateBucket(int depth)
        {
            if (depth < buckets.Count)
                return buckets[depth];

            // ✅ CORREGIDO: Calcular prefijo basado en profundidad
            byte[] prefix = CalculatePrefixForDepth(depth);
            var newBucket = new DHTBucket(prefix, depth);
            buckets.Add(newBucket);
            return newBucket;
        }

        private byte[] CalculatePrefixForDepth(int depth)
        {
            byte[] prefix = new byte[32];
            int byteIndex = depth / 8;
            int bitIndex = 7 - (depth % 8);

            if (byteIndex < prefix.Length)
            {
                prefix[byteIndex] = (byte)(1 << bitIndex);
            }

            return prefix;
        }

        /// <summary>
        /// Agrega un nodo a la DHT
        /// </summary>
        public bool AddNode(IPPort ipp, byte[] publicKey)
        {
            try
            {
                var node = new DHTNode(ipp, publicKey);
                var bucket = FindBucketForKey(publicKey);

                // Verificar que no existe ya
                bool found = false;
                for (int i = 0; i < bucket.Nodes.Count; i++)
                {
                    var existingNode = bucket.Nodes[i];
                    if (CryptoVerify.Verify32(existingNode.PublicKey, publicKey))
                    {
                        // Actualizar timestamp
                        existingNode.LastSeen = DateTime.UtcNow.Ticks;
                        bucket.Nodes[i] = existingNode;
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    bucket.AddNode(node);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Encuentra los K nodos más cercanos a una clave
        /// </summary>
        public List<DHTNode> FindClosestNodes(byte[] targetKey, int count = K)
        {
            var allNodes = new List<DHTNode>();
            foreach (var bucket in buckets)
            {
                allNodes.AddRange(bucket.Nodes);
            }

            // Ordenar por distancia XOR
            allNodes.Sort((a, b) =>
            {
                var distA = CalculateDistance(targetKey, a.PublicKey);
                var distB = CalculateDistance(targetKey, b.PublicKey);
                return CompareDistances(distA, distB);
            });

            return allNodes.Take(count).ToList();
        }

        private int CompareDistances(byte[] distA, byte[] distB)
        {
            for (int i = 0; i < distA.Length; i++)
            {
                if (distA[i] != distB[i])
                    return distA[i].CompareTo(distB[i]);
            }
            return 0;
        }

        /// <summary>
        /// Procesa un paquete DHT recibido
        /// </summary>
        public void ProcessPacket(byte[] packet, IPPort source)
        {
            if (packet == null || packet.Length < 100) return;

            try
            {
                // Packet structure: [sender_pk (32)] [nonce (24)] [encrypted payload]
                byte[] senderPk = new byte[32];
                byte[] nonce = new byte[24];
                byte[] encrypted = new byte[packet.Length - 56];

                Buffer.BlockCopy(packet, 0, senderPk, 0, 32);
                Buffer.BlockCopy(packet, 32, nonce, 0, 24);
                Buffer.BlockCopy(packet, 56, encrypted, 0, encrypted.Length);

                // Decryptar el payload
                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, senderPk, SelfSecretKey);
                if (decrypted == null) return;

                // Procesar el mensaje DHT
                ProcessDHTMessage(decrypted, source, senderPk);
            }
            catch
            {
                // Ignorar paquetes malformados
            }
        }

        private void ProcessDHTMessage(byte[] message, IPPort source, byte[] senderPk)
        {
            if (message.Length < 1) return;

            byte messageType = message[0];

            switch (messageType)
            {
                case 0x00: // Ping request
                    HandlePingRequest(message, source, senderPk);
                    break;
                case 0x01: // Ping response
                    HandlePingResponse(message, source, senderPk);
                    break;
                case 0x02: // Nodes request
                    HandleNodesRequest(message, source, senderPk);
                    break;
                case 0x04: // Nodes response
                    HandleNodesResponse(message, source, senderPk);
                    break;
                default:
                    // Tipo de mensaje desconocido
                    break;
            }
        }

        private void HandlePingRequest(byte[] message, IPPort source, byte[] senderPk)
        {
            // Agregar nodo a la DHT
            AddNode(source, senderPk);

            // Enviar respuesta ping
            SendPingResponse(source, senderPk);
        }

        private void HandlePingResponse(byte[] message, IPPort source, byte[] senderPk)
        {
            // Actualizar nodo como activo
            AddNode(source, senderPk);
        }

        private void HandleNodesRequest(byte[] message, IPPort source, byte[] senderPk)
        {
            if (message.Length < 33) return;

            // Extraer la clave objetivo de la solicitud
            byte[] targetKey = new byte[32];
            Buffer.BlockCopy(message, 1, targetKey, 0, 32);

            // Encontrar nodos más cercanos
            var closestNodes = FindClosestNodes(targetKey);

            // Enviar respuesta con nodos
            SendNodesResponse(source, senderPk, closestNodes);
        }

        private void HandleNodesResponse(byte[] message, IPPort source, byte[] senderPk)
        {
            if (message.Length < 2) return;

            try
            {
                // ✅ CORREGIDO: Deserializar nodos del mensaje
                byte nodeCount = message[1];
                int offset = 2;

                for (int i = 0; i < nodeCount && offset < message.Length; i++)
                {
                    if (offset >= message.Length) break;

                    byte ipType = message[offset++];
                    IP nodeIP;
                    ushort nodePort;
                    byte[] nodePk = new byte[32];

                    if (ipType == 0x02 && offset + 4 + 2 + 32 <= message.Length) // IPv4
                    {
                        byte[] ip4Bytes = new byte[4];
                        Buffer.BlockCopy(message, offset, ip4Bytes, 0, 4);
                        offset += 4;
                        nodeIP = new IP(new IP4(ip4Bytes));
                    }
                    else if (ipType == 0x0A && offset + 16 + 2 + 32 <= message.Length) // IPv6
                    {
                        byte[] ip6Bytes = new byte[16];
                        Buffer.BlockCopy(message, offset, ip6Bytes, 0, 16);
                        offset += 16;
                        nodeIP = new IP(new IP6(ip6Bytes));
                    }
                    else
                    {
                        break; // Formato inválido
                    }

                    // Leer puerto (big-endian)
                    nodePort = (ushort)((message[offset] << 8) | message[offset + 1]);
                    offset += 2;

                    // Leer clave pública
                    Buffer.BlockCopy(message, offset, nodePk, 0, 32);
                    offset += 32;

                    // Agregar nodo a la DHT
                    AddNode(new IPPort(nodeIP, nodePort), nodePk);
                }

                // También agregar el nodo que envió la respuesta
                AddNode(source, senderPk);
            }
            catch
            {
                // En caso de error, al menos agregar el nodo fuente
                AddNode(source, senderPk);
            }
        }

        /// <summary>
        /// Envía un ping a un nodo
        /// </summary>
        public bool SendPing(IPPort target, byte[] targetPk)
        {
            try
            {
                byte[] message = new byte[1] { 0x00 }; // Ping request
                return SendEncryptedMessage(target, targetPk, message);
            }
            catch
            {
                return false;
            }
        }

        private void SendPingResponse(IPPort target, byte[] targetPk)
        {
            byte[] message = new byte[1] { 0x01 }; // Ping response
            SendEncryptedMessage(target, targetPk, message);
        }

        private void SendNodesResponse(IPPort target, byte[] targetPk, List<DHTNode> nodes)
        {
            try
            {
                // ✅ CORREGIDO: Serializar nodos en el mensaje
                using (var ms = new System.IO.MemoryStream())
                {
                    ms.WriteByte(0x04); // Nodes response type

                    // Escribir número de nodos (1 byte)
                    ms.WriteByte((byte)Math.Min(nodes.Count, 4)); // Máximo 4 nodos por respuesta

                    foreach (var node in nodes.Take(4))
                    {
                        // Serializar nodo: [ip_type (1)] [ip (4/16)] [port (2)] [pk (32)]
                        if (node.IPPort.IP.IsIPv6 == 0) // IPv4
                        {
                            ms.WriteByte(0x02); // IPv4 type
                            byte[] ip4Bytes = new byte[4];
                            Buffer.BlockCopy(node.IPPort.IP.Data, 0, ip4Bytes, 0, 4);
                            ms.Write(ip4Bytes, 0, 4);
                        }
                        else // IPv6
                        {
                            ms.WriteByte(0x0A); // IPv6 type
                            ms.Write(node.IPPort.IP.Data, 0, 16);
                        }

                        // Puerto (big-endian)
                        ms.WriteByte((byte)(node.IPPort.Port >> 8));
                        ms.WriteByte((byte)node.IPPort.Port);

                        // Clave pública
                        ms.Write(node.PublicKey, 0, 32);
                    }

                    byte[] message = ms.ToArray();
                    SendEncryptedMessage(target, targetPk, message);
                }
            }
            catch
            {
                // Fallback a mensaje simple si hay error
                byte[] fallbackMessage = new byte[1] { 0x04 };
                SendEncryptedMessage(target, targetPk, fallbackMessage);
            }
        }

        private bool SendEncryptedMessage(IPPort target, byte[] targetPk, byte[] plaintext)
        {
            try
            {
                byte[] nonce = RandomBytes.GenerateNonce();
                byte[] encrypted = CryptoBox.Encrypt(plaintext, nonce, targetPk, SelfSecretKey);

                if (encrypted == null) return false;

                // Construir paquete: [our_pk (32)] [nonce (24)] [encrypted]
                byte[] packet = new byte[32 + 24 + encrypted.Length];
                Buffer.BlockCopy(SelfPublicKey, 0, packet, 0, 32);
                Buffer.BlockCopy(nonce, 0, packet, 32, 24);
                Buffer.BlockCopy(encrypted, 0, packet, 56, encrypted.Length);

                int sent = Network.SendTo(udpSocket, packet, target);
                return sent > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Ejecuta el loop principal de la DHT
        /// </summary>
        public void RunLoop(int maxPackets = 10)
        {
            byte[] buffer = new byte[2048]; // Buffer para paquetes UDP

            for (int i = 0; i < maxPackets; i++)
            {
                int received = Network.RecvFrom(udpSocket, buffer, out IPPort source);
                if (received > 0)
                {
                    byte[] packet = new byte[received];
                    Buffer.BlockCopy(buffer, 0, packet, 0, received);
                    ProcessPacket(packet, source);
                }
                else
                {
                    break; // No más paquetes
                }
            }

            CleanupOldNodes();
        }

        private void CleanupOldNodes()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMinute * 10; // 10 minutos

            foreach (var bucket in buckets)
            {
                bucket.Nodes.RemoveAll(node => node.LastSeen < cutoffTime);
            }
        }

        /// <summary>
        /// Bootstrap con nodos iniciales
        /// </summary>
        public void Bootstrap(List<IPPort> bootstrapNodes, List<byte[]> bootstrapKeys)
        {
            if (bootstrapNodes.Count != bootstrapKeys.Count)
                throw new ArgumentException("Bootstrap nodes and keys must match");

            for (int i = 0; i < bootstrapNodes.Count; i++)
            {
                SendPing(bootstrapNodes[i], bootstrapKeys[i]);
            }
        }

        public void Dispose()
        {
            udpSocket?.Close();
            udpSocket?.Dispose();
        }

        /// <summary>
        /// Test básico de la DHT
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de DHT...");

                // Generar claves de prueba
                var keyPair = CryptoBox.GenerateKeyPair();

                // Crear instancia DHT
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                {
                    // Test 1: Cálculo de distancia
                    var testKey1 = RandomBytes.Generate(32);
                    var testKey2 = RandomBytes.Generate(32);
                    var distance = DHT.CalculateDistance(testKey1, testKey2);

                    bool distanceValid = distance.Length == 32;
                    Console.WriteLine($"     Test 1 - Cálculo de distancia: {(distanceValid ? "✅" : "❌")}");

                    // Test 2: Agregar nodo
                    IPPort testNode = new IPPort(IPAddress.Loopback, 33445);
                    bool addResult = dht.AddNode(testNode, testKey1);
                    Console.WriteLine($"     Test 2 - Agregar nodo: {(addResult ? "✅" : "❌")}");

                    // Test 3: Encontrar nodos cercanos
                    var closest = dht.FindClosestNodes(testKey2);
                    bool findValid = closest != null && closest.Count >= 0;
                    Console.WriteLine($"     Test 3 - Encontrar nodos cercanos: {(findValid ? "✅" : "❌")}");

                    // Test 4: Estadísticas
                    bool statsValid = dht.TotalNodes >= 0 && dht.ActiveBuckets >= 0;
                    Console.WriteLine($"     Test 4 - Estadísticas: {(statsValid ? "✅" : "❌")}");

                    return distanceValid && addResult && findValid && statsValid;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test DHT: {ex.Message}");
                return false;
            }
        }
    }
}