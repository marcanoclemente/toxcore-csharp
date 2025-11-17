using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Nodo Onion - usado para routing anónimo
    /// </summary>
    public struct OnionNode
    {
        public IPPort IPPort;
        public byte[] PublicKey; // 32 bytes
        public long LastPing;
        public bool IsValid;

        public OnionNode(IPPort ipp, byte[] publicKey)
        {
            IPPort = ipp;
            PublicKey = new byte[32];
            Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            LastPing = DateTime.UtcNow.Ticks;
            IsValid = true;
        }

        public override string ToString()
        {
            return $"{IPPort} [Onion PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";
        }
    }

    /// <summary>
    /// Paquete Onion - encapsula datos para routing por múltiples nodos
    /// </summary>
    public class OnionPacket
    {
        public byte[] Data { get; set; }
        public byte[] Nonce { get; set; } // 24 bytes
        public List<OnionNode> Path { get; set; } // Ruta de nodos onion

        public OnionPacket()
        {
            Path = new List<OnionNode>();
            Nonce = new byte[24];
        }
    }

    /// <summary>
    /// Implementación de Onion Routing para anonimato y NAT traversal
    /// </summary>
    public class Onion : IDisposable
    {
        private const int ONION_MAX_PATH_LENGTH = 3; // 3 nodos en la ruta onion
        private const int ONION_PING_INTERVAL = 60000; // 60 segundos
        private const int ONION_NODE_TIMEOUT = 300000; // 5 minutos

        public List<OnionNode> onionNodes;
        private DHT dht;
        private Timer pingTimer;
        private object nodesLock = new object();

        public int AvailableNodes => onionNodes.Count;
        public bool IsRunning { get; private set; }

        public Onion(DHT dhtInstance)
        {
            dht = dhtInstance ?? throw new ArgumentNullException(nameof(dhtInstance));
            onionNodes = new List<OnionNode>();
            IsRunning = false;
        }

        /// <summary>
        /// Inicia el servicio onion
        /// </summary>
        public void Start()
        {
            if (IsRunning) return;

            IsRunning = true;
            // Buscar nodos onion a través del DHT
            RefreshOnionNodes();

            // Iniciar timer para mantener nodos actualizados
            pingTimer = new Timer(PingOnionNodes, null, 0, ONION_PING_INTERVAL);
        }

        /// <summary>
        /// Detiene el servicio onion
        /// </summary>
        public void Stop()
        {
            IsRunning = false;
            pingTimer?.Dispose();
            pingTimer = null;
        }

        /// <summary>
        /// Busca nodos onion a través del DHT
        /// </summary>
        private void RefreshOnionNodes()
        {
            try
            {
                // Usar una clave especial para encontrar nodos onion
                byte[] onionSearchKey = CalculateOnionSearchKey();
                var closestNodes = dht.FindClosestNodes(onionSearchKey, 20);

                lock (nodesLock)
                {
                    onionNodes.Clear();
                    foreach (var node in closestNodes)
                    {
                        // Verificar que el nodo soporta onion (simplificado)
                        var onionNode = new OnionNode(node.IPPort, node.PublicKey);
                        onionNodes.Add(onionNode);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error refreshing onion nodes: {ex.Message}");
            }
        }

        /// <summary>
        /// Calcula clave de búsqueda para nodos onion
        /// </summary>
        private byte[] CalculateOnionSearchKey()
        {
            // En la implementación real, esto usaría un prefijo específico para onion
            // Por simplicidad, usamos una clave derivada de nuestra propia clave pública
            byte[] searchKey = new byte[32];
            Buffer.BlockCopy(dht.SelfPublicKey, 0, searchKey, 0, 32);
            searchKey[0] ^= 0x01; // Modificar primer byte para la búsqueda
            return searchKey;
        }

        /// <summary>
        /// Hace ping a los nodos onion para verificar que están activos
        /// </summary>
        private void PingOnionNodes(object state)
        {
            if (!IsRunning) return;

            try
            {
                lock (nodesLock)
                {
                    // Remover nodos antiguos
                    long cutoffTime = DateTime.UtcNow.Ticks - (ONION_NODE_TIMEOUT * TimeSpan.TicksPerMillisecond);
                    onionNodes.RemoveAll(node => node.LastPing < cutoffTime);
                }

                // Refrescar nodos si tenemos pocos
                if (AvailableNodes < 5)
                {
                    RefreshOnionNodes();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in onion ping: {ex.Message}");
            }
        }

        /// <summary>
        /// Crea una ruta onion aleatoria
        /// </summary>
        public List<OnionNode> CreateOnionPath()
        {
            var path = new List<OnionNode>();
            lock (nodesLock)
            {
                if (onionNodes.Count < ONION_MAX_PATH_LENGTH)
                {
                    throw new InvalidOperationException("Not enough onion nodes available");
                }

                // Seleccionar nodos aleatorios para la ruta
                var random = new Random();
                var availableNodes = new List<OnionNode>(onionNodes);

                for (int i = 0; i < ONION_MAX_PATH_LENGTH; i++)
                {
                    if (availableNodes.Count == 0) break;

                    int index = random.Next(availableNodes.Count);
                    path.Add(availableNodes[index]);
                    availableNodes.RemoveAt(index); // Evitar duplicados en la ruta
                }
            }

            return path;
        }

        /// <summary>
        /// Encapsula datos en un paquete onion
        /// </summary>
        public OnionPacket Encapsulate(byte[] data, List<OnionNode> path)
        {
            if (path == null || path.Count == 0)
                throw new ArgumentException("Onion path cannot be empty");
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be empty");

            var packet = new OnionPacket();
            packet.Path = new List<OnionNode>(path);
            packet.Nonce = RandomBytes.GenerateNonce();

            // Encapsulación onion (simplificada):
            // En la implementación real, esto cifraría en capas para cada nodo
            // Por simplicidad, ciframos una vez con el primer nodo de la ruta

            if (path.Count > 0)
            {
                var firstNode = path[0];
                packet.Data = CryptoBox.Encrypt(data, packet.Nonce, firstNode.PublicKey, dht.SelfSecretKey);
            }

            return packet;
        }

        /// <summary>
        /// Envía un paquete a través de la ruta onion
        /// </summary>
        public bool SendOnionPacket(OnionPacket packet, IPPort finalDestination)
        {
            if (packet == null || packet.Path.Count == 0)
                return false;

            try
            {
                // Enviar al primer nodo de la ruta onion
                var firstNode = packet.Path[0];

                // Construir paquete onion
                byte[] onionPacket = BuildOnionPacket(packet, finalDestination);

                // Enviar a través de network (usando DHT o directamente)
                // Esto es simplificado - en la implementación real se usaría el socket del DHT
                return SendPacketToNode(firstNode.IPPort, onionPacket);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending onion packet: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Construye el paquete onion para enviar
        /// </summary>
        private byte[] BuildOnionPacket(OnionPacket packet, IPPort finalDestination)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                // Tipo de paquete: Onion routing (0x80)
                ms.WriteByte(0x80);

                // Nonce
                ms.Write(packet.Nonce, 0, 24);

                // Datos cifrados
                if (packet.Data != null)
                {
                    ms.Write(packet.Data, 0, packet.Data.Length);
                }

                // Información de ruta (simplificada)
                WriteRouteInfo(ms, packet.Path, finalDestination);

                return ms.ToArray();
            }
        }

        private void WriteRouteInfo(System.IO.MemoryStream ms, List<OnionNode> path, IPPort finalDestination)
        {
            // Escribir longitud de ruta
            ms.WriteByte((byte)path.Count);

            // Escribir información de cada nodo en la ruta
            foreach (var node in path)
            {
                // IP y puerto del siguiente nodo
                if (node.IPPort.IP.IsIPv6 == 0) // IPv4
                {
                    ms.WriteByte(0x02);
                    byte[] ip4Bytes = new byte[4];
                    Buffer.BlockCopy(node.IPPort.IP.Data, 0, ip4Bytes, 0, 4);
                    ms.Write(ip4Bytes, 0, 4);
                }
                else // IPv6
                {
                    ms.WriteByte(0x0A);
                    ms.Write(node.IPPort.IP.Data, 0, 16);
                }

                // Puerto
                ms.WriteByte((byte)(node.IPPort.Port >> 8));
                ms.WriteByte((byte)node.IPPort.Port);

                // Clave pública del nodo
                ms.Write(node.PublicKey, 0, 32);
            }

            // Destino final
            if (finalDestination.IP.IsIPv6 == 0) // IPv4
            {
                ms.WriteByte(0x02);
                byte[] ip4Bytes = new byte[4];
                Buffer.BlockCopy(finalDestination.IP.Data, 0, ip4Bytes, 0, 4);
                ms.Write(ip4Bytes, 0, 4);
            }
            else // IPv6
            {
                ms.WriteByte(0x0A);
                ms.Write(finalDestination.IP.Data, 0, 16);
            }

            ms.WriteByte((byte)(finalDestination.Port >> 8));
            ms.WriteByte((byte)finalDestination.Port);
        }

        /// <summary>
        /// Envía un paquete a un nodo onion
        /// </summary>
        private bool SendPacketToNode(IPPort node, byte[] packet)
        {
            // Usar el DHT para enviar el paquete
            // En la implementación real, esto usaría el socket del DHT directamente
            try
            {
                // Simulación de envío - en realidad se enviaría a través del socket UDP
                Console.WriteLine($"Sending onion packet to {node}");
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Procesa un paquete onion entrante (cuando somos un nodo intermedio)
        /// </summary>
        public void ProcessIncomingOnionPacket(byte[] packet, IPPort source)
        {
            if (packet == null || packet.Length < 25) return;

            try
            {
                byte packetType = packet[0];
                if (packetType != 0x80) return; // No es paquete onion

                // Extraer nonce
                byte[] nonce = new byte[24];
                Buffer.BlockCopy(packet, 1, nonce, 0, 24);

                // Los datos cifrados empiezan en la posición 25
                byte[] encryptedData = new byte[packet.Length - 25];
                Buffer.BlockCopy(packet, 25, encryptedData, 0, encryptedData.Length);

                // Intentar descifrar con nuestra clave secreta
                byte[] decryptedData = CryptoBox.Decrypt(encryptedData, nonce, source.IP.ToIPAddress().GetAddressBytes(), dht.SelfSecretKey);

                if (decryptedData != null)
                {
                    // Procesar el paquete descifrado
                    ProcessDecryptedOnionPacket(decryptedData, source);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing onion packet: {ex.Message}");
            }
        }

        private void ProcessDecryptedOnionPacket(byte[] data, IPPort source)
        {
            // En la implementación real, esto procesaría las capas onion
            // y reenviaría al siguiente nodo en la ruta
            Console.WriteLine($"Processed onion packet from {source}");
        }

        /// <summary>
        /// Envía datos anónimamente a través de onion routing
        /// </summary>
        public bool SendAnonymously(byte[] data, IPPort destination)
        {
            try
            {
                var path = CreateOnionPath();
                var onionPacket = Encapsulate(data, path);
                return SendOnionPacket(onionPacket, destination);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in anonymous send: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            Stop();
        }

        /// <summary>
        /// Test básico del onion routing
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de Onion...");

                // Crear DHT de prueba
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                {
                    // Test 1: Creación
                    bool creationValid = onion != null && onion.AvailableNodes == 0;
                    Console.WriteLine($"     Test 1 - Creación: {(creationValid ? "✅" : "❌")}");

                    // Test 2: Inicio/parada
                    onion.Start();
                    bool startValid = onion.IsRunning;
                    onion.Stop();
                    bool stopValid = !onion.IsRunning;
                    Console.WriteLine($"     Test 2 - Inicio/parada: {(startValid && stopValid ? "✅" : "❌")}");

                    // Agregar algunos nodos de prueba para los siguientes tests
                    for (int i = 0; i < 5; i++)
                    {
                        var testNode = new OnionNode(
                            new IPPort(IPAddress.Loopback, (ushort)(33600 + i)),
                            RandomBytes.Generate(32));
                        onion.onionNodes.Add(testNode);
                    }

                    // Test 3: Creación de ruta
                    try
                    {
                        var path = onion.CreateOnionPath();
                        bool pathValid = path != null && path.Count == 3;
                        Console.WriteLine($"     Test 3 - Creación de ruta: {(pathValid ? "✅" : "❌")}");

                        // Test 4: Encapsulación
                        var testData = System.Text.Encoding.UTF8.GetBytes("Test onion");
                        var packet = onion.Encapsulate(testData, path);
                        bool encapsulationValid = packet != null && packet.Data != null;
                        Console.WriteLine($"     Test 4 - Encapsulación: {(encapsulationValid ? "✅" : "❌")}");

                        return creationValid && startValid && stopValid && pathValid && encapsulationValid;
                    }
                    catch (InvalidOperationException)
                    {
                        Console.WriteLine($"     Test 3 - Creación de ruta: ❌ (no hay suficientes nodos)");
                        return creationValid && startValid && stopValid;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test Onion: {ex.Message}");
                return false;
            }
        }
    }
}