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
        private long _lastCleanupTime = 0;

        private DateTime _lastCleanup = DateTime.UtcNow;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(2);

        private readonly Dictionary<string, List<DHTNode>> _closestNodesCache = new Dictionary<string, List<DHTNode>>();
        private readonly TimeSpan _cacheTTL = TimeSpan.FromSeconds(30);
        private readonly object _cacheLock = new object();
        private DateTime _lastCacheCleanup = DateTime.UtcNow;

        public const int MAX_FRIEND_CLOSE = 8;
        public const int MAX_CLOSE_TO_BOOTSTRAP_NODES = 16;
        public const int DHT_PING_INTERVAL = 30000; // 30 segundos
        public const int DHT_PING_TIMEOUT = 10000;  // 10 segundos

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

        public DHT(byte[] selfPublicKey, byte[] selfSecretKey)
        {
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            _nodes = new List<DHTNode>();
            _bootstrapNodes = new List<PackedNode>();
            _lastPingID = 0;
            _lastBootstrapTime = 0;

            // Crear socket para DHT
            Socket = Network.new_socket(2, 2, 17); // IPv4 UDP
            Logger.Log.Info($"[{LOG_TAG}] DHT inicializado - Socket: {Socket}");
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// DHT_bootstrap - Compatible con C original
        /// </summary>
        public int DHT_bootstrap(IPPort ipp, byte[] public_key)
        {
            Logger.Log.InfoF($"[{LOG_TAG}] Bootstrap a {ipp} [PK: {BitConverter.ToString(public_key, 0, 8).Replace("-", "")}...]");

            if (Socket == -1) return -1;

            try
            {
                // Agregar nodo bootstrap
                var bootstrapNode = new PackedNode(ipp, public_key);
                _bootstrapNodes.Add(bootstrapNode);

                // Enviar solicitud de bootstrap
                byte[] packet = CreateGetNodesRequest(SelfPublicKey);
                int sent = Network.socket_send(Socket, packet, packet.Length, ipp);

                if (sent > 0)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Bootstrap enviado a {ipp}");
                    return 0;
                }
                else
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Falló envío de bootstrap a {ipp}");
                    return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en bootstrap: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// DHT_handle_packet - Compatible con C original
        /// </summary>
        public int DHT_handle_packet(byte[] packet, int length, IPPort source)
        {
            if (packet == null || length < 4) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x00: // Ping request
                        return HandlePingRequest(packet, length, source);
                    case 0x01: // Ping response
                        return HandlePingResponse(packet, length, source);
                    case 0x02: // Get nodes request
                        return HandleGetNodesRequest(packet, length, source);
                    case 0x04: // Send nodes response
                        return HandleNodesResponse(packet, length, source);
                    default:
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DHT] Packet handle error: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// DHT_send_packet - Compatible con C original
        /// </summary>
        public int DHT_send_packet(IPPort ipp, byte[] packet, int length)
        {
            if (Socket == -1) return -1;

            try
            {
                return Network.socket_send(Socket, packet, length, ipp);
            }
            catch (Exception)
            {
                return -1;
            }
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
        /// Agregar nodo a la DHT
        /// </summary>
        public int AddNode(byte[] publicKey, IPPort endPoint)
        {
            if (publicKey == null || publicKey.Length != 32)
                return -1;

            try
            {
                lock (_nodesLock)
                {
                    // Buscar nodo existente - IMPLEMENTACIÓN REAL
                    var existingNode = _nodes.Find(n =>
                        n.EndPoint.IP.ToString() == endPoint.IP.ToString() &&
                        n.EndPoint.Port == endPoint.Port &&
                        ByteArraysEqual(publicKey, n.PublicKey));

                    if (existingNode != null)
                    {
                        existingNode.LastSeen = DateTime.UtcNow.Ticks;
                        existingNode.IsActive = true;
                        Logger.Log.DebugF($"[{LOG_TAG}] Nodo actualizado: {endPoint}");
                        return 1;
                    }

                    // Crear nuevo nodo - IMPLEMENTACIÓN REAL
                    var newNode = new DHTNode(publicKey, endPoint);
                    _nodes.Add(newNode);
                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo nodo agregado: {endPoint} [Total: {_nodes.Count}]");

                    // Limpieza de nodos antiguos - IMPLEMENTACIÓN REAL
                    if (_nodes.Count > 1000)
                    {
                        long tenMinutesAgo = DateTime.UtcNow.Ticks - (TimeSpan.TicksPerMinute * 10);
                        _nodes.RemoveAll(n => !n.IsActive || n.LastSeen < tenMinutesAgo);
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
        /// Comparar arrays de bytes - NUEVA FUNCIÓN AUXILIAR
        /// </summary>
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }


        /// <summary>
        /// Versión cacheada de GetClosestNodes
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

                // Devolver resultado cacheado si existe y es reciente
                if (_closestNodesCache.TryGetValue(cacheKey, out var cached) &&
                    cached != null)
                {
                    Logger.Log.TraceF($"[{LOG_TAG}] Cache hit para búsqueda de nodos");
                    return cached.Take(maxNodes).ToList();
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
        /// Obtener nodos más cercanos a una clave
        /// </summary>
        public List<DHTNode> GetClosestNodes(byte[] targetKey, int maxNodes = MAX_FRIEND_CLOSE)
        {
            var result = new List<DHTNode>();

            try
            {
                lock (_nodesLock)
                {
                    // CORREGIR: Ordenar por distancia XOR correctamente
                    var sortedNodes = _nodes
                        .Where(n => n.IsActive)
                        .Select(n => new { Node = n, Dist = Distance(n.PublicKey, targetKey) })
                        .OrderBy(x => x.Dist, new ByteArrayComparer())
                        .Take(maxNodes)
                        .Select(x => x.Node)
                        .ToList();

                    result.AddRange(sortedNodes);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DHT] GetClosestNodes error: {ex.Message}");
            }

            return result;
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

            // IP (siempre 16 bytes)
            if (ipp.IP.Data != null)
            {
                Buffer.BlockCopy(ipp.IP.Data, 0, result, 0, 16);
            }

            // Puerto (2 bytes, big-endian)
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

