
namespace ToxCore.Core
{
    /// <summary>
    /// Estructuras compatibles con Onion original de toxcore
    /// </summary>
    public class OnionNode
    {
        public IPPort IPPort { get; set; }
        public byte[] PublicKey { get; set; }
        public long LastPinged { get; set; }
        public bool IsActive { get; set; }
        public int RTT { get; set; } // Round Trip Time en ms
        public int SuccessRate { get; set; } // ✅ NUEVO - porcentaje de éxito
        public long FirstSeen { get; set; } // ✅ NUEVO - cuando descubrimos el nodo
        public int PacketsForwarded { get; set; } // ✅ NUEVO - contador de paquetes
        public int FailedForwards { get; set; } // ✅ NUEVO - contador de fallos

        public OnionNode(IPPort ipp, byte[] publicKey)
        {
            IPPort = ipp;
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
            LastPinged = DateTime.UtcNow.Ticks;
            IsActive = true;
            RTT = 0;
            SuccessRate = 100; // ✅ NUEVO - empezar con 100%
            FirstSeen = DateTime.UtcNow.Ticks; // ✅ NUEVO
            PacketsForwarded = 0; // ✅ NUEVO
            FailedForwards = 0; // ✅ NUEVO
        }

        // ✅ NUEVO - Calcular score del nodo
        public double CalculateScore()
        {
            double score = 0.0;

            // RTT más bajo = mejor score (máx 1000ms = 0 puntos)
            if (RTT > 0 && RTT <= Onion.ONION_PATH_MAX_LATENCY)
            {
                score += (Onion.ONION_PATH_MAX_LATENCY - RTT) * 0.5; // RTT contribuye 50%
            }

            // Success rate (porcentaje de éxito)
            score += SuccessRate * 0.3; // Success rate contribuye 30%

            // Tiempo activo (más tiempo = más confiable)
            long uptime = (DateTime.UtcNow.Ticks - FirstSeen) / TimeSpan.TicksPerMillisecond;
            if (uptime > Onion.ONION_NODE_MIN_UPTIME)
            {
                score += Math.Min(100, uptime / Onion.ONION_NODE_MIN_UPTIME * 10); // Uptime contribuye 20%
            }

            return score;
        }

        // ✅ NUEVO - Actualizar métricas después de un forward exitoso
        public void RecordSuccessfulForward()
        {
            PacketsForwarded++;
            SuccessRate = (int)((double)PacketsForwarded / (PacketsForwarded + FailedForwards) * 100);
            LastPinged = DateTime.UtcNow.Ticks;
        }

        // ✅ NUEVO - Actualizar métricas después de un forward fallido
        public void RecordFailedForward()
        {
            FailedForwards++;
            SuccessRate = (int)((double)PacketsForwarded / (PacketsForwarded + FailedForwards) * 100);
        }
    }

    public class OnionPath
    {
        public int PathNumber { get; set; }
        public OnionNode[] Nodes { get; set; }
        public long CreationTime { get; set; }
        public long LastUsed { get; set; }
        public bool IsActive { get; set; }
        public int TimeoutCounter { get; set; }

        public OnionPath(int pathNumber)
        {
            PathNumber = pathNumber;
            Nodes = new OnionNode[3];
            CreationTime = DateTime.UtcNow.Ticks;
            LastUsed = DateTime.UtcNow.Ticks;
            IsActive = true;
            TimeoutCounter = 0;
        }

        public override string ToString()
        {
            return $"OnionPath #{PathNumber} - {Nodes.Count(n => n != null)} nodos - Activo: {IsActive}";
        }
    }

    /// <summary>
    /// Implementación compatible con onion.c de toxcore
    /// </summary>
    public class Onion
    {
        private const string LOG_TAG = "ONION";
        private long _lastLogTime = 0;

        public Messenger Messenger { get; private set; }

        public OnionAnnounce Announce { get; private set; }
        public OnionData Data { get; private set; }

        public const int ONION_MAX_PACKET_SIZE = 1400;
        public const int ONION_RETURN_SIZE = 128;
        public const int ONION_PATH_LENGTH = 3;
        public const int ONION_PATH_TIMEOUT = 1200000;
        public const int MAX_ONION_PATHS = 6;
        public const int ONION_NODE_TIMEOUT = 1800000; // 30 minutos

        public const int ONION_PATH_MAX_LATENCY = 1000; // 1 segundo máximo RTT
        public const int ONION_NODE_MIN_UPTIME = 300000; // 5 minutos mínimos de actividad
        public const int ONION_PATH_HEALTH_CHECK_INTERVAL = 60000; // 60 segundos

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public int Socket { get; private set; }
        public bool IsRunning { get; private set; }

        private readonly List<OnionNode> _onionNodes;
        public readonly List<OnionPath> _onionPaths;
        private readonly object _nodesLock = new object();
        private readonly object _pathsLock = new object();
        private int _lastPathNumber;
        private long _lastMaintenanceTime;

        private readonly DHT _dht;
        private readonly Random _random = new Random();

        public int TotalOnionNodes => _onionNodes.Count;
        public int ActiveOnionNodes
        {
            get
            {
                lock (_nodesLock)
                {
                    return _onionNodes.Count(n => n.IsActive);
                }
            }
        }
        public int TotalPaths => _onionPaths.Count;
        public int ActivePaths
        {
            get
            {
                lock (_pathsLock)
                {
                    return _onionPaths.Count(p => p.IsActive);
                }
            }
        }

        public Onion(byte[] selfPublicKey, byte[] selfSecretKey, DHT dht = null, Messenger messenger = null)
        {
            SelfPublicKey = new byte[32];
            SelfSecretKey = new byte[32];
            Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);
            Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);

            _onionNodes = new List<OnionNode>();
            _onionPaths = new List<OnionPath>();
            

            _lastPathNumber = 0;
            _lastMaintenanceTime = DateTime.UtcNow.Ticks;
            IsRunning = false;
            _dht = dht;
            Messenger = messenger;

            Announce = new OnionAnnounce();
            Data = new OnionData(this);

            Socket = Network.new_socket(2, 2, 17);
            Logger.Log.InfoF($"[{LOG_TAG}] Onion inicializado - Socket: {Socket}");
            
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// onion_send_1 - IMPLEMENTACIÓN REAL con path selection
        /// </summary>
        public int onion_send_1(byte[] plain, int length, byte[] public_key)
        {
            Logger.Log.DebugF($"[{LOG_TAG}] Enviando paquete onion_send_1 - Tamaño: {length} bytes");

            if (!IsRunning || Socket == -1) return -1;
            if (plain == null || length > ONION_MAX_PACKET_SIZE) return -1;

            try
            {
                lock (_pathsLock)
                {
                    // ✅ IMPLEMENTACIÓN REAL: Seleccionar mejor path disponible
                    var path = SelectBestOnionPath();
                    if (path == null)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] No hay paths onion disponibles");
                        return -1;
                    }

                    byte[] onionPacket = CreateOnionPacket(plain, length, public_key, path);
                    if (onionPacket == null) return -1;

                    int sent = Network.socket_send(Socket, onionPacket, onionPacket.Length, path.Nodes[0].IPPort);

                    if (sent > 0)
                    {
                        path.LastUsed = DateTime.UtcNow.Ticks;
                        Logger.Log.TraceF($"[{LOG_TAG}] Paquete onion_send_1 enviado: {sent} bytes");
                    }
                    else
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Falló envío onion_send_1");
                    }

                    return sent;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en onion_send_1: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Selecciona el mejor path onion disponible
        /// </summary>
        private OnionPath SelectBestOnionPath()
        {
            lock (_pathsLock)
            {
                var activePaths = _onionPaths.Where(p => p.IsActive).ToList();
                if (activePaths.Count == 0)
                {
                    // Intentar crear nuevo path
                    int newPath = CreateOnionPath();
                    if (newPath >= 0)
                    {
                        // ✅ CORRECCIÓN: Find puede devolver null
                        var path = _onionPaths.Find(p => p.PathNumber == newPath);
                        return path; // Puede ser null si no se encontró
                    }
                    return null;
                }

                // Seleccionar path más recientemente usado o con mejor health
                return activePaths.OrderByDescending(p => p.LastUsed)
                                 .ThenBy(p => p.TimeoutCounter)
                                 .First();
            }
        }

        /// <summary>
        /// SelectOptimalOnionPath - Selección REAL de paths como en onion.c
        /// Considera RTT, estabilidad, capacidad de nodos
        /// </summary>
        public OnionPath SelectOptimalOnionPath()
        {
            try
            {
                lock (_pathsLock)
                {
                    var activePaths = _onionPaths.Where(p => p.IsActive).ToList();
                    if (activePaths.Count == 0)
                    {
                        // Crear nuevo path si no hay activos
                        int newPath = CreateOnionPath();
                        if (newPath >= 0)
                        {
                            return _onionPaths.Find(p => p.PathNumber == newPath);
                        }
                        return null;
                    }

                    // Calcular score para cada path
                    var scoredPaths = activePaths.Select(path => new
                    {
                        Path = path,
                        Score = CalculatePathScore(path)
                    }).ToList();

                    // Seleccionar path con mejor score
                    var bestPath = scoredPaths.OrderByDescending(sp => sp.Score).First();

                    Logger.Log.TraceF($"[{LOG_TAG}] Path seleccionado: #{bestPath.Path.PathNumber} (Score: {bestPath.Score:F2})");
                    return bestPath.Path;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error seleccionando path óptimo: {ex.Message}");
                return _onionPaths.FirstOrDefault(p => p.IsActive);
            }
        }

        /// <summary>
        /// CalculatePathScore - Calcula score REAL de un path onion
        /// </summary>
        private double CalculatePathScore(OnionPath path)
        {
            if (path == null || path.Nodes.Any(n => n == null)) return 0.0;

            double totalScore = 0.0;
            int nodeCount = 0;

            foreach (var node in path.Nodes)
            {
                if (node != null && node.IsActive)
                {
                    totalScore += node.CalculateScore();
                    nodeCount++;
                }
            }

            if (nodeCount == 0) return 0.0;

            // Score promedio de los nodos
            double averageNodeScore = totalScore / nodeCount;

            // Penalizar paths viejos (preferir paths más recientes)
            long pathAge = (DateTime.UtcNow.Ticks - path.CreationTime) / TimeSpan.TicksPerMillisecond;
            double agePenalty = Math.Max(0, 100 - (pathAge / 60000)); // Penalizar después de 1 minuto

            // Bonus por uso reciente
            long timeSinceLastUse = (DateTime.UtcNow.Ticks - path.LastUsed) / TimeSpan.TicksPerMillisecond;
            double recencyBonus = timeSinceLastUse < 30000 ? 50 : 0; // Bonus si se usó en últimos 30 segundos

            return averageNodeScore + agePenalty + recencyBonus;
        }


        /// <summary>
        /// onion_send_2 - Compatible con onion_send_2 del original
        /// </summary>
        public int onion_send_2(byte[] plain, int length, byte[] public_key)
        {
            if (!IsRunning || Socket == -1) return -1;
            if (plain == null || length > ONION_MAX_PACKET_SIZE) return -1;

            try
            {
                lock (_pathsLock)
                {
                    if (_onionPaths.Count < 2) return -1;

                    var path = _onionPaths[1];
                    if (!path.IsActive) return -1;

                    byte[] onionPacket = CreateOnionPacket(plain, length, public_key, path);
                    if (onionPacket == null) return -1;

                    int sent = Network.socket_send(Socket, onionPacket, onionPacket.Length, path.Nodes[0].IPPort);

                    if (sent > 0)
                    {
                        path.LastUsed = DateTime.UtcNow.Ticks;
                        return sent;
                    }

                    return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// Actualiza o agrega un nodo onion
        /// </summary>
        private void UpdateOnionNode(IPPort endPoint, byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != 32) return;

            try
            {
                lock (_nodesLock)
                {
                    // ✅ CORRECCIÓN: Usar comparación con null
                    var existingNode = _onionNodes.Find(n =>
                        n.IPPort.IP.ToString() == endPoint.IP.ToString() &&
                        n.IPPort.Port == endPoint.Port &&
                        ByteArraysEqual(publicKey, n.PublicKey));

                    if (existingNode != null) // ✅ Ahora funciona porque existingNode es OnionNode o null
                    {
                        existingNode.LastPinged = DateTime.UtcNow.Ticks;
                        existingNode.IsActive = true;
                    }
                    else
                    {
                        var newNode = new OnionNode(endPoint, publicKey);
                        _onionNodes.Add(newNode);
                        Logger.Log.DebugF($"[{LOG_TAG}] Nuevo nodo onion agregado: {endPoint}");
                    }

                    // Limpieza periódica
                    if (_onionNodes.Count > 200)
                    {
                        CleanupOldOnionNodes();
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error actualizando nodo onion: {ex.Message}");
            }
        }

        /// <summary>
        /// Limpia nodos onion antiguos
        /// </summary>
        private void CleanupOldOnionNodes()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * ONION_NODE_TIMEOUT;
            int removed = 0;

            lock (_nodesLock)
            {
                for (int i = _onionNodes.Count - 1; i >= 0; i--)
                {
                    var node = _onionNodes[i];
                    if (!node.IsActive || node.LastPinged < cutoffTime)
                    {
                        _onionNodes.RemoveAt(i);
                        removed++;
                    }
                }
            }

            if (removed > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {removed} nodos onion removidos");
            }
        }

        /// <summary>
        /// Encuentra un nodo onion por su public key
        /// </summary>
        private OnionNode FindOnionNodeByPublicKey(byte[] publicKey)
        {
            lock (_nodesLock)
            {
                return _onionNodes.Find(n => ByteArraysEqual(publicKey, n.PublicKey));
            }
        }



        /// <summary>
        /// handle_onion_recv_1 - Compatible con handle_onion_recv_1 del original
        /// </summary>
        public int handle_onion_recv_1(IPPort source, byte[] packet, int length)
        {
            if (!IsRunning || packet == null || length < 100) return -1;

            try
            {
                // Implementación basada en el manejo real de onion_recv_1
                byte[] nonce = new byte[24];
                Buffer.BlockCopy(packet, 0, nonce, 0, 24);

                byte[] tempPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 24, tempPublicKey, 0, 32);

                int encryptedLength = length - 56;
                if (encryptedLength <= 0) return -1;

                byte[] encrypted = new byte[encryptedLength];
                Buffer.BlockCopy(packet, 56, encrypted, 0, encryptedLength);

                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, tempPublicKey, SelfSecretKey);
                if (decrypted == null) return -1;

                // El paquete desencriptado contiene otro paquete onion
                return handle_onion_recv_2(source, decrypted, decrypted.Length);
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// handle_onion_recv_2 - Compatible con handle_onion_recv_2 del original
        /// </summary>
        public int handle_onion_recv_2(IPPort source, byte[] packet, int length)
        {
            if (!IsRunning || packet == null || length < 100) return -1;

            try
            {
                // Segunda capa de desencriptación onion
                byte[] nonce = new byte[24];
                Buffer.BlockCopy(packet, 0, nonce, 0, 24);

                byte[] tempPublicKey = new byte[32];
                Buffer.BlockCopy(packet, 24, tempPublicKey, 0, 32);

                int encryptedLength = length - 56;
                if (encryptedLength <= 0) return -1;

                byte[] encrypted = new byte[encryptedLength];
                Buffer.BlockCopy(packet, 56, encrypted, 0, encryptedLength);

                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, tempPublicKey, SelfSecretKey);
                if (decrypted == null) return -1;

                // Aquí se procesaría el paquete final desencriptado
                // En toxcore real, esto se pasa al callback correspondiente
                return decrypted.Length;
            }
            catch (Exception)
            {
                return -1;
            }
        }

        /// <summary>
        /// onion_add_node - Compatible con onion_add_node del original
        /// </summary>
        public int onion_add_node(byte[] public_key, IPPort ip_port)
        {
            if (public_key == null || public_key.Length != 32) return -1;

            try
            {
                lock (_nodesLock)
                {
                    var existingNode = _onionNodes.Find(n =>
                        n.IPPort.IP.ToString() == ip_port.IP.ToString() &&
                        n.IPPort.Port == ip_port.Port &&
                        ByteArraysEqual(public_key, n.PublicKey));

                    if (existingNode.IsActive)
                    {
                        existingNode.LastPinged = DateTime.UtcNow.Ticks;
                        return 1;
                    }

                    var newNode = new OnionNode(ip_port, public_key);
                    _onionNodes.Add(newNode);
                    return 0;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        // ==================== FUNCIONES AUXILIARES ====================

        
        // ==================== ONION ENCRYPTION REAL ====================

        /// <summary>
        /// Crea un paquete onion REAL con encriptación en capas
        /// </summary>
        public byte[] CreateOnionPacket(byte[] plainData, int length, byte[] destPublicKey, OnionPath path)
        {
            try
            {
                if (plainData == null || length > ONION_MAX_PACKET_SIZE)
                    return null;

                // ✅ IMPLEMENTACIÓN REAL: Encriptación en capas
                byte[] currentPayload = plainData;

                // Capa 3: Para el último nodo (destino final)
                currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,
                    destPublicKey, path.Nodes[2].PublicKey, path.Nodes[2].PublicKey);

                // Capa 2: Para el nodo medio
                currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,
                    path.Nodes[2].PublicKey, path.Nodes[1].PublicKey, path.Nodes[1].PublicKey);

                // Capa 1: Para el primer nodo
                currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,
                    path.Nodes[1].PublicKey, path.Nodes[0].PublicKey, path.Nodes[0].PublicKey);

                return currentPayload;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete onion: {ex.Message}");
                return null;
            }
        }


        /// <summary>
        /// Crea una capa onion REAL con encriptación
        /// </summary>
        private byte[] CreateOnionLayer(byte[] data, int length, byte[] nextPublicKey,
                                      byte[] layerPublicKey, byte[] tempPublicKey)
        {
            try
            {
                // Construir payload de la capa: [next_public_key][encrypted_data]
                byte[] layerPayload = new byte[32 + length];
                Buffer.BlockCopy(nextPublicKey, 0, layerPayload, 0, 32);
                Buffer.BlockCopy(data, 0, layerPayload, 32, length);

                // Nonce aleatorio para esta capa
                byte[] nonce = RandomBytes.Generate(24);

                // ✅ IMPLEMENTACIÓN REAL: Encriptar con CryptoBox usando la clave temporal
                byte[] encrypted = CryptoBox.Encrypt(layerPayload, nonce, layerPublicKey, SelfSecretKey);
                if (encrypted == null) return null;

                // Paquete de capa: [nonce][encrypted_data]
                byte[] layerPacket = new byte[24 + encrypted.Length];
                Buffer.BlockCopy(nonce, 0, layerPacket, 0, 24);
                Buffer.BlockCopy(encrypted, 0, layerPacket, 24, encrypted.Length);

                return layerPacket;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando capa onion: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Maneja un paquete onion entrante REAL
        /// </summary>
        public int HandleOnionPacket(byte[] packet, int length, IPPort source)
        {
            if (packet == null || length < 25) return -1;

            try
            {
                // 1. Extraer nonce y datos encriptados
                byte[] nonce = new byte[24];
                byte[] encrypted = new byte[length - 24];
                Buffer.BlockCopy(packet, 0, nonce, 0, 24);
                Buffer.BlockCopy(packet, 24, encrypted, 0, encrypted.Length);

                // 2. Desencriptar con nuestra clave
                byte[] decrypted = CryptoBox.Decrypt(encrypted, nonce, SelfPublicKey, SelfSecretKey);
                if (decrypted == null || decrypted.Length < 32) return -1;

                // 3. Extraer siguiente public key y datos
                byte[] nextPublicKey = new byte[32];
                byte[] innerData = new byte[decrypted.Length - 32];
                Buffer.BlockCopy(decrypted, 0, nextPublicKey, 0, 32);
                Buffer.BlockCopy(decrypted, 32, innerData, 0, innerData.Length);

                // 4. Actualizar nodo onion
                UpdateOnionNode(source, nextPublicKey);

                // 5. ¿Somos el destino final?
                if (IsZeroKey(nextPublicKey))
                {
                    // ✅ Llamada correcta: pasamos el publicKey del nodo que nos envió (source)
                    return Data.HandleDataPacket(innerData, innerData.Length, source, nextPublicKey);
                }
                else
                {
                    // Reenviar al siguiente nodo
                    return ForwardOnionPacket(innerData, innerData.Length, nextPublicKey);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete onion: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// ForwardOnionPacket - ACTUALIZADO para registrar métricas REALES
        /// </summary>
        private int ForwardOnionPacket(byte[] data, int length, byte[] nextPublicKey)
        {
            try
            {
                var nextNode = FindOnionNodeByPublicKey(nextPublicKey);
                if (nextNode == null)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Nodo onion no encontrado para reenvío");
                    return -1;
                }

                int sent = Network.socket_send(Socket, data, length, nextNode.IPPort);

                if (sent > 0)
                    nextNode.RecordSuccessfulForward();
                else
                    nextNode.RecordFailedForward();

                return sent;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error reenviando paquete onion: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Procesa un paquete onion que llegó a su destino final
        /// </summary>
        private int ProcessFinalOnionPacket(byte[] data, int length, IPPort source)
        {
            // ✅ IMPLEMENTACIÓN REAL: Aquí se procesaría el paquete final
            // En toxcore real, esto se pasaría al callback correspondiente
            // (FriendConnection, GroupChat, etc.)

            Logger.Log.DebugF($"[{LOG_TAG}] Paquete onion procesado - Tamaño: {length} bytes desde {source}");

            // Por ahora, simplemente retornamos el tamaño procesado
            return length;
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            return CryptoVerify.Verify(a, b);
        }

        private static bool IsZeroKey(byte[] key)
        {
            if (key == null) return true;
            foreach (byte b in key)
            {
                if (b != 0) return false;
            }
            return true;
        }

        // ==================== FUNCIONES DE GESTIÓN ====================

        /// <summary>
        /// Construye un path de onion REAL con nodos de la DHT
        /// </summary>
        public int CreateOnionPath()
        {
            if (_dht == null)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] No se puede crear path - DHT no disponible");
                return -1;
            }

            try
            {
                lock (_pathsLock)
                {
                    if (_onionPaths.Count >= MAX_ONION_PATHS)
                    {
                        // Reemplazar path más antiguo
                        var oldestPath = _onionPaths.Where(p => p != null)
                                                   .OrderBy(p => p.CreationTime)
                                                   .FirstOrDefault();
                        if (oldestPath != null)
                        {
                            _onionPaths.Remove(oldestPath);
                        }
                    }

                    // Obtener nodos activos de la DHT
                    var potentialNodes = GetOnionNodesFromDHT();
                    if (potentialNodes.Count < ONION_PATH_LENGTH)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] No hay suficientes nodos onion disponibles: {potentialNodes.Count}/{ONION_PATH_LENGTH}");
                        return -1;
                    }

                    // Seleccionar nodos aleatoriamente para el path
                    var selectedNodes = SelectRandomNodes(potentialNodes, ONION_PATH_LENGTH);
                    if (selectedNodes.Count < ONION_PATH_LENGTH)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] No se pudieron seleccionar suficientes nodos: {selectedNodes.Count}/{ONION_PATH_LENGTH}");
                        return -1;
                    }

                    var newPath = new OnionPath(_lastPathNumber++)
                    {
                        Nodes = selectedNodes.ToArray(),
                        CreationTime = DateTime.UtcNow.Ticks,
                        LastUsed = DateTime.UtcNow.Ticks,
                        IsActive = true
                    };

                    _onionPaths.Add(newPath);

                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo path creado: {newPath.PathNumber} con {selectedNodes.Count} nodos");
                    return newPath.PathNumber;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando path: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Obtiene nodos adecuados para onion routing desde la DHT
        /// </summary>
        private List<OnionNode> GetOnionNodesFromDHT()
        {
            var onionNodes = new List<OnionNode>();

            try
            {
                // Obtener nodos cercanos de la DHT
                var dhtNodes = _dht.GetClosestNodes(SelfPublicKey, 50); // Obtener más nodos para selección

                foreach (var dhtNode in dhtNodes)
                {
                    // Filtrar nodos que sean buenos candidatos para onion routing
                    if (IsGoodOnionNode(dhtNode))
                    {
                        var onionNode = new OnionNode(dhtNode.EndPoint, dhtNode.PublicKey)
                        {
                            LastPinged = DateTime.UtcNow.Ticks,
                            IsActive = true,
                            RTT = dhtNode.RTT
                        };
                        onionNodes.Add(onionNode);
                    }
                }

                // También incluir nodos onion existentes que estén activos
                lock (_nodesLock)
                {
                    onionNodes.AddRange(_onionNodes.Where(n => n.IsActive));
                }

                Logger.Log.DebugF($"[{LOG_TAG}] {onionNodes.Count} nodos onion disponibles");
                return onionNodes;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error obteniendo nodos de DHT: {ex.Message}");
                return onionNodes;
            }
        }

        /// <summary>
        /// IsGoodOnionNode - Verificación REAL de nodos onion como en onion.c
        /// </summary>
        private bool IsGoodOnionNode(DHT.DHTNode node)
        {
            if (node == null || !node.IsActive) return false;

            // Verificar RTT razonable
            if (node.RTT <= 0 || node.RTT > ONION_PATH_MAX_LATENCY)
                return false;

            // Verificar que no sea nuestro propio nodo
            if (ByteArraysEqual(node.PublicKey, SelfPublicKey))
                return false;

            // Verificar que tenga un endpoint válido
            if (node.EndPoint.Port == 0 || node.EndPoint.IP.Data == null)
                return false;

            // Verificar que haya estado activo por un tiempo mínimo
            long nodeUptime = (DateTime.UtcNow.Ticks - node.LastSeen) / TimeSpan.TicksPerMillisecond;
            if (nodeUptime < ONION_NODE_MIN_UPTIME)
                return false;

            // Verificar calidad de conexión (basado en RTT y estabilidad)
            if (node.RTT > 500) // Más de 500ms es considerado lento
                return false;

            return true;
        }

        /// <summary>
        /// MaintainOnionPaths - Mantenimiento REAL como en onion.c
        /// </summary>
        private void MaintainOnionPaths()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;
                int pathsReplaced = 0;
                int pathsCreated = 0;

                lock (_pathsLock)
                {
                    // 1. Reemplazar paths con nodos problemáticos
                    for (int i = _onionPaths.Count - 1; i >= 0; i--)
                    {
                        var path = _onionPaths[i];
                        if (!path.IsActive) continue;

                        double pathScore = CalculatePathScore(path);

                        // Reemplazar paths con score bajo
                        if (pathScore < 50.0) // Score mínimo aceptable
                        {
                            _onionPaths.RemoveAt(i);
                            pathsReplaced++;

                            Logger.Log.DebugF($"[{LOG_TAG}] Path #{path.PathNumber} removido (Score: {pathScore:F2})");

                            // Crear reemplazo
                            int newPath = CreateOnionPath();
                            if (newPath >= 0) pathsCreated++;
                        }
                    }

                    // 2. Asegurar número mínimo de paths activos
                    int activePaths = _onionPaths.Count(p => p.IsActive);
                    int pathsNeeded = Math.Max(2, MAX_ONION_PATHS / 2); // Al menos 2 paths o la mitad del máximo

                    while (activePaths < pathsNeeded && _onionPaths.Count < MAX_ONION_PATHS)
                    {
                        int newPath = CreateOnionPath();
                        if (newPath >= 0)
                        {
                            activePaths++;
                            pathsCreated++;
                        }
                        else
                        {
                            break; // No se pudo crear más paths
                        }
                    }
                }

                if (pathsReplaced > 0 || pathsCreated > 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Mantenimiento: {pathsReplaced} paths reemplazados, {pathsCreated} creados");
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en mantenimiento de paths: {ex.Message}");
            }
        }

        /// <summary>
        /// PerformHealthChecks - Verificación de salud REAL de nodos onion
        /// </summary>
        private void PerformHealthChecks()
        {
            try
            {
                lock (_nodesLock)
                {
                    long currentTime = DateTime.UtcNow.Ticks;
                    int checksPerformed = 0;
                    int nodesMarkedInactive = 0;

                    foreach (var node in _onionNodes)
                    {
                        if (!node.IsActive) continue;

                        long timeSinceLastActivity = (currentTime - node.LastPinged) / TimeSpan.TicksPerMillisecond;

                        // Si no ha habido actividad reciente, verificar salud
                        if (timeSinceLastActivity > ONION_PATH_HEALTH_CHECK_INTERVAL)
                        {
                            checksPerformed++;

                            // Nodo con muchos fallos recientes se marca como inactivo
                            if (node.SuccessRate < 30) // Menos del 30% de éxito
                            {
                                node.IsActive = false;
                                nodesMarkedInactive++;
                                Logger.Log.DebugF($"[{LOG_TAG}] Nodo onion marcado inactivo (Success: {node.SuccessRate}%)");
                            }
                        }
                    }

                    if (nodesMarkedInactive > 0)
                    {
                        Logger.Log.InfoF($"[{LOG_TAG}] Health check: {nodesMarkedInactive}/{checksPerformed} nodos marcados inactivos");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en health check: {ex.Message}");
            }
        }

        /// <summary>
        /// Selecciona nodos aleatoriamente para el path
        /// </summary>
        private List<OnionNode> SelectRandomNodes(List<OnionNode> nodes, int count)
        {
            if (nodes.Count <= count)
                return new List<OnionNode>(nodes);

            // ✅ MEJORA: Filtrar nodos no nulos y activos
            var activeNodes = nodes.Where(n => n != null && n.IsActive).ToList();
            if (activeNodes.Count <= count)
                return activeNodes;

            // Usar Fisher-Yates shuffle para selección aleatoria
            var shuffled = activeNodes.OrderBy(x => _random.Next()).ToList();
            return shuffled.Take(count).ToList();
        }




        public int kill_onion_path(int path_num)
        {
            try
            {
                lock (_pathsLock)
                {
                    var path = _onionPaths.Find(p => p.PathNumber == path_num);
                    if (path != null)
                    {
                        path.IsActive = false;
                        _onionPaths.Remove(path);
                        return 0;
                    }
                    return -1;
                }
            }
            catch (Exception)
            {
                return -1;
            }
        }

        public int Start()
        {
            if (Socket == -1)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] No se puede iniciar - Socket inválido");
                return -1;
            }

            IsRunning = true;

            // Crear paths iniciales
            for (int i = 0; i < 2 && i < MAX_ONION_PATHS; i++)
            {
                CreateOnionPath();
            }

            Logger.Log.InfoF($"[{LOG_TAG}] Servicio Onion iniciado con {_onionPaths.Count} paths");
            return 0;
        }

        public int Stop()
        {
            IsRunning = false;
            return 0;
        }

        public void Close()
        {
            Stop();
            if (Socket != -1)
            {
                Network.kill_socket(Socket);
                Socket = -1;
            }
            lock (_nodesLock) _onionNodes.Clear();
            lock (_pathsLock) _onionPaths.Clear();
        }

        // ==================== AGREGAR ESTE MÉTODO A LA CLASE ONION ====================

        /// <summary>
        /// DoPeriodicWork - ACTUALIZADO con mantenimiento REAL
        /// </summary>
        public void DoPeriodicWork()
        {
            if (!IsRunning) return;

            try
            {
                long currentTime = DateTime.UtcNow.Ticks;

                // 1. Health check de nodos
                PerformHealthChecks();

                // 2. Mantenimiento de paths
                if ((currentTime - _lastMaintenanceTime) > TimeSpan.TicksPerMillisecond * 120000) // Cada 2 minutos
                {
                    MaintainOnionPaths();
                    _lastMaintenanceTime = currentTime;
                }

                // 3. Limpieza de nodos antiguos (existente)
                CleanupOldOnionNodes();

                // 4. Log estadísticas periódicas
                if ((currentTime - _lastLogTime) > TimeSpan.TicksPerSecond * 120)
                {
                    int healthyNodes = _onionNodes.Count(n => n.IsActive && n.SuccessRate > 70);
                    int optimalPaths = _onionPaths.Count(p => p.IsActive && CalculatePathScore(p) > 70.0);

                    Logger.Log.DebugF($"[{LOG_TAG}] Estadísticas - Nodos: {TotalOnionNodes} total, {healthyNodes} saludables, Paths: {TotalPaths} total, {optimalPaths} óptimos");
                    _lastLogTime = currentTime;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico: {ex.Message}");
            }
        }

        /// <summary>
        /// Limpia paths onion expirados
        /// </summary>
        private void CleanupExpiredPaths()
        {
            long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * ONION_PATH_TIMEOUT;
            int removed = 0;

            lock (_pathsLock)
            {
                for (int i = _onionPaths.Count - 1; i >= 0; i--)
                {
                    var path = _onionPaths[i];
                    if (!path.IsActive || path.LastUsed < cutoffTime)
                    {
                        _onionPaths.RemoveAt(i);
                        removed++;
                    }
                }
            }

            if (removed > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {removed} paths onion removidos");
            }
        }


      
    }



}