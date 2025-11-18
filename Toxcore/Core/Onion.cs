using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Estructuras compatibles con Onion original de toxcore
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct OnionNode
    {
        public IPPort IPPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        public long LastPinged;
        public bool IsActive;
        public int RTT;

        public OnionNode(IPPort ipp, byte[] publicKey)
        {
            IPPort = ipp;
            PublicKey = new byte[32];
            if (publicKey != null)
            {
                Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);
            }
            LastPinged = 0;
            IsActive = true;
            RTT = 0;
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
    }

    /// <summary>
    /// Implementación compatible con onion.c de toxcore
    /// </summary>
    public class Onion
    {
        private const string LOG_TAG = "ONION";
        private long _lastLogTime = 0;

        public const int ONION_MAX_PACKET_SIZE = 1400;
        public const int ONION_RETURN_SIZE = 128;
        public const int ONION_PATH_LENGTH = 3;
        public const int ONION_PATH_TIMEOUT = 1200000;
        public const int MAX_ONION_PATHS = 6;

        public byte[] SelfPublicKey { get; private set; }
        public byte[] SelfSecretKey { get; private set; }
        public int Socket { get; private set; }
        public bool IsRunning { get; private set; }

        private readonly List<OnionNode> _onionNodes;
        private readonly List<OnionPath> _onionPaths;
        private readonly object _nodesLock = new object();
        private readonly object _pathsLock = new object();
        private int _lastPathNumber;
        private long _lastMaintenanceTime;

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

        public Onion(byte[] selfPublicKey, byte[] selfSecretKey)
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

            Socket = Network.new_socket(2, 2, 17);
            Logger.Log.InfoF($"[{LOG_TAG}] Onion inicializado - Socket: {Socket}");
        }

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// onion_send_1 - Compatible con onion_send_1 del original
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
                    if (_onionPaths.Count == 0) return -1;

                    var path = _onionPaths[0];
                    if (!path.IsActive) return -1;

                    byte[] onionPacket = CreateOnionPacket(plain, length, public_key, path);
                    if (onionPacket == null) return -1;

                    int sent = Network.socket_send(Socket, onionPacket, onionPacket.Length, path.Nodes[0].IPPort);

                    if (sent > 0)
                    {
                        path.LastUsed = DateTime.UtcNow.Ticks;
                        Logger.Log.TraceF($"[{LOG_TAG}] Paquete onion_send_1 enviado: {sent} bytes");
                        return sent;
                    }
                    
                    Logger.Log.WarningF($"[{LOG_TAG}] Falló envío onion_send_1");
                    return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en onion_send_1: {ex.Message}");
                return -1;
            }
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

        private byte[] CreateOnionPacket(byte[] data, int length, byte[] destPublicKey, OnionPath path)
        {
            try
            {
                // Implementación basada en la creación real de paquetes onion
                // Capa 3: para el último nodo
                byte[] nonce3 = RandomBytes.Generate(24);
                byte[] layer3 = CreateOnionLayer(data, length, destPublicKey, nonce3);

                // Capa 2: para el nodo medio
                byte[] nonce2 = RandomBytes.Generate(24);
                byte[] layer2 = CreateOnionLayer(layer3, layer3.Length, path.Nodes[2].PublicKey, nonce2);

                // Capa 1: para el primer nodo
                byte[] nonce1 = RandomBytes.Generate(24);
                byte[] layer1 = CreateOnionLayer(layer2, layer2.Length, path.Nodes[1].PublicKey, nonce1);

                return layer1;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private byte[] CreateOnionLayer(byte[] data, int length, byte[] publicKey, byte[] nonce)
        {
            byte[] encrypted = CryptoBox.Encrypt(data, nonce, publicKey, SelfSecretKey);
            if (encrypted == null) return null;

            byte[] layer = new byte[24 + 32 + encrypted.Length];
            Buffer.BlockCopy(nonce, 0, layer, 0, 24);
            Buffer.BlockCopy(publicKey, 0, layer, 24, 32);
            Buffer.BlockCopy(encrypted, 0, layer, 56, encrypted.Length);

            return layer;
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        // ==================== FUNCIONES DE GESTIÓN ====================

        public int create_onion_path(DHT dht)
        {
            Logger.Log.DebugF($"[{LOG_TAG}] Creando nuevo path Onion");

            if (dht == null) return -1;

            try
            {
                lock (_pathsLock)
                {
                    if (_onionPaths.Count >= MAX_ONION_PATHS) return -1;

                    var closestNodes = dht.GetClosestNodes(SelfPublicKey, ONION_PATH_LENGTH);
                    if (closestNodes.Count < ONION_PATH_LENGTH)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] No hay suficientes nodos para crear path (necesarios: {ONION_PATH_LENGTH}, disponibles: {closestNodes.Count})");
                        return -1;
                    }

                    var newPath = new OnionPath(_lastPathNumber++);

                    for (int i = 0; i < ONION_PATH_LENGTH && i < closestNodes.Count; i++)
                    {
                        newPath.Nodes[i] = new OnionNode(closestNodes[i].EndPoint, closestNodes[i].PublicKey);
                    }

                    _onionPaths.Add(newPath);
                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo path creado: {newPath.PathNumber} [Total: {_onionPaths.Count}]");
                    return newPath.PathNumber;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando path: {ex.Message}");
                return -1;
            }
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
                Logger.Log.Error($"[{LOG_TAG}] No se puede iniciar - Socket inválido");
                return -1;
            }

            IsRunning = true;
            Logger.Log.Info($"[{LOG_TAG}] Servicio Onion iniciado");
            return 0;
        }

        public int Stop()
        {
            IsRunning = false;
            return 0;
        }

        // ==================== AGREGAR ESTE MÉTODO A LA CLASE ONION ====================

        /// <summary>
        /// DoPeriodicWork - Mantenimiento periódico de Onion
        /// </summary>
        public void DoPeriodicWork()
        {
            if (!IsRunning) return;

            try
            {
                long currentTime = DateTime.UtcNow.Ticks;

                // Verificar timeouts de paths
                lock (_pathsLock)
                {
                    for (int i = _onionPaths.Count - 1; i >= 0; i--)
                    {
                        var path = _onionPaths[i];
                        if ((currentTime - path.LastUsed) > ONION_PATH_TIMEOUT)
                        {
                            path.IsActive = false;
                            _onionPaths.RemoveAt(i);
                        }
                    }
                }

                // Crear nuevos paths si es necesario
                if (_onionPaths.Count < 3 && (currentTime - _lastMaintenanceTime) > TimeSpan.TicksPerSecond * 60)
                {
                    // En una implementación real, usaríamos DHT aquí para crear nuevos paths
                    _lastMaintenanceTime = currentTime;
                }

                if ((currentTime - _lastLogTime) > TimeSpan.TicksPerSecond * 60)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Estadísticas - Nodos: {TotalOnionNodes}, Paths: {TotalPaths}, Activos: {ActivePaths}");
                    _lastLogTime = currentTime;
                }

            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico: {ex.Message}");
            }
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
    }
}