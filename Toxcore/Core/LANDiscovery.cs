using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Linq;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de LAN_discovery.c - Descubrimiento de clientes Tox en red local
    /// </summary>
    public class LANDiscovery : IDisposable
    {
        private const string LOG_TAG = "LANDISCOVERY";

        // Configuración
        private const int DISCOVERY_PORT = 33445;
        private const int DISCOVERY_INTERVAL_MS = 30000; // 30 segundos
        private const int PACKET_TIMEOUT_MS = 120000;    // 2 minutos

        // Componentes
        private UdpClient _udpClientV4;
        private UdpClient _udpClientV6;
        private Thread _discoveryThread;
        private Thread _receiveThreadV4;
        private Thread _receiveThreadV6;
        private bool _isRunning;
        private byte[] _selfPublicKey;

        // Almacenamiento de peers descubiertos
        private readonly Dictionary<string, DiscoveredPeer> _discoveredPeers;
        private readonly object _peersLock = new object();

        // Callbacks
        public Action<DiscoveredPeer> PeerDiscoveredCallback { get; set; }
        public Action<DiscoveredPeer> PeerExpiredCallback { get; set; }

        public LANDiscovery(byte[] selfPublicKey)
        {
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));
            _discoveredPeers = new Dictionary<string, DiscoveredPeer>();
            _isRunning = false;

            Logger.Log.Info($"[{LOG_TAG}] LAN Discovery inicializado");
        }

        /// <summary>
        /// Iniciar servicio de descubrimiento LAN
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Servicio ya está ejecutándose");
                return true;
            }

            try
            {
                // Crear socket UDP IPv4
                _udpClientV4 = new UdpClient(AddressFamily.InterNetwork);
                _udpClientV4.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _udpClientV4.Client.Bind(new IPEndPoint(IPAddress.Any, DISCOVERY_PORT));
                _udpClientV4.EnableBroadcast = true;
                _udpClientV4.MulticastLoopback = true;

                // Unirse al grupo multicast para IPv4
                try
                {
                    _udpClientV4.JoinMulticastGroup(IPAddress.Parse("239.192.255.250"), 50);
                    Logger.Log.Debug($"[{LOG_TAG}] Unido a grupo multicast IPv4");
                }
                catch (Exception ex)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] No se pudo unir a grupo multicast IPv4: {ex.Message}");
                }

                // Crear socket UDP IPv6 (si está disponible)
                try
                {
                    _udpClientV6 = new UdpClient(AddressFamily.InterNetworkV6);
                    _udpClientV6.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    _udpClientV6.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, DISCOVERY_PORT));
                    _udpClientV6.MulticastLoopback = true;

                    // Unirse al grupo multicast para IPv6
                    _udpClientV6.JoinMulticastGroup(IPAddress.Parse("ff02::1"));
                    Logger.Log.Debug($"[{LOG_TAG}] Unido a grupo multicast IPv6");
                }
                catch (Exception ex)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] No se pudo crear socket IPv6: {ex.Message}");
                    _udpClientV6 = null;
                }

                _isRunning = true;

                // Iniciar hilo de envío de anuncios
                _discoveryThread = new Thread(DiscoveryWorker);
                _discoveryThread.IsBackground = true;
                _discoveryThread.Name = "LANDiscovery-Sender";
                _discoveryThread.Start();

                // Iniciar hilos de recepción
                _receiveThreadV4 = new Thread(() => ReceiveWorker(_udpClientV4, "IPv4"));
                _receiveThreadV4.IsBackground = true;
                _receiveThreadV4.Name = "LANDiscovery-Receiver-IPv4";
                _receiveThreadV4.Start();

                if (_udpClientV6 != null)
                {
                    _receiveThreadV6 = new Thread(() => ReceiveWorker(_udpClientV6, "IPv6"));
                    _receiveThreadV6.IsBackground = true;
                    _receiveThreadV6.Name = "LANDiscovery-Receiver-IPv6";
                    _receiveThreadV6.Start();
                }

                Logger.Log.Info($"[{LOG_TAG}] Servicio LAN Discovery iniciado en puerto {DISCOVERY_PORT}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando LAN Discovery: {ex.Message}");
                Stop();
                return false;
            }
        }

        /// <summary>
        /// Detener servicio de descubrimiento LAN
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;

            try
            {
                _discoveryThread?.Join(1000);
                _receiveThreadV4?.Join(1000);
                _receiveThreadV6?.Join(1000);

                _udpClientV4?.Close();
                _udpClientV4?.Dispose();
                _udpClientV4 = null;

                _udpClientV6?.Close();
                _udpClientV6?.Dispose();
                _udpClientV6 = null;

                Logger.Log.Info($"[{LOG_TAG}] Servicio LAN Discovery detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo LAN Discovery: {ex.Message}");
            }
        }

        /// <summary>
        /// Trabajador que envía anuncios periódicos
        /// </summary>
        private void DiscoveryWorker()
        {
            Logger.Log.Debug($"[{LOG_TAG}] Hilo de descubrimiento iniciado");

            while (_isRunning)
            {
                try
                {
                    SendDiscoveryPacket();
                    CleanupExpiredPeers();
                }
                catch (Exception ex)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Error en trabajador de descubrimiento: {ex.Message}");
                }

                // Esperar hasta el próximo anuncio
                for (int i = 0; i < DISCOVERY_INTERVAL_MS / 1000 && _isRunning; i++)
                {
                    Thread.Sleep(1000);
                }
            }

            Logger.Log.Debug($"[{LOG_TAG}] Hilo de descubrimiento finalizado");
        }

        /// <summary>
        /// Trabajador que recibe paquetes de descubrimiento
        /// </summary>
        private void ReceiveWorker(UdpClient client, string family)
        {
            Logger.Log.DebugF($"[{LOG_TAG}] Hilo de recepción {family} iniciado");

            while (_isRunning && client != null)
            {
                try
                {
                    IPEndPoint remoteEndPoint = new IPEndPoint(
                        family == "IPv4" ? IPAddress.Any : IPAddress.IPv6Any,
                        0
                    );
                    byte[] receivedData = client.Receive(ref remoteEndPoint);

                    if (receivedData != null && receivedData.Length > 0)
                    {
                        ProcessDiscoveryPacket(receivedData, remoteEndPoint, family);
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                {
                    // Socket cerrado, salir normalmente
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // Socket disposed, salir normalmente
                    break;
                }
                catch (Exception ex)
                {
                    if (_isRunning) // Solo loguear errores si todavía estamos ejecutándonos
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Error recibiendo paquete {family}: {ex.Message}");
                    }
                }
            }

            Logger.Log.DebugF($"[{LOG_TAG}] Hilo de recepción {family} finalizado");
        }

        /// <summary>
        /// Enviar paquete de descubrimiento a la red local
        /// </summary>
        private void SendDiscoveryPacket()
        {
            try
            {
                // Crear paquete de descubrimiento
                byte[] discoveryPacket = CreateDiscoveryPacket();
                if (discoveryPacket == null) return;

                // Enviar por broadcast IPv4
                IPEndPoint broadcastV4 = new IPEndPoint(IPAddress.Broadcast, DISCOVERY_PORT);
                _udpClientV4?.Send(discoveryPacket, discoveryPacket.Length, broadcastV4);

                // Enviar por multicast IPv4
                IPEndPoint multicastV4 = new IPEndPoint(IPAddress.Parse("239.192.255.250"), DISCOVERY_PORT);
                _udpClientV4?.Send(discoveryPacket, discoveryPacket.Length, multicastV4);

                // Enviar por multicast IPv6 (si está disponible)
                if (_udpClientV6 != null)
                {
                    IPEndPoint multicastV6 = new IPEndPoint(IPAddress.Parse("ff02::1"), DISCOVERY_PORT);
                    _udpClientV6.Send(discoveryPacket, discoveryPacket.Length, multicastV6);
                }

                Logger.Log.TraceF($"[{LOG_TAG}] Paquete de descubrimiento enviado");
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error enviando paquete de descubrimiento: {ex.Message}");
            }
        }

        /// <summary>
        /// Crear paquete de descubrimiento LAN
        /// </summary>
        private byte[] CreateDiscoveryPacket()
        {
            try
            {
                // Formato del paquete: [MAGIC][PUBLIC_KEY][RESERVED]
                const int PACKET_SIZE = 32 + 32 + 16; // magic + public_key + reserved
                byte[] packet = new byte[PACKET_SIZE];

                // Magic bytes "ToxLANDiscovery"
                byte[] magic = Encoding.UTF8.GetBytes("ToxLANDiscovery");
                Buffer.BlockCopy(magic, 0, packet, 0, Math.Min(magic.Length, 32));

                // Clave pública
                Buffer.BlockCopy(_selfPublicKey, 0, packet, 32, 32);

                // Reserved bytes (ceros)
                for (int i = 64; i < PACKET_SIZE; i++)
                {
                    packet[i] = 0;
                }

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete de descubrimiento: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Procesar paquete de descubrimiento recibido
        /// </summary>
        private void ProcessDiscoveryPacket(byte[] packet, IPEndPoint sender, string family)
        {
            try
            {
                // Verificar tamaño mínimo
                if (packet.Length < 64) // magic + public_key
                {
                    Logger.Log.TraceF($"[{LOG_TAG}] Paquete demasiado corto: {packet.Length} bytes");
                    return;
                }

                // Verificar magic bytes
                byte[] expectedMagic = Encoding.UTF8.GetBytes("ToxLANDiscovery");
                bool magicValid = true;
                for (int i = 0; i < expectedMagic.Length && i < 32; i++)
                {
                    if (packet[i] != expectedMagic[i])
                    {
                        magicValid = false;
                        break;
                    }
                }

                if (!magicValid)
                {
                    Logger.Log.TraceF($"[{LOG_TAG}] Magic bytes inválidos en paquete");
                    return;
                }

                // Extraer clave pública
                byte[] publicKey = new byte[32];
                Buffer.BlockCopy(packet, 32, publicKey, 0, 32);

                // Ignorar nuestros propios paquetes
                if (CryptoBytes.MemCompare(publicKey, _selfPublicKey))
                {
                    return;
                }

                // Crear objeto de peer descubierto
                var peer = new DiscoveredPeer
                {
                    PublicKey = publicKey,
                    IPAddress = sender.Address,
                    Port = (ushort)DISCOVERY_PORT,
                    LastSeen = DateTime.UtcNow,
                    DiscoveryMethod = $"LAN-{family}"
                };

                // Agregar o actualizar peer
                string peerKey = BitConverter.ToString(publicKey).Replace("-", "");
                bool isNewPeer = false;

                lock (_peersLock)
                {
                    if (!_discoveredPeers.ContainsKey(peerKey))
                    {
                        _discoveredPeers[peerKey] = peer;
                        isNewPeer = true;
                    }
                    else
                    {
                        // Actualizar timestamp
                        _discoveredPeers[peerKey].LastSeen = DateTime.UtcNow;
                    }
                }

                // Llamar callback si es un peer nuevo
                if (isNewPeer)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo peer descubierto: {peer.IPAddress} [PK: {peerKey.Substring(0, 16)}...] via {family}");
                    PeerDiscoveredCallback?.Invoke(peer);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error procesando paquete de descubrimiento: {ex.Message}");
            }
        }

        /// <summary>
        /// Limpiar peers expirados
        /// </summary>
        private void CleanupExpiredPeers()
        {
            try
            {
                DateTime cutoffTime = DateTime.UtcNow.AddMilliseconds(-PACKET_TIMEOUT_MS);
                List<DiscoveredPeer> expiredPeers = new List<DiscoveredPeer>();

                lock (_peersLock)
                {
                    var expiredKeys = _discoveredPeers
                        .Where(kvp => kvp.Value.LastSeen < cutoffTime)
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (string key in expiredKeys)
                    {
                        expiredPeers.Add(_discoveredPeers[key]);
                        _discoveredPeers.Remove(key);
                    }
                }

                // Notificar peers expirados
                foreach (var peer in expiredPeers)
                {
                    Logger.Log.DebugF($"[{LOG_TAG}] Peer expirado: {peer.IPAddress}");
                    PeerExpiredCallback?.Invoke(peer);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error limpiando peers expirados: {ex.Message}");
            }
        }

        /// <summary>
        /// Obtener lista de peers descubiertos
        /// </summary>
        public List<DiscoveredPeer> GetDiscoveredPeers()
        {
            lock (_peersLock)
            {
                return _discoveredPeers.Values.ToList();
            }
        }

        /// <summary>
        /// Obtener estadísticas de descubrimiento
        /// </summary>
        public LANDiscoveryStats GetStats()
        {
            lock (_peersLock)
            {
                return new LANDiscoveryStats
                {
                    TotalPeersDiscovered = _discoveredPeers.Count,
                    ActivePeers = _discoveredPeers.Count(p => p.Value.LastSeen > DateTime.UtcNow.AddMinutes(-5)),
                    IsRunning = _isRunning
                };
            }
        }

        /// <summary>
        /// Forzar descubrimiento inmediato
        /// </summary>
        public void ForceDiscovery()
        {
            try
            {
                SendDiscoveryPacket();
                Logger.Log.Debug($"[{LOG_TAG}] Descubrimiento forzado ejecutado");
            }
            catch (Exception ex)
            {
                Logger.Log.WarningF($"[{LOG_TAG}] Error en descubrimiento forzado: {ex.Message}");
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }

    // ... (las clases DiscoveredPeer, LANDiscoveryStats, y CryptoBytes se mantienen igual)


    /// <summary>
    /// Información de un peer descubierto
    /// </summary>
    public class DiscoveredPeer
    {
        public byte[] PublicKey { get; set; }
        public IPAddress IPAddress { get; set; }
        public ushort Port { get; set; }
        public DateTime LastSeen { get; set; }
        public string DiscoveryMethod { get; set; }

        public override string ToString()
        {
            string keyShort = PublicKey != null ? BitConverter.ToString(PublicKey, 0, 8).Replace("-", "") : "N/A";
            return $"{IPAddress}:{Port} [PK: {keyShort}...] ({DiscoveryMethod})";
        }
    }



    /// <summary>
    /// Estadísticas de LAN Discovery
    /// </summary>
    public class LANDiscoveryStats
    {
        public int TotalPeersDiscovered { get; set; }
        public int ActivePeers { get; set; }
        public bool IsRunning { get; set; }

        public override string ToString()
        {
            return $"LAN Discovery - Ejecutándose: {IsRunning}, Peers: {TotalPeersDiscovered} total, {ActivePeers} activos";
        }
    }

    /// <summary>
    /// Helper para comparación de bytes
    /// </summary>
    internal static class CryptoBytes
    {
        public static bool MemCompare(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }
    }


}