// Core/LanDiscoveryService.cs
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación del servicio de descubrimiento LAN.
    /// Traducción de LAN_discovery.c
    /// </summary>
    public sealed class LanDiscoveryService : ILanDiscoveryService, IDisposable
    {
        // Constantes de LAN_discovery.c
        public const int LanDiscoveryInterval = 10; // segundos
        public const byte LanDiscoveryPacketId = 0x21; // NET_PACKET_LAN_DISCOVERY

        private readonly INetworkCore _network;
        private readonly IDht _dht;
        private readonly MonoTime _monoTime;
        private readonly ushort _port;

        private CancellationTokenSource _cts;
        private Task _sendTask;
        private ulong _lastDiscoverySent;
        private bool _enabled = true;

        public bool Enabled
        {
            get => _enabled;
            set => _enabled = value;
        }

        public LanDiscoveryService(
            INetworkCore network,
            IDht dht,
            MonoTime monoTime,
            ushort port = NetworkConstants.ToxPortDefault)
        {
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _port = port;
        }

        public void Init()
        {
            // El handler ya está registrado en DHT.cs, aquí iniciamos el envío periódico
            if (_sendTask == null)
            {
                _cts = new CancellationTokenSource();
                _sendTask = SendLoop(_cts.Token);
                Logger.Log.Info("[LAN] Discovery service initialized");
            }
        }

        public void Kill()
        {
            _cts?.Cancel();
            try
            {
                _sendTask?.Wait(TimeSpan.FromSeconds(1));
            }
            catch { }
            _sendTask = null;
            Logger.Log.Info("[LAN] Discovery service stopped");
        }

        public bool SendDiscovery()
        {
            if (!_enabled) return false;

            // Construir paquete: [0x21][public_key(32 bytes)]
            byte[] packet = new byte[1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            packet[0] = LanDiscoveryPacketId;
            Buffer.BlockCopy(_dht.SelfPublicKey.ToArray(), 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            bool sentAny = false;

            try
            {
                // Enviar a broadcast IPv4 (255.255.255.255)
                var broadcastEp = new IPEndPoint(IPAddress.Broadcast, _port);
                if (_network.SendPacket(broadcastEp, packet, packet.Length) > 0)
                {
                    sentAny = true;
                    Logger.Log.Debug("[LAN] Sent discovery to 255.255.255.255");
                }

                // Enviar a multicast IPv6 (FF02::1) si el socket soporta IPv6
                if (_network.Family == AddressFamily.InterNetworkV6 || _network.IsDualStack)
                {
                    try
                    {
                        var multicastEp = new IPEndPoint(IPAddress.Parse("FF02::1"), _port);
                        if (_network.SendPacket(multicastEp, packet, packet.Length) > 0)
                        {
                            sentAny = true;
                            Logger.Log.Debug("[LAN] Sent discovery to FF02::1");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Log.Debug($"[LAN] IPv6 multicast failed: {ex.Message}");
                    }
                }

                // Enviar a broadcast de cada interfaz de red local
                sentAny |= SendToInterfaceBroadcasts(packet);

                _lastDiscoverySent = _monoTime.GetSeconds();
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[LAN] Error sending discovery: {ex.Message}");
            }

            return sentAny;
        }

        private bool SendToInterfaceBroadcasts(byte[] packet)
        {
            bool sent = false;

            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (var ni in interfaces)
                {
                    // Solo interfaces activas y que soporten multicast (broadcast)
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var props = ni.GetIPProperties();

                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                        // Calcular dirección de broadcast
                        var ip = addr.Address;
                        var mask = addr.IPv4Mask;

                        if (mask == null) continue;

                        var broadcast = CalculateBroadcast(ip, mask);
                        if (broadcast != null)
                        {
                            var ep = new IPEndPoint(broadcast, _port);
                            try
                            {
                                if (_network.SendPacket(ep, packet, packet.Length) > 0)
                                {
                                    sent = true;
                                    Logger.Log.Debug($"[LAN] Sent discovery to {broadcast}");
                                }
                            }
                            catch { /* Ignorar errores de interfaces individuales */ }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Warning($"[LAN] Error getting interfaces: {ex.Message}");
            }

            return sent;
        }

        private IPAddress CalculateBroadcast(IPAddress ip, IPAddress mask)
        {
            try
            {
                var ipBytes = ip.GetAddressBytes();
                var maskBytes = mask.GetAddressBytes();
                var broadcastBytes = new byte[4];

                for (int i = 0; i < 4; i++)
                {
                    broadcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
                }

                return new IPAddress(broadcastBytes);
            }
            catch
            {
                return null;
            }
        }

        public bool IsLanIp(IPAddress ip)
        {
            if (ip == null) return false;

            // Loopback es considerado LAN
            if (IPAddress.IsLoopback(ip)) return true;

            // IPv4 LAN ranges
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();

                // 10.0.0.0/8
                if (bytes[0] == 10) return true;

                // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;

                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;

                // 169.254.0.0/16 (Link-local)
                if (bytes[0] == 169 && bytes[1] == 254) return true;
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();

                // FF02::/16 (Multicast link-local)
                if (bytes[0] == 0xFF && bytes[1] == 0x02) return true;

                // FE80::/10 (Link-local)
                if ((bytes[0] & 0xFE) == 0xFE && (bytes[1] & 0xC0) == 0x80) return true;

                // FC00::/7 (Unique local)
                if ((bytes[0] & 0xFE) == 0xFC) return true;
            }

            return false;
        }

        private async Task SendLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // Enviar cada LAN_DISCOVERY_INTERVAL segundos
                    if (_monoTime.IsTimeout(_lastDiscoverySent, LanDiscoveryInterval))
                    {
                        SendDiscovery();
                    }

                    await Task.Delay(1000, ct); // Chequear cada segundo
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[LAN] Error in send loop: {ex.Message}");
                    await Task.Delay(5000, ct); // Esperar más en caso de error
                }
            }
        }

        public void Dispose()
        {
            Kill();
            _cts?.Dispose();
        }
    }
}