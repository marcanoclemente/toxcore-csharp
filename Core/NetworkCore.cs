// Core/NetworkCore.cs
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Crypto;

namespace Toxcore.Core
{
    /// <summary>
    /// Información de handler de paquete.
    /// Equivalente a Packet_Handler en C.
    /// </summary>
    public sealed class NetworkCore : INetworkCore, INetworkAddressUtilities, IDisposable
    {
        private readonly PacketHandler[] _packetHandlers;
        private readonly PacketRateLimit _rateLimiter;
        private readonly CancellationTokenSource _cts;
        private readonly INetProfile _netProfile;

        private Socket? _socket;
        private Task? _receiveTask;
        private bool _disposed;
        private readonly object _lockObject = new();

        public IPEndPoint? LocalEndPoint { get; private set; }
        public bool IsRunning => _socket?.IsBound ?? false;
        public AddressFamily Family { get; private set; }
        public ushort Port { get; private set; }
        public bool IsDualStack { get; private set; }

        public NetworkCore(IPAddress? bindAddress = null,
            ushort portFrom = NetworkConstants.ToxPortRangeFrom,
            ushort portTo = NetworkConstants.ToxPortRangeTo,
            bool enableRateLimit = true, INetProfile netProfile = null)
        {
            _netProfile = netProfile; // Default si no se proporciona
            _packetHandlers = new PacketHandler[256];
            for (int i = 0; i < 256; i++) _packetHandlers[i] = new PacketHandler();

            for (int i = 0; i < 256; i++) _packetHandlers[i] = new PacketHandler();

            // CORREGIDO: Usar parámetros del constructor para PacketRateLimit
            _rateLimiter = enableRateLimit
                ? new PacketRateLimit(
                    capacityBytes: 100000,      // 100KB por bucket
                    refillIntervalMs: 1000,     // Refill cada 1 segundo
                    maxBuckets: 1024)           // Máximo 1024 endpoints
                : null;

            _cts = new CancellationTokenSource();

            Initialize(bindAddress, portFrom, portTo);
        }

        public INetProfile Profile => _netProfile;


        // ========== INetworkCore Implementation ==========

        public void Initialize(IPAddress? bindAddress = null, ushort portFrom = NetworkConstants.ToxPortRangeFrom, ushort portTo = NetworkConstants.ToxPortRangeTo)
        {
            // Implementación moveda desde el constructor para poder reiniciar
            if (_socket != null)
            {
                Shutdown();
            }

            // Normalizar rango de puertos
            if (portFrom == 0 && portTo == 0)
            {
                portFrom = NetworkConstants.ToxPortRangeFrom;
                portTo = NetworkConstants.ToxPortRangeTo;
            }
            else if (portFrom == 0 && portTo != 0)
            {
                portFrom = portTo;
            }
            else if (portFrom != 0 && portTo == 0)
            {
                portTo = portFrom;
            }
            else if (portFrom > portTo)
            {
                (portFrom, portTo) = (portTo, portFrom);
            }

            bindAddress ??= IPAddress.IPv6Any;
            bool isIPv6 = bindAddress.AddressFamily == AddressFamily.InterNetworkV6
                || bindAddress == IPAddress.IPv6Any;

            Family = isIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;

            _socket = new Socket(Family, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, NetworkConstants.SocketBufferSize);
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, NetworkConstants.SocketBufferSize);
                _socket.Blocking = false;

                if (isIPv6)
                {
                    try
                    {
                        _socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                        IsDualStack = true;
                        Logger.Log.Info("[Network] Dual-stack socket enabled");
                    }
                    catch (SocketException ex)
                    {
                        Logger.Log.Warning($"[Network] Dual-stack socket failed: {ex.Message}. IPv4 connections may fail.");
                        IsDualStack = false;
                    }

                    try
                    {
                        var multicastOption = new IPv6MulticastOption(IPAddress.Parse("FF02::1"));
                        _socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, multicastOption);
                        Logger.Log.Info("[Network] Joined multicast group FF02::1");
                    }
                    catch (Exception ex)
                    {
                        Logger.Log.Debug($"[Network] Failed to join multicast: {ex.Message}");
                    }
                }

                // Bind con retry
                bool bound = false;
                ushort currentPort = portFrom;

                for (int attempt = 0; attempt <= (portTo - portFrom) && !bound; attempt++)
                {
                    try
                    {
                        var endPoint = new IPEndPoint(bindAddress, currentPort);
                        _socket.Bind(endPoint);

                        LocalEndPoint = (IPEndPoint)_socket.LocalEndPoint!;
                        Port = (ushort)LocalEndPoint.Port;
                        bound = true;

                        Logger.Log.Info($"[Network] Bound successfully to {LocalEndPoint}");
                    }
                    catch (SocketException) when (currentPort < portTo)
                    {
                        currentPort++;
                    }
                }

                if (!bound)
                {
                    throw new InvalidOperationException($"Failed to bind to any port in range {portFrom}-{portTo}");
                }

                _receiveTask = ReceiveLoop(_cts.Token);
            }
            catch
            {
                _socket?.Dispose();
                _socket = null;
                throw;
            }
        }

        /// <summary>
        /// CORREGIDO: Cierre graceful con timeout.
        /// </summary>
        public void Shutdown()
        {
            if (_socket == null) return;

            try
            {
                _cts.Cancel();

                try
                {
                    _receiveTask?.Wait(TimeSpan.FromSeconds(2));
                }
                catch { }

                _socket.Close();
                _socket.Dispose();
                _socket = null;

                Logger.Log.Info("[Network] Shutdown complete");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[Network] Error during shutdown: {ex.Message}");
            }
        }

        public int SendPacket(IPEndPoint destination, NetPacket packet)
        {
            return SendPacket(destination, packet.Data.ToArray(), packet.Length);
        }

        public int SendPacket(IPEndPoint destination, byte[] data, int length)
        {
            if (_socket == null || !_socket.IsBound)
            {
                Logger.Log.Warning("[Network] Attempted to send on uninitialized socket");
                return -1;
            }

            if (destination.AddressFamily == AddressFamily.Unknown)
            {
                Logger.Log.Warning("[Network] Attempted to send to unspecified address family");
                return -1;
            }

            // IPv4 a IPv4-mapped si es necesario
            if (Family == AddressFamily.InterNetworkV6 &&
                IsDualStack &&
                destination.AddressFamily == AddressFamily.InterNetwork)
            {
                var ipv4Bytes = destination.Address.GetAddressBytes();
                var ipv6Bytes = new byte[16];
                ipv6Bytes[10] = 0xFF;
                ipv6Bytes[11] = 0xFF;
                Buffer.BlockCopy(ipv4Bytes, 0, ipv6Bytes, 12, 4);
                destination = new IPEndPoint(new IPAddress(ipv6Bytes), destination.Port);
            }
            else if (Family == AddressFamily.InterNetwork && destination.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Logger.Log.Warning("[Network] Attempted to send IPv6 packet on IPv4 socket");
                return -1;
            }

            try
            {
                int sent = _socket.SendTo(data, 0, length, SocketFlags.None, destination);

                if (sent > 0)
                {
                    _netProfile?.RecordPacket(data[0], sent, PacketDirection.Send);
                    Logger.Log.DebugF("[Network] O=> {0} bytes to {1}", sent, destination);
                }

                return sent;
            }
            catch (SocketException ex)
            {
                Logger.Log.ErrorF("[Network] Send error to {0}: {1}", destination, ex.Message);
                return -1;
            }
        }

        public void RegisterHandler(byte packetType, PacketHandlerCallback callback, object? state = null)
        {
            lock (_lockObject)
            {
                _packetHandlers[packetType].Function = callback;
                _packetHandlers[packetType].Object = state;
            }
            Logger.Log.DebugF("[Network] Registered handler for packet type 0x{0:X2}", packetType);
        }

        public void UnregisterHandler(byte packetType)
        {
            lock (_lockObject)
            {
                _packetHandlers[packetType].Function = null;
                _packetHandlers[packetType].Object = null;
            }
        }

        public void Poll(object? userData = null)
        {
            // En implementación async, el loop ya corre automáticamente
            // Este método existe por compatibilidad con INetworkCore
        }

        private async Task ReceiveLoop(CancellationToken ct)
        {
            var buffer = new byte[NetworkConstants.MaxUdpPacketSize];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var result = await _socket!.ReceiveFromAsync(
                        new ArraySegment<byte>(buffer),
                        SocketFlags.None,
                        remoteEndPoint);

                    if (result.ReceivedBytes == 0) continue;

                    remoteEndPoint = result.RemoteEndPoint;
                    ProcessReceivedPacket((IPEndPoint)remoteEndPoint, buffer, result.ReceivedBytes);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock
                    || ex.SocketErrorCode == SocketError.Interrupted)
                {
                    await Task.Yield();
                }
                catch (OperationCanceledException)
                {
                    // ✅ Cancelación normal por Dispose - no es error
                    Logger.Log.Debug("[Network] Receive loop cancelled gracefully");
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // ✅ Socket cerrado por Dispose - no es error
                    Logger.Log.Debug("[Network] Socket disposed, exiting receive loop");
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    // ✅ Esta es la que estás viendo - cancelación normal
                    Logger.Log.Debug("[Network] Receive operation aborted (shutdown)");
                    break;
                }
                catch (Exception ex)
                {
                    // Solo loggear como error si es realmente inesperado
                    if (!ct.IsCancellationRequested && _socket?.IsBound == true)
                    {
                        Logger.Log.Error($"[Network] Unexpected receive error: {ex.Message}");
                    }
                    break;
                }
            }
        }

        private void ProcessReceivedPacket(IPEndPoint source, byte[] data, int length)
        {
            Logger.Log.DebugF($"[NetworkCore] RECIBIDO: {length} bytes de {source}, tipo: 0x{data[0]:X2}");

            if (_rateLimiter != null && !_rateLimiter.ShouldAllow(source, length))
            {
                Logger.Log.Debug($"[Network] Packet from {source} rate limited");
                return;
            }

            Logger.Log.DebugF("[Network] <=O {0} bytes from {1}", length, source);

            _netProfile?.RecordPacket(data[0], length, PacketDirection.Receive);

            if (length < 1) return;

            byte packetId = data[0];
            var handler = _packetHandlers[packetId];

            if (handler.Function == null)
            {
                Logger.Log.DebugF("[Network] Packet {0:X2} has no handler", packetId);
                return;
            }

            try
            {
                handler.Function(handler.Object, source, data.AsSpan(0, length), null);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF("[Network] Handler error for packet {0:X2}: {1}", packetId, ex.Message);
            }
        }


        // ========== INetworkAddressUtilities Implementation ==========
        // Implementaciones de instancia que llaman a la lógica estática existente

        bool INetworkAddressUtilities.IpEqual(IPAddress? a, IPAddress? b)
        {
            return IpEqual(a, b);
        }

        bool INetworkAddressUtilities.IpPortEqual(IPEndPoint? a, IPEndPoint? b)
        {
            return IpPortEqual(a, b);
        }

        bool INetworkAddressUtilities.PackIpPort(IPEndPoint ipPort, Span<byte> buffer, out int bytesWritten)
        {
            return SerializeIpPort(ipPort, buffer, out bytesWritten);
        }

        bool INetworkAddressUtilities.UnpackIpPort(ReadOnlySpan<byte> data, out IPEndPoint? ipPort, bool tcpEnabled)
        {
            return DeserializeIpPort(data, out ipPort, tcpEnabled);
        }

        bool INetworkAddressUtilities.IsIPv4MappedToIPv6(IPAddress address)
        {
            return IsIPv4MappedToIPv6(address);
        }

        Task<IReadOnlyList<IPEndPoint>> INetworkAddressUtilities.ResolveAsync(string host, ushort port,
            AddressFamily family, bool dnsEnabled)
        {
            return ResolveAsync(host, port, family, dnsEnabled);
        }

        // ========== Métodos Estáticos (mantenidos por compatibilidad y uso interno) ==========

        public static bool IpEqual(IPAddress? a, IPAddress? b)
        {
            if (a == null || b == null) return false;
            if (a.Equals(b)) return true;

            if (a.IsIPv4MappedToIPv6 && b.AddressFamily == AddressFamily.InterNetwork)
            {
                return a.MapToIPv4().Equals(b);
            }
            if (b.IsIPv4MappedToIPv6 && a.AddressFamily == AddressFamily.InterNetwork)
            {
                return b.MapToIPv4().Equals(a);
            }

            return false;
        }

        public static bool IpPortEqual(IPEndPoint? a, IPEndPoint? b)
        {
            if (a == null || b == null) return false;
            if (a.Port != b.Port) return false;
            return IpEqual(a.Address, b.Address);
        }

        /// <summary>
        /// ÚNICO método de serialización IP/Port. Todos los demás deben llamar a este.
        /// </summary>
        public static bool SerializeIpPort(IPEndPoint ipPort, Span<byte> buffer, out int bytesWritten)
        {
            bytesWritten = 0;
            if (buffer.Length < 19) return false;

            bool isIPv6 = ipPort.AddressFamily == AddressFamily.InterNetworkV6;

            buffer[0] = isIPv6 ? (byte)10 : (byte)2; // TOX_AF_INET6 : TOX_AF_INET

            if (isIPv6)
            {
                if (buffer.Length < 19) return false;
                ipPort.Address.GetAddressBytes().CopyTo(buffer.Slice(1, 16));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(17, 2), (ushort)ipPort.Port);
                bytesWritten = 19;
            }
            else
            {
                if (buffer.Length < 7) return false;
                var ipv4Bytes = ipPort.Address.MapToIPv4().GetAddressBytes();
                ipv4Bytes.CopyTo(buffer.Slice(1, 4));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(5, 2), (ushort)ipPort.Port);
                bytesWritten = 7;
            }

            return true;
        }


        /// <summary>
        /// ÚNICO método de deserialización IP/Port
        /// </summary>
        public static bool DeserializeIpPort(ReadOnlySpan<byte> data, out IPEndPoint ipPort, bool allowTcp = false)
        {
            ipPort = null;
            if (data.Length < 1) return false;

            byte family = data[0];
            bool isIPv6;
            int expectedSize;

            switch (family)
            {
                case 2: // TOX_AF_INET
                    isIPv6 = false;
                    expectedSize = 7;
                    break;
                case 10: // TOX_AF_INET6
                    isIPv6 = true;
                    expectedSize = 19;
                    break;
                case 130 when allowTcp: // TOX_TCP_INET
                    isIPv6 = false;
                    expectedSize = 7;
                    break;
                case 138 when allowTcp: // TOX_TCP_INET6
                    isIPv6 = true;
                    expectedSize = 19;
                    break;
                default:
                    return false;
            }

            if (data.Length < expectedSize) return false;

            IPAddress address;
            int portOffset;

            if (isIPv6)
            {
                byte[] ipBytes = data.Slice(1, 16).ToArray();
                address = new IPAddress(ipBytes);
                portOffset = 17;
            }
            else
            {
                byte[] ipBytes = data.Slice(1, 4).ToArray();
                address = new IPAddress(ipBytes);
                portOffset = 5;
            }

            ushort port = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(portOffset, 2));
            ipPort = new IPEndPoint(address, port);

            return true;
        }

        public static bool IsIPv4MappedToIPv6(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            var bytes = address.GetAddressBytes();
            for (int i = 0; i < 10; i++)
                if (bytes[i] != 0) return false;
            return bytes[10] == 0xFF && bytes[11] == 0xFF;
        }

        public static async Task<IReadOnlyList<IPEndPoint>> ResolveAsync(string host, ushort port = 0,
            AddressFamily family = AddressFamily.Unspecified, bool dnsEnabled = true)
        {
            if (!dnsEnabled)
            {
                if (IPAddress.TryParse(host, out var ip))
                {
                    return new[] { new IPEndPoint(ip, port) };
                }
                return Array.Empty<IPEndPoint>();
            }

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                var results = new List<IPEndPoint>();

                foreach (var addr in addresses)
                {
                    if (family == AddressFamily.Unspecified || addr.AddressFamily == family)
                    {
                        results.Add(new IPEndPoint(addr, port));
                    }
                }

                return results;
            }
            catch
            {
                if (IPAddress.TryParse(host, out var ip))
                {
                    return new[] { new IPEndPoint(ip, port) };
                }
                return Array.Empty<IPEndPoint>();
            }
        }

        // ========== IDisposable ==========

        public void Dispose()
        {
            if (_disposed) return;
            Shutdown();
            _cts.Dispose();
            _disposed = true;
        }

        // Auxiliares
        private class PacketHandler
        {
            public PacketHandlerCallback? Function { get; set; }
            public object? Object { get; set; }
        }

        //private enum PacketDirection { Send, Receive }

        private class NetProfile
        {
            public void RecordPacket(byte packetType, int size, PacketDirection direction) { }
        }
    }
}