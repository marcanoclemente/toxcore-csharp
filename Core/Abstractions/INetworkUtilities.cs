// Core/Abstractions/INetworkUtilities.cs
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Utilidades estáticas de manipulación de IP/Port.
    /// Equivalente a las funciones ip_* y addr_* de network.h
    /// Separado de INetworkCore para mantener la interfaz limpia.
    /// </summary>
    public interface INetworkAddressUtilities
    {
        /// <summary>
        /// Compara dos direcciones IP (maneja IPv4-mapped IPv6).
        /// Equivalente a ip_equal().
        /// </summary>
        bool IpEqual(IPAddress? a, IPAddress? b);

        /// <summary>
        /// Compara dos endpoints (IP + Puerto).
        /// Equivalente a ipport_equal().
        /// </summary>
        bool IpPortEqual(IPEndPoint? a, IPEndPoint? b);

        /// <summary>
        /// Serializa un IPEndPoint al formato binario de Tox.
        /// Equivalente a pack_ip_port().
        /// </summary>
        bool PackIpPort(IPEndPoint ipPort, Span<byte> buffer, out int bytesWritten);

        /// <summary>
        /// Deserializa desde formato binario de Tox.
        /// Equivalente a unpack_ip_port().
        /// </summary>
        bool UnpackIpPort(ReadOnlySpan<byte> data, out IPEndPoint? ipPort, bool tcpEnabled = false);

        /// <summary>
        /// Verifica si IPv6 es IPv4-mapped (::ffff:xxxx:xxxx).
        /// Equivalente a ipv6_ipv4_in_v6().
        /// </summary>
        bool IsIPv4MappedToIPv6(IPAddress address);

        /// <summary>
        /// Resuelve un hostname a lista de IPs.
        /// Equivalente a addr_resolve_or_parse_ip() / net_getipport().
        /// </summary>
        Task<IReadOnlyList<IPEndPoint>> ResolveAsync(string host, ushort port = 0,
            System.Net.Sockets.AddressFamily family = System.Net.Sockets.AddressFamily.Unspecified,
            bool dnsEnabled = true);
    }
}