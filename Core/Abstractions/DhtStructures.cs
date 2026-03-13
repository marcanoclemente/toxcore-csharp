// Core/Abstractions/DhtStructures.cs
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Representa un nodo DHT con su clave pública y endpoint.
    /// Equivalente exacto a Node_format en DHT.c
    /// </summary>
    public struct NodeFormat
    {
        public byte[] PublicKey; // 32 bytes
        public IPEndPoint IpPort;

        public static NodeFormat Empty => new()
        {
            PublicKey = new byte[32],
            IpPort = new IPEndPoint(0, 0)
        };

        public readonly bool IsEmpty => PublicKey == null || PublicKey.All(b => b == 0);
    }

    /// <summary>
    /// Información de asociación IP+Puerto con timestamp.
    /// Equivalente a IPPTs en DHT.c
    /// </summary>
    public struct IpPts
    {
        public IPEndPoint IpPort;
        public ulong Timestamp;
    }

    /// <summary>
    /// Información de asociación IP+Puerto con timestamp.
    /// Equivalente a IPPTsPng en DHT.c
    /// AHORA ES CLASE para permitir modificación directa.
    /// </summary>
    public class IpPtsPng
    {
        public IPEndPoint IpPort { get; set; }
        public ulong Timestamp { get; set; }
        public ulong LastPinged { get; set; }
        public IPEndPoint RetIpPort { get; set; } // Retornado por este nodo
        public ulong RetTimestamp { get; set; }
        public bool RetIpSelf { get; set; }

    }

    /// <summary>
    /// Datos de un cliente/nodo conocido (estructura pública para queries).
    /// Equivalente a Client_data en DHT.c
    /// </summary>
    public class ClientData
    {
        public byte[] PublicKey { get; set; } = new byte[32];
        public IpPtsPng Assoc4 { get; set; } = new IpPtsPng(); // IPv4
        public IpPtsPng Assoc6 { get; set; } = new IpPtsPng(); // IPv6
        public bool AnnounceNode { get; set; }
    }

    /// <summary>
    /// Estado de NAT punching para un amigo.
    /// Equivalente a NAT en DHT.c
    /// </summary>
    public struct NatState
    {
        public bool HolePunching;
        public uint PunchingIndex;
        public uint Tries;
        public uint PunchingIndex2;
        public ulong PunchingTimestamp;
        public ulong RecvNatPingTimestamp;
        public ulong NatPingId;
        public ulong NatPingTimestamp;
    }

    /// <summary>
    /// Callback almacenado para un amigo.
    /// Equivalente a DHT_Friend_Callback en DHT.c
    /// </summary>
    public class DhtFriendCallback
    {
        public DhtIpCallback? IpCallback;
        public object? Data;
        public int Number;
    }

    /// <summary>
    /// Representa un "amigo" en el DHT (nodo que estamos buscando).
    /// Equivalente a DHT_Friend en DHT.c - versión pública de solo lectura.
    /// </summary>
    public interface IDhtFriend
    {
        byte[] PublicKey { get; }
        ClientData[] ClientList { get; }
        ulong LastNodesRequest { get; }
        uint BootstrapTimes { get; }
        NatState Nat { get; }
    }
}