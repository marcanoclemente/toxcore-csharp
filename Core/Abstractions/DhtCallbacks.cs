// Core/Abstractions/DhtCallbacks.cs
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Callback cuando se encuentra la IP de un amigo.
    /// Equivalente a dht_ip_cb en DHT.c
    /// </summary>
    public delegate void DhtIpCallback(object data, int number, IPEndPoint ipPort);

    /// <summary>
    /// Callback para respuesta de nodos.
    /// Equivalente a dht_nodes_response_cb en DHT.c
    /// </summary>
    public delegate void DhtNodesResponseCallback(IDht dht, NodeFormat node, object userdata);

    /// <summary>
    /// Handler para paquetes criptográficos.
    /// Equivalente a cryptopacket_handler_cb en DHT.c
    /// </summary>
    public delegate void CryptoPacketHandlerCallback(object state, IPEndPoint source, byte[] senderPk, ReadOnlySpan<byte> data, object userdata);
}