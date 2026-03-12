// Core/Abstractions/NetPacketType.cs
namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Tipos de paquetes de red definidos en el protocolo Tox.
    /// Equivalente a Net_Packet_Type en network.h
    /// </summary>
    public enum NetPacketType : byte
    {
        // DHT
        PingRequest = 0x00,
        PingResponse = 0x01,
        NodesRequest = 0x02,
        NodesResponse = 0x04,

        // Handshake/Crypto
        CookieRequest = 0x18,
        CookieResponse = 0x19,
        CryptoHandshake = 0x1a,
        CryptoData = 0x1b,
        Crypto = 0x20,

        // LAN
        LanDiscovery = 0x21,

        // Group Chats
        GroupHandshake = 0x5a,
        GroupLossless = 0x5b,
        GroupLossy = 0x5c,

        // Onion Routing
        OnionSendInitial = 0x80,
        OnionSend1 = 0x81,
        OnionSend2 = 0x82,
        OnionDataRequest = 0x85,
        OnionDataResponse = 0x86,
        OnionAnnounceRequest = 0x87,
        OnionAnnounceResponse = 0x88,
        OnionRecv3 = 0x8c,
        OnionRecv2 = 0x8d,
        OnionRecv1 = 0x8e,

        // Forwarding
        ForwardRequest = 0x90,
        Forwarding = 0x91,
        ForwardReply = 0x92,

        // DHT Store (Datos)
        DataSearchRequest = 0x93,
        DataSearchResponse = 0x94,
        DataRetrieveRequest = 0x95,
        DataRetrieveResponse = 0x96,
        StoreAnnounceRequest = 0x97,
        StoreAnnounceResponse = 0x98,

        // Bootstrap
        BootstrapInfo = 0xf0,

        // Deprecated/Legacy (mantener para compatibilidad)
        AnnounceRequestOld = 0x83,
        AnnounceResponseOld = 0x84,

        Max = 0xff
    }
}