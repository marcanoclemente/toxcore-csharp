// Core/Abstractions/IDht.cs
using System.Net;
using System.Net.Sockets;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz de la tabla hash distribuida (DHT).
    /// Implementación completa compatible con dht.c original.
    /// </summary>
    public interface IDht : IDisposable
    {
        // Propiedades de estado
        ReadOnlySpan<byte> SelfPublicKey { get; }
        ReadOnlySpan<byte> SelfSecretKey { get; }
        bool IsConnected { get; }
        bool NonLanConnected { get; }
        ushort NumFriends { get; }
        ushort LocalPort { get; }

        // Callbacks
        void CallbackNodesResponse(DhtNodesResponseCallback callback);

        // Gestión de amigos
        int AddFriend(byte[] publicKey, out uint lockToken, DhtIpCallback ipCallback = null!, int number = 0);
        int DeleteFriend(byte[] publicKey, uint lockToken);
        int GetFriendIp(byte[] publicKey, out IPEndPoint ipPort);
        byte[] GetPublicKeyByIpPort(IPEndPoint endpoint);

        // Bootstrap
        bool Bootstrap(IPEndPoint ipPort, byte[] publicKey);
        bool BootstrapFromAddress(string address, bool ipv6Enabled, bool dnsEnabled, ushort port, byte[] publicKey);

        // Ciclo principal
        void DoDht();

        // Nodos cercanos
        int GetCloseNodes(byte[] publicKey, NodeFormat[] nodesList, AddressFamily? family = null, bool isLan = false, bool wantAnnounce = false);
        bool AddToList(NodeFormat[] nodesList, uint length, byte[] pk, IPEndPoint ipPort, byte[] cmpPk);
        bool IsNodeAddableToCloseList(byte[] publicKey, IPEndPoint ipPort);

        // Routing
        int RoutePacket(byte[] publicKey, ReadOnlySpan<byte> packet);
        uint RouteToFriend(byte[] friendId, NetPacket packet);

        // Gestión de nodos
        uint AddToLists(IPEndPoint ipPort, byte[] publicKey);

        // Dispatcher principal de paquetes DHT
        void DHT_handle_packet(byte[] data, int length, IPPort source);

        // Crypto packets
        void RegisterCryptoHandler(byte packetId, CryptoPacketHandlerCallback callback, object state = null!);

        // Persistencia
        uint GetSaveSize();
        void Save(Span<byte> data);
        int Load(ReadOnlySpan<byte> data);
        int ConnectAfterLoad();

        // Helpers
        byte[] GetSharedKeyRecv(byte[] publicKey);
        byte[] GetSharedKeySent(byte[] publicKey);

        // NAT punching
        void SetHolePunchingEnabled(bool enabled);
    }

    // Delegados
    
    
    
}