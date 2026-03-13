// Core/Abstractions/DhtConstants.cs (completo basado en DHT.c)
namespace Toxcore.Core.Abstractions
{
    public static class DhtConstants
    {
        // Timeouts e intervalos (segundos)
        public const int PingTimeout = 5;
        public const int PingInterval = 60;
        public const int BadNodeTimeout = 70; // PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD * (PING_INTERVAL + PING_ROUNDTRIP)
        public const int KillNodeTimeout = 130; // BAD_NODE_TIMEOUT + PING_INTERVAL
        public const int NodesRequestInterval = 20;
        public const int PunchInterval = 3;
        public const int PunchResetTime = 40;

        // Límites
        public const int MaxFriendClients = 8;
        public const int LclientLength = 128;
        public const int LclientList = LclientLength * MaxFriendClients;
        public const int MaxCloseToBootstrapNodes = 8;
        public const int MaxSentNodes = 4;
        public const int MaxPunchingPorts = 48;
        public const int MaxNormalPunchingTries = 5;
        public const int MaxBootstrapTimes = 5;
        public const int DhtFakeFriendNumber = 2;
        public const int DhtPingArraySize = 512;
        public const int MaxCryptoRequestSize = 1024;
        public const int DhtFriendMaxLocks = 32;
        public const int MaxSavedDhtNodes = ((DhtFakeFriendNumber * MaxFriendClients) + LclientList) * 2;
        public const int SaveBootstrapFrequency = 8;
        public const int MaxFriendTcpConnections = 4;


        // Tamaños de paquetes
        public const int PackedNodeSizeIp4 = 1 + 4 + 2 + 32; // family + ip4 + port + pubkey
        public const int PackedNodeSizeIp6 = 1 + 16 + 2 + 32; // family + ip6 + port + pubkey

        // NAT Ping
        public const byte NatPingRequest = 0;
        public const byte NatPingResponse = 1;

        // Caché de claves compartidas
        public const int MaxKeysPerSlot = 4;
        public const int KeysTimeout = 600;

        // Estado guardado
        public const uint DhtStateCookieGlobal = 0x159000d;
        public const ushort DhtStateCookieType = 0x11ce;
        public const byte DhtStateTypeNodes = 4;
    }
}