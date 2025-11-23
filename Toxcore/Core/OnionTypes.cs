namespace ToxCore.Core
{
    public enum OnionPacketType : byte
    {
        ONION_ANNOUNCE_REQUEST = 0x80,
        ONION_ANNOUNCE_RESPONSE = 0x81,
        ONION_DATA_REQUEST = 0x82,
        ONION_DATA_RESPONSE = 0x83
    }
}
