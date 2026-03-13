// Core/Abstractions/NetPacket.cs
using System;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Representa un paquete de red saliente.
    /// Equivalente a Net_Packet en network.h pero usando Span para eficiencia.
    /// </summary>
        public readonly ref struct NetPacket
        {
            public ReadOnlySpan<byte> Data { get; }
            public ushort Length => (ushort)Data.Length;

            public NetPacket(ReadOnlySpan<byte> data)
            {
                if (data.Length > NetworkConstants.MaxUdpPacketSize)
                    throw new ArgumentException($"Packet too large: {data.Length} > {NetworkConstants.MaxUdpPacketSize}");
            
                Data = data;
            }

            public NetPacketType PacketType => Data.Length > 0 ? (NetPacketType)Data[0] : (NetPacketType)0xFF;
        }
}