using System;
using System.Buffers.Binary;

namespace Toxcore.Core
{
    /// <summary>
    /// Utilidades de serialización de estado (state.h/state.c).
    /// Formato binario little-endian compatible con toxcore C.
    /// </summary>
    public static class State
    {
        public const uint StateCookieGlobal = 0x15ed1b1f;
        public const ushort StateCookieType = 0x01ce;

        // Tipos de sección
        public const ushort StateTypeNospamKeys = 1;
        public const ushort StateTypeDht = 2;
        public const ushort StateTypeFriends = 3;
        public const ushort StateTypeName = 4;
        public const ushort StateTypeStatusMessage = 5;
        public const ushort StateTypeStatus = 6;
        public const ushort StateTypeGroups = 7;
        public const ushort StateTypeTcpRelay = 10;
        public const ushort StateTypePathNode = 11;
        public const ushort StateTypeConferences = 20;
        public const ushort StateTypeEnd = 255;

        // Endianness helpers (little-endian es nativo en x86/x64 y ARM)
        public static ushort LendianToHost16(ushort lendian) => lendian; // .NET ya es LE en la mayoría de plataformas
        public static ushort HostToLendian16(ushort host) => host;

        public static void HostToLendianBytes64(Span<byte> dest, ulong num)
        {
            if (dest.Length < 8) throw new ArgumentException("Buffer too small");
            BinaryPrimitives.WriteUInt64LittleEndian(dest, num);
        }

        public static ulong LendianBytesToHost64(ReadOnlySpan<byte> lendian)
        {
            if (lendian.Length < 8) return 0;
            return BinaryPrimitives.ReadUInt64LittleEndian(lendian);
        }

        public static void HostToLendianBytes32(Span<byte> dest, uint num)
        {
            if (dest.Length < 4) throw new ArgumentException("Buffer too small");
            BinaryPrimitives.WriteUInt32LittleEndian(dest, num);
        }

        public static uint LendianBytesToHost32(ReadOnlySpan<byte> lendian)
        {
            if (lendian.Length < 4) return 0;
            return BinaryPrimitives.ReadUInt32LittleEndian(lendian);
        }

        public static void HostToLendianBytes16(Span<byte> dest, ushort num)
        {
            if (dest.Length < 2) throw new ArgumentException("Buffer too small");
            BinaryPrimitives.WriteUInt16LittleEndian(dest, num);
        }

        public static ushort LendianBytesToHost16(ReadOnlySpan<byte> lendian)
        {
            if (lendian.Length < 2) return 0;
            return BinaryPrimitives.ReadUInt16LittleEndian(lendian);
        }

        /// <summary>
        /// Escribe header de sección para save data.
        /// Equivalente a state_write_section_header.
        /// </summary>
        public static int WriteSectionHeader(Span<byte> data, ushort cookieType, uint len, ushort sectionType)
        {
            if (data.Length < 8) return -1;

            HostToLendianBytes32(data.Slice(0, 4), len);
            uint typeField = (uint)((HostToLendian16(cookieType) << 16) | HostToLendian16(sectionType));
            HostToLendianBytes32(data.Slice(4, 4), typeField);

            return 8;
        }
    }

    /// <summary>
    /// Estados de retorno para callback de carga.
    /// </summary>
    public enum StateLoadStatus
    {
        Continue = 0,
        Error = 1,
        End = 2
    }

    /// <summary>
    /// Delegado para callback de carga de secciones.
    /// </summary>
    public delegate StateLoadStatus StateLoadCallback(object outer, ReadOnlySpan<byte> data, uint length, ushort type);
}