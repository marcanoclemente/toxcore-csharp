// Core/Abstractions/IBinPack.cs
using System;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz para empaquetado binario de datos (bin_pack.h).
    /// Serializa datos a formato MessagePack y binario específico del protocolo Tox.
    /// </summary>
    public interface IBinPack
    {
        // ========== MessagePack array ==========
        bool PackArray(uint size);

        // ========== MessagePack tipos básicos ==========
        bool PackBool(bool val);
        bool PackU8(byte val);
        bool PackU16(ushort val);
        bool PackU32(uint val);
        bool PackU64(ulong val);
        bool PackNil();

        // ========== MessagePack bin/str ==========
        bool PackBin(ReadOnlySpan<byte> data);
        bool PackStr(string data);

        // ========== Binary big-endian (_b suffix) ==========
        bool PackU8B(byte val);
        bool PackU16B(ushort val);
        bool PackU32B(uint val);
        bool PackU64B(ulong val);
        bool PackBinB(ReadOnlySpan<byte> data);

        // ========== Utilidades ==========
        byte[] GetResult();
        int Size { get; }
        int Capacity { get; }
    }
}