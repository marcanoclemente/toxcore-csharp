// Core/Abstractions/IBinUnpack.cs
using System;

namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Interfaz para desempaquetado binario de datos (bin_unpack.h).
    /// Deserializa datos desde formato MessagePack y binario específico del protocolo Tox.
    /// </summary>
    public interface IBinUnpack
    {
        // ========== MessagePack array ==========
        bool UnpackArray(out uint size);
        bool UnpackArrayFixed(uint requiredSize, out uint actualSize);

        // ========== MessagePack tipos básicos ==========
        bool UnpackBool(out bool val);
        bool UnpackU8(out byte val);
        bool UnpackU16(out ushort val);
        bool UnpackU32(out uint val);
        bool UnpackU64(out ulong val);
        bool UnpackNil();

        // ========== MessagePack bin ==========
        bool UnpackBin(out byte[] data);
        bool UnpackBinMax(byte[] buffer, out ushort actualLength, ushort maxLength);
        bool UnpackBinFixed(uint length, out byte[] data);

        // ========== Binary big-endian (_b suffix) ==========
        bool UnpackU8B(out byte val);
        bool UnpackU16B(out ushort val);
        bool UnpackU32B(out uint val);
        bool UnpackU64B(out ulong val);
        bool UnpackBinB(byte[] data, uint length);

        // ========== Utilidades ==========
        int Remaining { get; }
        int Position { get; }
        int Length { get; }
    }
}