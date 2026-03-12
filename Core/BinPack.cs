// Core/BinPack.cs - Implementación manual de MessagePack
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación manual de empaquetado binario compatible con bin_pack.c.
    /// Usa formato MessagePack sin dependencias externas.
    /// </summary>
    public sealed class BinPack : IBinPack, IDisposable
    {
        private readonly MemoryStream _stream;
        private readonly int _capacity;
        private bool _disposed;

        public int Size => (int)_stream.Position;
        public int Capacity => _capacity;

        public BinPack(int initialCapacity = 1024)
        {
            _capacity = initialCapacity;
            _stream = new MemoryStream(initialCapacity);
        }

        // ========== MessagePack format constants ==========
        private const byte MP_NIL = 0xc0;
        private const byte MP_FALSE = 0xc2;
        private const byte MP_TRUE = 0xc3;
        private const byte MP_BIN8 = 0xc4;
        private const byte MP_BIN16 = 0xc5;
        private const byte MP_BIN32 = 0xc6;
        private const byte MP_STR8 = 0xd9;
        private const byte MP_STR16 = 0xda;
        private const byte MP_STR32 = 0xdb;
        private const byte MP_ARRAY16 = 0xdc;
        private const byte MP_ARRAY32 = 0xdd;
        private const byte MP_UINT8 = 0xcc;
        private const byte MP_UINT16 = 0xcd;
        private const byte MP_UINT32 = 0xce;
        private const byte MP_UINT64 = 0xcf;

        // ========== MessagePack array ==========
        public bool PackArray(uint size)
        {
            if (_disposed) return false;
            if (size <= 15)
            {
                // fixarray: 1001XXXX where XXXX is size
                return WriteByte((byte)(0x90 | size));
            }
            else if (size <= ushort.MaxValue)
            {
                if (!WriteByte(MP_ARRAY16)) return false;
                return WriteUInt16BigEndian((ushort)size);
            }
            else
            {
                if (!WriteByte(MP_ARRAY32)) return false;
                return WriteUInt32BigEndian(size);
            }
        }

        // ========== MessagePack tipos básicos ==========
        public bool PackBool(bool val)
        {
            if (_disposed) return false;
            return WriteByte(val ? MP_TRUE : MP_FALSE);
        }

        public bool PackU8(byte val)
        {
            if (_disposed) return false;
            if (val <= 127)
            {
                // positive fixint: 0XXXXXXX
                return WriteByte(val);
            }
            else
            {
                if (!WriteByte(MP_UINT8)) return false;
                return WriteByte(val);
            }
        }

        public bool PackU16(ushort val)
        {
            if (_disposed) return false;
            if (val <= 127)
            {
                return WriteByte((byte)val);
            }
            else if (val <= byte.MaxValue)
            {
                if (!WriteByte(MP_UINT8)) return false;
                return WriteByte((byte)val);
            }
            else
            {
                if (!WriteByte(MP_UINT16)) return false;
                return WriteUInt16BigEndian(val);
            }
        }

        public bool PackU32(uint val)
        {
            if (_disposed) return false;
            if (val <= 127)
            {
                return WriteByte((byte)val);
            }
            else if (val <= byte.MaxValue)
            {
                if (!WriteByte(MP_UINT8)) return false;
                return WriteByte((byte)val);
            }
            else if (val <= ushort.MaxValue)
            {
                if (!WriteByte(MP_UINT16)) return false;
                return WriteUInt16BigEndian((ushort)val);
            }
            else
            {
                if (!WriteByte(MP_UINT32)) return false;
                return WriteUInt32BigEndian(val);
            }
        }

        public bool PackU64(ulong val)
        {
            if (_disposed) return false;
            if (val <= uint.MaxValue)
            {
                return PackU32((uint)val);
            }
            else
            {
                if (!WriteByte(MP_UINT64)) return false;
                return WriteUInt64BigEndian(val);
            }
        }

        public bool PackNil()
        {
            if (_disposed) return false;
            return WriteByte(MP_NIL);
        }

        // ========== MessagePack bin/str ==========
        public bool PackBin(ReadOnlySpan<byte> data)
        {
            if (_disposed) return false;
            uint length = (uint)data.Length;

            if (length <= byte.MaxValue)
            {
                if (!WriteByte(MP_BIN8)) return false;
                if (!WriteByte((byte)length)) return false;
            }
            else if (length <= ushort.MaxValue)
            {
                if (!WriteByte(MP_BIN16)) return false;
                if (!WriteUInt16BigEndian((ushort)length)) return false;
            }
            else
            {
                if (!WriteByte(MP_BIN32)) return false;
                if (!WriteUInt32BigEndian(length)) return false;
            }

            if (length > 0)
            {
                return WriteBytes(data);
            }
            return true;
        }

        public bool PackStr(string data)
        {
            if (_disposed) return false;
            if (data == null) return PackNil();

            byte[] bytes = Encoding.UTF8.GetBytes(data);
            uint length = (uint)bytes.Length;

            if (length <= 31)
            {
                // fixstr: 101XXXXX where XXXXX is length
                if (!WriteByte((byte)(0xa0 | length))) return false;
            }
            else if (length <= byte.MaxValue)
            {
                if (!WriteByte(MP_STR8)) return false;
                if (!WriteByte((byte)length)) return false;
            }
            else if (length <= ushort.MaxValue)
            {
                if (!WriteByte(MP_STR16)) return false;
                if (!WriteUInt16BigEndian((ushort)length)) return false;
            }
            else
            {
                if (!WriteByte(MP_STR32)) return false;
                if (!WriteUInt32BigEndian(length)) return false;
            }

            if (length > 0)
            {
                return WriteBytes(bytes);
            }
            return true;
        }

        // ========== Binary big-endian (_b suffix) ==========
        public bool PackU8B(byte val)
        {
            if (_disposed) return false;
            return WriteByte(val);
        }

        public bool PackU16B(ushort val)
        {
            if (_disposed) return false;
            return WriteUInt16BigEndian(val);
        }

        public bool PackU32B(uint val)
        {
            if (_disposed) return false;
            return WriteUInt32BigEndian(val);
        }

        public bool PackU64B(ulong val)
        {
            if (_disposed) return false;
            return WriteUInt64BigEndian(val);
        }

        public bool PackBinB(ReadOnlySpan<byte> data)
        {
            if (_disposed) return false;
            return WriteBytes(data);
        }

        // ========== Private helper methods ==========
        private bool WriteByte(byte val)
        {
            if (Size + 1 > _capacity) return false;
            _stream.WriteByte(val);
            return true;
        }

        private bool WriteUInt16BigEndian(ushort val)
        {
            if (Size + 2 > _capacity) return false;
            Span<byte> bytes = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(bytes, val);
            _stream.Write(bytes);
            return true;
        }

        private bool WriteUInt32BigEndian(uint val)
        {
            if (Size + 4 > _capacity) return false;
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, val);
            _stream.Write(bytes);
            return true;
        }

        private bool WriteUInt64BigEndian(ulong val)
        {
            if (Size + 8 > _capacity) return false;
            Span<byte> bytes = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(bytes, val);
            _stream.Write(bytes);
            return true;
        }

        private bool WriteBytes(ReadOnlySpan<byte> data)
        {
            if (Size + data.Length > _capacity) return false;
            _stream.Write(data);
            return true;
        }

        // ========== Public methods ==========
        public byte[] GetResult()
        {
            if (_disposed) return Array.Empty<byte>();
            return _stream.ToArray();
        }

        public void Reset()
        {
            if (_disposed) return;
            _stream.SetLength(0);
            _stream.Position = 0;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _stream?.Dispose();
                _disposed = true;
            }
        }
    }
}