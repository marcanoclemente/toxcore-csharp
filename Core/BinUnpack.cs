// Core/BinUnpack.cs - Implementación manual de MessagePack
using System;
using System.Buffers.Binary;
using System.Text;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core
{
    /// <summary>
    /// Implementación manual de desempaquetado binario compatible con bin_unpack.c.
    /// Usa formato MessagePack sin dependencias externas.
    /// </summary>
    public sealed class BinUnpack : IBinUnpack, IDisposable
    {
        private readonly byte[] _data;
        private int _position;
        private bool _disposed;

        public int Position => _position;
        public int Length => _data?.Length ?? 0;
        public int Remaining => Length - _position;

        public BinUnpack(ReadOnlySpan<byte> data)
        {
            _data = data.ToArray();
            _position = 0;
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
        public bool UnpackArray(out uint size)
        {
            size = 0;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            if ((b & 0xf0) == 0x90)
            {
                // fixarray: 1001XXXX
                size = (uint)(b & 0x0f);
                _position++;
                return true;
            }
            else if (b == MP_ARRAY16)
            {
                _position++;
                return ReadUInt16BigEndian(out ushort val) && (size = val) >= 0;
            }
            else if (b == MP_ARRAY32)
            {
                _position++;
                return ReadUInt32BigEndian(out uint val) && (size = val) >= 0;
            }
            return false;
        }

        public bool UnpackArrayFixed(uint requiredSize, out uint actualSize)
        {
            actualSize = 0;
            if (!UnpackArray(out uint size))
                return false;
            actualSize = size;
            return size == requiredSize;
        }

        // ========== MessagePack tipos básicos ==========
        public bool UnpackBool(out bool val)
        {
            val = false;
            if (_disposed) return false;
            if (!ReadByte(out byte b)) return false;

            if (b == MP_FALSE)
            {
                val = false;
                return true;
            }
            else if (b == MP_TRUE)
            {
                val = true;
                return true;
            }
            return false;
        }

        public bool UnpackU8(out byte val)
        {
            val = 0;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            if (b <= 127)
            {
                // positive fixint
                val = b;
                _position++;
                return true;
            }
            else if (b == MP_UINT8)
            {
                _position++;
                return ReadByte(out val);
            }
            return false;
        }

        public bool UnpackU16(out ushort val)
        {
            val = 0;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            if (b <= 127)
            {
                val = b;
                _position++;
                return true;
            }
            else if (b == MP_UINT8)
            {
                _position++;
                if (!ReadByte(out byte v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT16)
            {
                _position++;
                return ReadUInt16BigEndian(out val);
            }
            return false;
        }

        public bool UnpackU32(out uint val)
        {
            val = 0;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            if (b <= 127)
            {
                val = b;
                _position++;
                return true;
            }
            else if (b == MP_UINT8)
            {
                _position++;
                if (!ReadByte(out byte v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT16)
            {
                _position++;
                if (!ReadUInt16BigEndian(out ushort v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT32)
            {
                _position++;
                return ReadUInt32BigEndian(out val);
            }
            return false;
        }

        public bool UnpackU64(out ulong val)
        {
            val = 0;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            if (b <= 127)
            {
                val = b;
                _position++;
                return true;
            }
            else if (b == MP_UINT8)
            {
                _position++;
                if (!ReadByte(out byte v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT16)
            {
                _position++;
                if (!ReadUInt16BigEndian(out ushort v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT32)
            {
                _position++;
                if (!ReadUInt32BigEndian(out uint v)) return false;
                val = v;
                return true;
            }
            else if (b == MP_UINT64)
            {
                _position++;
                return ReadUInt64BigEndian(out val);
            }
            return false;
        }

        public bool UnpackNil()
        {
            if (_disposed) return false;
            if (!ReadByte(out byte b)) return false;
            return b == MP_NIL;
        }

        // ========== MessagePack bin ==========
        public bool UnpackBin(out byte[] data)
        {
            data = null;
            if (_disposed) return false;
            if (!PeekByte(out byte b)) return false;

            uint length = 0;
            if (b == MP_BIN8)
            {
                _position++;
                if (!ReadByte(out byte len)) return false;
                length = len;
            }
            else if (b == MP_BIN16)
            {
                _position++;
                if (!ReadUInt16BigEndian(out ushort len)) return false;
                length = len;
            }
            else if (b == MP_BIN32)
            {
                _position++;
                if (!ReadUInt32BigEndian(out uint len)) return false;
                length = len;
            }
            else
            {
                return false;
            }

            if (length > int.MaxValue || Remaining < length)
                return false;

            data = new byte[length];
            if (length > 0)
            {
                Buffer.BlockCopy(_data, _position, data, 0, (int)length);
                _position += (int)length;
            }
            return true;
        }

        public bool UnpackBinMax(byte[] buffer, out ushort actualLength, ushort maxLength)
        {
            actualLength = 0;
            if (_disposed) return false;

            if (!UnpackBin(out byte[] data))
                return false;

            if (data.Length > maxLength)
                return false;

            actualLength = (ushort)data.Length;
            Buffer.BlockCopy(data, 0, buffer, 0, actualLength);
            return true;
        }

        public bool UnpackBinFixed(uint length, out byte[] data)
        {
            data = null;
            if (_disposed) return false;

            if (!UnpackBin(out byte[] binData))
                return false;

            if (binData.Length != length)
                return false;

            data = binData;
            return true;
        }

        // ========== Binary big-endian (_b suffix) ==========
        public bool UnpackU8B(out byte val)
        {
            val = 0;
            if (_disposed) return false;
            return ReadByte(out val);
        }

        public bool UnpackU16B(out ushort val)
        {
            val = 0;
            if (_disposed) return false;
            return ReadUInt16BigEndian(out val);
        }

        public bool UnpackU32B(out uint val)
        {
            val = 0;
            if (_disposed) return false;
            return ReadUInt32BigEndian(out val);
        }

        public bool UnpackU64B(out ulong val)
        {
            val = 0;
            if (_disposed) return false;
            return ReadUInt64BigEndian(out val);
        }

        public bool UnpackBinB(byte[] data, uint length)
        {
            if (_disposed) return false;
            if (Remaining < length) return false;
            Buffer.BlockCopy(_data, _position, data, 0, (int)length);
            _position += (int)length;
            return true;
        }

        // ========== Private helper methods ==========
        private bool PeekByte(out byte val)
        {
            val = 0;
            if (Remaining < 1) return false;
            val = _data[_position];
            return true;
        }

        private bool ReadByte(out byte val)
        {
            val = 0;
            if (Remaining < 1) return false;
            val = _data[_position++];
            return true;
        }

        private bool ReadUInt16BigEndian(out ushort val)
        {
            val = 0;
            if (Remaining < 2) return false;
            val = BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(_position, 2));
            _position += 2;
            return true;
        }

        private bool ReadUInt32BigEndian(out uint val)
        {
            val = 0;
            if (Remaining < 4) return false;
            val = BinaryPrimitives.ReadUInt32BigEndian(_data.AsSpan(_position, 4));
            _position += 4;
            return true;
        }

        private bool ReadUInt64BigEndian(out ulong val)
        {
            val = 0;
            if (Remaining < 8) return false;
            val = BinaryPrimitives.ReadUInt64BigEndian(_data.AsSpan(_position, 8));
            _position += 8;
            return true;
        }

        // ========== Public methods ==========
        public void Reset()
        {
            if (_disposed) return;
            _position = 0;
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}