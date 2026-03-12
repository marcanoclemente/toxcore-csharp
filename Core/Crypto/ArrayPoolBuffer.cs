using System;
using System.Buffers;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Rent-devolve automática con using-pattern
    /// </summary>
    internal readonly struct ArrayBuffer : IDisposable
    {
        private readonly byte[] _buffer;
        public byte[] Buffer => _buffer;
        public int Size { get; }

        private ArrayBuffer(int size)
        {
            Size = size;
            _buffer = ArrayPool<byte>.Shared.Rent(size);
        }

        public static ArrayBuffer Rent(int size) => new(size);
        public void Dispose() => ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
    }
}
