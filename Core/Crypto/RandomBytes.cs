using System;
using Toxcore.Core;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Generación de bytes aleatorios vía LibSodiumReal
    /// </summary>
    public static class RandomBytes
    {
        public static byte[] Generate(uint length)
        {
            if (length == 0) return Array.Empty<byte>();
            byte[] buffer = new byte[length];
            if (!LibSodium.TryRandomBytes(buffer))
                throw new InvalidOperationException("Failed to generate random bytes");
            return buffer;
        }

        public static void Generate(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (!LibSodium.TryRandomBytes(buffer))
                throw new InvalidOperationException("Failed to generate random bytes");
        }

        public static byte[] GenerateNonce() => LibSodium.GenerateNonce();
        public static byte[] GenerateKey() => LibSodium.GenerateKey();
    }
}