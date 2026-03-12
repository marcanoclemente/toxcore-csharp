using System;
using System.Security.Cryptography;

namespace Toxcore.Core.Crypto
{
    public sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new ByteArrayComparer();

        public bool Equals(byte[]? a, byte[]? b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a is null || b is null) return false;
            if (a.Length != b.Length) return false;
            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        public int GetHashCode(byte[] obj)
        {
            if (obj is null) return 0;
            unchecked
            {
                // FNV-1a simple y estable
                int h = 1469598107;
                for (int i = 0; i < obj.Length; i++)
                    h = (h ^ obj[i]) * 16777619;
                return h;
            }
        }
    }
}
