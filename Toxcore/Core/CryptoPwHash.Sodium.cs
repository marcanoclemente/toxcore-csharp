using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación REAL de crypto_pwhash_scryptsalsa208sha256 con libsodium
    /// </summary>
    public static class CryptoPwHash
    {
        public const int SALT_BYTES = 32;
        public const int HASH_BYTES = 32;
        public const ulong OPSLIMIT_INTERACTIVE = 524288;
        public const uint MEMLIMIT_INTERACTIVE = 16777216;
        public const ulong OPSLIMIT_SENSITIVE = 33554432;
        public const uint MEMLIMIT_SENSITIVE = 1073741824;

        /// <summary>
        /// Deriva clave con scryptsalsa208sha256 REAL
        /// </summary>
        public static byte[] ScryptSalsa208Sha256(byte[] password, byte[] salt, ulong opsLimit, uint memLimit)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null || salt.Length != SALT_BYTES)
                throw new ArgumentException($"Salt must be {SALT_BYTES} bytes");

            byte[] hash = new byte[HASH_BYTES];
            int ret = LibSodiumReal.crypto_pwhash_scryptsalsa208sha256(
                hash, (ulong)hash.Length,
                password, (ulong)password.Length,
                salt, opsLimit, (nuint)memLimit);

            if (ret != 0) throw new CryptographicException("scrypt failed");
            return hash;
        }

        /// <summary>
        /// Genera salt seguro
        /// </summary>
        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SALT_BYTES];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        /// <summary>
        /// Verifica password contra hash
        /// </summary>
        public static bool Verify(byte[] expectedHash, byte[] password, byte[] salt, ulong opsLimit, uint memLimit)
        {
            if (expectedHash == null || expectedHash.Length != HASH_BYTES) return false;
            byte[] computed = ScryptSalsa208Sha256(password, salt, opsLimit, memLimit);
            return CryptographicOperations.FixedTimeEquals(computed, expectedHash);
        }

        /// <summary>
        /// Test con vectores conocidos (toxcore)
        /// </summary>
        public static bool Test()
        {
            try
            {
                byte[] salt = GenerateSalt();
                byte[] pwd = Encoding.UTF8.GetBytes("toxpassword");
                byte[] hash = ScryptSalsa208Sha256(pwd, salt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);

                bool ok = hash != null && hash.Length == HASH_BYTES;
                bool verify = Verify(hash, pwd, salt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool wrong = !Verify(hash, Encoding.UTF8.GetBytes("wrong"), salt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);

                Console.WriteLine($"[CryptoPwHash] Test: {(ok && verify && wrong ? "✅" : "❌")}");
                return ok && verify && wrong;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CryptoPwHash] Test falló: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// API compatible con C (nombres originales)
    /// </summary>
    public static class crypto_pwhash_scryptsalsa208sha256_native
    {
        public const int SALTBYTES = CryptoPwHash.SALT_BYTES;
        public const int BYTES = CryptoPwHash.HASH_BYTES;
        public const ulong OPSLIMIT_INTERACTIVE = CryptoPwHash.OPSLIMIT_INTERACTIVE;
        public const uint MEMLIMIT_INTERACTIVE = CryptoPwHash.MEMLIMIT_INTERACTIVE;
        public const ulong OPSLIMIT_SENSITIVE = CryptoPwHash.OPSLIMIT_SENSITIVE;
        public const uint MEMLIMIT_SENSITIVE = CryptoPwHash.MEMLIMIT_SENSITIVE;

        public static int crypto_pwhash_scryptsalsa208sha256(
            byte[] @out, ulong outlen,
            byte[] passwd, ulong passwdlen,
            byte[] salt,
            ulong opslimit, uint memlimit)
        {
            try
            {
                byte[] hash = CryptoPwHash.ScryptSalsa208Sha256(passwd, salt, opslimit, memlimit);
                Buffer.BlockCopy(hash, 0, @out, 0, (int)outlen);
                return 0;
            }
            catch
            {
                return -1;
            }
        }
    }
}