using System.Security.Cryptography;
using Sodium;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación CORREGIDA de crypto_pwhash_scryptsalsa208sha256 usando Sodium
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
        /// Deriva clave usando scryptsalsa208sha256 - CORREGIDO para Sodium.Core 1.4.0
        /// </summary>
        public static byte[] ScryptSalsa208Sha256(byte[] password, byte[] salt, ulong opsLimit, uint memLimit)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null || salt.Length != SALT_BYTES)
                throw new ArgumentException($"Salt must be {SALT_BYTES} bytes");

            try
            {
                // CORRECCIÓN: Sodium.Core 1.4.0 
                return PasswordHash.ScryptHashBinary(
                    password: password,         
                    salt: salt,               
                    opsLimit: (long)opsLimit, 
                    memLimit: (int)memLimit, 
                    outputLength: (long)HASH_BYTES  
                );
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"Scrypt key derivation failed", ex);
            }
        }

        /// <summary>
        /// Genera salt seguro
        /// </summary>
        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SALT_BYTES];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        /// <summary>
        /// Verifica password contra hash
        /// </summary>
        public static bool Verify(byte[] expectedHash, byte[] password, byte[] salt,
                                ulong opsLimit, uint memLimit)
        {
            if (expectedHash == null || expectedHash.Length != HASH_BYTES)
                return false;

            byte[] computedHash = ScryptSalsa208Sha256(password, salt, opsLimit, memLimit);
            return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
        }

        /// <summary>
        /// Test de Scrypt
        /// </summary>
        public static bool Test()
        {
            try
            {
                byte[] salt1 = GenerateSalt();
                byte[] salt2 = GenerateSalt();

                bool saltValid = salt1.Length == SALT_BYTES && salt2.Length == SALT_BYTES;
                bool saltsDifferent = !CryptographicOperations.FixedTimeEquals(salt1, salt2);

                byte[] password = System.Text.Encoding.UTF8.GetBytes("test_password");
                byte[] hash = ScryptSalsa208Sha256(password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool derivationValid = hash != null && hash.Length == HASH_BYTES;

                bool verifyCorrect = Verify(hash, password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);

                byte[] wrongPassword = System.Text.Encoding.UTF8.GetBytes("wrong_password");
                bool verifyWrong = Verify(hash, wrongPassword, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);

                byte[] hash2 = ScryptSalsa208Sha256(password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool deterministic = CryptographicOperations.FixedTimeEquals(hash, hash2);

                byte[] hash3 = ScryptSalsa208Sha256(password, salt2, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool differentWithDifferentSalt = !CryptographicOperations.FixedTimeEquals(hash, hash3);

                return saltValid && saltsDifferent && derivationValid && verifyCorrect &&
                       !verifyWrong && deterministic && differentWithDifferentSalt;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// API compatible con nombres C originales
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
                byte[] passwordSegment = new byte[passwdlen];
                Buffer.BlockCopy(passwd, 0, passwordSegment, 0, (int)passwdlen);

                byte[] result = CryptoPwHash.ScryptSalsa208Sha256(
                    passwordSegment, salt, opslimit, memlimit);

                Buffer.BlockCopy(result, 0, @out, 0, (int)outlen);
                return 0;
            }
            catch
            {
                return -1;
            }
        }
    }
}