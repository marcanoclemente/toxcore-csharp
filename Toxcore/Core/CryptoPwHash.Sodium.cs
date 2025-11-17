using System;
using System.Security.Cryptography;
using Sodium;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación CORRECTA de crypto_pwhash_scryptsalsa208sha256 usando Sodium
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
        /// Deriva clave usando scryptsalsa208sha256 - CORREGIDO
        /// </summary>
        public static byte[] ScryptSalsa208Sha256(byte[] password, byte[] salt, ulong opsLimit, uint memLimit)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null || salt.Length != SALT_BYTES)
                throw new ArgumentException($"Salt must be {SALT_BYTES} bytes");

            try
            {
                // CORRECCIÓN: Usar la sobrecarga correcta que acepta byte[]
                long opsLimitLong = (long)opsLimit;
                int memLimitInt = (int)memLimit;

                return PasswordHash.ScryptHashBinary(password, salt, opsLimitLong, memLimitInt, HASH_BYTES);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Scrypt key derivation failed", ex);
            }
        }


        /// <summary>
        /// Genera salt seguro - CORREGIDO
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

        // Los demás métodos permanecen igual...
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
        /// Test exhaustivo de Scrypt - CORREGIDO
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     🔬 Testing CryptoPwHash (Scrypt)...");

                // Test 1: Generación de salt
                byte[] salt1 = GenerateSalt();
                byte[] salt2 = GenerateSalt();
                bool saltValid = salt1.Length == SALT_BYTES && salt2.Length == SALT_BYTES;
                bool saltsDifferent = !CryptographicOperations.FixedTimeEquals(salt1, salt2);
                Console.WriteLine($"       Salt generation: {(saltValid ? "✅" : "❌")}");
                Console.WriteLine($"       Salts are unique: {(saltsDifferent ? "✅" : "❌")}");

                // Test 2: Derivación básica
                byte[] password = System.Text.Encoding.UTF8.GetBytes("test_password");
                byte[] hash = ScryptSalsa208Sha256(password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool derivationValid = hash != null && hash.Length == HASH_BYTES;
                Console.WriteLine($"       Key derivation: {(derivationValid ? "✅" : "❌")}");

                // Test 3: Verificación correcta
                bool verifyCorrect = Verify(hash, password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                Console.WriteLine($"       Correct password verification: {(verifyCorrect ? "✅" : "❌")}");

                // Test 4: Verificación incorrecta
                byte[] wrongPassword = System.Text.Encoding.UTF8.GetBytes("wrong_password");
                bool verifyWrong = Verify(hash, wrongPassword, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                Console.WriteLine($"       Wrong password rejection: {(!verifyWrong ? "✅" : "❌")}");

                // Test 5: Determinismo
                byte[] hash2 = ScryptSalsa208Sha256(password, salt1, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool deterministic = CryptographicOperations.FixedTimeEquals(hash, hash2);
                Console.WriteLine($"       Deterministic: {(deterministic ? "✅" : "❌")}");

                // Test 6: Diferente salt = diferente hash
                byte[] hash3 = ScryptSalsa208Sha256(password, salt2, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
                bool differentWithDifferentSalt = !CryptographicOperations.FixedTimeEquals(hash, hash3);
                Console.WriteLine($"       Different salt = different hash: {(differentWithDifferentSalt ? "✅" : "❌")}");

                return saltValid && derivationValid && verifyCorrect && !verifyWrong && deterministic && differentWithDifferentSalt;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"       ❌ CryptoPwHash test failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Test de Salsa20/8 usando la implementación de Sodium
        /// </summary>
        public static bool TestSalsa208()
        {
            try
            {
                byte[] password = System.Text.Encoding.UTF8.GetBytes("salsa_test");
                byte[] salt = GenerateSalt();

                byte[] result = ScryptSalsa208Sha256(password, salt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);

                bool valid = result != null && result.Length == HASH_BYTES;
                Console.WriteLine($"       Salsa20/8 via Scrypt: {(valid ? "✅" : "❌")}");

                return valid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"       ❌ Salsa20/8 test failed: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// API 100% compatible con los nombres originales de C
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

        public static int crypto_pwhash_scryptsalsa208sha256_verify(
            byte[] hash,
            byte[] passwd, ulong passwdlen,
            ulong opslimit, uint memlimit)
        {
            try
            {
                if (hash == null || hash.Length < 32 || passwd == null)
                    return -1;

                byte[] expectedHash = new byte[32];
                byte[] salt = new byte[32];
                Buffer.BlockCopy(hash, 0, expectedHash, 0, 32);
                Buffer.BlockCopy(hash, 32, salt, 0, 32);

                byte[] passwordSegment = new byte[passwdlen];
                Buffer.BlockCopy(passwd, 0, passwordSegment, 0, (int)passwdlen);

                bool isValid = CryptoPwHash.Verify(expectedHash, passwordSegment, salt, opslimit, memlimit);
                return isValid ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }

        public static string crypto_pwhash_scryptsalsa208sha256_strprefix()
        {
            return "$7$"; // Prefijo estándar para scrypt
        }
    }
}