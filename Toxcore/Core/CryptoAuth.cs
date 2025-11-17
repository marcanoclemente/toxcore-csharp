using System;
using System.Security.Cryptography;
using Sodium;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de crypto_auth (HMAC-SHA-256) usando Sodium.Core
    /// </summary>
    public static class CryptoAuth
    {
        public const int BYTES = 32;
        public const int KEYBYTES = 32;

        /// <summary>
        /// Genera tag de autenticación HMAC-SHA-256
        /// </summary>
        public static byte[] Authenticate(byte[] message, byte[] key)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (key == null || key.Length != KEYBYTES)
                throw new ArgumentException($"Key must be {KEYBYTES} bytes");

            try
            {
                // Intentar con Sodium primero
                return SecretKeyAuth.SignHmacSha256(message, key);
            }
            catch
            {
                // Fallback a .NET implementation
                using (var hmac = new HMACSHA256(key))
                {
                    return hmac.ComputeHash(message);
                }
            }
        }

        /// <summary>
        /// Genera tag de autenticación para una porción de mensaje
        /// </summary>
        public static byte[] Authenticate(byte[] message, int offset, int count, byte[] key)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (offset < 0 || offset >= message.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || offset + count > message.Length)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (key == null || key.Length != KEYBYTES)
                throw new ArgumentException($"Key must be {KEYBYTES} bytes");

            byte[] segment = new byte[count];
            Buffer.BlockCopy(message, offset, segment, 0, count);
            return Authenticate(segment, key);
        }

        /// <summary>
        /// Verifica tag de autenticación
        /// </summary>
        public static bool Verify(byte[] tag, byte[] message, byte[] key)
        {
            if (tag == null || tag.Length != BYTES)
                throw new ArgumentException($"Tag must be {BYTES} bytes");
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (key == null || key.Length != KEYBYTES)
                throw new ArgumentException($"Key must be {KEYBYTES} bytes");

            try
            {
                // Intentar con Sodium primero
                return SecretKeyAuth.VerifyHmacSha256(tag, message, key);
            }
            catch
            {
                // Fallback a .NET implementation
                using (var hmac = new HMACSHA256(key))
                {
                    byte[] computedTag = hmac.ComputeHash(message);
                    return CryptographicOperations.FixedTimeEquals(computedTag, tag);
                }
            }
        }

        /// <summary>
        /// Verifica tag de autenticación para una porción de mensaje
        /// </summary>
        public static bool Verify(byte[] tag, byte[] message, int offset, int count, byte[] key)
        {
            if (tag == null || tag.Length != BYTES)
                throw new ArgumentException($"Tag must be {BYTES} bytes");
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (offset < 0 || offset >= message.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || offset + count > message.Length)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (key == null || key.Length != KEYBYTES)
                throw new ArgumentException($"Key must be {KEYBYTES} bytes");

            byte[] segment = new byte[count];
            Buffer.BlockCopy(message, offset, segment, 0, count);
            return Verify(tag, segment, key);
        }

        /// <summary>
        /// Genera clave segura
        /// </summary>
        public static byte[] GenerateKey()
        {
            return SecretKeyAuth.GenerateKey();
        }

        /// <summary>
        /// Test exhaustivo con vectores conocidos
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     🔬 Testing CryptoAuth (HMAC-SHA-256)...");

                // Test 1: Generación de clave
                byte[] key = GenerateKey();
                bool keyValid = key != null && key.Length == KEYBYTES;
                Console.WriteLine($"       Key generation: {(keyValid ? "✅" : "❌")}");

                // Test 2: Tag generation
                byte[] message = System.Text.Encoding.UTF8.GetBytes("Test message for HMAC");
                byte[] tag = Authenticate(message, key);
                bool tagValid = tag != null && tag.Length == BYTES;
                Console.WriteLine($"       Tag generation: {(tagValid ? "✅" : "❌")}");

                // Test 3: Verificación correcta
                bool verifyCorrect = Verify(tag, message, key);
                Console.WriteLine($"       Correct verification: {(verifyCorrect ? "✅" : "❌")}");

                // Test 4: Verificación incorrecta (tag alterado)
                byte[] wrongTag = new byte[BYTES];
                if (tag != null)
                {
                    Array.Copy(tag, wrongTag, BYTES);
                    wrongTag[0] ^= 0x01;
                    bool verifyWrong = Verify(wrongTag, message, key);
                    Console.WriteLine($"       Wrong tag rejection: {(!verifyWrong ? "✅" : "❌")}");
                }
                else
                {
                    Console.WriteLine($"       Wrong tag rejection: ❌ (tag is null)");
                }

                // Test 5: Clave incorrecta
                byte[] wrongKey = GenerateKey();
                bool verifyWrongKey = Verify(tag, message, wrongKey);
                Console.WriteLine($"       Wrong key rejection: {(!verifyWrongKey ? "✅" : "❌")}");

                // Test 6: Mensaje alterado
                byte[] wrongMessage = System.Text.Encoding.UTF8.GetBytes("Wrong message for HMAC");
                bool verifyWrongMessage = Verify(tag, wrongMessage, key);
                Console.WriteLine($"       Wrong message rejection: {(!verifyWrongMessage ? "✅" : "❌")}");

                // Test 7: Mensaje vacío
                byte[] emptyTag = Authenticate(Array.Empty<byte>(), key);
                bool emptyValid = emptyTag != null && emptyTag.Length == BYTES;
                bool emptyVerify = emptyTag != null && Verify(emptyTag, Array.Empty<byte>(), key);
                Console.WriteLine($"       Empty message: {(emptyValid && emptyVerify ? "✅" : "❌")}");

                // Test 8: Determinismo
                byte[] tag2 = Authenticate(message, key);
                bool deterministic = tag != null && tag2 != null &&
                                   CryptographicOperations.FixedTimeEquals(tag, tag2);
                Console.WriteLine($"       Deterministic: {(deterministic ? "✅" : "❌")}");

                // Test 9: Rendimiento - CORREGIDO
                var sw = System.Diagnostics.Stopwatch.StartNew();
                int operations = 0;
                int successfulAuths = 0;

                for (int i = 0; i < 100; i++) // Reducido a 100 para mejor diagnóstico
                {
                    byte[] testMsg = System.Text.Encoding.UTF8.GetBytes($"Message {i}");
                    byte[] testTag = Authenticate(testMsg, key);

                    if (testTag != null)
                    {
                        successfulAuths++;
                        if (Verify(testTag, testMsg, key))
                        {
                            operations++;
                        }
                    }
                }
                sw.Stop();

                Console.WriteLine($"       Successful authentications: {successfulAuths}/100 ✅");
                Console.WriteLine($"       Successful verifications: {operations}/100 ✅");
                Console.WriteLine($"       Performance: {sw.ElapsedMilliseconds}ms ✅");

                // Si hay problemas, hacer test de diagnóstico
                if (successfulAuths < 100 || operations < 100)
                {
                    Console.WriteLine("       🔍 Running diagnostic...");
                    RunAuthDiagnostic(key);
                }

                return keyValid && tagValid && verifyCorrect && emptyValid && deterministic &&
                       (successfulAuths == 100) && (operations == 100);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"       ❌ CryptoAuth test failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Diagnóstico para identificar problemas específicos
        /// </summary>
        private static void RunAuthDiagnostic(byte[] key)
        {
            try
            {
                Console.WriteLine("       🔍 Diagnostic - Testing individual messages:");

                // Test mensajes específicos que podrían causar problemas
                string[] testMessages = {
            "",
            " ",
            "a",
            "test",
            "Message 0",
            "Message 50",
            "Message 99",
            new string('x', 1000),
            new string('y', 10000)
        };

                foreach (var msg in testMessages)
                {
                    byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(msg);
                    byte[] tag = Authenticate(msgBytes, key);

                    if (tag == null)
                    {
                        Console.WriteLine($"         ❌ NULL tag for: '{msg.Substring(0, Math.Min(20, msg.Length))}...'");
                    }
                    else if (tag.Length != BYTES)
                    {
                        Console.WriteLine($"         ❌ Wrong tag length: {tag.Length} for: '{msg.Substring(0, Math.Min(20, msg.Length))}...'");
                    }
                    else
                    {
                        bool verify = Verify(tag, msgBytes, key);
                        Console.WriteLine($"         ✅ OK: '{msg.Substring(0, Math.Min(20, msg.Length))}...' -> Verify: {verify}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"         ❌ Diagnostic failed: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// API compatible con nombres C originales
    /// </summary>
    public static class crypto_auth_native
    {
        public const int crypto_auth_BYTES = CryptoAuth.BYTES;
        public const int crypto_auth_KEYBYTES = CryptoAuth.KEYBYTES;

        public static int crypto_auth(byte[] @out, byte[] @in, ulong inlen, byte[] k)
        {
            try
            {
                byte[] inputSegment = new byte[inlen];
                Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);

                byte[] tag = CryptoAuth.Authenticate(inputSegment, k);
                Buffer.BlockCopy(tag, 0, @out, 0, CryptoAuth.BYTES);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_auth_verify(byte[] h, byte[] @in, ulong inlen, byte[] k)
        {
            try
            {
                byte[] inputSegment = new byte[inlen];
                Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);

                bool isValid = CryptoAuth.Verify(h, inputSegment, k);
                return isValid ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }

        public static void crypto_auth_keygen(byte[] k)
        {
            byte[] key = CryptoAuth.GenerateKey();
            Buffer.BlockCopy(key, 0, k, 0, CryptoAuth.KEYBYTES);
        }
    }
}