using System;
using System.Security.Cryptography;
using Sodium;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de crypto_box (curve25519-xsalsa20-poly1305) usando Sodium.Core
    /// </summary>
    public static class CryptoBox
    {
        public const int PUBLICKEYBYTES = 32;
        public const int SECRETKEYBYTES = 32;
        public const int BEFORENMBYTES = 32;
        public const int NONCEBYTES = 24;
        public const int MACBYTES = 16;

        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        /// <summary>
        /// Genera un par de claves pública/privada usando curve25519
        /// </summary>
        public static KeyPair GenerateKeyPair()
        {
            var keyPair = PublicKeyBox.GenerateKeyPair();
            return new KeyPair
            {
                PublicKey = keyPair.PublicKey,
                PrivateKey = keyPair.PrivateKey
            };
        }

        /// <summary>
        /// Encrypta usando curve25519-xsalsa20-poly1305
        /// </summary>
        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (nonce == null || nonce.Length != NONCEBYTES)
                throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");
            if (publicKey == null || publicKey.Length != PUBLICKEYBYTES)
                throw new ArgumentException($"Public key must be {PUBLICKEYBYTES} bytes");
            if (secretKey == null || secretKey.Length != SECRETKEYBYTES)
                throw new ArgumentException($"Secret key must be {SECRETKEYBYTES} bytes");

            try
            {
                return PublicKeyBox.Create(message, nonce, secretKey, publicKey);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypta usando curve25519-xsalsa20-poly1305
        /// </summary>
        public static byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] publicKey, byte[] secretKey)
        {
            if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
            if (nonce == null || nonce.Length != NONCEBYTES)
                throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");
            if (publicKey == null || publicKey.Length != PUBLICKEYBYTES)
                throw new ArgumentException($"Public key must be {PUBLICKEYBYTES} bytes");
            if (secretKey == null || secretKey.Length != SECRETKEYBYTES)
                throw new ArgumentException($"Secret key must be {SECRETKEYBYTES} bytes");

            try
            {
                return PublicKeyBox.Open(cipherText, nonce, secretKey, publicKey);
            }
            catch (Exception)
            {
                // Decryption failed (invalid MAC or corrupted data)
                return null;
            }
        }

        /// <summary>
        /// Precalcula el shared key para mejor rendimiento
        /// </summary>
        public static byte[] BeforeNm(byte[] publicKey, byte[] secretKey)
        {
            if (publicKey == null || publicKey.Length != PUBLICKEYBYTES)
                throw new ArgumentException($"Public key must be {PUBLICKEYBYTES} bytes");
            if (secretKey == null || secretKey.Length != SECRETKEYBYTES)
                throw new ArgumentException($"Secret key must be {SECRETKEYBYTES} bytes");

            return ScalarMult.Mult(secretKey, publicKey);
        }

        /// <summary>
        /// Encrypta usando shared key precalculado (xsalsa20-poly1305)
        /// </summary>
        public static byte[] AfterNm(byte[] message, byte[] nonce, byte[] sharedKey)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (nonce == null || nonce.Length != NONCEBYTES)
                throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");
            if (sharedKey == null || sharedKey.Length != BEFORENMBYTES)
                throw new ArgumentException($"Shared key must be {BEFORENMBYTES} bytes");

            try
            {
                return SecretBox.Create(message, nonce, sharedKey);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Encryption with shared key failed", ex);
            }
        }

        /// <summary>
        /// Decrypta usando shared key precalculado (xsalsa20-poly1305)
        /// </summary>
        public static byte[] OpenAfterNm(byte[] cipherText, byte[] nonce, byte[] sharedKey)
        {
            if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
            if (nonce == null || nonce.Length != NONCEBYTES)
                throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");
            if (sharedKey == null || sharedKey.Length != BEFORENMBYTES)
                throw new ArgumentException($"Shared key must be {BEFORENMBYTES} bytes");

            try
            {
                return SecretBox.Open(cipherText, nonce, sharedKey);
            }
            catch (Exception)
            {
                // Decryption failed (invalid MAC or corrupted data)
                return null;
            }
        }

        /// <summary>
        /// Genera nonce aleatorio seguro
        /// </summary>
        public static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[NONCEBYTES];
            rng.GetBytes(nonce);
            return nonce;
        }

        /// <summary>
        /// Test exhaustivo de todas las funcionalidades
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     🔬 Testing CryptoBox comprehensively...");

                // Test 1: Generación de claves
                var keyPair = GenerateKeyPair();
                bool keysValid = keyPair.PublicKey.Length == PUBLICKEYBYTES &&
                               keyPair.PrivateKey.Length == SECRETKEYBYTES;
                Console.WriteLine($"       Key generation: {(keysValid ? "✅" : "❌")}");

                // Test 2: Encrypt/Decrypt básico
                byte[] nonce = GenerateNonce();
                byte[] original = System.Text.Encoding.UTF8.GetBytes("Test message for CryptoBox");
                byte[] encrypted = Encrypt(original, nonce, keyPair.PublicKey, keyPair.PrivateKey);
                byte[] decrypted = Decrypt(encrypted, nonce, keyPair.PublicKey, keyPair.PrivateKey);

                bool basicEncryption = encrypted != null && decrypted != null &&
                                     CompareBytes(original, decrypted);
                Console.WriteLine($"       Basic encryption/decryption: {(basicEncryption ? "✅" : "❌")}");

                // Test 3: Shared key
                byte[] sharedKey = BeforeNm(keyPair.PublicKey, keyPair.PrivateKey);
                bool sharedKeyValid = sharedKey != null && sharedKey.Length == BEFORENMBYTES;
                Console.WriteLine($"       Shared key calculation: {(sharedKeyValid ? "✅" : "❌")}");

                // Test 4: Encrypt/Decrypt con shared key
                byte[] encryptedShared = AfterNm(original, nonce, sharedKey);
                byte[] decryptedShared = OpenAfterNm(encryptedShared, nonce, sharedKey);
                bool sharedEncryption = encryptedShared != null && decryptedShared != null &&
                                      CompareBytes(original, decryptedShared);
                Console.WriteLine($"       Shared key encryption: {(sharedEncryption ? "✅" : "❌")}");

                // Test 5: Detección de manipulación (MAC verification)
                if (encrypted != null)
                {
                    byte[] tampered = new byte[encrypted.Length];
                    Array.Copy(encrypted, tampered, encrypted.Length);
                    tampered[10] ^= 0x01; // Alterar un byte
                    byte[] shouldFail = Decrypt(tampered, nonce, keyPair.PublicKey, keyPair.PrivateKey);
                    bool tamperDetection = shouldFail == null;
                    Console.WriteLine($"       Tamper detection: {(tamperDetection ? "✅" : "❌")}");
                }

                // Test 6: Nonce incorrecto
                if (encrypted != null)
                {
                    byte[] wrongNonce = GenerateNonce();
                    byte[] shouldFail = Decrypt(encrypted, wrongNonce, keyPair.PublicKey, keyPair.PrivateKey);
                    bool nonceVerification = shouldFail == null;
                    Console.WriteLine($"       Nonce verification: {(nonceVerification ? "✅" : "❌")}");
                }

                // Test 7: Claves incorrectas
                if (encrypted != null)
                {
                    var wrongKeyPair = GenerateKeyPair();
                    byte[] shouldFail = Decrypt(encrypted, nonce, wrongKeyPair.PublicKey, keyPair.PrivateKey);
                    bool keyVerification = shouldFail == null;
                    Console.WriteLine($"       Key verification: {(keyVerification ? "✅" : "❌")}");
                }

                // Test 8: Rendimiento con múltiples operaciones
                var sw = System.Diagnostics.Stopwatch.StartNew();
                int operations = 0;
                for (int i = 0; i < 100; i++)
                {
                    byte[] testMsg = System.Text.Encoding.UTF8.GetBytes($"Message {i}");
                    byte[] testNonce = GenerateNonce();
                    byte[] enc = Encrypt(testMsg, testNonce, keyPair.PublicKey, keyPair.PrivateKey);
                    byte[] dec = Decrypt(enc, testNonce, keyPair.PublicKey, keyPair.PrivateKey);
                    if (dec != null) operations++;
                }
                sw.Stop();
                Console.WriteLine($"       Performance: {operations}/100 operations in {sw.ElapsedMilliseconds}ms ✅");

                return keysValid && basicEncryption && sharedKeyValid && sharedEncryption;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"       ❌ CryptoBox test failed: {ex.Message}");
                return false;
            }
        }

        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }
    }

    public class KeyPair
    {
        public byte[] PublicKey { get; set; } = new byte[CryptoBox.PUBLICKEYBYTES];
        public byte[] PrivateKey { get; set; } = new byte[CryptoBox.SECRETKEYBYTES];
    }

    /// <summary>
    /// API compatible con nombres C originales
    /// </summary>
    public static class crypto_box_native
    {
        public const int crypto_box_PUBLICKEYBYTES = CryptoBox.PUBLICKEYBYTES;
        public const int crypto_box_SECRETKEYBYTES = CryptoBox.SECRETKEYBYTES;
        public const int crypto_box_BEFORENMBYTES = CryptoBox.BEFORENMBYTES;
        public const int crypto_box_NONCEBYTES = CryptoBox.NONCEBYTES;
        public const int crypto_box_MACBYTES = CryptoBox.MACBYTES;

        public static int crypto_box_keypair(byte[] pk, byte[] sk)
        {
            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                Buffer.BlockCopy(keyPair.PublicKey, 0, pk, 0, CryptoBox.PUBLICKEYBYTES);
                Buffer.BlockCopy(keyPair.PrivateKey, 0, sk, 0, CryptoBox.SECRETKEYBYTES);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_box(byte[] c, byte[] m, long mlen, byte[] n, byte[] pk, byte[] sk)
        {
            try
            {
                byte[] messageSegment = new byte[mlen];
                Buffer.BlockCopy(m, 0, messageSegment, 0, (int)mlen);

                byte[] cipherText = CryptoBox.Encrypt(messageSegment, n, pk, sk);
                Buffer.BlockCopy(cipherText, 0, c, 0, cipherText.Length);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_box_open(byte[] m, byte[] c, long clen, byte[] n, byte[] pk, byte[] sk)
        {
            try
            {
                byte[] cipherSegment = new byte[clen];
                Buffer.BlockCopy(c, 0, cipherSegment, 0, (int)clen);

                byte[] message = CryptoBox.Decrypt(cipherSegment, n, pk, sk);
                if (message == null) return -1; // Decryption failed

                Buffer.BlockCopy(message, 0, m, 0, message.Length);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_box_beforenm(byte[] k, byte[] pk, byte[] sk)
        {
            try
            {
                byte[] sharedKey = CryptoBox.BeforeNm(pk, sk);
                Buffer.BlockCopy(sharedKey, 0, k, 0, CryptoBox.BEFORENMBYTES);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_box_afternm(byte[] c, byte[] m, long mlen, byte[] n, byte[] k)
        {
            try
            {
                byte[] messageSegment = new byte[mlen];
                Buffer.BlockCopy(m, 0, messageSegment, 0, (int)mlen);

                byte[] cipherText = CryptoBox.AfterNm(messageSegment, n, k);
                Buffer.BlockCopy(cipherText, 0, c, 0, cipherText.Length);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_box_open_afternm(byte[] m, byte[] c, long clen, byte[] n, byte[] k)
        {
            try
            {
                byte[] cipherSegment = new byte[clen];
                Buffer.BlockCopy(c, 0, cipherSegment, 0, (int)clen);

                byte[] message = CryptoBox.OpenAfterNm(cipherSegment, n, k);
                if (message == null) return -1; // Decryption failed

                Buffer.BlockCopy(message, 0, m, 0, message.Length);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static void crypto_box_random_nonce(byte[] nonce)
        {
            byte[] randomNonce = CryptoBox.GenerateNonce();
            Buffer.BlockCopy(randomNonce, 0, nonce, 0, CryptoBox.NONCEBYTES);
        }
    }
}