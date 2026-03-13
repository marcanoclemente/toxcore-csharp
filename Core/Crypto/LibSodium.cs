// Core/LibSodium.cs - ACTUALIZADO CON CRYPTO_SECRETBOX PARA SENDBACK
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Toxcore.Core
{
    /// <summary>
    /// Wrapper completo de libsodium para ToxCore.
    /// Incluye crypto_secretbox para cifrado simétrico del sendback onion.
    /// </summary>
    public static partial class LibSodium
    {
        private const string LibSodiumNativeLibraryName = "libsodium";
        private static readonly bool _isAvailable;

        public static bool IsAvailable => _isAvailable;

        // Constantes existentes...
        public const int CRYPTO_PUBLIC_KEY_SIZE = 32;
        public const int CRYPTO_SECRET_KEY_SIZE = 32;
        public const int CRYPTO_SHARED_KEY_SIZE = 32;
        public const int CRYPTO_NONCE_SIZE = 24;
        public const int CRYPTO_MAC_SIZE = 16;
        public const int CRYPTO_SYMMETRIC_KEY_SIZE = 32;
        public const int CRYPTO_SHA256_SIZE = 32;
        public const int CRYPTO_SHA512_SIZE = 64;
        public const int CRYPTO_HASH_SIZE = 64;

        // NUEVO: Constantes para crypto_secretbox
        public const int CRYPTO_SECRETBOX_KEY_SIZE = 32;
        public const int CRYPTO_SECRETBOX_NONCE_SIZE = 24;
        public const int CRYPTO_SECRETBOX_MAC_SIZE = 16;

        public const int SIG_PUBLIC_KEY_SIZE = 32;
        public const int SIG_SECRET_KEY_SIZE = 64;
        public const int ENC_PUBLIC_KEY_SIZE = 32;
        public const int ENC_SECRET_KEY_SIZE = 32;
        public const int SIGNATURE_SIZE = 64;

        static LibSodium()
        {
            try
            {
                int init = sodium_init();
                _isAvailable = init >= 0;
                if (!_isAvailable)
                    Logger.Log.WarningF("[LibSodium] sodium_init failed: {0}", init);
            }
            catch (DllNotFoundException)
            {
                _isAvailable = false;
                Logger.Log.Warning("[LibSodium] Native library not found");
            }
            catch (Exception ex)
            {
                _isAvailable = false;
                Logger.Log.WarningF("[LibSodium] Init error: {0}", ex.Message);
            }
        }

        public static void ThrowIfUnavailable()
        {
            if (!IsAvailable)
                throw new DllNotFoundException("libsodium not available");
        }

        #region Nonce Increment

        public static void crypto_increment_nonce(byte[] nonce)
        {
            if (nonce == null || nonce.Length != CRYPTO_NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {CRYPTO_NONCE_SIZE} bytes", nameof(nonce));

            for (int i = 0; i < CRYPTO_NONCE_SIZE; i++)
            {
                if (++nonce[i] != 0)
                    break;
            }
        }

        public static void crypto_increment_nonce(byte[] nonce, int nonceOffset)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (nonceOffset < 0 || nonceOffset + CRYPTO_NONCE_SIZE > nonce.Length)
                throw new ArgumentOutOfRangeException(nameof(nonceOffset));

            for (int i = 0; i < CRYPTO_NONCE_SIZE; i++)
            {
                if (++nonce[nonceOffset + i] != 0)
                    break;
            }
        }

        #endregion

        #region SHA256 / SHA512

        public static bool TrySha256(byte[] out32, byte[] message)
        {
            if (!IsAvailable) return false;
            if (out32 == null || out32.Length != CRYPTO_SHA256_SIZE) return false;
            if (message == null) message = Array.Empty<byte>();

            try
            {
                return crypto_hash_sha256(out32, message, (ulong)message.Length) == 0;
            }
            catch { return false; }
        }

        public static bool TrySha512(byte[] out64, byte[] message)
        {
            if (!IsAvailable) return false;
            if (out64 == null || out64.Length != CRYPTO_SHA512_SIZE) return false;
            if (message == null) message = Array.Empty<byte>();

            try
            {
                return crypto_hash_sha512(out64, message, (ulong)message.Length) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region HMAC-SHA256

        public static bool TryHmacSha256(byte[] out32, byte[] message, byte[] key)
        {
            if (!IsAvailable) return false;
            if (out32 == null || out32.Length != 32) return false;
            if (key == null || key.Length != 32) return false;
            if (message == null) message = Array.Empty<byte>();

            try
            {
                return crypto_auth_hmacsha256(out32, message, (ulong)message.Length, key) == 0;
            }
            catch { return false; }
        }

        public static bool TryHmacSha256Verify(byte[] tag32, byte[] message, byte[] key)
        {
            if (!IsAvailable) return false;
            if (tag32 == null || tag32.Length != 32) return false;
            if (key == null || key.Length != 32) return false;
            if (message == null) message = Array.Empty<byte>();

            try
            {
                return crypto_auth_hmacsha256_verify(tag32, message, (ulong)message.Length, key) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region Verify Constant-Time

        public static bool TryVerify16(byte[] a, byte[] b)
        {
            if (!IsAvailable) return false;
            if (a == null || b == null || a.Length < 16 || b.Length < 16) return false;

            try
            {
                return crypto_verify_16(a, b) == 0;
            }
            catch { return false; }
        }

        public static bool TryVerify32(byte[] a, byte[] b)
        {
            if (!IsAvailable) return false;
            if (a == null || b == null || a.Length < 32 || b.Length < 32) return false;

            try
            {
                return crypto_verify_32(a, b) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region CryptoBox (Curve25519-XSalsa20-Poly1305)

        public static bool TryCryptoBoxKeyPair(byte[] publicKey32, byte[] secretKey32)
        {
            if (!IsAvailable) return false;
            if (publicKey32?.Length != 32 || secretKey32?.Length != 32) return false;

            try
            {
                return crypto_box_keypair(publicKey32, secretKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryCryptoBoxEasy(byte[] cipherOut, byte[] message, byte[] nonce24, byte[] publicKey32, byte[] secretKey32)
        {
            if (!IsAvailable) return false;
            if (cipherOut == null || message == null || nonce24?.Length != 24) return false;
            if (publicKey32?.Length != 32 || secretKey32?.Length != 32) return false;
            if (cipherOut.Length != message.Length + CRYPTO_MAC_SIZE) return false;

            try
            {
                return crypto_box_easy(cipherOut, message, (ulong)message.Length, nonce24, publicKey32, secretKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryCryptoBoxOpenEasy(byte[] messageOut, byte[] cipher, byte[] nonce24, byte[] publicKey32, byte[] secretKey32)
        {
            if (!IsAvailable) return false;
            if (messageOut == null || cipher == null || nonce24?.Length != 24) return false;
            if (publicKey32?.Length != 32 || secretKey32?.Length != 32) return false;
            if (cipher.Length < CRYPTO_MAC_SIZE || messageOut.Length != cipher.Length - CRYPTO_MAC_SIZE) return false;

            try
            {
                return crypto_box_open_easy(messageOut, cipher, (ulong)cipher.Length, nonce24, publicKey32, secretKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryCryptoBoxBeforeNm(byte[] sharedKey32, byte[] publicKey32, byte[] secretKey32)
        {
            if (!IsAvailable) return false;
            if (sharedKey32?.Length != 32 || publicKey32?.Length != 32 || secretKey32?.Length != 32) return false;

            try
            {
                return crypto_box_beforenm(sharedKey32, publicKey32, secretKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryCryptoBoxEasyAfterNm(byte[] cipherOut, byte[] message, byte[] nonce24, byte[] sharedKey32)
        {
            if (!IsAvailable) return false;
            if (cipherOut == null || message == null || nonce24?.Length != 24 || sharedKey32?.Length != 32) return false;
            if (cipherOut.Length != message.Length + CRYPTO_MAC_SIZE) return false;

            try
            {
                return crypto_box_easy_afternm(cipherOut, message, (ulong)message.Length, nonce24, sharedKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryCryptoBoxOpenEasyAfterNm(byte[] messageOut, byte[] cipher, byte[] nonce24, byte[] sharedKey32)
        {
            if (!IsAvailable) return false;
            if (messageOut == null || cipher == null || nonce24?.Length != 24 || sharedKey32?.Length != 32) return false;
            if (cipher.Length < CRYPTO_MAC_SIZE || messageOut.Length != cipher.Length - CRYPTO_MAC_SIZE) return false;

            try
            {
                return crypto_box_open_easy_afternm(messageOut, cipher, (ulong)cipher.Length, nonce24, sharedKey32) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region NUEVO: CryptoSecretBox (XSalsa20-Poly1305 para cifrado simétrico)

        /// <summary>
        /// Cifra un mensaje usando XSalsa20-Poly1305 con clave simétrica.
        /// </summary>
        public static bool TryCryptoSecretBoxEasy(byte[] cipherOut, byte[] message, byte[] nonce24, byte[] key32)
        {
            if (!IsAvailable) return false;
            if (cipherOut == null || message == null || nonce24?.Length != CRYPTO_SECRETBOX_NONCE_SIZE) return false;
            if (key32?.Length != CRYPTO_SECRETBOX_KEY_SIZE) return false;
            if (cipherOut.Length != message.Length + CRYPTO_SECRETBOX_MAC_SIZE) return false;

            try
            {
                int result = crypto_secretbox_easy(
                    cipherOut,
                    message,
                    (ulong)message.Length,
                    nonce24,
                    key32);

                return result == 0;
            }
            catch { return false; }
        }

        /// <summary>
        /// Descifra un mensaje usando XSalsa20-Poly1305 con clave simétrica.
        /// </summary>
        public static bool TryCryptoSecretBoxOpenEasy(byte[] messageOut, byte[] cipher, byte[] nonce24, byte[] key32)
        {
            if (!IsAvailable) return false;
            if (messageOut == null || cipher == null || nonce24?.Length != CRYPTO_SECRETBOX_NONCE_SIZE) return false;
            if (key32?.Length != CRYPTO_SECRETBOX_KEY_SIZE) return false;
            if (cipher.Length < CRYPTO_SECRETBOX_MAC_SIZE || messageOut.Length != cipher.Length - CRYPTO_SECRETBOX_MAC_SIZE) return false;

            try
            {
                int result = crypto_secretbox_open_easy(
                    messageOut,
                    cipher,
                    (ulong)cipher.Length,
                    nonce24,
                    key32);

                return result == 0;
            }
            catch { return false; }
        }


        #endregion

        #region ScalarMult

        public static bool TryScalarMultBase(byte[] publicKey32, byte[] secretKey32)
        {
            if (!IsAvailable) return false;
            if (publicKey32?.Length != 32 || secretKey32?.Length != 32) return false;

            try
            {
                return crypto_scalarmult_base(publicKey32, secretKey32) == 0;
            }
            catch { return false; }
        }

        public static bool TryScalarMult(byte[] shared32, byte[] secret32, byte[] public32)
        {
            if (!IsAvailable) return false;
            if (shared32?.Length != 32 || secret32?.Length != 32 || public32?.Length != 32) return false;

            try
            {
                return crypto_scalarmult(shared32, secret32, public32) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region Password Hashing (Scrypt)

        public static bool TryPwhashScrypt(byte[] hashOut, byte[] password, byte[] salt, ulong opsLimit, uint memLimit)
        {
            if (!IsAvailable) return false;
            if (hashOut == null || password == null || salt?.Length != 32) return false;

            try
            {
                return crypto_pwhash_scryptsalsa208sha256(
                    hashOut, (ulong)hashOut.Length,
                    password, (ulong)password.Length,
                    salt, opsLimit, (nuint)memLimit) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region Auth HMAC-SHA512

        public static bool TryAuthHmacSha512(byte[] out64, byte[] message, byte[] key)
        {
            if (!IsAvailable) return false;
            if (out64 == null || out64.Length != 64 || message == null || key == null)
                return false;

            try
            {
                return crypto_auth_hmacsha512(out64, message, (ulong)message.Length, key) == 0;
            }
            catch { return false; }
        }

        public static bool TryAuthHmacSha512Verify(byte[] expected64, byte[] message, byte[] key)
        {
            if (!IsAvailable) return false;
            if (expected64 == null || expected64.Length != 64 || message == null || key == null)
                return false;

            try
            {
                return crypto_auth_hmacsha512_verify(expected64, message, (ulong)message.Length, key) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region Random

        public static bool TryRandomBytes(byte[] buffer)
        {
            if (!IsAvailable) return false;
            if (buffer == null) return false;

            try
            {
                randombytes_buf(buffer, (UIntPtr)buffer.Length);
                return true;
            }
            catch { return false; }
        }

        public static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[CRYPTO_NONCE_SIZE];
            TryRandomBytes(nonce);
            return nonce;
        }

        public static byte[] GenerateKey()
        {
            byte[] key = new byte[CRYPTO_SYMMETRIC_KEY_SIZE];
            TryRandomBytes(key);
            return key;
        }

        #endregion

        #region Generic Hash (BLAKE2b)

        public static bool TryGenericHash(byte[] outBuf, byte[] message, byte[] key = null!)
        {
            if (!IsAvailable) return false;
            if (outBuf == null) return false;

            try
            {
                return crypto_generichash(
                    outBuf, (ulong)outBuf.Length,
                    message, (ulong)(message?.Length ?? 0),
                    key, (ulong)(key?.Length ?? 0)) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region Métodos de Firma (Ed25519)

        public static bool TrySignDetached(byte[] signature, ReadOnlySpan<byte> message, byte[] secretKey)
        {
            if (!IsAvailable) return false;
            if (signature?.Length != SIGNATURE_SIZE) return false;
            if (secretKey?.Length != SIG_SECRET_KEY_SIZE) return false;

            try
            {
                return crypto_sign_detached(signature, out _, message.ToArray(), (ulong)message.Length, secretKey) == 0;
            }
            catch { return false; }
        }

        public static bool TrySignDetached(byte[] signature, ReadOnlySpan<byte> message, int messageLen, byte[] secretKey)
        {
            return TrySignDetached(signature, message.Slice(0, messageLen), secretKey);
        }

        public static bool TryVerifyDetached(byte[] signature, ReadOnlySpan<byte> message, byte[] publicKey)
        {
            if (!IsAvailable) return false;
            if (signature?.Length != SIGNATURE_SIZE) return false;
            if (publicKey?.Length != SIG_PUBLIC_KEY_SIZE) return false;

            try
            {
                return crypto_sign_verify_detached(signature, message.ToArray(), (ulong)message.Length, publicKey) == 0;
            }
            catch { return false; }
        }

        #endregion

        #region P/Invoke Imports

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_sign_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_detached(byte[] sig, out ulong siglen, byte[] m, ulong mlen, byte[] sk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_sign_verify_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_verify_detached(byte[] sig, byte[] m, ulong mlen, byte[] pk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "sodium_init")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int sodium_init();

        // SHA
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_hash_sha256")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_hash_sha256(byte[] @out, byte[] @in, ulong inlen);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_hash_sha512")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_hash_sha512(byte[] @out, byte[] @in, ulong inlen);

        // HMAC
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_auth_hmacsha256")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_auth_hmacsha256(byte[] @out, byte[] @in, ulong inlen, byte[] k);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_auth_hmacsha256_verify")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_auth_hmacsha256_verify(byte[] h, byte[] @in, ulong inlen, byte[] k);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_auth_hmacsha512")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_auth_hmacsha512(byte[] out64, byte[] m, ulong mlen, byte[] k);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_auth_hmacsha512_verify")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_auth_hmacsha512_verify(byte[] expected, byte[] m, ulong mlen, byte[] k);

        // Verify
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_verify_16")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_verify_16(byte[] x, byte[] y);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_verify_32")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_verify_32(byte[] x, byte[] y);

        // CryptoBox
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_keypair")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_keypair(byte[] pk, byte[] sk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_easy")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_easy(byte[] c, byte[] m, ulong mlen, byte[] n, byte[] pk, byte[] sk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_open_easy")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_open_easy(byte[] m, byte[] c, ulong clen, byte[] n, byte[] pk, byte[] sk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_beforenm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_beforenm(byte[] k, byte[] pk, byte[] sk);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_easy_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_easy_afternm(byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_box_open_easy_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_open_easy_afternm(byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

        // Reemplaza las declaraciones de P/Invoke de crypto_secretbox_easy y crypto_secretbox_open_easy
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_secretbox_easy")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_secretbox_easy(byte[] c, byte[] m, ulong mlen, byte[] n, byte[] k);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_secretbox_open_easy")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_secretbox_open_easy(byte[] m, byte[] c, ulong clen, byte[] n, byte[] k);

        // ScalarMult
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_scalarmult_base")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_scalarmult_base(byte[] q, byte[] n);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_scalarmult")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_scalarmult(byte[] q, byte[] n, byte[] p);

        // Password Hashing
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_pwhash_scryptsalsa208sha256")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_pwhash_scryptsalsa208sha256(
            byte[] outbuf, ulong outlen,
            byte[] passwd, ulong passwdlen,
            byte[] salt, ulong opslimit, nuint memlimit);

        // Random
        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "randombytes_buf")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial void randombytes_buf(byte[] buf, UIntPtr size);

        [LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_generichash")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_generichash(
            byte[] outbuf, ulong outlen,
            byte[] inbuf, ulong inlen,
            byte[] key, ulong keylen);

        #endregion
    }
}