// Core/Extensions/CryptoExtensions.cs - NUEVO ARCHIVO
using System;
using System.Buffers.Binary;

namespace Toxcore.Core.Crypto
{
    public static class CryptoExtensions
    {
        // Constantes - AHORA REFERENCIAN A LibSodium (no duplicadas)
        public const int PublicKeySize = LibSodium.CRYPTO_PUBLIC_KEY_SIZE;  // 32
        public const int SecretKeySize = LibSodium.CRYPTO_SECRET_KEY_SIZE; // 32
        public const int NonceSize = LibSodium.CRYPTO_NONCE_SIZE;          // 24
        public const int MacSize = LibSodium.CRYPTO_MAC_SIZE;

        /// <summary>
        /// CORREGIDO: Validación completa de clave pública Curve25519.
        /// Verifica: tamaño, no-ceros, y clamping de punto en curva.
        /// </summary>
        public static bool IsValidPublicKey(this byte[] key)
        {
            if (key == null || key.Length != PublicKeySize)
                return false;

            // Verificar que no sea todos ceros
            bool allZero = true;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            if (allZero)
                return false;

            // CORREGIDO: Verificar clamping de Curve25519
            // El bit más significativo del último byte debe ser 0
            // (coordenada x debe ser < 2^255 - 19)
            if ((key[31] & 0x80) != 0)
                return false;

            // CORREGIDO: Verificar que los 3 bits menos significativos sean 0
            // (propiedad de la curva 25519)
            if ((key[0] & 0x07) != 0)
                return false;

            return true;
        }

        /// <summary>
        /// CORREGIDO: Validación con mensaje de error detallado.
        /// </summary>
        public static bool IsValidPublicKey(this byte[] key, out string error)
        {
            error = null;

            if (key == null)
            {
                error = "Clave nula";
                return false;
            }

            if (key.Length != PublicKeySize)
            {
                error = $"Tamaño inválido: {key.Length}, esperado: {PublicKeySize}";
                return false;
            }

            bool allZero = true;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            if (allZero)
            {
                error = "Clave es todos ceros";
                return false;
            }

            if ((key[31] & 0x80) != 0)
            {
                error = "Bit 255 no está en 0 (violación Curve25519)";
                return false;
            }

            if ((key[0] & 0x07) != 0)
            {
                error = "Bits de orden bajo no están en 0 (violación Curve25519)";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Valida que un array sea un nonce válido
        /// </summary>
        public static bool IsValidNonce(this byte[] nonce)
        {
            return nonce != null && nonce.Length == NonceSize;
        }

        /// <summary>
        /// Compara dos public keys de forma constant-time
        /// </summary>
        public static bool ConstantTimeEquals(this byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Limpia de forma segura el contenido de un array
        /// </summary>
        public static void SecureClear(this byte[] data)
        {
            if (data != null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(data);
        }
    }
}