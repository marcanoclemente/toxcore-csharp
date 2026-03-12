// Core/Extensions/CryptoExtensions.cs - NUEVO ARCHIVO

using System;

namespace Toxcore.Core.Crypto
{
    public static class CryptoExtensions
    {
        public const int PublicKeySize = 32;
        public const int SecretKeySize = 32;
        public const int NonceSize = 24;
        public const int MacSize = 16;

        /// <summary>
        /// Valida que un array sea una public key válida (no null, tamaño correcto, no todos ceros)
        /// </summary>
        public static bool IsValidPublicKey(this byte[] key)
        {
            if (key == null || key.Length != PublicKeySize) return false;

            // Verificar que no sea todos ceros
            for (int i = 0; i < key.Length; i++)
                if (key[i] != 0) return true;

            return false;
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