// Core/CryptoCorePack.cs - Implementación concreta
using System;
using System.Security.Cryptography;
using Toxcore.Core;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Implementación del empaquetado de claves extendidas.
    /// Traducción directa de crypto_core_pack.c
    /// </summary>
    public class CryptoCorePack : ICryptoCorePack
    {
        public bool PackExtendedPublicKey(ExtendedPublicKey key, IBinPack bp)
        {
            // Validar tamaños usando constantes de LibSodium
            if (key.Enc?.Length != LibSodium.ENC_PUBLIC_KEY_SIZE ||
                key.Sig?.Length != LibSodium.SIG_PUBLIC_KEY_SIZE)
            {
                return false;
            }

            byte[] extKey = new byte[ExtendedPublicKey.Size];

            try
            {
                Buffer.BlockCopy(key.Enc, 0, extKey, 0, LibSodium.ENC_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(key.Sig, 0, extKey, LibSodium.ENC_PUBLIC_KEY_SIZE, LibSodium.SIG_PUBLIC_KEY_SIZE);
                return bp.PackBin(extKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(extKey);
            }
        }

        public bool PackExtendedSecretKey(ExtendedSecretKey key, IBinPack bp)
        {
            if (key.Enc?.Length != LibSodium.ENC_SECRET_KEY_SIZE ||
                key.Sig?.Length != LibSodium.SIG_SECRET_KEY_SIZE)
            {
                return false;
            }

            byte[] extKey = new byte[ExtendedSecretKey.Size];

            try
            {
                Buffer.BlockCopy(key.Enc, 0, extKey, 0, LibSodium.ENC_SECRET_KEY_SIZE);
                Buffer.BlockCopy(key.Sig, 0, extKey, LibSodium.ENC_SECRET_KEY_SIZE, LibSodium.SIG_SECRET_KEY_SIZE);
                return bp.PackBin(extKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(extKey);
            }
        }

        public bool UnpackExtendedPublicKey(out ExtendedPublicKey key, IBinUnpack bu)
        {
            key = default;

            byte[] extKey = new byte[ExtendedPublicKey.Size];

            try
            {
                if (!bu.UnpackBinFixed(ExtendedPublicKey.Size, out extKey))
                {
                    return false;
                }

                key.Enc = new byte[LibSodium.ENC_PUBLIC_KEY_SIZE];
                key.Sig = new byte[LibSodium.SIG_PUBLIC_KEY_SIZE];

                Buffer.BlockCopy(extKey, 0, key.Enc, 0, LibSodium.ENC_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(extKey, LibSodium.ENC_PUBLIC_KEY_SIZE, key.Sig, 0, LibSodium.SIG_PUBLIC_KEY_SIZE);

                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(extKey);
            }
        }

        public bool UnpackExtendedSecretKey(out ExtendedSecretKey key, IBinUnpack bu)
        {
            key = default;

            byte[] extKey = new byte[ExtendedSecretKey.Size];

            try
            {
                if (!bu.UnpackBinFixed(ExtendedSecretKey.Size, out extKey))
                {
                    return false;
                }

                key.Enc = new byte[LibSodium.ENC_SECRET_KEY_SIZE];
                key.Sig = new byte[LibSodium.SIG_SECRET_KEY_SIZE];

                Buffer.BlockCopy(extKey, 0, key.Enc, 0, LibSodium.ENC_SECRET_KEY_SIZE);
                Buffer.BlockCopy(extKey, LibSodium.ENC_SECRET_KEY_SIZE, key.Sig, 0, LibSodium.SIG_SECRET_KEY_SIZE);

                CryptographicOperations.ZeroMemory(extKey);
                return true;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(extKey);
                throw;
            }
        }
    }
}