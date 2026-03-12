// Core/Abstractions/ICryptoCorePack.cs
using System;

namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Interfaz para empaquetado/desempaquetado de claves extendidas.
    /// Equivalente a las funciones en crypto_core_pack.h
    /// </summary>
    public interface ICryptoCorePack
    {
        /// <summary>
        /// Empaqueta una clave pública extendida.
        /// </summary>
        bool PackExtendedPublicKey(ExtendedPublicKey key, IBinPack bp);

        /// <summary>
        /// Empaqueta una clave secreta extendida.
        /// </summary>
        bool PackExtendedSecretKey(ExtendedSecretKey key, IBinPack bp);

        /// <summary>
        /// Desempaqueta una clave pública extendida.
        /// </summary>
        bool UnpackExtendedPublicKey(out ExtendedPublicKey key, IBinUnpack bu);

        /// <summary>
        /// Desempaqueta una clave secreta extendida.
        /// </summary>
        bool UnpackExtendedSecretKey(out ExtendedSecretKey key, IBinUnpack bu);
    }

    /// <summary>
    /// Estructura de clave pública extendida (enc + sig).
    /// Equivalente a Extended_Public_Key en crypto_core.h
    /// </summary>
    public struct ExtendedPublicKey
    {
        /// <summary>
        /// Clave pública de cifrado (Curve25519/X25519) - 32 bytes
        /// </summary>
        public byte[] Enc;

        /// <summary>
        /// Clave pública de firma (Ed25519) - 32 bytes
        /// </summary>
        public byte[] Sig;

        public ExtendedPublicKey(byte[] enc, byte[] sig)
        {
            Enc = enc;
            Sig = sig;
        }

        public const int Size = 64; // 32 + 32
    }

    /// <summary>
    /// Estructura de clave secreta extendida (enc + sig).
    /// Equivalente a Extended_Secret_Key en crypto_core.h
    /// </summary>
    public struct ExtendedSecretKey
    {
        /// <summary>
        /// Clave secreta de cifrado (Curve25519/X25519) - 32 bytes
        /// </summary>
        public byte[] Enc;

        /// <summary>
        /// Clave secreta de firma (Ed25519) - 64 bytes
        /// </summary>
        public byte[] Sig;

        public ExtendedSecretKey(byte[] enc, byte[] sig)
        {
            Enc = enc;
            Sig = sig;
        }

        public const int Size = 96; // 32 + 64
    }
}