using System;

namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Interfaz para cache de claves compartidas (shared_key_cache.h).
    /// Evita recalcular scalar_mult en cada paquete.
    /// </summary>
    public interface ISharedKeyCache : IDisposable
    {
        /// <summary>
        /// Busca o computa la clave compartida para una clave pública.
        /// </summary>
        /// <param name="publicKey">Clave pública del peer (32 bytes).</param>
        /// <returns>Clave compartida de 32 bytes, o null si error.</returns>
        byte[] Lookup(ReadOnlySpan<byte> publicKey);
    }
}