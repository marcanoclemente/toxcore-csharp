// Core/Abstractions/Onion/IOnionAnnounce.cs - ACTUALIZADO
using System;
using System.Net;

namespace ToxCore.Core.Abstractions.Onion
{
    /// <summary>
    /// Interfaz para el sistema de anuncios vía onion (onion_announce).
    /// Permite publicar y buscar información de peers de forma anónima.
    /// </summary>
    public interface IOnionAnnounce : IDisposable
    {
        /// <summary>
        /// Publica un anuncio en la red onion.
        /// </summary>
        /// <param name="path">Path onion de 3 nodos</param>
        /// <param name="publicKey">Clave pública a anunciar</param>
        /// <param name="nonce">Nonce para el anuncio</param>
        /// <param name="data">Datos adicionales del anuncio (hasta 64 bytes)</param>
        /// <returns>true si se envió el anuncio</returns>
        bool AnnounceOnion(IPEndPoint[] path, byte[] publicKey, byte[] nonce, byte[] data = null);

        /// <summary>
        /// Busca anuncios para una clave pública específica.
        /// </summary>
        /// <param name="path">Path onion para la búsqueda</param>
        /// <param name="targetPublicKey">Clave pública a buscar</param>
        /// <param name="searchNonce">Nonce de búsqueda</param>
        /// <returns>true si se inició la búsqueda</returns>
        bool SearchOnion(IPEndPoint[] path, byte[] targetPublicKey, byte[] searchNonce);

        /// <summary>
        /// Establece callback para resultados de búsqueda.
        /// </summary>
        void SetSearchCallback(OnionSearchCallback callback);

        /// <summary>
        /// Establece callback para confirmación de anuncio.
        /// </summary>
        void SetAnnounceCallback(OnionAnnounceCallback callback);

        /// <summary>
        /// Ciclo de mantenimiento.
        /// </summary>
        void DoOnionAnnounce();
    }

    /// <summary>
    /// Callback para resultados de búsqueda onion.
    /// </summary>
    /// <param name="searcherPublicKey">Quién buscó</param>
    /// <param name="announcedPublicKey">Clave encontrada</param>
    /// <param name="data">Datos del anuncio</param>
    /// <param name="endpoint">Endpoint donde se encuentra</param>
    public delegate void OnionSearchCallback(
        byte[] searcherPublicKey,
        byte[] announcedPublicKey,
        byte[] data,
        IPEndPoint endpoint);

    /// <summary>
    /// Callback para confirmación de anuncio.
    /// Llamado cuando el anuncio es aceptado por un nodo de la red onion.
    /// </summary>
    /// <param name="success">true si el anuncio fue aceptado y almacenado</param>
    /// <param name="pingId">ID de ping generado para mantener el anuncio vivo</param>
    /// <param name="nodes">Nodos cercanos devueltos en la respuesta</param>
    public delegate void OnionAnnounceCallback(bool success, byte[] pingId, IPEndPoint[] nodes);
}