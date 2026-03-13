// Core/Abstractions/IAnnounce.cs
using System;
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz de sistema de anuncio de presencia en DHT.
    /// </summary>
    public interface IAnnounce : IDisposable
    {
        /// <summary>
        /// Establece los datos a anunciar (nombre, status, etc.).
        /// </summary>
        void SetSelfData(byte[] data);

        /// <summary>
        /// Inicia el proceso de auto-anuncio en la red.
        /// </summary>
        void StartSelfAnnounce();

        /// <summary>
        /// Busca un peer por su clave pública.
        /// </summary>
        bool SearchPeer(byte[] publicKey, out IPEndPoint endpoint, out byte[] data);

        /// <summary>
        /// Ciclo principal de mantenimiento.
        /// </summary>
        void DoAnnounce();
    }
}