// Core/Abstractions/Onion/IOnionClient.cs - ACTUALIZADO
using System;
using System.Net;

namespace Toxcore.Core.Abstractions.Onion
{
    /// <summary>
    /// Interfaz del cliente onion para ToxCore.
    /// Gestiona paths onion y envío de datos anónimos.
    /// </summary>
    public interface IOnionClient : IDisposable
    {
        /// <summary>
        /// Crea un nuevo path onion aleatorio
        /// </summary>
        /// <param name="pathId">ID del path creado</param>
        /// <returns>true si se creó exitosamente</returns>
        bool CreatePath(out int pathId);

        /// <summary>
        /// Destruye un path onion existente
        /// </summary>
        void KillPath(int pathId);

        /// <summary>
        /// Envía datos a través de un path onion específico
        /// </summary>
        /// <param name="pathId">ID del path a usar</param>
        /// <param name="destPublicKey">Clave pública destino (null para broadcast)</param>
        /// <param name="data">Datos a enviar</param>
        /// <returns>true si se envió correctamente</returns>
        bool SendData(int pathId, byte[] destPublicKey, byte[] data);

        /// <summary>
        /// Busca un amigo a través de la red onion
        /// </summary>
        /// <param name="friendPublicKey">Clave pública del amigo a buscar</param>
        /// <returns>true si se inició la búsqueda</returns>
        bool FindFriend(byte[] friendPublicKey);

        /// <summary>
        /// Obtiene el número de paths onion activos
        /// </summary>
        int ActivePathsCount { get; }

        /// <summary>
        /// Ciclo de mantenimiento del cliente onion
        /// </summary>
        void DoOnionClient();

        // Eventos
        event Action<int, IPEndPoint, byte[]> OnDataReceived;  // pathId, source, data
        event Action<int> OnPathEstablished;                 // pathId
        event Action<int> OnPathTimeout;                     // pathId
        event Action<byte[], IPEndPoint> OnFriendFound;        // publicKey, endpoint
    }
}