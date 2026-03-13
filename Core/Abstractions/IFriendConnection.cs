// Core/Abstractions/IFriendConnection.cs
using System;
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Estados de conexión de un amigo.
    /// Equivalente a Friend_Connection_Status en friend_connection.h
    /// </summary>
    public enum FriendConnectionStatus : byte
    {
        /// <summary>
        /// No hay conexión activa.
        /// </summary>
        FRIENDCONN_STATUS_NONE = 0,

        /// <summary>
        /// Conexión establecida correctamente.
        /// </summary>
        FRIENDCONN_STATUS_CONNECTED = 1,

        /// <summary>
        /// Conexión establecida pero aún no confirmada (handshake pendiente).
        /// </summary>
        FRIENDCONN_STATUS_CONNECTING = 2
    }

    /// <summary>
    /// Razones de desconexión de un amigo.
    /// </summary>
    public enum FriendConnectionDisconnectReason : byte
    {
        FRIENDCONN_DISCONNECT_NONE = 0,
        FRIENDCONN_DISCONNECT_TIMEOUT = 1,
        FRIENDCONN_DISCONNECT_HANDSHAKE_FAILED = 2,
        FRIENDCONN_DISCONNECT_REQUESTED = 3,
        FRIENDCONN_DISCONNECT_CRYPTO_FAILED = 4
    }

    /// <summary>
    /// Callback cuando cambia el estado de conexión de un amigo.
    /// </summary>
    /// <param name="friendNumber">Número de amigo</param>
    /// <param name="status">Nuevo estado de conexión</param>
    /// <param name="userData">Datos de usuario pasados al registrar</param>
    public delegate void FriendConnectionStatusCallback(int friendNumber, FriendConnectionStatus status, object userData);

    /// <summary>
    /// Callback para datos recibidos de un amigo.
    /// </summary>
    /// <param name="friendNumber">Número de amigo</param>
    /// <param name="data">Datos recibidos</param>
    /// <param name="userData">Datos de usuario</param>
    public delegate void FriendConnectionDataCallback(int friendNumber, byte[] data, object userData);

    /// <summary>
    /// Callback para solicitudes de amistad entrantes.
    /// Equivalente a fr_friend_request_cb en friend_connection.h
    /// </summary>
    /// <param name="obj">Objeto pasado al registrar</param>
    /// <param name="publicKey">Clave pública del solicitante (32 bytes)</param>
    /// <param name="message">Mensaje de solicitud</param>
    /// <param name="length">Longitud del mensaje</param>
    /// <param name="userdata">Datos de usuario</param>
    public delegate void FriendRequestReceivedCallback(object obj, byte[] publicKey,
                                                       byte[] message, uint length, object userdata);

    /// <summary>
    /// Callback para solicitud de conexión entrante.
    /// </summary>
    /// <param name="friendNumber">Número de amigo</param>
    /// <param name="publicKey">Clave pública del solicitante</param>
    /// <param name="userData">Datos de usuario</param>
    /// <returns>true para aceptar la conexión</returns>
    public delegate bool FriendConnectionRequestCallback(int friendNumber, byte[] publicKey, object userData);

    /// <summary>
    /// Interfaz de gestión de conexiones de amigos.
    /// Traducción de friend_connection.h/c - Gestiona conexiones P2P cifradas con amigos.
    /// </summary>
    public interface IFriendConnection : IDisposable
    {
        #region Propiedades de Estado

        /// <summary>
        /// Número máximo de conexiones de amigos permitidas.
        /// </summary>
        int MaxFriendConnections { get; }

        /// <summary>
        /// Número actual de conexiones activas.
        /// </summary>
        int ConnectionCount { get; }

        /// <summary>
        /// Timeout de conexión en segundos.
        /// </summary>
        int ConnectionTimeout { get; }

        /// <summary>
        /// Intervalo de ping en segundos.
        /// </summary>
        int PingInterval { get; }

        #endregion

        #region Gestión de Conexiones

        /// <summary>
        /// Crea una nueva conexión de amigo.
        /// Equivalente a create_friend_connection().
        /// </summary>
        /// <param name="friendPublicKey">Clave pública del amigo (32 bytes)</param>
        /// <param name="friendNumber">Número asignado al amigo (out)</param>
        /// <returns>true si se creó correctamente</returns>
        bool CreateConnection(byte[] friendPublicKey, out int friendNumber);

        /// <summary>
        /// Elimina una conexión de amigo existente.
        /// Equivalente a kill_friend_connection().
        /// </summary>
        /// <param name="friendNumber">Número de amigo a eliminar</param>
        /// <returns>true si se eliminó correctamente</returns>
        bool KillConnection(int friendNumber);

        /// <summary>
        /// Obtiene el estado de conexión de un amigo.
        /// </summary>
        /// <param name="friendNumber">Número de amigo</param>
        /// <returns>Estado de conexión</returns>
        FriendConnectionStatus GetConnectionStatus(int friendNumber);

        /// <summary>
        /// Verifica si un amigo está conectado.
        /// </summary>
        bool IsFriendConnected(int friendNumber);

        /// <summary>
        /// Obtiene el connection_id de NetCrypto para un amigo.
        /// </summary>
        int GetCryptoConnectionId(int friendNumber);

        #endregion

        #region Envío de Datos

        /// <summary>
        /// Envía datos a un amigo a través de la conexión cifrada.
        /// Equivalente a send_friend_connection_packet().
        /// </summary>
        /// <param name="friendNumber">Número de amigo</param>
        /// <param name="data">Datos a enviar</param>
        /// <returns>Bytes enviados o -1 en error</returns>
        int SendData(int friendNumber, byte[] data);

        /// <summary>
        /// Envía datos con prioridad alta (bypass de cola si es posible).
        /// </summary>
        int SendDataPriority(int friendNumber, byte[] data);

        #endregion

        #region Callbacks

        /// <summary>
        /// Registra callback para cambios de estado de conexión.
        /// </summary>
        void RegisterStatusCallback(FriendConnectionStatusCallback callback, object userData);

        /// <summary>
        /// Registra callback para datos recibidos.
        /// </summary>
        void RegisterDataCallback(FriendConnectionDataCallback callback, object userData);

        /// <summary>
        /// Registra callback para solicitudes de conexión entrantes.
        /// </summary>
        void RegisterRequestCallback(FriendConnectionRequestCallback callback, object userData);

        /// <summary>
        /// Desregistra un callback de estado.
        /// </summary>
        void UnregisterStatusCallback(FriendConnectionStatusCallback callback);

        /// <summary>
        /// Desregistra un callback de datos.
        /// </summary>
        void UnregisterDataCallback(FriendConnectionDataCallback callback);

        #endregion

        #region Utilidades

        /// <summary>
        /// Obtiene la clave pública de un amigo por su número.
        /// </summary>
        byte[] GetFriendPublicKey(int friendNumber);

        /// <summary>
        /// Obtiene el número de amigo por su clave pública.
        /// </summary>
        int GetFriendNumber(byte[] publicKey);

        /// <summary>
        /// Establece el connection_id de NetCrypto para un amigo.
        /// Llamado por NetCrypto cuando se establece conexión segura.
        /// </summary>
        void SetCryptoConnectionId(int friendNumber, int cryptoConnectionId);

        /// <summary>
        /// Notifica que la conexión cifrada está lista.
        /// Llamado por NetCrypto cuando el handshake se completa.
        /// </summary>
        void NotifyCryptoConnected(int friendNumber);

        /// <summary>
        /// Notifica que la conexión cifrada se perdió.
        /// Llamado por NetCrypto cuando hay timeout o error.
        /// </summary>
        void NotifyCryptoDisconnected(int friendNumber, FriendConnectionDisconnectReason reason);

        #endregion

        #region Ciclo Principal

        /// <summary>
        /// Ejecuta el ciclo de mantenimiento de conexiones.
        /// Equivalente a do_friend_connections().
        /// Debe llamarse periódicamente (cada iteración de tox_iterate).
        /// </summary>
        void DoFriendConnections();

        #endregion

        #region Friend Requests

        /// <summary>
        /// Establece el callback para solicitudes de amistad entrantes.
        /// Equivalente a set_friend_request_callback().
        /// </summary>
        /// <param name="callback">Función a llamar cuando llegue solicitud</param>
        /// <param name="obj">Objeto que se pasará como primer parámetro</param>
        void SetFriendRequestCallback(FriendRequestReceivedCallback callback, object obj);

        #endregion

    }
}