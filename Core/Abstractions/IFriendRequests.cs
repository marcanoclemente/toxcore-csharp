// Core/Abstractions/IFriendRequests.cs - CORREGIDO según friend_requests.h real
using System;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Callback para solicitudes de amistad entrantes.
    /// Equivalente a fr_friend_request_cb en friend_requests.h
    /// </summary>
    /// <param name="obj">Objecto Friend_Requests (this)</param>
    /// <param name="publicKey">Clave pública del solicitante (32 bytes)</param>
    /// <param name="message">Mensaje de solicitud (null-terminated en C)</param>
    /// <param name="length">Longitud del mensaje</param>
    /// <param name="userData">Datos de usuario pasados al registrar</param>
    public delegate void FriendRequestCallback(object obj, byte[] publicKey, byte[] message, uint length, object userData);

    /// <summary>
    /// Callback de filtro para validar solicitudes.
    /// Equivalente a filter_function_cb en friend_requests.h
    /// Debe retornar 0 si la solicitud es válida, cualquier otro valor si es spam.
    /// </summary>
    /// <param name="obj">Objecto de contexto</param>
    /// <param name="publicKey">Clave pública del solicitante</param>
    /// <returns>0 para aceptar, otro valor para rechazar</returns>
    public delegate int FriendRequestFilterCallback(object obj, byte[] publicKey);

    /// <summary>
    /// Interfaz de gestión de solicitudes de amistad entrantes.
    /// Traducción exacta de friend_requests.h/c - Solo maneja recepción.
    /// 
    /// NOTA: El envío de solicitudes se maneja en otro lado (Messenger/Onion).
    /// Esta clase solo procesa solicitudes entrantes.
    /// </summary>
    public interface IFriendRequests : IDisposable
    {
        /// <summary>
        /// Establece el valor nospam para prevenir spam de solicitudes.
        /// Equivalente a set_nospam().
        /// </summary>
        void SetNospam(uint nospam);

        /// <summary>
        /// Obtiene el valor nospam actual.
        /// Equivalente a get_nospam().
        /// </summary>
        uint GetNospam();

        /// <summary>
        /// Elimina una clave pública de la lista de solicitudes recibidas.
        /// Equivalente a remove_request_received().
        /// </summary>
        /// <param name="publicKey">Clave pública a remover (32 bytes)</param>
        /// <returns>0 si se removió, -1 si no se encontró</returns>
        int RemoveRequestReceived(byte[] publicKey);

        /// <summary>
        /// Registra el callback para solicitudes entrantes.
        /// Equivalente a callback_friendrequest().
        /// </summary>
        void SetFriendRequestCallback(FriendRequestCallback callback, object obj);

        /// <summary>
        /// Establece función de filtro para validar solicitudes.
        /// Equivalente a set_filter_function().
        /// </summary>
        void SetFilterFunction(FriendRequestFilterCallback filterCallback, object userdata);

        /// <summary>
        /// Inicializa los handlers de paquetes friendreq.
        /// Equivalente a friendreq_init().
        /// Registra el callback en Friend_Connections.
        /// </summary>
        void Init(IFriendConnection friendConnections);
    }
}