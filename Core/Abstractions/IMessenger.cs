// Core/Abstractions/IMessenger.cs - CORREGIDO FINAL (separar delegates públicos de internos)
using System;
using System.Net;

namespace ToxCore.Core.Abstractions
{
    // NOTA: Usamos los delegates existentes de IFriendRequests e IFriendConnection para comunicación interna,
    // pero definimos delegates públicos más limpios para la API de IMessenger.

    /// <summary>
    /// Estados de conexión de un amigo en Tox (versión pública/API).
    /// Equivalente a TOX_CONNECTION en tox.h
    /// </summary>
    public enum ToxConnectionStatus
    {
        /// <summary>
        /// No hay conexión con el amigo.
        /// </summary>
        None = 0,

        /// <summary>
        /// Conexión a través de TCP (relay).
        /// </summary>
        Tcp = 1,

        /// <summary>
        /// Conexión directa UDP.
        /// </summary>
        Udp = 2
    }

    /// <summary>
    /// Estados de usuario en Tox.
    /// Equivalente a TOX_USER_STATUS en tox.h
    /// </summary>
    public enum ToxUserStatus : byte
    {
        /// <summary>
        /// Usuario disponible.
        /// </summary>
        Online = 0,

        /// <summary>
        /// Usuario ausente.
        /// </summary>
        Away = 1,

        /// <summary>
        /// Usuario ocupado.
        /// </summary>
        Busy = 2
    }

    /// <summary>
    /// Tipos de mensajes en Tox.
    /// Equivalente a TOX_MESSAGE_TYPE en tox.h
    /// </summary>
    public enum ToxMessageType : byte
    {
        /// <summary>
        /// Mensaje de texto normal.
        /// </summary>
        Normal = 0,

        /// <summary>
        /// Mensaje de acción (/me).
        /// </summary>
        Action = 1
    }

    /// <summary>
    /// Errores al agregar un amigo.
    /// Equivalente a TOX_ERR_FRIEND_ADD en tox.h
    /// </summary>
    public enum ToxFriendAddError
    {
        Ok = 0,
        Null = -1,
        TooLong = -2,
        NoMessage = -3,
        OwnKey = -4,
        AlreadySent = -5,
        BadChecksum = -6,
        SetNewNospam = -7,
        Malloc = -8
    }

    /// <summary>
    /// Errores al enviar un mensaje.
    /// Equivalente a TOX_ERR_FRIEND_SEND_MESSAGE en tox.h
    /// </summary>
    public enum ToxFriendSendMessageError
    {
        Ok = 0,
        Null = -1,
        FriendNotFound = -2,
        FriendNotConnected = -3,
        SendQ = -4,
        TooLong = -5,
        Empty = -6
    }

    // Delegados PÚBLICOS para la API de IMessenger (más limpios, sin parámetros internos)

    /// <summary>
    /// Callback público para solicitudes de amistad entrantes.
    /// Versión simplificada del delegate interno de IFriendRequests.
    /// Equivalente a tox_friend_request_cb en tox.h
    /// </summary>
    /// <param name="publicKey">Clave pública del solicitante (32 bytes)</param>
    /// <param name="message">Mensaje de solicitud</param>
    /// <param name="length">Longitud del mensaje</param>
    public delegate void MessengerFriendRequestCallback(byte[] publicKey, byte[] message, uint length);

    /// <summary>
    /// Callback para mensajes de amigos entrantes.
    /// Equivalente a tox_friend_message_cb en tox.h
    /// </summary>
    public delegate void FriendMessageCallback(int friendNumber, ToxMessageType messageType, byte[] message, uint length);

    /// <summary>
    /// Callback para cambios de nombre de amigos.
    /// Equivalente a tox_friend_name_cb en tox.h
    /// </summary>
    public delegate void FriendNameCallback(int friendNumber, byte[] name, uint length);

    /// <summary>
    /// Callback para cambios de mensaje de estado de amigos.
    /// Equivalente a tox_friend_status_message_cb en tox.h
    /// </summary>
    public delegate void FriendStatusMessageCallback(int friendNumber, byte[] message, uint length);

    /// <summary>
    /// Callback para cambios de estado de conexión de amigos (versión pública Tox).
    /// Equivalente a tox_friend_connection_status_cb en tox.h
    /// </summary>
    public delegate void FriendToxConnectionStatusCallback(int friendNumber, ToxConnectionStatus connectionStatus);

    /// <summary>
    /// Callback para cambios de estado de usuario de amigos (online/away/busy).
    /// Equivalente a tox_friend_status_cb en tox.h
    /// </summary>
    public delegate void FriendStatusCallback(int friendNumber, ToxUserStatus status);

    /// <summary>
    /// Callback para cuando cambia la conexión propia a la red.
    /// Equivalente a tox_self_connection_status_cb en tox.h
    /// </summary>
    public delegate void SelfConnectionStatusCallback(ToxConnectionStatus connectionStatus);

    /// <summary>
    /// Interfaz principal del Messenger de ToxCore.
    /// API pública equivalente a tox.h/tox.c pero sin grupos.
    /// </summary>
    public interface IMessenger : IDisposable
    {
        #region Propiedades de Estado

        ReadOnlySpan<byte> SelfPublicKey { get; }
        byte[] SelfAddress { get; }
        ToxConnectionStatus SelfConnectionStatus { get; }
        int FriendCount { get; }
        bool IsRunning { get; }

        #endregion

        #region Callbacks - Registro (usando delegates públicos limpios)

        void SetFriendRequestCallback(MessengerFriendRequestCallback callback);
        void SetFriendMessageCallback(FriendMessageCallback callback);
        void SetFriendNameCallback(FriendNameCallback callback);
        void SetFriendStatusMessageCallback(FriendStatusMessageCallback callback);
        void SetFriendToxConnectionStatusCallback(FriendToxConnectionStatusCallback callback);
        void SetFriendStatusCallback(FriendStatusCallback callback);
        void SetSelfConnectionStatusCallback(SelfConnectionStatusCallback callback);

        #endregion

        #region Gestión de Amigos

        ToxFriendAddError AddFriend(byte[] address, byte[] message, uint length, out int friendNumber);
        bool AddFriendNoRequest(byte[] publicKey, out int friendNumber);
        bool DeleteFriend(int friendNumber);
        int GetFriendByPublicKey(byte[] publicKey);
        bool GetFriendPublicKey(int friendNumber, out byte[] publicKey);
        bool FriendExists(int friendNumber);
        ToxConnectionStatus GetFriendConnectionStatus(int friendNumber);
        int[] GetFriendList();

        #endregion

        #region Envío de Mensajes

        ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType messageType,
            byte[] message, uint length, out uint messageId);
        ToxFriendSendMessageError SendAction(int friendNumber, byte[] action, uint length, out uint messageId);

        #endregion

        #region Atributos del Usuario (Self)

        bool SetSelfName(byte[] name, uint length);
        byte[] GetSelfName();
        uint GetSelfNameSize();
        bool SetSelfStatusMessage(byte[] message, uint length);
        byte[] GetSelfStatusMessage();
        uint GetSelfStatusMessageSize();
        void SetSelfStatus(ToxUserStatus status);
        ToxUserStatus GetSelfStatus();
        void SetSelfNospam(uint nospam);
        uint GetSelfNospam();

        #endregion

        #region Atributos de Amigos

        bool GetFriendName(int friendNumber, out byte[] name);
        uint GetFriendNameSize(int friendNumber);
        bool GetFriendStatusMessage(int friendNumber, out byte[] message);
        uint GetFriendStatusMessageSize(int friendNumber);
        ToxUserStatus GetFriendStatus(int friendNumber);
        ulong GetFriendLastOnline(int friendNumber);

        #endregion

        #region Bootstrap y Networking

        bool Bootstrap(string address, ushort port, byte[] publicKey);
        bool AddTcpRelay(string address, ushort port, byte[] publicKey);
        void Reconnect();

        #endregion

        #region Ciclo Principal

        void Iterate();
        uint GetIterationInterval();

        #endregion

        #region Persistencia

        uint GetSaveDataSize();
        void GetSaveData(Span<byte> data);
        bool LoadSaveData(ReadOnlySpan<byte> data);

        #endregion

        #region Utilidades Avanzadas

        (uint major, uint minor, uint patch) GetVersion();
        bool IsAddressValid(ReadOnlySpan<byte> address);
        byte[] GetMessageHash(byte[] message, uint length);

        #endregion
    }
}