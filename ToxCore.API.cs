// ToxCore.API.cs - API Pública y Contratos
// Propósito: Definir la interfaz ITox, opciones, eventos y tipos públicos
// Equivalente a: tox.h + tox_options.h + tox_events.h (simplificado)

using System;
using System.Collections.Generic;
using Toxcore.Core.Abstractions;

namespace Toxcore
{
    #region Opciones de Configuración

    /// <summary>
    /// Opciones de configuración para instanciar Tox.
    /// Equivalente a Tox_Options en c-toxcore.
    /// </summary>
    public sealed class ToxOptions
    {
        public bool Ipv6Enabled { get; set; } = true;
        public bool UdpEnabled { get; set; } = true;
        public bool LocalDiscoveryEnabled { get; set; } = true;
        public bool HolePunchingEnabled { get; set; } = true;
        public ToxProxyType ProxyType { get; set; } = ToxProxyType.None;
        public string ProxyHost { get; set; } = string.Empty;
        public ushort ProxyPort { get; set; } = 0;
        public ushort StartPort { get; set; } = 33445;
        public ushort EndPort { get; set; } = 33545;
        public byte[] SavedData { get; set; }
        public byte[] SecretKey { get; set; }
        public bool ExperimentalThreadSafe { get; set; } = false;
    }

    public enum ToxProxyType : byte
    {
        None = 0,
        Socks5 = 1,
        Http = 2
    }

    #endregion

    #region Interfaz Principal ITox

    /// <summary>
    /// Interfaz pública principal del cliente Tox.
    /// Diseñada para ser compatible conceptualmente con tox.h pero idiomatica en C#.
    /// </summary>
    public interface ITox : IDisposable
    {
        // === Propiedades de Estado ===
        ToxOptions Options { get; }
        bool IsConnected { get; }
        byte[] SelfPublicKey { get; }
        byte[] SelfAddress { get; }
        int FriendCount { get; }

        // === Ciclo de Vida ===
        uint GetIterationInterval();
        void Iterate();

        // === Perfil de Usuario ===
        bool SetSelfName(string name);
        string GetSelfName();
        bool SetSelfStatusMessage(string message);
        string GetSelfStatusMessage();
        void SetSelfStatus(ToxUserStatus status);
        ToxUserStatus GetSelfStatus();
        void SetSelfNospam(uint nospam);
        uint GetSelfNospam();

        // === Gestión de Amigos ===
        ToxFriendAddError AddFriend(byte[] address, string message, out int friendNumber);
        ToxFriendAddError AddFriendNoRequest(byte[] publicKey, out int friendNumber);
        bool DeleteFriend(int friendNumber);
        int GetFriendByPublicKey(byte[] publicKey);
        bool GetFriendPublicKey(int friendNumber, out byte[] publicKey);
        bool FriendExists(int friendNumber);
        ToxConnectionStatus GetFriendConnectionStatus(int friendNumber);
        IReadOnlyList<int> GetFriendList();

        // === Información de Amigos ===
        string GetFriendName(int friendNumber);
        string GetFriendStatusMessage(int friendNumber);
        ToxUserStatus GetFriendStatus(int friendNumber);
        ulong GetFriendLastOnline(int friendNumber);

        // === Mensajería ===
        ToxFriendSendMessageError SendMessage(int friendNumber, ToxMessageType type,
            string message, out uint messageId);
        bool SetTyping(int friendNumber, bool isTyping);
        bool GetFriendTyping(int friendNumber);

        // === Networking ===
        bool Bootstrap(string address, ushort port, byte[] publicKey);
        bool AddTcpRelay(string address, ushort port, byte[] publicKey);
        ushort GetUdpPort();
        ushort GetTcpPort();

        // === Persistencia ===
        byte[] GetSaveData();
        bool LoadSaveData(byte[] data);

        // === Eventos (Nuevo sistema tipado) ===
        event EventHandler<ToxFriendRequestEventArgs> OnFriendRequest;
        event EventHandler<ToxFriendMessageEventArgs> OnFriendMessage;
        event EventHandler<ToxFriendNameChangeEventArgs> OnFriendNameChange;
        event EventHandler<ToxFriendStatusMessageChangeEventArgs> OnFriendStatusMessageChange;
        event EventHandler<ToxFriendStatusChangeEventArgs> OnFriendStatusChange;
        event EventHandler<ToxFriendConnectionStatusChangeEventArgs> OnFriendConnectionStatusChange;
        event EventHandler<ToxSelfConnectionStatusChangeEventArgs> OnSelfConnectionStatusChange;
        event EventHandler<ToxFriendTypingEventArgs> OnFriendTyping;
    }

    #endregion

    #region Event Args (Sistema Moderno C#)

    public abstract class ToxEventArgs : EventArgs
    {
        public DateTime Timestamp { get; } = DateTime.UtcNow;
    }

    public sealed class ToxFriendRequestEventArgs : ToxEventArgs
    {
        public byte[] PublicKey { get; }
        public string Message { get; }

        public ToxFriendRequestEventArgs(byte[] publicKey, string message)
        {
            PublicKey = publicKey?.ToArray() ?? Array.Empty<byte>();
            Message = message ?? string.Empty;
        }
    }

    public sealed class ToxFriendMessageEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public ToxMessageType MessageType { get; }
        public string Message { get; }
        public uint MessageId { get; }

        public ToxFriendMessageEventArgs(int friendNumber, ToxMessageType type,
            string message, uint messageId)
        {
            FriendNumber = friendNumber;
            MessageType = type;
            Message = message ?? string.Empty;
            MessageId = messageId;
        }
    }

    public sealed class ToxFriendNameChangeEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public string Name { get; }

        public ToxFriendNameChangeEventArgs(int friendNumber, string name)
        {
            FriendNumber = friendNumber;
            Name = name ?? string.Empty;
        }
    }

    public sealed class ToxFriendStatusMessageChangeEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public string StatusMessage { get; }

        public ToxFriendStatusMessageChangeEventArgs(int friendNumber, string statusMessage)
        {
            FriendNumber = friendNumber;
            StatusMessage = statusMessage ?? string.Empty;
        }
    }

    public sealed class ToxFriendStatusChangeEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public ToxUserStatus Status { get; }

        public ToxFriendStatusChangeEventArgs(int friendNumber, ToxUserStatus status)
        {
            FriendNumber = friendNumber;
            Status = status;
        }
    }

    public sealed class ToxFriendConnectionStatusChangeEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public ToxConnectionStatus ConnectionStatus { get; }

        public ToxFriendConnectionStatusChangeEventArgs(int friendNumber, ToxConnectionStatus status)
        {
            FriendNumber = friendNumber;
            ConnectionStatus = status;
        }
    }

    public sealed class ToxSelfConnectionStatusChangeEventArgs : ToxEventArgs
    {
        public ToxConnectionStatus ConnectionStatus { get; }

        public ToxSelfConnectionStatusChangeEventArgs(ToxConnectionStatus status)
        {
            ConnectionStatus = status;
        }
    }

    public sealed class ToxFriendTypingEventArgs : ToxEventArgs
    {
        public int FriendNumber { get; }
        public bool IsTyping { get; }

        public ToxFriendTypingEventArgs(int friendNumber, bool isTyping)
        {
            FriendNumber = friendNumber;
            IsTyping = isTyping;
        }
    }

    #endregion

    
}