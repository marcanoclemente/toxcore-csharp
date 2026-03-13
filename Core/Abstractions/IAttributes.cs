// Core/Abstractions/IAttributes.cs
using System;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz de gestión de atributos de usuario.
    /// </summary>
    public interface IAttributes : IDisposable
    {
        // Self attributes
        bool SetSelfName(string name);
        string GetSelfName();
        bool SetSelfStatusMessage(string message);
        string GetSelfStatusMessage();
        bool SetSelfStatus(byte status);
        byte GetSelfStatus();
        bool SetSelfAvatar(byte[] avatarData, string mimeType = "image/png");
        byte[] GetSelfAvatar();

        // Friend attributes
        void SetFriendName(byte[] publicKey, string name);
        string GetFriendName(byte[] publicKey);
        void SetFriendStatusMessage(byte[] publicKey, string message);
        string GetFriendStatusMessage(byte[] publicKey);
        void SetFriendStatus(byte[] publicKey, byte status);
        byte GetFriendStatus(byte[] publicKey);
        void RemoveFriendAttributes(byte[] publicKey);

        // Serialization
        byte[] SerializeSelf();
        bool DeserializeSelf(ReadOnlySpan<byte> data);
        byte[] SerializeFriends();
        bool DeserializeFriends(ReadOnlySpan<byte> data);

        // Events
        event Action OnSelfNameChanged;
        event Action OnSelfStatusMessageChanged;
        event Action<byte> OnSelfStatusChanged;
        event Action<byte[]> OnFriendNameChanged;
        event Action<byte[]> OnFriendStatusMessageChanged;
        event Action<byte[], byte> OnFriendStatusChanged;
    }
}