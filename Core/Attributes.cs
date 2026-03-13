// Core/Attributes.cs - Implementación completa de attributes.c
using System;
using System.Collections.Concurrent;
using System.Text;
using Toxcore.Core.Crypto;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core
{
    /// <summary>
    /// Gestiona atributos de usuario: nombre, status message, status (online/away/busy).
    /// Traducción de attributes.c - almacena y serializa metadatos de perfil.
    /// </summary>
    public sealed class Attributes : IAttributes, IDisposable
    {
        #region Constantes de attributes.h

        // Límites de tamaño (bytes)
        public const int MaxNameLength = 128;
        public const int MaxStatusMessageLength = 1007;
        public const int MaxAvatarDataSize = 65536; // 64KB para avatar

        // Estados de usuario
        public const byte UserStatusNone = 0;
        public const byte UserStatusAway = 1;
        public const byte UserStatusBusy = 2;

        // Tipos de atributos para serialización
        public const byte AttributeTypeName = 1;
        public const byte AttributeTypeStatusMessage = 2;
        public const byte AttributeTypeStatus = 3;
        public const byte AttributeTypeAvatar = 4;
        public const byte AttributeTypeCustom = 255;

        // Versión de formato
        public const byte AttributesVersion = 1;

        #endregion

        #region Estado

        // Atributos propios
        private byte[] _selfName = Array.Empty<byte>();
        private byte[] _selfStatusMessage = Array.Empty<byte>();
        private byte _selfStatus = UserStatusNone;
        private byte[] _selfAvatar = Array.Empty<byte>();
        private string _selfAvatarMimeType = "image/png";

        // Atributos de amigos (public_key -> atributos)
        private readonly ConcurrentDictionary<byte[], FriendAttributes> _friendAttributes = new(ByteArrayComparer.Instance);

        // Callbacks de cambio
        public event Action OnSelfNameChanged;
        public event Action OnSelfStatusMessageChanged;
        public event Action<byte> OnSelfStatusChanged;
        public event Action<byte[]> OnFriendNameChanged;
        public event Action<byte[]> OnFriendStatusMessageChanged;
        public event Action<byte[], byte> OnFriendStatusChanged;

        #endregion

        #region API Pública - Self Attributes

        /// <summary>
        /// Establece el nombre de usuario.
        /// </summary>
        public bool SetSelfName(string name)
        {
            return SetSelfName(Encoding.UTF8.GetBytes(name ?? string.Empty));
        }

        /// <summary>
        /// Establece el nombre de usuario (bytes).
        /// </summary>
        public bool SetSelfName(byte[] name)
        {
            if (name == null) name = Array.Empty<byte>();
            if (name.Length > MaxNameLength)
            {
                Array.Resize(ref name, MaxNameLength);
            }

            bool changed = !_selfName.AsSpan().SequenceEqual(name);
            _selfName = (byte[])name.Clone();

            if (changed)
            {
                OnSelfNameChanged?.Invoke();
                Logger.Log.Info($"[Attributes] Self name changed: {GetSelfName()}");
            }

            return true;
        }

        /// <summary>
        /// Obtiene el nombre de usuario.
        /// </summary>
        public string GetSelfName()
        {
            return Encoding.UTF8.GetString(_selfName);
        }

        /// <summary>
        /// Obtiene el nombre de usuario como bytes.
        /// </summary>
        public byte[] GetSelfNameBytes()
        {
            return (byte[])_selfName.Clone();
        }

        /// <summary>
        /// Establece el mensaje de status.
        /// </summary>
        public bool SetSelfStatusMessage(string message)
        {
            return SetSelfStatusMessage(Encoding.UTF8.GetBytes(message ?? string.Empty));
        }

        /// <summary>
        /// Establece el mensaje de status (bytes).
        /// </summary>
        public bool SetSelfStatusMessage(byte[] message)
        {
            if (message == null) message = Array.Empty<byte>();
            if (message.Length > MaxStatusMessageLength)
            {
                Array.Resize(ref message, MaxStatusMessageLength);
            }

            bool changed = !_selfStatusMessage.AsSpan().SequenceEqual(message);
            _selfStatusMessage = (byte[])message.Clone();

            if (changed)
            {
                OnSelfStatusMessageChanged?.Invoke();
                Logger.Log.Info($"[Attributes] Self status message changed: {GetSelfStatusMessage()}");
            }

            return true;
        }

        /// <summary>
        /// Obtiene el mensaje de status.
        /// </summary>
        public string GetSelfStatusMessage()
        {
            return Encoding.UTF8.GetString(_selfStatusMessage);
        }

        /// <summary>
        /// Obtiene el mensaje de status como bytes.
        /// </summary>
        public byte[] GetSelfStatusMessageBytes()
        {
            return (byte[])_selfStatusMessage.Clone();
        }

        /// <summary>
        /// Establece el estado de usuario (online/away/busy).
        /// </summary>
        public bool SetSelfStatus(byte status)
        {
            if (status > UserStatusBusy)
                status = UserStatusNone;

            bool changed = _selfStatus != status;
            _selfStatus = status;

            if (changed)
            {
                OnSelfStatusChanged?.Invoke(status);
                Logger.Log.Info($"[Attributes] Self status changed: {status}");
            }

            return true;
        }

        /// <summary>
        /// Obtiene el estado de usuario.
        /// </summary>
        public byte GetSelfStatus()
        {
            return _selfStatus;
        }

        /// <summary>
        /// Establece el avatar.
        /// </summary>
        public bool SetSelfAvatar(byte[] avatarData, string mimeType = "image/png")
        {
            if (avatarData == null) avatarData = Array.Empty<byte>();
            if (avatarData.Length > MaxAvatarDataSize)
            {
                Logger.Log.Warning($"[Attributes] Avatar too large: {avatarData.Length} > {MaxAvatarDataSize}");
                return false;
            }

            _selfAvatar = (byte[])avatarData.Clone();
            _selfAvatarMimeType = mimeType ?? "image/png";

            Logger.Log.Info($"[Attributes] Self avatar updated: {avatarData.Length} bytes");
            return true;
        }

        /// <summary>
        /// Obtiene el avatar.
        /// </summary>
        public byte[] GetSelfAvatar()
        {
            return (byte[])_selfAvatar.Clone();
        }

        /// <summary>
        /// Obtiene el MIME type del avatar.
        /// </summary>
        public string GetSelfAvatarMimeType()
        {
            return _selfAvatarMimeType;
        }

        #endregion

        #region API Pública - Friend Attributes

        /// <summary>
        /// Establece atributos de un amigo.
        /// </summary>
        public void SetFriendName(byte[] publicKey, string name)
        {
            SetFriendName(publicKey, Encoding.UTF8.GetBytes(name ?? string.Empty));
        }

        /// <summary>
        /// Establece nombre de un amigo.
        /// </summary>
        public void SetFriendName(byte[] publicKey, byte[] name)
        {
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE) return;
            if (name == null) name = Array.Empty<byte>();
            if (name.Length > MaxNameLength) Array.Resize(ref name, MaxNameLength);

            var attrs = _friendAttributes.GetOrAdd(publicKey, _ => new FriendAttributes
            {
                PublicKey = (byte[])publicKey.Clone()
            });

            bool changed = !attrs.Name.AsSpan().SequenceEqual(name);
            attrs.Name = (byte[])name.Clone();

            if (changed)
            {
                OnFriendNameChanged?.Invoke(publicKey);
            }
        }

        /// <summary>
        /// Obtiene nombre de un amigo.
        /// </summary>
        public string GetFriendName(byte[] publicKey)
        {
            if (_friendAttributes.TryGetValue(publicKey, out var attrs))
            {
                return Encoding.UTF8.GetString(attrs.Name);
            }
            return string.Empty;
        }

        /// <summary>
        /// Establece mensaje de status de un amigo.
        /// </summary>
        public void SetFriendStatusMessage(byte[] publicKey, string message)
        {
            SetFriendStatusMessage(publicKey, Encoding.UTF8.GetBytes(message ?? string.Empty));
        }

        /// <summary>
        /// Establece mensaje de status de un amigo (bytes).
        /// </summary>
        public void SetFriendStatusMessage(byte[] publicKey, byte[] message)
        {
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE) return;
            if (message == null) message = Array.Empty<byte>();
            if (message.Length > MaxStatusMessageLength) Array.Resize(ref message, MaxStatusMessageLength);

            var attrs = _friendAttributes.GetOrAdd(publicKey, _ => new FriendAttributes
            {
                PublicKey = (byte[])publicKey.Clone()
            });

            bool changed = !attrs.StatusMessage.AsSpan().SequenceEqual(message);
            attrs.StatusMessage = (byte[])message.Clone();

            if (changed)
            {
                OnFriendStatusMessageChanged?.Invoke(publicKey);
            }
        }

        /// <summary>
        /// Obtiene mensaje de status de un amigo.
        /// </summary>
        public string GetFriendStatusMessage(byte[] publicKey)
        {
            if (_friendAttributes.TryGetValue(publicKey, out var attrs))
            {
                return Encoding.UTF8.GetString(attrs.StatusMessage);
            }
            return string.Empty;
        }

        /// <summary>
        /// Establece estado de un amigo.
        /// </summary>
        public void SetFriendStatus(byte[] publicKey, byte status)
        {
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE) return;
            if (status > UserStatusBusy) status = UserStatusNone;

            var attrs = _friendAttributes.GetOrAdd(publicKey, _ => new FriendAttributes
            {
                PublicKey = (byte[])publicKey.Clone()
            });

            bool changed = attrs.Status != status;
            attrs.Status = status;

            if (changed)
            {
                OnFriendStatusChanged?.Invoke(publicKey, status);
            }
        }

        /// <summary>
        /// Obtiene estado de un amigo.
        /// </summary>
        public byte GetFriendStatus(byte[] publicKey)
        {
            if (_friendAttributes.TryGetValue(publicKey, out var attrs))
            {
                return attrs.Status;
            }
            return UserStatusNone;
        }

        /// <summary>
        /// Establece avatar de un amigo.
        /// </summary>
        public void SetFriendAvatar(byte[] publicKey, byte[] avatarData, string mimeType = "image/png")
        {
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE) return;
            if (avatarData == null) avatarData = Array.Empty<byte>();
            if (avatarData.Length > MaxAvatarDataSize) return;

            var attrs = _friendAttributes.GetOrAdd(publicKey, _ => new FriendAttributes
            {
                PublicKey = (byte[])publicKey.Clone()
            });

            attrs.Avatar = (byte[])avatarData.Clone();
            attrs.AvatarMimeType = mimeType ?? "image/png";
        }

        /// <summary>
        /// Obtiene avatar de un amigo.
        /// </summary>
        public byte[] GetFriendAvatar(byte[] publicKey)
        {
            if (_friendAttributes.TryGetValue(publicKey, out var attrs))
            {
                return (byte[])attrs.Avatar.Clone();
            }
            return Array.Empty<byte>();
        }

        /// <summary>
        /// Elimina atributos de un amigo (cuando se borra).
        /// </summary>
        public void RemoveFriendAttributes(byte[] publicKey)
        {
            _friendAttributes.TryRemove(publicKey, out _);
        }

        #endregion

        #region Serialización (para guardar/cargar estado)

        /// <summary>
        /// Serializa atributos propios para guardar en estado.
        /// </summary>
        public byte[] SerializeSelf()
        {
            using var ms = new System.IO.MemoryStream();

            // Versión
            ms.WriteByte(AttributesVersion);

            // Nombre
            ms.WriteByte(AttributeTypeName);
            ms.WriteByte((byte)_selfName.Length);
            ms.Write(_selfName, 0, _selfName.Length);

            // Status message
            ms.WriteByte(AttributeTypeStatusMessage);
            var statusLenBytes = BitConverter.GetBytes((ushort)_selfStatusMessage.Length);
            ms.Write(statusLenBytes, 0, 2);
            ms.Write(_selfStatusMessage, 0, _selfStatusMessage.Length);

            // Status
            ms.WriteByte(AttributeTypeStatus);
            ms.WriteByte(_selfStatus);

            // Avatar (si existe)
            if (_selfAvatar.Length > 0)
            {
                ms.WriteByte(AttributeTypeAvatar);
                var avatarLenBytes = BitConverter.GetBytes(_selfAvatar.Length);
                ms.Write(avatarLenBytes, 0, 4);
                ms.Write(_selfAvatar, 0, _selfAvatar.Length);

                // MIME type
                var mimeBytes = Encoding.UTF8.GetBytes(_selfAvatarMimeType);
                ms.WriteByte((byte)mimeBytes.Length);
                ms.Write(mimeBytes, 0, mimeBytes.Length);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializa atributos propios desde estado guardado.
        /// </summary>
        public bool DeserializeSelf(ReadOnlySpan<byte> data)
        {
            try
            {
                int offset = 0;

                // Versión
                if (data.Length < 1) return false;
                byte version = data[offset++];
                if (version != AttributesVersion) return false;

                while (offset < data.Length)
                {
                    byte type = data[offset++];

                    switch (type)
                    {
                        case AttributeTypeName:
                            if (offset >= data.Length) return false;
                            byte nameLen = data[offset++];
                            if (offset + nameLen > data.Length) return false;
                            _selfName = data.Slice(offset, nameLen).ToArray();
                            offset += nameLen;
                            break;

                        case AttributeTypeStatusMessage:
                            if (offset + 2 > data.Length) return false;
                            ushort statusLen = BitConverter.ToUInt16(data.Slice(offset, 2));
                            offset += 2;
                            if (offset + statusLen > data.Length) return false;
                            _selfStatusMessage = data.Slice(offset, statusLen).ToArray();
                            offset += statusLen;
                            break;

                        case AttributeTypeStatus:
                            if (offset >= data.Length) return false;
                            _selfStatus = data[offset++];
                            break;

                        case AttributeTypeAvatar:
                            if (offset + 4 > data.Length) return false;
                            int avatarLen = BitConverter.ToInt32(data.Slice(offset, 4));
                            offset += 4;
                            if (offset + avatarLen > data.Length) return false;
                            _selfAvatar = data.Slice(offset, avatarLen).ToArray();
                            offset += avatarLen;

                            // MIME type
                            if (offset >= data.Length) return false;
                            byte mimeLen = data[offset++];
                            if (offset + mimeLen > data.Length) return false;
                            _selfAvatarMimeType = Encoding.UTF8.GetString(data.Slice(offset, mimeLen));
                            offset += mimeLen;
                            break;

                        default:
                            // Tipo desconocido, ignorar resto
                            return true;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Serializa atributos de todos los amigos.
        /// </summary>
        public byte[] SerializeFriends()
        {
            using var ms = new System.IO.MemoryStream();

            // Número de amigos
            var countBytes = BitConverter.GetBytes(_friendAttributes.Count);
            ms.Write(countBytes, 0, 4);

            foreach (var attrs in _friendAttributes.Values)
            {
                // Public key
                ms.Write(attrs.PublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

                // Nombre
                ms.WriteByte((byte)attrs.Name.Length);
                ms.Write(attrs.Name, 0, attrs.Name.Length);

                // Status message
                var statusLenBytes = BitConverter.GetBytes((ushort)attrs.StatusMessage.Length);
                ms.Write(statusLenBytes, 0, 2);
                ms.Write(attrs.StatusMessage, 0, attrs.StatusMessage.Length);

                // Status
                ms.WriteByte(attrs.Status);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Deserializa atributos de amigos.
        /// </summary>
        public bool DeserializeFriends(ReadOnlySpan<byte> data)
        {
            try
            {
                if (data.Length < 4) return false;

                int offset = 0;
                int count = BitConverter.ToInt32(data.Slice(offset, 4));
                offset += 4;

                for (int i = 0; i < count; i++)
                {
                    if (offset + LibSodium.CRYPTO_PUBLIC_KEY_SIZE > data.Length) return false;

                    var pk = data.Slice(offset, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
                    offset += LibSodium.CRYPTO_PUBLIC_KEY_SIZE;

                    if (offset >= data.Length) return false;
                    byte nameLen = data[offset++];
                    if (offset + nameLen > data.Length) return false;
                    var name = data.Slice(offset, nameLen).ToArray();
                    offset += nameLen;

                    if (offset + 2 > data.Length) return false;
                    ushort statusMsgLen = BitConverter.ToUInt16(data.Slice(offset, 2));
                    offset += 2;
                    if (offset + statusMsgLen > data.Length) return false;
                    var statusMsg = data.Slice(offset, statusMsgLen).ToArray();
                    offset += statusMsgLen;

                    if (offset >= data.Length) return false;
                    byte status = data[offset++];

                    // Guardar
                    var attrs = new FriendAttributes
                    {
                        PublicKey = pk,
                        Name = name,
                        StatusMessage = statusMsg,
                        Status = status
                    };
                    _friendAttributes[pk] = attrs;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Utilidades

        /// <summary>
        /// Obtiene tamaño total de atributos propios serializados.
        /// </summary>
        public int GetSelfSerializedSize()
        {
            int size = 1; // versión

            size += 2 + _selfName.Length; // tipo + len + datos
            size += 3 + _selfStatusMessage.Length; // tipo + 2 bytes len + datos
            size += 2; // tipo + status

            if (_selfAvatar.Length > 0)
            {
                size += 5 + _selfAvatar.Length; // tipo + 4 bytes len + datos
                size += 1 + Encoding.UTF8.GetByteCount(_selfAvatarMimeType); // mime type
            }

            return size;
        }

        /// <summary>
        /// Limpia todos los atributos (logout).
        /// </summary>
        public void Clear()
        {
            _selfName = Array.Empty<byte>();
            _selfStatusMessage = Array.Empty<byte>();
            _selfStatus = UserStatusNone;
            _selfAvatar = Array.Empty<byte>();
            _friendAttributes.Clear();
        }

        #endregion

        public void Dispose()
        {
            Clear();
            _friendAttributes.Clear();
        }
    }

    #region Clases Auxiliares

    /// <summary>
    /// Atributos de un amigo.
    /// </summary>
    public class FriendAttributes
    {
        public byte[] PublicKey { get; set; }
        public byte[] Name { get; set; } = Array.Empty<byte>();
        public byte[] StatusMessage { get; set; } = Array.Empty<byte>();
        public byte Status { get; set; } = Attributes.UserStatusNone;
        public byte[] Avatar { get; set; } = Array.Empty<byte>();
        public string AvatarMimeType { get; set; } = "image/png";
        public ulong LastUpdate { get; set; }
    }

    #endregion
}