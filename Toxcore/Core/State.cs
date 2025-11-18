using System;
using System.IO;
using System.Linq;
using System.Text;

namespace ToxCore.Core
{
    /// <summary>
    /// Adaptación de state.c - Manejo de estado persistente del cliente Tox
    /// </summary>
    public class ToxState : IDisposable
    {
        private const string LOG_TAG = "STATE";

        private byte[] _stateData;
        private bool _modified;

        public ToxUser User { get; private set; }
        public ToxFriends Friends { get; private set; }
        public ToxConferences Conferences { get; private set; }

        public ToxState()
        {
            User = new ToxUser();
            Friends = new ToxFriends();
            Conferences = new ToxConferences();
            _stateData = Array.Empty<byte>();
            _modified = false;

            Logger.Log.Info($"[{LOG_TAG}] Estado inicializado");
        }

        /// <summary>
        /// tox_state_load - Cargar estado desde bytes (equivalente a state_load)
        /// </summary>
        public bool Load(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Datos de estado vacíos o nulos");
                return false;
            }

            try
            {
                using var stream = new MemoryStream(data);
                using var reader = new BinaryReader(stream);

                // Verificar magic number (similar al original)
                uint magic = reader.ReadUInt32();
                if (magic != 0x01546F78) // "Tox\0x01" en little-endian
                {
                    Logger.Log.Error($"[{LOG_TAG}] Magic number inválido: 0x{magic:X8}");
                    return false;
                }

                // Cargar usuario
                User = ToxUser.Load(reader);

                // Cargar amigos
                Friends = ToxFriends.Load(reader);

                // Cargar conferencias (si existen)
                if (stream.Position < stream.Length)
                {
                    Conferences = ToxConferences.Load(reader);
                }

                _stateData = data;
                _modified = false;

                Logger.Log.Info($"[{LOG_TAG}] Estado cargado correctamente - Tamaño: {data.Length} bytes");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error cargando estado: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// tox_state_save - Guardar estado a bytes (equivalente a state_save)
        /// </summary>
        public byte[] Save()
        {
            try
            {
                using var stream = new MemoryStream();
                using var writer = new BinaryWriter(stream);

                // Escribir magic number
                writer.Write(0x01546F78); // "Tox\0x01"

                // Guardar usuario
                User.Save(writer);

                // Guardar amigos
                Friends.Save(writer);

                // Guardar conferencias
                Conferences.Save(writer);

                _stateData = stream.ToArray();
                _modified = false;

                Logger.Log.Info($"[{LOG_TAG}] Estado guardado - Tamaño: {_stateData.Length} bytes");
                return _stateData;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error guardando estado: {ex.Message}");
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// tox_state_load_from_file - Cargar estado desde archivo
        /// </summary>
        public bool LoadFromFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Archivo no existe: {filePath}");
                    return false;
                }

                byte[] data = File.ReadAllBytes(filePath);
                bool success = Load(data);

                if (success)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Estado cargado desde: {filePath}");
                }

                return success;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error cargando estado desde archivo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// tox_state_save_to_file - Guardar estado a archivo
        /// </summary>
        public bool SaveToFile(string filePath)
        {
            try
            {
                byte[] data = Save();
                if (data.Length == 0)
                {
                    Logger.Log.Error($"[{LOG_TAG}] No hay datos para guardar");
                    return false;
                }

                // Crear directorio si no existe
                string directory = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                File.WriteAllBytes(filePath, data);
                Logger.Log.InfoF($"[{LOG_TAG}] Estado guardado en: {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error guardando estado en archivo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// tox_state_is_modified - Verificar si el estado ha sido modificado
        /// </summary>
        public bool IsModified()
        {
            return _modified;
        }

        /// <summary>
        /// tox_state_mark_modified - Marcar estado como modificado
        /// </summary>
        public void MarkModified()
        {
            _modified = true;
            Logger.Log.Trace($"[{LOG_TAG}] Estado marcado como modificado");
        }

        /// <summary>
        /// tox_state_get_size - Obtener tamaño del estado serializado
        /// </summary>
        public int GetSize()
        {
            return _stateData.Length;
        }

        public void Dispose()
        {
            // Limpiar recursos si es necesario
            _stateData = null;
        }
    }

    /// <summary>
    /// Datos del usuario (equivalente a USER_STATE en C)
    /// </summary>
    public class ToxUser
    {
        public byte[] PublicKey { get; set; }
        public byte[] SecretKey { get; set; }
        public string Name { get; set; }
        public string StatusMessage { get; set; }
        public ToxUserStatus Status { get; set; }
        public byte[] Nospam { get; set; }

        public ToxUser()
        {
            // INICIALIZAR ARRAYS PARA EVITAR NULL
            PublicKey = new byte[32];
            SecretKey = new byte[32];
            Name = string.Empty;
            StatusMessage = string.Empty;
            Status = ToxUserStatus.NONE;
            Nospam = new byte[4];

            // Generar nospam aleatorio por defecto
            new Random().NextBytes(Nospam);
        }

        public static ToxUser Load(BinaryReader reader)
        {
            var user = new ToxUser();

            try
            {
                // Cargar claves
                user.PublicKey = reader.ReadBytes(32);
                user.SecretKey = reader.ReadBytes(32);

                // Cargar nospam
                user.Nospam = reader.ReadBytes(4);

                // Cargar nombre
                ushort nameLength = reader.ReadUInt16();
                if (nameLength > 0 && nameLength <= 1024) // Límite razonable
                {
                    user.Name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));
                }

                // Cargar estado
                user.Status = (ToxUserStatus)reader.ReadByte();

                // Cargar mensaje de estado
                ushort statusLength = reader.ReadUInt16();
                if (statusLength > 0 && statusLength <= 1024) // Límite razonable
                {
                    user.StatusMessage = Encoding.UTF8.GetString(reader.ReadBytes(statusLength));
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error cargando usuario: {ex.Message}");
                // Devolver usuario por defecto en caso de error
                return new ToxUser();
            }

            return user;
        }

        public void Save(BinaryWriter writer)
        {
            try
            {
                // Asegurar que los arrays no sean null
                PublicKey ??= new byte[32];
                SecretKey ??= new byte[32];
                Nospam ??= new byte[4];

                writer.Write(PublicKey);
                writer.Write(SecretKey);
                writer.Write(Nospam);

                // Guardar nombre
                byte[] nameBytes = Encoding.UTF8.GetBytes(Name ?? "");
                writer.Write((ushort)Math.Min(nameBytes.Length, 1024)); // Limitar tamaño
                if (nameBytes.Length > 0)
                {
                    writer.Write(nameBytes, 0, Math.Min(nameBytes.Length, 1024));
                }

                // Guardar estado
                writer.Write((byte)Status);

                // Guardar mensaje de estado
                byte[] statusBytes = Encoding.UTF8.GetBytes(StatusMessage ?? "");
                writer.Write((ushort)Math.Min(statusBytes.Length, 1024)); // Limitar tamaño
                if (statusBytes.Length > 0)
                {
                    writer.Write(statusBytes, 0, Math.Min(statusBytes.Length, 1024));
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error guardando usuario: {ex.Message}");
                throw;
            }
        }
    }

    /// <summary>
    /// Lista de amigos (equivalente a FRIEND_STATE en C)
    /// </summary>
    public class ToxFriends
    {
        public ToxFriend[] Friends { get; set; }

        public ToxFriends()
        {
            Friends = Array.Empty<ToxFriend>();
        }

        public static ToxFriends Load(BinaryReader reader)
        {
            var friends = new ToxFriends();

            try
            {
                uint count = reader.ReadUInt32();
                // Limitar número máximo de amigos por seguridad
                count = Math.Min(count, 1000);

                friends.Friends = new ToxFriend[count];

                for (int i = 0; i < count; i++)
                {
                    friends.Friends[i] = ToxFriend.Load(reader);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error cargando amigos: {ex.Message}");
                // Devolver lista vacía en caso de error
                return new ToxFriends();
            }

            return friends;
        }

        public void Save(BinaryWriter writer)
        {
            try
            {
                Friends ??= Array.Empty<ToxFriend>();
                writer.Write((uint)Friends.Length);

                foreach (var friend in Friends)
                {
                    friend?.Save(writer);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error guardando amigos: {ex.Message}");
                throw;
            }
        }
    }

    /// <summary>
    /// Datos de un amigo individual
    /// </summary>
    public class ToxFriend
    {
        public byte[] PublicKey { get; set; }
        public string Name { get; set; }
        public string StatusMessage { get; set; }
        public ToxUserStatus Status { get; set; }
        public uint FriendNumber { get; set; }

        public ToxFriend()
        {
            PublicKey = new byte[32];
            Name = string.Empty;
            StatusMessage = string.Empty;
            Status = ToxUserStatus.NONE;
        }

        public static ToxFriend Load(BinaryReader reader)
        {
            var friend = new ToxFriend();

            try
            {
                friend.PublicKey = reader.ReadBytes(32);
                friend.FriendNumber = reader.ReadUInt32();

                // Cargar nombre
                ushort nameLength = reader.ReadUInt16();
                if (nameLength > 0 && nameLength <= 1024)
                {
                    friend.Name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));
                }

                // Cargar estado
                friend.Status = (ToxUserStatus)reader.ReadByte();

                // Cargar mensaje de estado
                ushort statusLength = reader.ReadUInt16();
                if (statusLength > 0 && statusLength <= 1024)
                {
                    friend.StatusMessage = Encoding.UTF8.GetString(reader.ReadBytes(statusLength));
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error cargando amigo: {ex.Message}");
                return new ToxFriend();
            }

            return friend;
        }

        public void Save(BinaryWriter writer)
        {
            try
            {
                PublicKey ??= new byte[32];
                writer.Write(PublicKey);
                writer.Write(FriendNumber);

                // Guardar nombre
                byte[] nameBytes = Encoding.UTF8.GetBytes(Name ?? "");
                writer.Write((ushort)Math.Min(nameBytes.Length, 1024));
                if (nameBytes.Length > 0)
                {
                    writer.Write(nameBytes, 0, Math.Min(nameBytes.Length, 1024));
                }

                // Guardar estado
                writer.Write((byte)Status);

                // Guardar mensaje de estado
                byte[] statusBytes = Encoding.UTF8.GetBytes(StatusMessage ?? "");
                writer.Write((ushort)Math.Min(statusBytes.Length, 1024));
                if (statusBytes.Length > 0)
                {
                    writer.Write(statusBytes, 0, Math.Min(statusBytes.Length, 1024));
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[STATE] Error guardando amigo: {ex.Message}");
                throw;
            }
        }
    }

    /// <summary>
    /// Conferencias/grupos (placeholder para group.c futuro)
    /// </summary>
    public class ToxConferences
    {
        public static ToxConferences Load(BinaryReader reader)
        {
            // Implementación básica - se expandirá con group.c
            return new ToxConferences();
        }

        public void Save(BinaryWriter writer)
        {
            // Implementación básica - no escribir nada por ahora
        }
    }

    public enum ToxUserStatus
    {
        NONE = 0,
        AWAY = 1,
        BUSY = 2
    }
}