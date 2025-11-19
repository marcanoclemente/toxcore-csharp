using System;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ToxCore.Core
{
    /// <summary>
    /// Adaptación de group.c - Chats grupales de Tox
    /// </summary>
    public class GroupManager : IDisposable
    {
        private const string LOG_TAG = "GROUP";

        private Messenger _messenger;
        private bool _isRunning;

        // Almacenamiento de grupos
        private readonly Dictionary<int, ToxGroup> _groups;
        private readonly object _groupsLock = new object();
        private int _lastGroupNumber = 0;

        // Callbacks de grupos (equivalente a group.h callbacks)
        public delegate void GroupInviteCallback(GroupManager manager, int friendNumber, byte[] inviteData, string groupName, object userData);
        public delegate void GroupMessageCallback(GroupManager manager, int groupNumber, int peerNumber, ToxMessageType type, string message, object userData);
        public delegate void GroupPeerJoinCallback(GroupManager manager, int groupNumber, int peerNumber, object userData);
        public delegate void GroupPeerExitCallback(GroupManager manager, int groupNumber, int peerNumber, ToxGroupExitType exitType, string name, object userData);
        public delegate void GroupSelfJoinCallback(GroupManager manager, int groupNumber, object userData);
        public delegate void GroupTopicCallback(GroupManager manager, int groupNumber, int peerNumber, string topic, object userData);
        public delegate void GroupPeerListUpdateCallback(GroupManager manager, int groupNumber, object userData);

        // Eventos
        public event GroupInviteCallback OnGroupInvite;
        public event GroupMessageCallback OnGroupMessage;
        public event GroupPeerJoinCallback OnGroupPeerJoin;
        public event GroupPeerExitCallback OnGroupPeerExit;
        public event GroupSelfJoinCallback OnGroupSelfJoin;
        public event GroupTopicCallback OnGroupTopic;
        public event GroupPeerListUpdateCallback OnGroupPeerListUpdate;

        public GroupManager(Messenger messenger)
        {
            _messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));
            _groups = new Dictionary<int, ToxGroup>();
            _isRunning = false;

            Logger.Log.Info($"[{LOG_TAG}] Group Manager inicializado");
        }

        /// <summary>
        /// Iniciar gestión de grupos
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Group Manager ya está ejecutándose");
                return true;
            }

            _isRunning = true;
            Logger.Log.Info($"[{LOG_TAG}] Group Manager iniciado");
            return true;
        }

        /// <summary>
        /// Detener gestión de grupos
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;

            lock (_groupsLock)
            {
                _groups.Clear();
            }

            Logger.Log.Info($"[{LOG_TAG}] Group Manager detenido");
        }

        // ==================== API PÚBLICA DE GRUPOS ====================

        /// <summary>
        /// tox_group_new - Crear nuevo grupo
        /// </summary>
        public int GroupNew(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                Logger.Log.Error($"[{LOG_TAG}] Nombre de grupo inválido");
                return -1;
            }

            try
            {
                lock (_groupsLock)
                {
                    int groupNumber = _lastGroupNumber++;
                    var group = new ToxGroup(groupNumber, name);

                    _groups[groupNumber] = group;

                    // Agregarnos como primer peer
                    var selfPeer = new GroupPeer(0, "Self", _messenger.State.User.PublicKey);
                    group.AddPeer(selfPeer);

                    Logger.Log.InfoF($"[{LOG_TAG}] Nuevo grupo creado: {name} (#{groupNumber})");

                    // Disparar callback de self-join
                    OnGroupSelfJoin?.Invoke(this, groupNumber, null);

                    return groupNumber;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando grupo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// tox_group_join - Unirse a grupo existente
        /// </summary>
        public int GroupJoin(byte[] inviteData)
        {
            if (inviteData == null || inviteData.Length == 0)
            {
                Logger.Log.Error($"[{LOG_TAG}] Datos de invitación inválidos");
                return -1;
            }

            try
            {
                // Simular unirse a un grupo (en implementación real, esto procesaría la invitación)
                lock (_groupsLock)
                {
                    int groupNumber = _lastGroupNumber++;
                    string groupName = Encoding.UTF8.GetString(inviteData, 0, Math.Min(inviteData.Length, 64));

                    var group = new ToxGroup(groupNumber, groupName);
                    _groups[groupNumber] = group;

                    // Agregarnos como peer
                    var selfPeer = new GroupPeer(0, "Self", _messenger.State.User.PublicKey);
                    group.AddPeer(selfPeer);

                    Logger.Log.InfoF($"[{LOG_TAG}] Unido a grupo: {groupName} (#{groupNumber})");

                    // Disparar callback
                    OnGroupSelfJoin?.Invoke(this, groupNumber, null);

                    return groupNumber;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error uniéndose a grupo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// tox_group_send_message - Enviar mensaje al grupo
        /// </summary>
        public int GroupSendMessage(int groupNumber, ToxMessageType type, string message)
        {
            if (string.IsNullOrEmpty(message))
            {
                Logger.Log.Error($"[{LOG_TAG}] Mensaje de grupo vacío");
                return -1;
            }

            try
            {
                lock (_groupsLock)
                {
                    if (!_groups.TryGetValue(groupNumber, out var group))
                    {
                        Logger.Log.Error($"[{LOG_TAG}] Grupo no encontrado: #{groupNumber}");
                        return -1;
                    }

                    if (message.Length > Constants.TOX_MAX_MESSAGE_LENGTH)
                    {
                        Logger.Log.Error($"[{LOG_TAG}] Mensaje de grupo demasiado largo");
                        return -1;
                    }

                    // En implementación real, esto enviaría el mensaje a todos los peers
                    Logger.Log.InfoF($"[{LOG_TAG}] Mensaje enviado al grupo #{groupNumber}: '{message}'");

                    // Simular recepción por otros peers
                    SimulateMessageReceipt(groupNumber, message, type);

                    return message.Length;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando mensaje de grupo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// tox_group_set_topic - Establecer tema del grupo
        /// </summary>
        public bool GroupSetTopic(int groupNumber, string topic)
        {
            if (string.IsNullOrEmpty(topic))
            {
                Logger.Log.Error($"[{LOG_TAG}] Tema de grupo inválido");
                return false;
            }

            try
            {
                lock (_groupsLock)
                {
                    if (!_groups.TryGetValue(groupNumber, out var group))
                    {
                        Logger.Log.Error($"[{LOG_TAG}] Grupo no encontrado: #{groupNumber}");
                        return false;
                    }

                    group.Topic = topic;
                    Logger.Log.InfoF($"[{LOG_TAG}] Tema establecido en grupo #{groupNumber}: '{topic}'");

                    // Disparar callback de cambio de tema
                    OnGroupTopic?.Invoke(this, groupNumber, 0, topic, null);

                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error estableciendo tema de grupo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// tox_group_get_topic - Obtener tema del grupo
        /// </summary>
        public string GroupGetTopic(int groupNumber)
        {
            lock (_groupsLock)
            {
                return _groups.TryGetValue(groupNumber, out var group) ? group.Topic : string.Empty;
            }
        }

        /// <summary>
        /// tox_group_get_name - Obtener nombre del grupo
        /// </summary>
        public string GroupGetName(int groupNumber)
        {
            lock (_groupsLock)
            {
                return _groups.TryGetValue(groupNumber, out var group) ? group.Name : string.Empty;
            }
        }

        /// <summary>
        /// tox_group_get_peer_name - Obtener nombre de peer en grupo
        /// </summary>
        public string GroupGetPeerName(int groupNumber, int peerNumber)
        {
            lock (_groupsLock)
            {
                if (!_groups.TryGetValue(groupNumber, out var group))
                    return string.Empty;

                var peer = group.GetPeer(peerNumber);
                return peer?.Name ?? string.Empty;
            }
        }

        /// <summary>
        /// tox_group_get_peer_count - Obtener número de peers en grupo
        /// </summary>
        public int GroupGetPeerCount(int groupNumber)
        {
            lock (_groupsLock)
            {
                return _groups.TryGetValue(groupNumber, out var group) ? group.PeerCount : 0;
            }
        }

        /// <summary>
        /// tox_group_get_number_groups - Obtener número de grupos
        /// </summary>
        public int GroupGetNumberGroups()
        {
            lock (_groupsLock)
            {
                return _groups.Count;
            }
        }

        /// <summary>
        /// tox_group_get_list - Obtener lista de números de grupo
        /// </summary>
        public int[] GroupGetList()
        {
            lock (_groupsLock)
            {
                return _groups.Keys.ToArray();
            }
        }

        /// <summary>
        /// tox_group_invite_friend - Invitar amigo a grupo
        /// </summary>
        public bool GroupInviteFriend(int groupNumber, int friendNumber)
        {
            try
            {
                lock (_groupsLock)
                {
                    if (!_groups.TryGetValue(groupNumber, out var group))
                    {
                        Logger.Log.Error($"[{LOG_TAG}] Grupo no encontrado: #{groupNumber}");
                        return false;
                    }

                    // Simular invitación
                    byte[] inviteData = Encoding.UTF8.GetBytes(group.Name);

                    Logger.Log.InfoF($"[{LOG_TAG}] Amigo {friendNumber} invitado al grupo #{groupNumber}");

                    // En implementación real, esto enviaría la invitación al amigo
                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error invitando amigo a grupo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// tox_group_leave - Abandonar grupo
        /// </summary>
        public bool GroupLeave(int groupNumber, string partMessage = "")
        {
            try
            {
                lock (_groupsLock)
                {
                    if (!_groups.Remove(groupNumber))
                    {
                        Logger.Log.Error($"[{LOG_TAG}] Grupo no encontrado: #{groupNumber}");
                        return false;
                    }

                    Logger.Log.InfoF($"[{LOG_TAG}] Abandonado grupo #{groupNumber}: '{partMessage}'");

                    // Disparar callback de salida
                    OnGroupPeerExit?.Invoke(this, groupNumber, 0, ToxGroupExitType.TOX_GROUP_EXIT_QUIT, partMessage, null);

                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error abandonando grupo: {ex.Message}");
                return false;
            }
        }

        // ==================== MÉTODOS DE SIMULACIÓN/TEST ====================

        /// <summary>
        /// Simular invitación a grupo (para pruebas)
        /// </summary>
        public void SimulateGroupInvite(int friendNumber, string groupName)
        {
            byte[] inviteData = Encoding.UTF8.GetBytes(groupName);
            OnGroupInvite?.Invoke(this, friendNumber, inviteData, groupName, null);
        }

        /// <summary>
        /// Simular unirse a grupo (para pruebas)
        /// </summary>
        public int SimulateGroupJoin(string groupName)
        {
            byte[] inviteData = Encoding.UTF8.GetBytes(groupName);
            return GroupJoin(inviteData);
        }

        /// <summary>
        /// Simular peer uniéndose a grupo (para pruebas)
        /// </summary>
        public void SimulatePeerJoin(int groupNumber, string peerName)
        {
            lock (_groupsLock)
            {
                if (_groups.TryGetValue(groupNumber, out var group))
                {
                    int peerNumber = group.PeerCount;
                    var peer = new GroupPeer(peerNumber, peerName, new byte[32]);
                    group.AddPeer(peer);

                    OnGroupPeerJoin?.Invoke(this, groupNumber, peerNumber, null);
                    OnGroupPeerListUpdate?.Invoke(this, groupNumber, null);
                }
            }
        }

        /// <summary>
        /// Simular peer abandonando grupo (para pruebas)
        /// </summary>
        public void SimulatePeerExit(int groupNumber, int peerNumber, ToxGroupExitType exitType, string exitMessage)
        {
            lock (_groupsLock)
            {
                if (_groups.TryGetValue(groupNumber, out var group))
                {
                    group.RemovePeer(peerNumber);
                    OnGroupPeerExit?.Invoke(this, groupNumber, peerNumber, exitType, exitMessage, null);
                    OnGroupPeerListUpdate?.Invoke(this, groupNumber, null);
                }
            }
        }

        // ==================== MÉTODOS PRIVADOS ====================

        private void SimulateMessageReceipt(int groupNumber, string message, ToxMessageType type)
        {
            // Simular que otros peers reciben el mensaje
            lock (_groupsLock)
            {
                if (_groups.TryGetValue(groupNumber, out var group))
                {
                    // En implementación real, esto enviaría a todos los peers
                    // Por ahora, solo disparamos el callback para simular recepción
                    OnGroupMessage?.Invoke(this, groupNumber, 1, type, $"(Eco) {message}", null);
                }
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }

    // ==================== CLASES DE DATOS DE GRUPO ====================

    /// <summary>
    /// Representa un grupo de chat
    /// </summary>
    public class ToxGroup
    {
        public int GroupNumber { get; }
        public string Name { get; set; }
        public string Topic { get; set; }
        public List<GroupPeer> Peers { get; }
        public int PeerCount => Peers.Count;
        public DateTime CreatedAt { get; }

        public ToxGroup(int groupNumber, string name)
        {
            GroupNumber = groupNumber;
            Name = name;
            Topic = string.Empty;
            Peers = new List<GroupPeer>();
            CreatedAt = DateTime.UtcNow;
        }

        public void AddPeer(GroupPeer peer)
        {
            Peers.Add(peer);
        }

        public void RemovePeer(int peerNumber)
        {
            Peers.RemoveAll(p => p.PeerNumber == peerNumber);
        }

        public GroupPeer GetPeer(int peerNumber)
        {
            return Peers.FirstOrDefault(p => p.PeerNumber == peerNumber);
        }

        public override string ToString()
        {
            return $"{Name} (#{GroupNumber}) - {PeerCount} miembros - Tema: {Topic}";
        }
    }

    /// <summary>
    /// Representa un peer en un grupo
    /// </summary>
    public class GroupPeer
    {
        public int PeerNumber { get; }
        public string Name { get; set; }
        public byte[] PublicKey { get; }
        public DateTime JoinedAt { get; }

        public GroupPeer(int peerNumber, string name, byte[] publicKey)
        {
            PeerNumber = peerNumber;
            Name = name;
            PublicKey = publicKey;
            JoinedAt = DateTime.UtcNow;
        }

        public override string ToString()
        {
            return $"{Name} (#{PeerNumber})";
        }
    }

    /// <summary>
    /// Tipos de salida de grupo
    /// </summary>
    public enum ToxGroupExitType
    {
        TOX_GROUP_EXIT_QUIT = 0,      // Salida voluntaria
        TOX_GROUP_EXIT_TIMEOUT = 1,   // Timeout de conexión
        TOX_GROUP_EXIT_DISCONNECT = 2,// Desconexión
        TOX_GROUP_EXIT_KICK = 3       // Expulsado
    }

    /// <summary>
    /// Constantes para grupos
    /// </summary>
    public static class Constants
    {
        public const int TOX_MAX_MESSAGE_LENGTH = 1372;
        public const int TOX_MAX_NAME_LENGTH = 128;
        public const int TOX_GROUP_MAX_PEERS = 500;
    }
}
