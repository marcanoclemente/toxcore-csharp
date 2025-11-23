using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ToxCore.Core;
using static ToxCore.Core.ToxState;

namespace ToxCore.Core
{
    #region ---- API pública (callbacks idénticos a tox.h) ----
    public delegate void GroupInviteCallback(GroupManager mgr, int friendNumber, byte[] inviteData, string groupName, object userData);
    public delegate void GroupMessageCallback(GroupManager mgr, int groupNumber, int peerNumber, ToxMessageType type, string message, object userData);
    public delegate void GroupPeerJoinCallback(GroupManager mgr, int groupNumber, int peerNumber, object userData);
    public delegate void GroupPeerExitCallback(GroupManager mgr, int groupNumber, int peerNumber, ToxGroupExitType exitType, string name, object userData);
    public delegate void GroupSelfJoinCallback(GroupManager mgr, int groupNumber, object userData);
    public delegate void GroupTopicCallback(GroupManager mgr, int groupNumber, int peerNumber, string topic, object userData);
    public delegate void GroupPeerListUpdateCallback(GroupManager mgr, int groupNumber, object userData);
    #endregion

    public class GroupManager : IDisposable
    {
        private const string LOG_TAG = "GROUP";
        private readonly Messenger _messenger;
        private readonly Dictionary<int, ToxGroup> _groups = new();
        private readonly object _groupsLock = new();
        private int _lastGroupNumber = 0;
        private bool _isRunning = false;

        #region ---- Eventos públicos ----
        public event GroupInviteCallback OnGroupInvite;
        public event GroupMessageCallback OnGroupMessage;
        public event GroupPeerJoinCallback OnGroupPeerJoin;
        public event GroupPeerExitCallback OnGroupPeerExit;
        public event GroupSelfJoinCallback OnGroupSelfJoin;
        public event GroupTopicCallback OnGroupTopic;
        public event GroupPeerListUpdateCallback OnGroupPeerListUpdate;
        #endregion

        public GroupManager(Messenger messenger)
        {
            _messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));
        }

        #region ---- API pública (igual que toxgroup.h) ----
        public int GroupNew(string name = "New Group")
        {
            lock (_groupsLock)
            {
                int g = _lastGroupNumber++;
                var group = new ToxGroup(g, name, _messenger.State.User.PublicKey, _messenger);
                _groups[g] = group;

                group.OnGroupPacket += (pkt, senderPk) => HandleGroupPacket(g, pkt, senderPk);
                Logger.Log.InfoF($"[{LOG_TAG}] Grupo creado: {name} (#{g})");
                OnGroupSelfJoin?.Invoke(this, g, null);
                return g;
            }
        }

        public int GroupJoin(byte[] inviteData)
        {
            if (inviteData == null || inviteData.Length < 97) return -1;
            lock (_groupsLock)
            {
                int g = _lastGroupNumber++;
                var group = new ToxGroup(g, "Recibido", _messenger.State.User.PublicKey, _messenger);
                group.HandleInvite(inviteData);
                _groups[g] = group;
                group.OnGroupPacket += (pkt, senderPk) => HandleGroupPacket(g, pkt, senderPk);
                Logger.Log.InfoF($"[{LOG_TAG}] Unido a grupo #{g}");
                OnGroupSelfJoin?.Invoke(this, g, null);
                return g;
            }
        }

        public bool GroupLeave(int groupNumber, string partMessage = "")
        {
            lock (_groupsLock)
            {
                if (!_groups.TryGetValue(groupNumber, out var g)) return false;
                g.BroadcastExit(partMessage);
                _groups.Remove(groupNumber);
                Logger.Log.InfoF($"[{LOG_TAG}] Abandonado grupo #{groupNumber}");
                return true;
            }
        }

        public bool GroupSendMessage(int groupNumber, ToxMessageType type, string message)
        {
            lock (_groupsLock)
            {
                return _groups.TryGetValue(groupNumber, out var g) && g.SendMessage(type, message);
            }
        }

        public bool GroupSetTopic(int groupNumber, string topic)
        {
            lock (_groupsLock)
            {
                return _groups.TryGetValue(groupNumber, out var g) && g.SetTopic(topic);
            }
        }

        public string GroupGetTopic(int groupNumber)
        {
            lock (_groupsLock) return _groups.TryGetValue(groupNumber, out var g) ? g.Topic : "";
        }

        public string GroupGetName(int groupNumber)
        {
            lock (_groupsLock) return _groups.TryGetValue(groupNumber, out var g) ? g.Name : "";
        }

        public int GroupGetPeerCount(int groupNumber)
        {
            lock (_groupsLock) return _groups.TryGetValue(groupNumber, out var g) ? g.PeerCount : 0;
        }

        public int[] GroupGetList()
        {
            lock (_groupsLock) return _groups.Keys.ToArray();
        }

        public bool GroupInviteFriend(int groupNumber, int friendNumber)
        {
            lock (_groupsLock)
            {
                if (!_groups.TryGetValue(groupNumber, out var g)) return false;
                var invite = g.CreateInvite();
                var friend = _messenger.State.Friends.Friends.FirstOrDefault(f => f.FriendNumber == friendNumber);
                if (friend == null) return false;
                int sent = _messenger.Onion.onion_send_1(invite, invite.Length, friend.PublicKey);
                return sent > 0;
            }
        }
        #endregion

        #region ---- Manejo de paquetes entrantes ----
        public int HandleGroupPacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 5) return -1;
            byte type = packet[0];
            int groupNumber = BitConverter.ToInt32(packet, 1);

            lock (_groupsLock)
            {
                if (!_groups.TryGetValue(groupNumber, out var group)) return -1;
                var friend = _messenger.State.Friends.Friends.FirstOrDefault(f => f.FriendNumber == friendNumber);
                if (friend == null) return -1;
                group.HandleMessage(packet, length, friend.PublicKey);
                return 0;
            }
        }

        private void HandleGroupPacket(int groupNumber, byte[] packet, byte[] senderPk)
        {
            // usado internamente por onion
            lock (_groupsLock)
            {
                if (_groups.TryGetValue(groupNumber, out var g))
                    g.HandleMessage(packet, packet.Length, senderPk);
            }
        }
        #endregion

        #region ---- Persistencia ----
        public void SaveRuntimeState(ToxRuntimeState runtime)
        {
            lock (_groupsLock)
            {
                runtime.ActiveGroups = _groups.Values.Select(g => new ToxGroupState
                {
                    GroupNumber = g.GroupNumber,
                    Name = g.Name,
                    Topic = g.Topic,
                    Peers = g.Peers.Select(p => new ToxGroupPeerState
                    {
                        PeerNumber = p.PeerNumber,
                        Name = p.Name,
                        PublicKey = p.PublicKey
                    }).ToList()
                }).ToList();
            }
        }

        public bool Start()
        {
            _isRunning = true;
            Logger.Log.Info($"[{LOG_TAG}] GroupManager iniciado");
            return true;
        }

        public void Stop()
        {
            _isRunning = false;
            Logger.Log.Info($"[{LOG_TAG}] GroupManager detenido");
        }

        public void LoadRuntimeState(ToxRuntimeState runtime)
        {
            lock (_groupsLock)
            {
                foreach (var gs in runtime.ActiveGroups ?? new())
                {
                    var g = new ToxGroup(gs.GroupNumber, gs.Name, gs.Peers.First().PublicKey, _messenger) { Topic = gs.Topic };
                    _groups[gs.GroupNumber] = g;
                    g.OnGroupPacket += (pkt, senderPk) => HandleGroupPacket(gs.GroupNumber, pkt, senderPk);
                }
            }
        }
        #endregion

        #region ---- Tests ----
        public static bool Test()
        {
            Console.WriteLine("🔬 Testing GroupManager...");
            var messenger = new Messenger();
            var gm = new GroupManager(messenger);

            int g = gm.GroupNew("TestGroup");
            if (g < 0) { Console.WriteLine("❌ GroupNew falló"); return false; }

            bool ok = gm.GroupSetTopic(g, "Nuevo topic");
            if (!ok) { Console.WriteLine("❌ GroupSetTopic falló"); return false; }

            Console.WriteLine("✅ GroupManager tests pasados");
            return true;
        }
        #endregion

        public void Dispose()
        {
            lock (_groupsLock) _groups.Clear();
        }
    }

    #region ---- Modelos internos ----
    public class ToxGroup
    {
        public int GroupNumber { get; }
        public string Name { get; set; }
        public string Topic { get; set; }
        public List<GroupPeer> Peers { get; } = new();
        public int PeerCount => Peers.Count;

        public delegate void GroupPacketHandler(byte[] packet, byte[] senderPk);
        public event GroupPacketHandler OnGroupPacket;

        private readonly byte[] _selfPk;
        private readonly Messenger _messenger;

        public Action<int, int, ToxMessageType, string, byte[]> OnGroupMessageReceived;
        public Action<int, int, string, byte[]> OnGroupTopicChanged;
        public Action<int, int, byte[]> OnGroupPeerJoined;
        public Action<int, int, ToxGroupExitType, string, byte[]> OnGroupPeerLeft;

        public ToxGroup(int groupNumber, string name, byte[] selfPk, Messenger messenger)
        {
            GroupNumber = groupNumber;
            Name = name;
            Topic = "";
            _selfPk = selfPk;
            _messenger = messenger;
            Peers.Add(new GroupPeer(0, "Self", selfPk));
        }

        public byte[] CreateInvite()
        {
            byte[] invite = new byte[97];
            invite[0] = 0x60; // GROUP_INVITE
            Buffer.BlockCopy(_selfPk, 0, invite, 1, 32);
            Buffer.BlockCopy(BitConverter.GetBytes(GroupNumber), 0, invite, 33, 4);
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(Name.PadRight(32)), 0, invite, 65, 32);
            return invite;
        }

        public void HandleInvite(byte[] data)
        {
            if (data.Length < 97 || data[0] != 0x60) return;
            Buffer.BlockCopy(data, 65, new byte[32], 0, 32);
            Name = Encoding.UTF8.GetString(data, 65, 32).TrimEnd('\0');
        }

        public bool SendMessage(ToxMessageType type, string message)
        {
            if (string.IsNullOrWhiteSpace(message)) return false;
            byte[] payload = Encoding.UTF8.GetBytes(message);
            byte[] packet = new byte[6 + payload.Length];
            packet[0] = 0x62; // GROUP_MESSAGE
            Buffer.BlockCopy(BitConverter.GetBytes(GroupNumber), 0, packet, 1, 4);
            packet[5] = (byte)type;
            Buffer.BlockCopy(payload, 0, packet, 6, payload.Length);
            BroadcastPacket(packet);
            return true;
        }

        public bool SetTopic(string topic)
        {
            if (string.IsNullOrWhiteSpace(topic)) return false;
            Topic = topic;
            byte[] payload = Encoding.UTF8.GetBytes(topic);
            byte[] packet = new byte[5 + payload.Length];
            packet[0] = 0x63; // GROUP_TOPIC
            Buffer.BlockCopy(BitConverter.GetBytes(GroupNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);
            BroadcastPacket(packet);
            return true;
        }

        public void BroadcastPacket(byte[] packet)
        {
            foreach (var peer in Peers.Where(p => !ByteArraysEqual(p.PublicKey, _selfPk)))
                _messenger.Onion.onion_send_1(packet, packet.Length, peer.PublicKey);
        }

        public void HandleMessage(byte[] data, int length, byte[] senderPk)
        {
            if (length < 5) return;
            var type = (ToxGroupPacketType)data[0];
            int peerNumber = GetPeerNumber(senderPk);

            switch (type)
            {
                case ToxGroupPacketType.GROUP_MESSAGE:
                    string msg = Encoding.UTF8.GetString(data, 6, length - 6);
                    var msgType = (ToxMessageType)data[5];
                    OnGroupMessageReceived?.Invoke(GroupNumber, peerNumber, msgType, msg, senderPk);
                    break;

                case ToxGroupPacketType.GROUP_TOPIC:
                    Topic = Encoding.UTF8.GetString(data, 5, length - 5);
                    OnGroupTopicChanged?.Invoke(GroupNumber, peerNumber, Topic, senderPk);
                    break;

                case ToxGroupPacketType.GROUP_PEER_JOIN:
                    string name = Encoding.UTF8.GetString(data, 5, length - 5);
                    Peers.Add(new GroupPeer(Peers.Count, name, senderPk));
                    OnGroupPeerJoined?.Invoke(GroupNumber, Peers.Count - 1, senderPk);
                    break;

                case ToxGroupPacketType.GROUP_PEER_EXIT:
                    var peer = Peers.FirstOrDefault(p => ByteArraysEqual(p.PublicKey, senderPk));
                    if (peer != null)
                    {
                        Peers.Remove(peer);
                        OnGroupPeerLeft?.Invoke(GroupNumber, peer.PeerNumber, ToxGroupExitType.QUIT, peer.Name, senderPk);
                    }
                    break;
            }
        }


        public void BroadcastExit(string reason)
        {
            byte[] payload = Encoding.UTF8.GetBytes(reason);
            byte[] packet = new byte[5 + payload.Length];
            packet[0] = 0x64; // GROUP_PEER_EXIT
            Buffer.BlockCopy(BitConverter.GetBytes(GroupNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);
            BroadcastPacket(packet);
        }

        private int GetPeerNumber(byte[] publicKey) => Peers.FindIndex(p => ByteArraysEqual(p.PublicKey, publicKey));

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }

    public class GroupPeer
    {
        public int PeerNumber { get; }
        public string Name { get; set; }
        public byte[] PublicKey { get; }
        public GroupPeer(int peerNumber, string name, byte[] publicKey)
        {
            PeerNumber = peerNumber;
            Name = name;
            PublicKey = publicKey ?? new byte[32];
        }
    }

    public enum ToxGroupExitType { QUIT, TIMEOUT, KICK, DISCONNECT }

    public enum ToxGroupPacketType : byte
    {
        GROUP_INVITE = 0x60,
        GROUP_PEER_JOIN = 0x61,
        GROUP_MESSAGE = 0x62,
        GROUP_TOPIC = 0x63,
        GROUP_PEER_EXIT = 0x64
    }

    public class ToxGroupState
    {
        public int GroupNumber { get; set; }
        public string Name { get; set; }
        public string Topic { get; set; }
        public List<ToxGroupPeerState> Peers { get; set; } = new();
    }

    public class ToxGroupPeerState
    {
        public int PeerNumber { get; set; }
        public string Name { get; set; }
        public byte[] PublicKey { get; set; }
    }
    #endregion
}