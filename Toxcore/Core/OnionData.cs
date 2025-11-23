using System;
using System.Text;
using ToxCore.Core;

namespace ToxCore.Core
{
    public class OnionData
    {
        private const string LOG_TAG = "ONION_DATA";
        private readonly Onion _onion;

        public OnionData(Onion onion)
        {
            _onion = onion ?? throw new ArgumentNullException(nameof(onion));
        }

        public bool SendData(byte[] data, byte[] friendPublicKey)
        {
            if (data == null || friendPublicKey == null) return false;

            try
            {
                var path = _onion.SelectOptimalOnionPath();
                if (path == null) return false;

                byte[] packet = _onion.CreateOnionPacket(data, data.Length, friendPublicKey, path);
                if (packet == null) return false;

                int sent = Network.socket_send(_onion.Socket, packet, packet.Length, path.Nodes[0].IPPort);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en SendData: {ex.Message}");
                return false;
            }
        }

        public int HandleDataPacket(byte[] decrypted, int length, IPPort source, byte[] senderTempPublicKey)
        {
            if (length < 1) return -1;

            byte type = decrypted[0];
            switch (type)
            {
                case 0x20: // Mensaje de amigo
                    return HandleFriendMessage(decrypted, length, senderTempPublicKey);
                case 0x30: // Handshake
                    return HandleFriendHandshake(decrypted, length, senderTempPublicKey);
                default:
                    Logger.Log.DebugF($"[{LOG_TAG}] Tipo onion_data desconocido: 0x{type:X2}");
                    return -1;
            }
        }

        private int HandleFriendMessage(byte[] data, int length, byte[] senderTempPublicKey)
        {
            if (length < 5) return -1;
            int friendNumber = BitConverter.ToInt32(data, 1);
            byte[] msg = new byte[length - 5];
            Buffer.BlockCopy(data, 5, msg, 0, msg.Length);

            // ✅ Llamada correcta al Messenger a través de Onion
            _onion.Messenger?.TriggerOnionFriendMessage(friendNumber, msg);
            return 0;
        }

        private int HandleFriendHandshake(byte[] data, int length, byte[] senderTempPublicKey)
        {
            // Placeholder para handshake futuro
            return 0;
        }
    }
}