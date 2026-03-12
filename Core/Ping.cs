// Core/Ping.cs - Implementación completa con PingArray expuesto
using System;
using System.Net;
using System.Runtime.CompilerServices;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación del sistema de ping DHT (ping.c).
    /// Mantiene lista de nodos a pinguear y gestiona PingArray.
    /// </summary>
    public sealed class Ping : IPing, IDisposable
    {
        private const int PingNumMax = 512;
        private const int MaxToPing = 32;
        private const int TimeToPing = 2; // segundos
        private const int PingTimeout = 5; // segundos (de ping_array.h)

        // Tamaños de paquetes
        private const int PingPlainSize = 1 + sizeof(ulong); // 1 byte tipo + 8 bytes ping_id
        private const int DhtPingSize = 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE + PingPlainSize + LibSodium.CRYPTO_MAC_SIZE;
        private const int PingDataSize = LibSodium.CRYPTO_PUBLIC_KEY_SIZE + 8; // IP_Port serializado = 8 bytes típicamente

        private readonly MonoTime _monoTime;
        private readonly INetworkCore _network;
        private readonly ISharedKeyCache _sharedKeysSent;
        private readonly ISharedKeyCache _sharedKeysRecv;
        private IDht _dht;

        // PingArray interno - ahora expuesto a través de métodos
        private readonly PingArray _pingArray;

        // Lista de nodos pendientes de ping (to_ping)
        private readonly NodeFormat[] _toPing = new NodeFormat[MaxToPing];
        private ulong _lastToPing;

        public Ping(
        MonoTime monoTime,
        INetworkCore network,
        ISharedKeyCache sharedKeysSent,
        ISharedKeyCache sharedKeysRecv,
        IDht? dht = null)  // <-- Hacer opcional
        {
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _sharedKeysSent = sharedKeysSent ?? throw new ArgumentNullException(nameof(sharedKeysSent));
            _sharedKeysRecv = sharedKeysRecv ?? throw new ArgumentNullException(nameof(sharedKeysRecv));
            _dht = dht;  // Puede ser null inicialmente

            // Inicializar PingArray con tamaño y timeout
            _pingArray = new PingArray(monoTime, (uint)PingNumMax, (uint)PingTimeout);

            // Registrar handlers de red
            _network.RegisterHandler((byte)NetPacketType.PingRequest, HandlePingRequest, this);
            _network.RegisterHandler((byte)NetPacketType.PingResponse, HandlePingResponse, this);
        }

        public void Dispose()
        {
            _network.UnregisterHandler((byte)NetPacketType.PingRequest);
            _network.UnregisterHandler((byte)NetPacketType.PingResponse);
            _pingArray?.Dispose();
        }

        #region IPing Implementation

        public int Add(byte[] publicKey, IPEndPoint ipPort)
        {
            if (_dht == null) return -1;

            if (ipPort == null || publicKey == null) return -1;
            if (PkEqual(publicKey, _dht.SelfPublicKey.ToArray())) return -1;

            // Verificar si ya está en la lista close (simplificado)
            if (!_dht.IsNodeAddableToCloseList(publicKey, ipPort)) return -1;

            // Verificar si ya está en to_ping
            for (int i = 0; i < MaxToPing; i++)
            {
                if (_toPing[i].PublicKey != null && PkEqual(_toPing[i].PublicKey, publicKey))
                    return -1;
            }

            // Buscar slot vacío
            for (int i = 0; i < MaxToPing; i++)
            {
                if (_toPing[i].PublicKey == null || IpIsUnspecified(_toPing[i].IpPort))
                {
                    _toPing[i].PublicKey = (byte[])publicKey.Clone();
                    _toPing[i].IpPort = ipPort;
                    return 0;
                }
            }

            // Lista llena, reemplazar usando add_to_list (por distancia XOR)
            if (_dht.AddToList(_toPing, (uint)MaxToPing, publicKey, ipPort, _dht.SelfPublicKey.ToArray()))
            {
                return 0;
            }

            return -1;
        }

        /// <summary>
        /// Establece el DHT después de la creación (para romper dependencia circular).
        /// </summary>
        public void SetDht(IDht dht)
        {
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
        }

        public void Iterate()
        {
            if (!_monoTime.IsTimeout(_lastToPing, (uint)TimeToPing))
                return;

            bool sentAny = false;

            for (int i = 0; i < MaxToPing; i++)
            {
                if (_toPing[i].PublicKey == null || IpIsUnspecified(_toPing[i].IpPort))
                    continue;

                if (!_dht.IsNodeAddableToCloseList(_toPing[i].PublicKey, _toPing[i].IpPort))
                {
                    continue;
                }

                SendRequest(_toPing[i].IpPort, _toPing[i].PublicKey);

                // Resetear entrada
                _toPing[i].PublicKey = null;
                _toPing[i].IpPort = null;
                sentAny = true;
            }

            if (sentAny)
            {
                _lastToPing = _monoTime.GetSeconds();
            }
        }

        public void SendRequest(IPEndPoint ipPort, byte[] publicKey)
        {
            if (PkEqual(publicKey, _dht.SelfPublicKey.ToArray())) return;

            var sharedKey = _sharedKeysSent.Lookup(publicKey);
            if (sharedKey == null) return;

            // Generar ping_id usando PingArray
            byte[] data = new byte[PingDataSize];
            Buffer.BlockCopy(publicKey, 0, data, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            // Serializar IP_Port (simplificado)
            byte[] ipPortBytes = IpPortToBytes(ipPort);
            Buffer.BlockCopy(ipPortBytes, 0, data, LibSodium.CRYPTO_PUBLIC_KEY_SIZE, Math.Min(ipPortBytes.Length, 8));

            ulong pingId = _pingArray.Add(data);
            if (pingId == 0) return;

            // Construir paquete
            byte[] packet = new byte[DhtPingSize];
            packet[0] = (byte)NetPacketType.PingRequest;

            // Copiar nuestra public key
            var selfPk = _dht.SelfPublicKey.ToArray();
            Buffer.BlockCopy(selfPk, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            // Nonce aleatorio
            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            // Datos a cifrar: [1 byte tipo][8 bytes ping_id]
            byte[] plain = new byte[PingPlainSize];
            plain[0] = (byte)NetPacketType.PingRequest;
            Buffer.BlockCopy(BitConverter.GetBytes(pingId), 0, plain, 1, sizeof(ulong));

            // Cifrar
            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            // Enviar
            _network.SendPacket(ipPort, packet, packet.Length);
        }

        /// <summary>
        /// Agrega datos al PingArray y retorna ping_id.
        /// </summary>
        public ulong AddToPingArray(byte[] data)
        {
            return _pingArray.Add(data);
        }

        /// <summary>
        /// Verifica ping_id en PingArray y recupera datos.
        /// </summary>
        public int CheckPingArray(ulong pingId, byte[] data)
        {
            return _pingArray.Check(pingId, data);
        }

        #endregion

        #region Private Methods

        private void SendResponse(IPEndPoint ipPort, byte[] publicKey, ulong pingId, byte[] sharedKey)
        {
            if (PkEqual(publicKey, _dht.SelfPublicKey.ToArray())) return;

            byte[] packet = new byte[DhtPingSize];
            packet[0] = (byte)NetPacketType.PingResponse;

            var selfPk = _dht.SelfPublicKey.ToArray();
            Buffer.BlockCopy(selfPk, 0, packet, 1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);

            var nonce = LibSodium.GenerateNonce();
            Buffer.BlockCopy(nonce, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);

            byte[] plain = new byte[PingPlainSize];
            plain[0] = (byte)NetPacketType.PingResponse;
            Buffer.BlockCopy(BitConverter.GetBytes(pingId), 0, plain, 1, sizeof(ulong));

            byte[] cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, nonce, sharedKey))
                return;

            Buffer.BlockCopy(cipher, 0, packet, 1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

            _network.SendPacket(ipPort, packet, packet.Length);
        }

        private static void HandlePingRequest(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var ping = (Ping)state;
            if (packet.Length != DhtPingSize) return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, ping._dht.SelfPublicKey.ToArray())) return;

            var sharedKey = ping._sharedKeysRecv.Lookup(senderPk);
            if (sharedKey == null) return;

            // Descifrar
            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[PingPlainSize];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            if (plain[0] != (byte)NetPacketType.PingRequest) return;

            ulong pingId = BitConverter.ToUInt64(plain, 1);

            // Enviar respuesta
            ping.SendResponse(source, senderPk, pingId, sharedKey);
            ping.Add(senderPk, source);
        }

        private static void HandlePingResponse(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var ping = (Ping)state;
            if (packet.Length != DhtPingSize) return;

            var senderPk = packet.Slice(1, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
            if (PkEqual(senderPk, ping._dht.SelfPublicKey.ToArray())) return;

            var sharedKey = ping._sharedKeysSent.Lookup(senderPk);
            if (sharedKey == null) return;

            var nonce = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
            var cipher = packet.Slice(1 + LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE).ToArray();

            byte[] plain = new byte[PingPlainSize];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, nonce, sharedKey))
                return;

            if (plain[0] != (byte)NetPacketType.PingResponse) return;

            ulong pingId = BitConverter.ToUInt64(plain, 1);

            // Verificar en PingArray usando el nuevo método expuesto
            byte[] data = new byte[PingDataSize];
            if (ping.CheckPingArray(pingId, data) != PingDataSize)
                return;

            // Verificar que el public key coincide
            if (!PkEqual(senderPk, data.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray()))
                return;

            // Agregar a listas DHT
            ping._dht.AddToLists(source, senderPk);
        }

        // Helpers
        private static bool PkEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            return a.AsSpan().SequenceEqual(b);
        }

        private static bool IpIsUnspecified(IPEndPoint ep)
        {
            return ep == null || ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.IPv6Any);
        }

        private byte[] IpPortToBytes(IPEndPoint ipPort)
        {
            // Simplificación: serialización básica
            var bytes = new byte[8];
            var addrBytes = ipPort.Address.GetAddressBytes();
            Buffer.BlockCopy(addrBytes, 0, bytes, 0, Math.Min(addrBytes.Length, 4));
            bytes[4] = (byte)(ipPort.Port >> 8);
            bytes[5] = (byte)(ipPort.Port & 0xFF);
            return bytes;
        }

        #endregion
    }
}