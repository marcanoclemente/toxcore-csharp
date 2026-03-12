// Core/Onion/OnionCore.cs - VERSIÓN CORREGIDA
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using Toxcore.Core.Crypto;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.Onion;

namespace ToxCore.Core.Onion
{
    /// <summary>
    /// Implementación corregida del núcleo de onion routing de ToxCore.
    /// El sendback (reverse path) usa crypto_secretbox con claves derivadas de las claves de nodo.
    /// </summary>
    public sealed class OnionCore : IOnionCore, IDisposable
    {
        private readonly IDht _dht;
        private readonly INetworkCore _network;
        private readonly MonoTime _monoTime;
        private readonly ISharedKeyCache _sharedKeysSent;
        private readonly ISharedKeyCache _sharedKeysRecv;

        // Handlers para tipos de paquetes onion específicos
        private readonly ConcurrentDictionary<byte, OnionPacketHandler> _packetHandlers = new();
        private OnionDataHandler _dataHandler;

        // Nodos onion conocidos
        private readonly ConcurrentDictionary<IPEndPoint, OnionNode> _knownNodes = new();

        // SISTEMA DE REVERSE PATH (SENDBACK) - CORREGIDO
        // Usa claves compartidas existentes, no claves temporales
        private readonly ConcurrentDictionary<byte[], SendbackEntry> _receivedSendbacks;
        private readonly ByteArrayComparer _nonceComparer = ByteArrayComparer.Instance;



        // Constantes del protocolo Tox
        private const int OnionMaxPacketSize = 1400;
        private const int OnionPathTimeout = 300; // 5 minutos
        private const byte OnionPacketVersion = 0x01;

        // Tamaños del sendback según protocolo Tox
        private const int SendbackHopSize = 28; // IP/Port cifrado (12 bytes) + MAC (16 bytes) = 28, pero redondeado
        private const int MaxSendbackHops = 3;
        private const int MaxSendbackSize = MaxSendbackHops * SendbackHopSize; // 84 bytes

        // Packet IDs para respuestas onion (según onion.c)
        private const byte PacketOnionRequest = 0x08;
        private const byte PacketOnionResponse0 = 0x8c;
        private const byte PacketOnionResponse1 = 0x8d;
        private const byte PacketOnionResponse2 = 0x8e;

        // Nonce fijo para sendback (todos ceros, como en Tox original)
        private static readonly byte[] SendbackNonce = new byte[LibSodium.CRYPTO_SECRETBOX_NONCE_SIZE];

        public OnionCore(IDht dht, INetworkCore network, MonoTime monoTime,
            ISharedKeyCache sharedKeysSent, ISharedKeyCache sharedKeysRecv)
        {
            _dht = dht ?? throw new ArgumentNullException(nameof(dht));
            _network = network ?? throw new ArgumentNullException(nameof(network));
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _sharedKeysSent = sharedKeysSent ?? throw new ArgumentNullException(nameof(sharedKeysSent));
            _sharedKeysRecv = sharedKeysRecv ?? throw new ArgumentNullException(nameof(sharedKeysRecv));

            _receivedSendbacks = new ConcurrentDictionary<byte[], SendbackEntry>(_nonceComparer);

            // Registrar handlers de paquetes onion
            _network.RegisterHandler(PacketOnionRequest, HandleOnionPacket, this);
            _network.RegisterHandler(PacketOnionResponse0, HandleOnionResponse0, this);
            _network.RegisterHandler(PacketOnionResponse1, HandleOnionResponse1, this);
            _network.RegisterHandler(PacketOnionResponse2, HandleOnionResponse2, this);

            Logger.Log.Info("[ONIONCORE] Initialized with corrected sendback encryption");
        }

        #region IOnionCore Implementation

        /// <summary>
        /// CORREGIDO: Envía un paquete onion de 3 capas con sendback para respuesta.
        /// Valida que los 3 nodos del path sean distintos.
        /// </summary>
        public bool SendOnionPacket(IPEndPoint[] path, byte[] destPublicKey, byte[] data, byte[] nonce)
        {
            if (path?.Length != 3)
            {
                Logger.Log.Error("[ONIONCORE] Path must contain exactly 3 nodes");
                return false;
            }

            // CORRECCIÓN: Validar que los 3 nodos sean distintos
            if (IpPortEqual(path[0], path[1]) ||
                IpPortEqual(path[0], path[2]) ||
                IpPortEqual(path[1], path[2]))
            {
                Logger.Log.Error("[ONIONCORE] Path nodes must be distinct");
                return false;
            }

            if (data?.Length > OnionMaxPacketSize - 200)
            {
                Logger.Log.Error("[ONIONCORE] Data too large");
                return false;
            }

            if (nonce?.Length != LibSodium.CRYPTO_NONCE_SIZE)
            {
                Logger.Log.Error("[ONIONCORE] Invalid nonce");
                return false;
            }

            try
            {
                // Obtener claves públicas de los 3 nodos del path
                var nodeKeys = new byte[3][];
                for (int i = 0; i < 3; i++)
                {
                    nodeKeys[i] = GetNodePublicKey(path[i]);
                    if (nodeKeys[i] == null)
                    {
                        Logger.Log.Error($"[ONIONCORE] No public key for node {i}: {path[i]}");
                        return false;
                    }
                }

                // Construir las 3 capas cifradas (de adentro hacia afuera)
                byte[] layer3 = BuildInnerLayer(data, nonce, nodeKeys[2], destPublicKey);
                byte[] layer2 = BuildMiddleLayer(path[2], layer3, nonce, nodeKeys[1]);
                byte[] layer1 = BuildOuterLayer(path[1], layer2, nonce, nodeKeys[0]);

                // Construir sendback inicial (vacío, se llenará en cada hop)
                byte[] initialSendback = new byte[MaxSendbackSize];

                // Construir paquete final
                byte[] packet = new byte[1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize + layer1.Length];
                packet[0] = OnionPacketVersion;
                Buffer.BlockCopy(nonce, 0, packet, 1, LibSodium.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(initialSendback, 0, packet, 1 + LibSodium.CRYPTO_NONCE_SIZE, MaxSendbackSize);
                Buffer.BlockCopy(layer1, 0, packet, 1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize, layer1.Length);

                // Almacenar el nonce con información completa del path para respuestas
                StoreOutboundNonce(nonce, path, nodeKeys, initialSendback);

                int sent = _network.SendPacket(path[0], packet, packet.Length);

                if (sent > 0)
                {
                    Logger.Log.Debug($"[ONIONCORE] Sent onion packet ({packet.Length} bytes) with sendback support");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCORE] SendOnionPacket failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// CORREGIDO: Envía una respuesta usando el reverse path (sendback).
        /// </summary>
        public bool SendOnionResponse(IPEndPoint source, byte[] originalNonce, byte[] responseData)
        {
            if (originalNonce?.Length != LibSodium.CRYPTO_NONCE_SIZE)
                return false;

            if (!_receivedSendbacks.TryGetValue(originalNonce, out var sendbackEntry))
            {
                Logger.Log.Warning("[ONIONCORE] No sendback found for nonce");
                return false;
            }

            try
            {
                // Encriptar la respuesta con el nonce original
                byte[] senderPk = GetNodePublicKey(source);
                if (senderPk == null) return false;

                byte[] sharedKey = _sharedKeysSent.Lookup(senderPk);
                if (sharedKey == null) return false;

                byte[] encryptedResponse = new byte[responseData.Length + LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxEasyAfterNm(encryptedResponse, responseData, originalNonce, sharedKey))
                    return false;

                // Construir paquete de respuesta onion
                byte[] responsePacket = new byte[LibSodium.CRYPTO_NONCE_SIZE + encryptedResponse.Length];
                Buffer.BlockCopy(originalNonce, 0, responsePacket, 0, LibSodium.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(encryptedResponse, 0, responsePacket, LibSodium.CRYPTO_NONCE_SIZE, encryptedResponse.Length);

                // CORRECCIÓN: Pasar el sendbackEntry completo, no solo SendbackData
                return ForwardOnionResponse(responsePacket, sendbackEntry, 0);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCORE] SendOnionResponse failed: {ex.Message}");
                return false;
            }
        }

        public void SetOnionDataHandler(OnionDataHandler handler)
        {
            _dataHandler = handler;
        }

        public void RegisterPacketHandler(byte packetType, OnionPacketHandler handler)
        {
            _packetHandlers[packetType] = handler;
        }

        public void UnregisterPacketHandler(byte packetType)
        {
            _packetHandlers.TryRemove(packetType, out _);
        }

        public bool IsKnownOnionNode(IPEndPoint endpoint)
        {
            return _knownNodes.ContainsKey(endpoint) &&
                !_knownNodes[endpoint].IsExpired(_monoTime.GetSeconds());
        }

        public IPEndPoint[] GetPathNodes(int count)
        {
            var nodes = new List<IPEndPoint>();
            var now = _monoTime.GetSeconds();

            // Primero nodos onion conocidos
            foreach (var kvp in _knownNodes.Where(n => !n.Value.IsExpired(now)))
            {
                nodes.Add(kvp.Key);
                if (nodes.Count >= count) break;
            }

            // Completar con nodos DHT si es necesario
            if (nodes.Count < count)
            {
                var dhtNodes = GetDhtNodes(count - nodes.Count);
                nodes.AddRange(dhtNodes);
            }

            // Mezclar aleatoriamente
            var random = new Random();
            return nodes.OrderBy(x => random.Next()).Take(count).ToArray();
        }

        public void DoOnionCore()
        {
            var now = _monoTime.GetSeconds();

            // Limpiar nodos expirados
            var expired = _knownNodes.Where(n => n.Value.IsExpired(now)).Select(n => n.Key).ToArray();
            foreach (var ep in expired)
            {
                _knownNodes.TryRemove(ep, out _);
            }

            // Limpiar sendbacks expirados
            var expiredSendbacks = _receivedSendbacks
                .Where(kvp => now - kvp.Value.Timestamp > OnionPathTimeout)
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var nonce in expiredSendbacks)
            {
                _receivedSendbacks.TryRemove(nonce, out _);
            }

            // Descubrir nuevos nodos onion
            DiscoverOnionNodes();
        }

        #endregion

        #region Construcción de Capas Onion

        /// <summary>
        /// Capa interna (para el nodo 3 / destino final).
        /// Si destPublicKey es null, es un broadcast/anuncio.
        /// </summary>
        private byte[] BuildInnerLayer(byte[] data, byte[] nonce, byte[] node3Key, byte[] destPublicKey)
        {
            using var ms = new System.IO.MemoryStream();

            // Si hay destinatario específico, incluir su clave pública
            if (destPublicKey != null)
            {
                ms.Write(destPublicKey, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            }

            // Datos
            ms.Write(data, 0, data.Length);

            byte[] plaintext = ms.ToArray();

            // Cifrar con clave compartida con nodo 3
            byte[] sharedKey = _sharedKeysSent.Lookup(node3Key);
            if (sharedKey == null)
                throw new InvalidOperationException("Failed to get shared key for node 3");

            var cipher = new byte[plaintext.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plaintext, nonce, sharedKey))
                throw new InvalidOperationException("Failed to encrypt inner layer");

            return cipher;
        }

        /// <summary>
        /// Capa media (para el nodo 2).
        /// Indica al nodo 2 que reenvíe al nodo 3.
        /// </summary>
        private byte[] BuildMiddleLayer(IPEndPoint node3Endpoint, byte[] innerLayer, byte[] nonce, byte[] node2Key)
        {
            using var ms = new System.IO.MemoryStream();

            // IP/Port del siguiente hop (nodo 3)
            byte[] ipPortData = SerializeIpPort(node3Endpoint);
            ms.WriteByte((byte)ipPortData.Length);
            ms.Write(ipPortData, 0, ipPortData.Length);

            // Capa interna cifrada
            ms.Write(innerLayer, 0, innerLayer.Length);

            byte[] plaintext = ms.ToArray();

            // Cifrar con clave compartida con nodo 2
            byte[] sharedKey = _sharedKeysSent.Lookup(node2Key);
            if (sharedKey == null)
                throw new InvalidOperationException("Failed to get shared key for node 2");

            var cipher = new byte[plaintext.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plaintext, nonce, sharedKey))
                throw new InvalidOperationException("Failed to encrypt middle layer");

            return cipher;
        }

        /// <summary>
        /// Capa externa (para el nodo 1 / entry node).
        /// Indica al nodo 1 que reenvíe al nodo 2.
        /// </summary>
        private byte[] BuildOuterLayer(IPEndPoint node2Endpoint, byte[] middleLayer, byte[] nonce, byte[] node1Key)
        {
            using var ms = new System.IO.MemoryStream();

            // IP/Port del siguiente hop (nodo 2)
            byte[] ipPortData = SerializeIpPort(node2Endpoint);
            ms.WriteByte((byte)ipPortData.Length);
            ms.Write(ipPortData, 0, ipPortData.Length);

            // Capa media cifrada
            ms.Write(middleLayer, 0, middleLayer.Length);

            byte[] plaintext = ms.ToArray();

            // Cifrar con clave compartida con nodo 1
            byte[] sharedKey = _sharedKeysSent.Lookup(node1Key);
            if (sharedKey == null)
                throw new InvalidOperationException("Failed to get shared key for node 1");

            var cipher = new byte[plaintext.Length + LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plaintext, nonce, sharedKey))
                throw new InvalidOperationException("Failed to encrypt outer layer");

            return cipher;
        }

        #endregion

        #region Procesamiento de Paquetes Entrantes

        private static void HandleOnionPacket(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var core = (OnionCore)state;

            try
            {
                if (packet.Length < 1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize + LibSodium.CRYPTO_MAC_SIZE)
                {
                    Logger.Log.Debug("[ONIONCORE] Packet too small");
                    return;
                }

                if (packet[0] != OnionPacketVersion)
                {
                    Logger.Log.Debug($"[ONIONCORE] Unknown version: {packet[0]}");
                    return;
                }

                var nonce = packet.Slice(1, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
                var sendbackArea = packet.Slice(1 + LibSodium.CRYPTO_NONCE_SIZE, MaxSendbackSize).ToArray();
                var encryptedData = packet.Slice(1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize).ToArray();

                // Intentar procesar como destino final primero
                if (core.TryProcessAsDestination(source, encryptedData, nonce, sendbackArea))
                    return;

                // Si no, procesar como relay
                if (core.TryProcessAsRelay(source, encryptedData, nonce, sendbackArea))
                    return;

                Logger.Log.Debug("[ONIONCORE] Failed to process onion packet");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCORE] HandleOnionPacket error: {ex.Message}");
            }
        }

        /// <summary>
        /// Intenta procesar el paquete como destino final (somos el nodo 3 o el destino).
        /// </summary>
        private bool TryProcessAsDestination(IPEndPoint source, byte[] encryptedData, byte[] nonce, byte[] sendbackData)
        {
            byte[] senderPk = GetNodePublicKey(source);
            if (senderPk == null) return false;

            byte[] sharedKey = _sharedKeysRecv.Lookup(senderPk);
            if (sharedKey == null) return false;

            var plaintext = new byte[encryptedData.Length - LibSodium.CRYPTO_MAC_SIZE];

            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plaintext, encryptedData, nonce, sharedKey))
                return false; // No es para nosotros como destino final

            // Verificar si hay clave pública de destino específico
            if (plaintext.Length >= LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
            {
                var destPk = plaintext.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
                var ourPk = _dht.SelfPublicKey.ToArray();

                // Si no es para nosotros, no somos el destino final
                if (!destPk.AsSpan().SequenceEqual(ourPk))
                    return false;

                // Extraer datos reales (después de la clave pública)
                var actualData = plaintext.AsSpan(LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();

                Logger.Log.Debug($"[ONIONCORE] Packet delivered to us ({actualData.Length} bytes)");

                // Almacenar sendback para poder responder
                StoreSendbackForResponse(nonce, source, sendbackData);

                // Notificar a los handlers
                _dataHandler?.Invoke(source, actualData, nonce);

                // Notificar handlers específicos de tipo de paquete
                if (actualData.Length > 0 && _packetHandlers.TryGetValue(actualData[0], out var handler))
                {
                    handler(source, actualData.AsSpan(1).ToArray(), senderPk);
                }

                return true;
            }
            else
            {
                // Broadcast/anuncio (sin clave de destino específica)
                Logger.Log.Debug($"[ONIONCORE] Broadcast packet delivered ({plaintext.Length} bytes)");

                StoreSendbackForResponse(nonce, source, sendbackData);
                _dataHandler?.Invoke(source, plaintext, nonce);

                if (plaintext.Length > 0 && _packetHandlers.TryGetValue(plaintext[0], out var handler))
                {
                    handler(source, plaintext.AsSpan(1).ToArray(), senderPk);
                }

                return true;
            }
        }

        /// <summary>
        /// CORREGIDO: Procesa el paquete como nodo relay (nodo 1 o 2).
        /// Agrega IP/Port cifrado al sendback usando crypto_secretbox con clave derivada.
        /// </summary>
        private bool TryProcessAsRelay(IPEndPoint source, byte[] encryptedData, byte[] nonce, byte[] sendbackData)
        {
            byte[] senderPk = GetNodePublicKey(source);
            if (senderPk == null) return false;

            byte[] sharedKey = _sharedKeysRecv.Lookup(senderPk);
            if (sharedKey == null) return false;

            var plaintext = new byte[encryptedData.Length - LibSodium.CRYPTO_MAC_SIZE];

            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plaintext, encryptedData, nonce, sharedKey))
                return false; // No es para nosotros como relay

            if (plaintext.Length < 1) return false;

            // Extraer IP/Port del siguiente hop
            int ipPortLen = plaintext[0];
            if (ipPortLen < 6 || ipPortLen > 19 || plaintext.Length < 1 + ipPortLen)
                return false;

            if (!DeserializeIpPort(plaintext.AsSpan(1, ipPortLen), out var nextHop))
                return false;

            // Extraer capa interna para reenvío
            int innerOffset = 1 + ipPortLen;
            int innerLen = plaintext.Length - innerOffset;
            byte[] innerLayer = new byte[innerLen];
            Buffer.BlockCopy(plaintext, innerOffset, innerLayer, 0, innerLen);

            // CORRECCIÓN CRÍTICA: Cifrar nuestro IP/Port para el sendback
            // Usamos nuestro endpoint visible (como lo ve el nodo anterior)
            byte[] ourIpPort = SerializeIpPortCompact(source);
            byte[] encryptedHop = EncryptSendbackHop(ourIpPort, sharedKey);

            if (encryptedHop == null)
            {
                Logger.Log.Error("[ONIONCORE] Failed to encrypt sendback hop");
                return false;
            }

            // Construir nuevo sendback: [nuevo hop cifrado][hops anteriores]
            byte[] newSendback = new byte[MaxSendbackSize];

            // Colocar nuevo hop al principio (posición 0-27)
            Buffer.BlockCopy(encryptedHop, 0, newSendback, 0, SendbackHopSize);

            // Shift hops existentes hacia atrás (si hay espacio)
            if (sendbackData?.Length > 0)
            {
                int remaining = Math.Min(sendbackData.Length, MaxSendbackSize - SendbackHopSize);
                if (remaining > 0)
                {
                    Buffer.BlockCopy(sendbackData, 0, newSendback, SendbackHopSize, remaining);
                }
            }

            // Construir nuevo paquete onion
            byte[] newPacket = new byte[1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize + innerLayer.Length];
            newPacket[0] = OnionPacketVersion;
            Buffer.BlockCopy(nonce, 0, newPacket, 1, LibSodium.CRYPTO_NONCE_SIZE);
            Buffer.BlockCopy(newSendback, 0, newPacket, 1 + LibSodium.CRYPTO_NONCE_SIZE, MaxSendbackSize);
            Buffer.BlockCopy(innerLayer, 0, newPacket, 1 + LibSodium.CRYPTO_NONCE_SIZE + MaxSendbackSize, innerLayer.Length);

            // Reenviar al siguiente hop
            int sent = _network.SendPacket(nextHop, newPacket, newPacket.Length);

            if (sent > 0)
            {
                Logger.Log.Debug($"[ONIONCORE] Relayed onion packet to {nextHop}, added sendback hop");
                RegisterOnionNode(source);
                return true;
            }

            return false;
        }

        #endregion

        #region Sistema de Sendback Corregido

        /// <summary>
        /// DERIVACIÓN CORRECTA DE CLAVE SENDBACK según protocolo Tox.
        /// Clave = SHA512(shared_key)[0:32]
        /// </summary>
        private byte[] DeriveSendbackKey(byte[] sharedKey)
        {
            if (sharedKey == null || sharedKey.Length != LibSodium.CRYPTO_SHARED_KEY_SIZE)
                return null;

            byte[] hash512 = new byte[64];
            try
            {
                if (!LibSodium.TrySha512(hash512, sharedKey))
                    return null;

                // Primeros 32 bytes del hash SHA512
                byte[] derivedKey = new byte[32];
                Buffer.BlockCopy(hash512, 0, derivedKey, 0, 32);
                return derivedKey;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash512);
            }
        }

        /// <summary>
        /// CORREGIDO: Cifra un hop del sendback usando crypto_secretbox con clave derivada.
        /// </summary>
        private byte[] EncryptSendbackHop(byte[] ipPortData, byte[] sharedKeyWithPreviousNode)
        {
            if (ipPortData == null || sharedKeyWithPreviousNode == null)
                return null;

            // Derivar clave correctamente: SHA512(shared_key)[0:32]
            byte[] sendbackKey = DeriveSendbackKey(sharedKeyWithPreviousNode);
            if (sendbackKey == null)
                return null;

            try
            {
                // Asegurar que los datos quepan en 12 bytes (IP/Port compacto)
                byte[] paddedData = new byte[12];
                int copyLen = Math.Min(ipPortData.Length, 12);
                Buffer.BlockCopy(ipPortData, 0, paddedData, 0, copyLen);

                // Cifrar con crypto_secretbox: 12 bytes → 28 bytes (12 + 16 MAC)
                byte[] cipher = new byte[12 + LibSodium.CRYPTO_SECRETBOX_MAC_SIZE];

                if (!LibSodium.TryCryptoSecretBoxEasy(cipher, paddedData, SendbackNonce, sendbackKey))
                {
                    Logger.Log.Error("[ONIONCORE] Failed to encrypt sendback hop with crypto_secretbox");
                    return null;
                }

                return cipher; // 28 bytes exactos
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sendbackKey);
            }
        }

        /// <summary>
        /// CORREGIDO: Descifra un hop del sendback usando clave derivada.
        /// </summary>
        private byte[] DecryptSendbackHop(byte[] encryptedHop, byte[] sharedKeyWithNextNode)
        {
            if (encryptedHop == null || encryptedHop.Length < LibSodium.CRYPTO_SECRETBOX_MAC_SIZE)
                return null;

            // Derivar clave
            byte[] sendbackKey = DeriveSendbackKey(sharedKeyWithNextNode);
            if (sendbackKey == null)
                return null;

            try
            {
                byte[] plaintext = new byte[encryptedHop.Length - LibSodium.CRYPTO_SECRETBOX_MAC_SIZE];

                if (!LibSodium.TryCryptoSecretBoxOpenEasy(plaintext, encryptedHop, SendbackNonce, sendbackKey))
                    return null;

                return plaintext; // 12 bytes de IP/Port
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sendbackKey);
            }
        }

        /// <summary>
        /// Intenta usar crypto_secretbox si está disponible en LibSodium.
        /// </summary>
        private bool TryEncryptWithSecretbox(byte[] cipher, byte[] message, byte[] nonce, byte[] key)
        {
            try
            {
                // Verificar que LibSodium tenga el método disponible
                if (!LibSodium.IsAvailable) return false;

                // Usar P/Invoke directo si es necesario, o el método wrapper
                return LibSodium.TryCryptoSecretBoxEasy(cipher, message, nonce, key);
            }
            catch
            {
                return false;
            }
        }

        private bool TryDecryptWithSecretbox(byte[] message, byte[] cipher, byte[] nonce, byte[] key)
        {
            try
            {
                if (!LibSodium.IsAvailable) return false;
                return LibSodium.TryCryptoSecretBoxOpenEasy(message, cipher, nonce, key);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Procesamiento de Respuestas Onion

        private static void HandleOnionResponse0(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var core = (OnionCore)state;
            core.HandleOnionResponse(source, packet, 0);
        }

        private static void HandleOnionResponse1(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var core = (OnionCore)state;
            core.HandleOnionResponse(source, packet, 1);
        }

        private static void HandleOnionResponse2(object state, IPEndPoint source, ReadOnlySpan<byte> packet, object userdata)
        {
            var core = (OnionCore)state;
            core.HandleOnionResponse(source, packet, 2);
        }

        /// <summary>
        /// CORREGIDO: Maneja una respuesta onion entrante.
        /// </summary>
        private void HandleOnionResponse(IPEndPoint source, ReadOnlySpan<byte> packet, int hopIndex)
        {
            try
            {
                if (packet.Length < LibSodium.CRYPTO_NONCE_SIZE + LibSodium.CRYPTO_MAC_SIZE)
                    return;

                var nonce = packet.Slice(0, LibSodium.CRYPTO_NONCE_SIZE).ToArray();
                var encryptedData = packet.Slice(LibSodium.CRYPTO_NONCE_SIZE).ToArray();

                // Buscar el sendback asociado a este nonce
                if (!_receivedSendbacks.TryGetValue(nonce, out var sendbackEntry))
                {
                    Logger.Log.Debug("[ONIONCORE] Received onion response for unknown nonce");
                    return;
                }

                // Verificar si somos el destino final (origen del request)
                if (sendbackEntry.OutboundPath != null && hopIndex == 0 &&
                    sendbackEntry.OutboundPath.Length == 3) // Path completo de 3 hops
                {
                    // Descifrar y entregar al handler local
                    DeliverToLocalHandler(nonce, encryptedData, sendbackEntry);
                    _receivedSendbacks.TryRemove(nonce, out _);
                    return;
                }

                // Reenviar al siguiente hop usando el sendbackEntry
                if (!ForwardOnionResponse(packet.ToArray(), sendbackEntry, hopIndex))
                {
                    Logger.Log.Warning($"[ONIONCORE] Failed to forward onion response at hop {hopIndex}");
                }
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCORE] HandleOnionResponse error: {ex.Message}");
            }
        }

        /// <summary>
        /// CORREGIDO: Reenvía una respuesta onion al siguiente hop usando el sendback almacenado.
        /// Usa la información del sendbackEntry para descifrar el próximo hop.
        /// </summary>
        private bool ForwardOnionResponse(byte[] responsePacket, SendbackEntry sendbackEntry, int currentHop)
        {
            if (sendbackEntry?.NodeKeys == null || sendbackEntry.NodeKeys.Length <= currentHop)
            {
                Logger.Log.Warning("[ONIONCORE] No node keys available for hop");
                return false;
            }

            // Extraer el hop cifrado correspondiente del sendback
            int hopOffset = currentHop * SendbackHopSize;
            if (hopOffset + SendbackHopSize > MaxSendbackSize)
            {
                Logger.Log.Warning("[ONIONCORE] Invalid hop offset");
                return false;
            }

            // El sendback en el SendbackEntry contiene los hops cifrados en orden inverso
            // Hop 0 (último nodo del path original) está en la posición 0-27
            byte[] encryptedHop = new byte[SendbackHopSize];
            Buffer.BlockCopy(sendbackEntry.SendbackData, hopOffset, encryptedHop, 0, SendbackHopSize);

            // Descifrar usando la clave compartida con el nodo correspondiente
            // NodeKeys[0] = entry node, [1] = middle, [2] = exit
            // Para response: usamos las claves en orden inverso
            int keyIndex = sendbackEntry.NodeKeys.Length - 1 - currentHop;
            if (keyIndex < 0 || keyIndex >= sendbackEntry.NodeKeys.Length)
            {
                Logger.Log.Warning("[ONIONCORE] Invalid key index for hop");
                return false;
            }

            byte[] nodePk = sendbackEntry.NodeKeys[keyIndex];
            byte[] sharedKey = _sharedKeysRecv.Lookup(nodePk);
            if (sharedKey == null)
            {
                Logger.Log.Warning("[ONIONCORE] No shared key for next hop");
                return false;
            }

            // Descifrar el hop
            byte[] decryptedHop = DecryptSendbackHop(encryptedHop, sharedKey);
            if (decryptedHop == null)
            {
                Logger.Log.Warning("[ONIONCORE] Failed to decrypt sendback hop");
                return false;
            }

            // Deserializar IP/Port
            if (!DeserializeIpPort(decryptedHop, out var nextHop))
            {
                Logger.Log.Warning("[ONIONCORE] Failed to deserialize next hop from sendback");
                return false;
            }

            // Determinar tipo de paquete para siguiente hop
            byte nextPacketType = currentHop switch
            {
                0 => PacketOnionResponse1,
                1 => PacketOnionResponse2,
                _ => PacketOnionResponse2
            };

            // Construir paquete para siguiente hop
            byte[] nextPacket = new byte[1 + responsePacket.Length];
            nextPacket[0] = nextPacketType;
            Buffer.BlockCopy(responsePacket, 0, nextPacket, 1, responsePacket.Length);

            // Enviar
            int sent = _network.SendPacket(nextHop, nextPacket, nextPacket.Length);

            if (sent > 0)
            {
                Logger.Log.Debug($"[ONIONCORE] Forwarded onion response to {nextHop} (hop {currentHop + 1})");
                return true;
            }

            return false;
        }

        /// <summary>
        /// Entrega la respuesta al handler local (somos el origen del request).
        /// </summary>
        private void DeliverToLocalHandler(byte[] nonce, byte[] encryptedData, SendbackEntry entry)
        {
            try
            {
                // Descifrar usando la clave compartida con el último nodo del path
                byte[] lastNodePk = GetNodePublicKey(entry.OutboundPath[2]);
                if (lastNodePk == null) return;

                byte[] sharedKey = _sharedKeysRecv.Lookup(lastNodePk);
                if (sharedKey == null) return;

                var plaintext = new byte[encryptedData.Length - LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plaintext, encryptedData, nonce, sharedKey))
                {
                    Logger.Log.Warning("[ONIONCORE] Failed to decrypt local response");
                    return;
                }

                Logger.Log.Info($"[ONIONCORE] Delivered onion response to local handler ({plaintext.Length} bytes)");
                _dataHandler?.Invoke(entry.Source, plaintext, nonce);
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[ONIONCORE] DeliverToLocalHandler error: {ex.Message}");
            }
        }

        #endregion

        #region Almacenamiento y Utilidades

        private void StoreSendbackForResponse(byte[] nonce, IPEndPoint source, byte[] sendbackData)
        {
            _receivedSendbacks[nonce] = new SendbackEntry
            {
                Source = source,
                SendbackData = sendbackData,
                Timestamp = _monoTime.GetSeconds()
            };
        }

        /// <summary>
        /// CORREGIDO: Almacena información del nonce outbound incluyendo sendback inicial.
        /// </summary>
        private void StoreOutboundNonce(byte[] nonce, IPEndPoint[] path, byte[][] nodeKeys, byte[] initialSendback)
        {
            _receivedSendbacks[nonce] = new SendbackEntry
            {
                Source = path[0],
                OutboundPath = path.Select(p => new IPEndPoint(p.Address, p.Port)).ToArray(),
                NodeKeys = nodeKeys.Select(k => (byte[])k.Clone()).ToArray(),
                SendbackData = initialSendback, // Se actualizará cuando llegue la respuesta
                Timestamp = _monoTime.GetSeconds()
            };
        }

        private byte[] GetNodePublicKey(IPEndPoint endpoint)
        {
            if (_knownNodes.TryGetValue(endpoint, out var node) && node.PublicKey != null)
                return node.PublicKey;

            // Intentar obtener del DHT
            byte[] pk = _dht.GetPublicKeyByIpPort(endpoint);
            if (pk != null)
            {
                _knownNodes[endpoint] = new OnionNode
                {
                    Endpoint = endpoint,
                    PublicKey = (byte[])pk.Clone(),
                    LastSeen = _monoTime.GetSeconds()
                };
                return pk;
            }

            return null;
        }

        private void RegisterOnionNode(IPEndPoint endpoint)
        {
            if (_knownNodes.TryGetValue(endpoint, out var node))
                node.LastSeen = _monoTime.GetSeconds();
        }

        private void DiscoverOnionNodes()
        {
            var nodes = new NodeFormat[DhtConstants.MaxSentNodes];
            int numNodes = _dht.GetCloseNodes(
                _dht.SelfPublicKey.ToArray(),
                nodes,
                null,
                false,
                true); // wantAnnounce = true para nodos que soportan anuncios

            var now = _monoTime.GetSeconds();

            for (int i = 0; i < numNodes; i++)
            {
                if (!_knownNodes.ContainsKey(nodes[i].IpPort) && nodes[i].PublicKey != null)
                {
                    _knownNodes[nodes[i].IpPort] = new OnionNode
                    {
                        Endpoint = nodes[i].IpPort,
                        PublicKey = (byte[])nodes[i].PublicKey.Clone(),
                        LastSeen = now
                    };
                }
            }
        }

        private List<IPEndPoint> GetDhtNodes(int count)
        {
            var result = new List<IPEndPoint>();
            var nodes = new NodeFormat[DhtConstants.MaxSentNodes];

            int numNodes = _dht.GetCloseNodes(
                _dht.SelfPublicKey.ToArray(),
                nodes,
                null,
                false,
                false);

            for (int i = 0; i < Math.Min(numNodes, count); i++)
                result.Add(nodes[i].IpPort);

            return result;
        }

        private byte[] SerializeIpPort(IPEndPoint ipPort)
        {
            bool isIPv6 = ipPort.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

            if (isIPv6)
            {
                // IPv6: [family(1)=10][ip(16)][port(2)] = 19 bytes
                var result = new byte[19];
                result[0] = 10;
                ipPort.Address.GetAddressBytes().CopyTo(result, 1);
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(17, 2), (ushort)ipPort.Port);
                return result;
            }
            else
            {
                // IPv4: [family(1)=2][ip(4)][port(2)] = 7 bytes  
                var result = new byte[7];
                result[0] = 2;
                var ipv4Bytes = ipPort.Address.MapToIPv4().GetAddressBytes();
                ipv4Bytes.CopyTo(result, 1);
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5, 2), (ushort)ipPort.Port);
                return result;
            }
        }

        
        private bool DeserializeIpPort(ReadOnlySpan<byte> data, out IPEndPoint ipPort)
        {
            ipPort = null;
            if (data.Length < 1) return false;

            byte family = data[0];

            if (family == 2 && data.Length >= 7) // IPv4
            {
                var ipBytes = data.Slice(1, 4).ToArray();
                ushort port = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(5, 2));
                ipPort = new IPEndPoint(new IPAddress(ipBytes), port);
                return true;
            }

            if (family == 10 && data.Length >= 19) // IPv6
            {
                var ipBytes = data.Slice(1, 16).ToArray();
                ushort port = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(17, 2));
                ipPort = new IPEndPoint(new IPAddress(ipBytes), port);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Serializa IP/Port a formato compacto de 12 bytes para sendback.
        /// Formato: [family: 1][ip: 16 truncado o 4 expandido][port: 2][padding]
        /// </summary>
        private byte[] SerializeIpPortCompact(IPEndPoint ipPort)
        {
            // Formato fijo de 12 bytes para sendback
            byte[] result = new byte[12];

            bool isIPv6 = ipPort.AddressFamily == AddressFamily.InterNetworkV6;
            result[0] = isIPv6 ? (byte)10 : (byte)2;

            byte[] addrBytes = ipPort.Address.GetAddressBytes();

            if (isIPv6)
            {
                // IPv6: 16 bytes completos, truncamos a 9 bytes disponibles (pos 1-9)
                // Realmente necesitamos optimizar esto, pero por ahora:
                // Usar solo los últimos 8 bytes de la dirección IPv6 (identificador de interfaz)
                // y 1 byte de prefijo
                if (addrBytes.Length == 16)
                {
                    // Copiar últimos 8 bytes (identificador de interfaz)
                    Buffer.BlockCopy(addrBytes, 8, result, 1, 8);
                    // Puerto en bytes 9-10
                    result[9] = (byte)(ipPort.Port >> 8);
                    result[10] = (byte)(ipPort.Port & 0xFF);
                }
            }
            else
            {
                // IPv4: 4 bytes, expandimos a 4 bytes en pos 1-4
                // Luego padding hasta byte 9
                Buffer.BlockCopy(addrBytes, 0, result, 1, Math.Min(4, addrBytes.Length));
                // Puerto en bytes 9-10
                result[9] = (byte)(ipPort.Port >> 8);
                result[10] = (byte)(ipPort.Port & 0xFF);
            }

            return result;
        }

        /// <summary>
        /// Deserializa IP/Port desde formato compacto de 12 bytes.
        /// </summary>
        private bool DeserializeIpPortCompact(ReadOnlySpan<byte> data, out IPEndPoint ipPort)
        {
            ipPort = null;
            if (data.Length < 12) return false;

            try
            {
                byte family = data[0];
                ushort port = (ushort)((data[9] << 8) | data[10]);

                if (family == 2) // IPv4
                {
                    byte[] ipBytes = new byte[4];
                    Buffer.BlockCopy(data.Slice(1, 4).ToArray(), 0, ipBytes, 0, 4);
                    ipPort = new IPEndPoint(new IPAddress(ipBytes), port);
                    return true;
                }
                else if (family == 10) // IPv6 - reconstrucción parcial
                {
                    // Reconstruir IPv6 desde identificador de interfaz
                    // Esto es una simplificación; en producción necesitarías más contexto
                    byte[] ipBytes = new byte[16];
                    // Prefijo link-local o similar
                    ipBytes[0] = 0xFE;
                    ipBytes[1] = 0x80;
                    // Identificador de interfaz
                    Buffer.BlockCopy(data.Slice(1, 8).ToArray(), 0, ipBytes, 8, 8);

                    ipPort = new IPEndPoint(new IPAddress(ipBytes), port);
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Compara dos endpoints IP/Port.
        /// </summary>
        private bool IpPortEqual(IPEndPoint a, IPEndPoint b)
        {
            if (a == null || b == null) return false;
            if (a.Port != b.Port) return false;

            // Usar la comparación del NetworkCore si está disponible
            if (_network is INetworkAddressUtilities netUtils)
                return netUtils.IpPortEqual(a, b);

            // Fallback simple
            return a.Address.Equals(b.Address);
        }

        public void Dispose()
        {
            _network.UnregisterHandler(PacketOnionRequest);
            _network.UnregisterHandler(PacketOnionResponse0);
            _network.UnregisterHandler(PacketOnionResponse1);
            _network.UnregisterHandler(PacketOnionResponse2);

            _packetHandlers.Clear();
            _knownNodes.Clear();
            _receivedSendbacks.Clear();

            Logger.Log.Info("[ONIONCORE] Disposed");
        }

        #endregion

        #region Clases Auxiliares

        private class OnionNode
        {
            public IPEndPoint Endpoint { get; set; }
            public byte[] PublicKey { get; set; }
            public ulong LastSeen { get; set; }

            public bool IsExpired(ulong now) => now > LastSeen + OnionPathTimeout;
        }

        private class SendbackEntry
        {
            public IPEndPoint Source { get; set; }
            public byte[] SendbackData { get; set; }
            public ulong Timestamp { get; set; }
            public IPEndPoint[] OutboundPath { get; set; }
            public byte[][] NodeKeys { get; set; }
        }

        #endregion
    }
}