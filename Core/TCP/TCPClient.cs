// Core/TCP/TCPClient.cs
using System;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.TCP;

namespace Toxcore.Core.TCP
{
    /// <summary>
    /// Cliente TCP para conexiones salientes a relays TCP.
    /// Traducción de TCP_client.c usando TCPCommon.
    /// </summary>
    public sealed class TCPClient : ITCPClient, IDisposable
    {
        // Estados de conexión
        public const byte TcpClientDisconnected = 0;
        public const byte TcpClientConnected = 1;
        public const byte TcpClientUnconfirmed = 2;

        private readonly MonoTime _monoTime;
        private readonly byte[] _selfPublicKey;
        private readonly byte[] _selfSecretKey;

        private TcpClient _tcpClient;
        private CancellationTokenSource _cts;
        private Task _receiveTask;

        private byte _status = TcpClientDisconnected;
        private ulong _lastRecvTime;
        private ulong _lastSendTime;
        private byte[] _relayPublicKey;

        // Estado de conexión TCP compartido (para TCPCommon)
        private readonly TCPConnectionState _conState = new TCPConnectionState();

        public byte Status => _status;
        public IPEndPoint RemoteEndPoint { get; private set; }
        public bool IsConnected => _status == TcpClientConnected;
        public TCPConnectionState ConnectionState => _conState;

        public event Action<byte[]> OnDataReceived;
        public event Action OnConnected;
        public event Action OnDisconnected;
        public event Action<Exception> OnError;

        public TCPClient(
            MonoTime monoTime,
            byte[] selfPublicKey,
            byte[] selfSecretKey)
        {
            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));
            _selfSecretKey = selfSecretKey ?? throw new ArgumentNullException(nameof(selfSecretKey));
        }

        public async Task<bool> ConnectAsync(IPEndPoint relayEndpoint, byte[] relayPublicKey, CancellationToken ct = default)
        {
            if (_status != TcpClientDisconnected)
            {
                Logger.Log.Warning("[TCPClient] Already connected or connecting");
                return false;
            }

            try
            {
                _relayPublicKey = relayPublicKey;
                RemoteEndPoint = relayEndpoint;

                _tcpClient = new TcpClient(relayEndpoint.AddressFamily);
                _tcpClient.NoDelay = true;

                await _tcpClient.ConnectAsync(relayEndpoint.Address, relayEndpoint.Port);

                // Configurar estado de conexión
                _conState.Sock = _tcpClient.Client;
                _conState.IpPort = relayEndpoint;

                _status = TcpClientUnconfirmed;
                _lastRecvTime = _monoTime.GetSeconds();
                _lastSendTime = _lastRecvTime;

                // Enviar handshake
                if (!SendClientHandshake())
                {
                    Disconnect();
                    return false;
                }

                _cts = new CancellationTokenSource();
                _receiveTask = ReceiveLoop(_cts.Token);

                Logger.Log.Info($"[TCPClient] Connected to {relayEndpoint}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPClient] Connection failed: {ex.Message}");
                Disconnect();
                return false;
            }
        }

        /// <summary>
        /// Envía handshake inicial al relay (cliente).
        /// Formato: [ephemeral_public(32)][nonce(24)][encrypted_data]
        /// </summary>
        private bool SendClientHandshake()
        {
            try
            {
                // Generar ephemeral keys
                var ephemeralPublic = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
                var ephemeralSecret = new byte[LibSodium.CRYPTO_SECRET_KEY_SIZE];
                if (!LibSodium.TryCryptoBoxKeyPair(ephemeralPublic, ephemeralSecret))
                    return false;

                // Nonce aleatorio para envío
                var sentNonce = LibSodium.GenerateNonce();
                Buffer.BlockCopy(sentNonce, 0, _conState.SentNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);

                // Derivar shared key: ephemeral_secret + relay_public
                if (!LibSodium.TryCryptoBoxBeforeNm(_conState.SharedKey, _relayPublicKey, ephemeralSecret))
                    return false;

                // Datos a cifrar: [public_key_permanente(32)][nonce_recepcion(24)]
                var plain = new byte[TCPCommon.TcpHandshakePlainSize];
                Buffer.BlockCopy(_selfPublicKey, 0, plain, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                // Los últimos 24 bytes son padding (nonce de recepción, generado por servidor)

                // Cifrar con sentNonce
                var cipher = new byte[plain.Length + LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher, plain, sentNonce, _conState.SharedKey))
                    return false;

                // Construir paquete: [ephemeral_public(32)][nonce(24)][cipher]
                var packet = new byte[TCPCommon.TcpClientHandshakeSize];
                Buffer.BlockCopy(ephemeralPublic, 0, packet, 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
                Buffer.BlockCopy(sentNonce, 0, packet, LibSodium.CRYPTO_PUBLIC_KEY_SIZE, LibSodium.CRYPTO_NONCE_SIZE);
                Buffer.BlockCopy(cipher, 0, packet, LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE, cipher.Length);

                // Limpiar secret ephemeral
                CryptographicOperations.ZeroMemory(ephemeralSecret);

                // Enviar usando TCPCommon
                return _tcpClient.Client.Send(packet) == packet.Length;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPClient] Handshake send failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Escribe paquete a conexión segura usando TCPCommon.
        /// </summary>
        public bool WritePacket(ReadOnlySpan<byte> data, bool priority)
        {
            if (_status != TcpClientConnected)
                return false;

            int result = TCPConnectionHandler.WritePacketTcpSecureConnection(
                _conState,
                data,
                (ushort)data.Length,
                priority);

            if (result == 1)
            {
                _lastSendTime = _monoTime.GetSeconds();
                return true;
            }

            return false;
        }

        /// <summary>
        /// Lee paquete de conexión segura usando TCPCommon.
        /// </summary>
        public int ReadPacket(Span<byte> buffer)
        {
            if (_status != TcpClientConnected)
                return -1;

            ushort nextLen = 0; // TCPCommon maneja esto internamente en el bucle de recepción
            return TCPConnectionHandler.ReadPacketTcpSecureConnection(
                _conState.Sock,
                ref nextLen,
                _conState.SharedKey,
                new byte[LibSodium.CRYPTO_NONCE_SIZE], // recvNonce - debería guardarse en estado
                buffer,
                (ushort)buffer.Length,
                RemoteEndPoint);
        }

        private async Task ReceiveLoop(CancellationToken ct)
        {
            var recvNonce = new byte[LibSodium.CRYPTO_NONCE_SIZE]; // Nonce para recibir (del servidor)
            ushort nextPacketLength = 0;

            while (!ct.IsCancellationRequested && _status != TcpClientDisconnected)
            {
                try
                {
                    if (_conState.Sock == null || !_conState.Sock.Connected)
                    {
                        await Task.Delay(100, ct);
                        continue;
                    }

                    // Si estamos en handshake, esperar respuesta
                    if (_status == TcpClientUnconfirmed)
                    {
                        if (!ProcessServerHandshakeResponse(recvNonce))
                        {
                            Logger.Log.Error("[TCPClient] Handshake response failed");
                            break;
                        }

                        _status = TcpClientConnected;
                        _lastRecvTime = _monoTime.GetSeconds();
                        OnConnected?.Invoke();
                        Logger.Log.Info("[TCPClient] Handshake completed, connection secured");
                        continue;
                    }

                    // Leer paquete usando TCPCommon
                    var buffer = new byte[TCPCommon.MaxPacketSize];
                    int len = TCPConnectionHandler.ReadPacketTcpSecureConnection(
                        _conState.Sock,
                        ref nextPacketLength,
                        _conState.SharedKey,
                        recvNonce,
                        buffer,
                        (ushort)buffer.Length,
                        RemoteEndPoint);

                    if (len == -1)
                    {
                        Logger.Log.Error("[TCPClient] Read error");
                        break;
                    }

                    if (len == 0)
                    {
                        await Task.Delay(10, ct); // No hay datos, esperar
                        continue;
                    }

                    _lastRecvTime = _monoTime.GetSeconds();
                    OnDataReceived?.Invoke(buffer.AsSpan(0, len).ToArray());
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[TCPClient] Receive error: {ex.Message}");
                    OnError?.Invoke(ex);
                    break;
                }
            }

            Disconnect();
        }

        /// <summary>
        /// Procesa respuesta del handshake del servidor.
        /// </summary>
        private bool ProcessServerHandshakeResponse(byte[] recvNonce)
        {
            try
            {
                // Leer longitud (2 bytes)
                var lenBuf = new byte[2];
                int read = _conState.Sock.Receive(lenBuf);
                if (read != 2) return false;

                ushort length = (ushort)((lenBuf[0] << 8) | lenBuf[1]);
                if (length != TCPCommon.TcpServerHandshakeSize - 2) return false;

                // Leer resto del handshake
                var handshakeData = new byte[length];
                read = _conState.Sock.Receive(handshakeData);
                if (read != length) return false;

                // Extraer nonce y ciphertext
                Buffer.BlockCopy(handshakeData, 0, recvNonce, 0, LibSodium.CRYPTO_NONCE_SIZE);
                var cipher = handshakeData.AsSpan(LibSodium.CRYPTO_NONCE_SIZE).ToArray();

                // Descifrar
                var plain = new byte[cipher.Length - LibSodium.CRYPTO_MAC_SIZE];
                if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, cipher, recvNonce, _conState.SharedKey))
                    return false;

                // Verificar que contiene nuestra public key
                var receivedPk = plain.AsSpan(0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE).ToArray();
                if (!receivedPk.AsSpan().SequenceEqual(_selfPublicKey))
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPClient] Process handshake response failed: {ex.Message}");
                return false;
            }
        }

        public void Disconnect()
        {
            if (_status == TcpClientDisconnected) return;

            _status = TcpClientDisconnected;
            _cts?.Cancel();

            // Limpiar colas de prioridad
            TCPConnectionHandler.WipePriorityList(_conState.PriorityQueueStart);
            _conState.PriorityQueueStart = null;
            _conState.PriorityQueueEnd = null;

            // Limpiar shared key
            CryptographicOperations.ZeroMemory(_conState.SharedKey);

            try
            {
                _tcpClient?.Close();
            }
            catch { }

            OnDisconnected?.Invoke();
            Logger.Log.Info("[TCPClient] Disconnected");
        }

        public void Dispose()
        {
            Disconnect();
            _cts?.Dispose();
            _tcpClient?.Dispose();
        }
    }
}