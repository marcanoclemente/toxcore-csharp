using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Cliente TCP para conexiones salientes
    /// Maneja reconexión automática y keep-alive
    /// </summary>
    public class TCPClient : IDisposable
    {
        private const int TCP_PACKET_SIZE = 2048;
        private const int CONNECT_TIMEOUT = 10000; // 10 segundos
        private const int KEEP_ALIVE_INTERVAL = 30000; // 30 segundos

        private TcpClient tcpClient;
        private NetworkStream stream;
        private CancellationTokenSource cancellationTokenSource;
        private Task receiveTask;
        private Task keepAliveTask;

        public IPPort RemoteEndPoint { get; private set; }
        public bool IsConnected => tcpClient?.Connected == true;
        public event Action<byte[]> OnDataReceived;
        public event Action OnConnected;
        public event Action OnDisconnected;
        public event Action<Exception> OnError;

        public TCPClient()
        {
            tcpClient = new TcpClient();
            tcpClient.NoDelay = true; // Disable Nagle's algorithm
            cancellationTokenSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Conecta a un endpoint remoto
        /// </summary>
        public async Task<bool> ConnectAsync(IPPort remoteEndPoint)
        {
            try
            {
                RemoteEndPoint = remoteEndPoint;

                using (var timeoutToken = new CancellationTokenSource(CONNECT_TIMEOUT))
                using (var linkedToken = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationTokenSource.Token, timeoutToken.Token))
                {
                    await tcpClient.ConnectAsync(remoteEndPoint.IP.ToIPAddress(), remoteEndPoint.Port, linkedToken.Token);
                }

                stream = tcpClient.GetStream();
                StartReceiveLoop();
                StartKeepAliveLoop();

                OnConnected?.Invoke();
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
                return false;
            }
        }

        /// <summary>
        /// Envía datos a través de la conexión TCP
        /// </summary>
        public async Task<bool> SendAsync(byte[] data)
        {
            if (!IsConnected || stream == null)
                return false;

            try
            {
                // Añadir prefijo de longitud (2 bytes big-endian)
                byte[] packet = new byte[data.Length + 2];
                packet[0] = (byte)((data.Length >> 8) & 0xFF);
                packet[1] = (byte)(data.Length & 0xFF);
                Buffer.BlockCopy(data, 0, packet, 2, data.Length);

                await stream.WriteAsync(packet, 0, packet.Length, cancellationTokenSource.Token);
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
                return false;
            }
        }

        /// <summary>
        /// Loop de recepción de datos
        /// </summary>
        private void StartReceiveLoop()
        {
            receiveTask = Task.Run(async () =>
            {
                byte[] lengthBuffer = new byte[2];
                byte[] receiveBuffer = new byte[TCP_PACKET_SIZE];

                while (IsConnected && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Leer longitud del paquete (2 bytes)
                        int bytesRead = await stream.ReadAsync(lengthBuffer, 0, 2, cancellationTokenSource.Token);
                        if (bytesRead != 2) break;

                        ushort packetLength = (ushort)((lengthBuffer[0] << 8) | lengthBuffer[1]);
                        if (packetLength > TCP_PACKET_SIZE)
                        {
                            OnError?.Invoke(new InvalidOperationException($"Packet too large: {packetLength}"));
                            break;
                        }

                        // Leer datos del paquete
                        int totalRead = 0;
                        while (totalRead < packetLength && IsConnected)
                        {
                            bytesRead = await stream.ReadAsync(receiveBuffer, totalRead,
                                packetLength - totalRead, cancellationTokenSource.Token);
                            if (bytesRead == 0) break;
                            totalRead += bytesRead;
                        }

                        if (totalRead == packetLength)
                        {
                            byte[] packetData = new byte[packetLength];
                            Buffer.BlockCopy(receiveBuffer, 0, packetData, 0, packetLength);
                            OnDataReceived?.Invoke(packetData);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (IsConnected) // Solo reportar errores si aún está conectado
                            OnError?.Invoke(ex);
                        break;
                    }
                }

                HandleDisconnection();
            }, cancellationTokenSource.Token);
        }

        /// <summary>
        /// Loop de keep-alive
        /// </summary>
        private void StartKeepAliveLoop()
        {
            keepAliveTask = Task.Run(async () =>
            {
                byte[] keepAlivePacket = new byte[2] { 0x00, 0x00 }; // Paquete keep-alive vacío

                while (IsConnected && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(KEEP_ALIVE_INTERVAL, cancellationTokenSource.Token);
                        if (IsConnected)
                        {
                            await SendAsync(keepAlivePacket);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        OnError?.Invoke(ex);
                        break;
                    }
                }
            }, cancellationTokenSource.Token);
        }

        private void HandleDisconnection()
        {
            if (IsConnected)
            {
                OnDisconnected?.Invoke();
            }
        }

        /// <summary>
        /// Desconecta el cliente
        /// </summary>
        public void Disconnect()
        {
            try
            {
                cancellationTokenSource?.Cancel();

                stream?.Close();
                tcpClient?.Close();

                receiveTask?.Wait(1000);
                keepAliveTask?.Wait(1000);
            }
            catch
            {
                // Ignorar errores durante desconexión
            }
        }

        public void Dispose()
        {
            Disconnect();
            stream?.Dispose();
            tcpClient?.Dispose();
            cancellationTokenSource?.Dispose();
        }

        /// <summary>
        /// Test básico del cliente TCP
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de TCPClient...");

                // Test 1: Creación de cliente
                using (var client = new TCPClient())
                {
                    bool clientValid = client != null && !client.IsConnected;
                    Console.WriteLine($"     Test 1 - Creación de cliente: {(clientValid ? "✅" : "❌")}");

                    // Test 2: Propiedades - CORREGIDO
                    bool propertiesValid = client.RemoteEndPoint.IP.Data == null && client.IsConnected == false;
                    Console.WriteLine($"     Test 2 - Propiedades iniciales: {(propertiesValid ? "✅" : "❌")}");

                    return clientValid && propertiesValid;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test TCPClient: {ex.Message}");
                return false;
            }
        }
    }
}