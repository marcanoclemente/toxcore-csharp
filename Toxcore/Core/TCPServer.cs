using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ToxCore.Core
{
    /// <summary>
    /// Cliente conectado al servidor TCP
    /// </summary>
    public class TCPClientConnection : IDisposable
    {
        public TcpClient TcpClient { get; }
        public NetworkStream Stream { get; private set; }
        public IPPort RemoteEndPoint { get; private set; }
        public bool IsConnected => TcpClient?.Connected == true;

        public TCPClientConnection(TcpClient client)
        {
            TcpClient = client;
            Stream = client.GetStream();

            if (client.Client.RemoteEndPoint is IPEndPoint remoteEp)
            {
                RemoteEndPoint = new IPPort(remoteEp.Address, (ushort)remoteEp.Port);
            }
        }

        public void Dispose()
        {
            Stream?.Close();
            TcpClient?.Close();
            TcpClient?.Dispose();
        }
    }

    /// <summary>
    /// Servidor TCP para conexiones entrantes
    /// </summary>
    public class TCPServer : IDisposable
    {
        private const int BACKLOG = 100;

        private TcpListener listener;
        private CancellationTokenSource cancellationTokenSource;
        private Task acceptTask;
        private List<TCPClientConnection> connectedClients;

        public ushort ListenPort { get; private set; }
        public bool IsListening { get; private set; }
        public int ConnectedClientsCount => connectedClients.Count;

        public event Action<TCPClientConnection> OnClientConnected;
        public event Action<TCPClientConnection> OnClientDisconnected;
        public event Action<TCPClientConnection, byte[]> OnClientDataReceived;
        public event Action<Exception> OnError;

        public TCPServer()
        {
            connectedClients = new List<TCPClientConnection>();
            cancellationTokenSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Inicia el servidor en un puerto específico
        /// </summary>
        public async Task<bool> StartAsync(ushort port = 0)
        {
            try
            {
                ListenPort = port;
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start(BACKLOG);

                // Obtener puerto real si se usó 0 (puerto aleatorio)
                if (port == 0)
                {
                    ListenPort = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;
                }

                IsListening = true;
                StartAcceptLoop();
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
                return false;
            }
        }

        /// <summary>
        /// Loop de aceptación de conexiones
        /// </summary>
        private void StartAcceptLoop()
        {
            acceptTask = Task.Run(async () =>
            {
                while (IsListening && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        var tcpClient = await listener.AcceptTcpClientAsync();
                        tcpClient.NoDelay = true; // Disable Nagle's algorithm

                        var clientConnection = new TCPClientConnection(tcpClient);
                        lock (connectedClients)
                        {
                            connectedClients.Add(clientConnection);
                        }

                        OnClientConnected?.Invoke(clientConnection);
                        StartClientReceiveLoop(clientConnection);
                    }
                    catch (ObjectDisposedException)
                    {
                        break; // Listener fue cerrado
                    }
                    catch (Exception ex)
                    {
                        if (IsListening) // Solo reportar errores si aún está escuchando
                            OnError?.Invoke(ex);
                    }
                }
            }, cancellationTokenSource.Token);
        }

        /// <summary>
        /// Loop de recepción para un cliente específico
        /// </summary>
        private void StartClientReceiveLoop(TCPClientConnection client)
        {
            Task.Run(async () =>
            {
                byte[] lengthBuffer = new byte[2];
                byte[] receiveBuffer = new byte[2048];

                while (client.IsConnected && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Leer longitud del paquete
                        int bytesRead = await client.Stream.ReadAsync(lengthBuffer, 0, 2, cancellationTokenSource.Token);
                        if (bytesRead != 2) break;

                        ushort packetLength = (ushort)((lengthBuffer[0] << 8) | lengthBuffer[1]);
                        if (packetLength > receiveBuffer.Length)
                        {
                            OnError?.Invoke(new InvalidOperationException($"Packet too large: {packetLength}"));
                            break;
                        }

                        // Leer datos del paquete
                        int totalRead = 0;
                        while (totalRead < packetLength && client.IsConnected)
                        {
                            bytesRead = await client.Stream.ReadAsync(receiveBuffer, totalRead,
                                packetLength - totalRead, cancellationTokenSource.Token);
                            if (bytesRead == 0) break;
                            totalRead += bytesRead;
                        }

                        if (totalRead == packetLength)
                        {
                            byte[] packetData = new byte[packetLength];
                            Buffer.BlockCopy(receiveBuffer, 0, packetData, 0, packetLength);
                            OnClientDataReceived?.Invoke(client, packetData);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (client.IsConnected)
                            OnError?.Invoke(ex);
                        break;
                    }
                }

                HandleClientDisconnection(client);
            }, cancellationTokenSource.Token);
        }

        /// <summary>
        /// Envía datos a un cliente específico
        /// </summary>
        public async Task<bool> SendToClientAsync(TCPClientConnection client, byte[] data)
        {
            if (!client.IsConnected || client.Stream == null)
                return false;

            try
            {
                // Añadir prefijo de longitud
                byte[] packet = new byte[data.Length + 2];
                packet[0] = (byte)((data.Length >> 8) & 0xFF);
                packet[1] = (byte)(data.Length & 0xFF);
                Buffer.BlockCopy(data, 0, packet, 2, data.Length);

                await client.Stream.WriteAsync(packet, 0, packet.Length, cancellationTokenSource.Token);
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
                return false;
            }
        }

        /// <summary>
        /// Envía datos a todos los clientes conectados
        /// </summary>
        public async Task BroadcastAsync(byte[] data)
        {
            List<TCPClientConnection> clients;
            lock (connectedClients)
            {
                clients = new List<TCPClientConnection>(connectedClients);
            }

            var tasks = new List<Task>();
            foreach (var client in clients)
            {
                if (client.IsConnected)
                {
                    tasks.Add(SendToClientAsync(client, data));
                }
            }

            await Task.WhenAll(tasks);
        }

        private void HandleClientDisconnection(TCPClientConnection client)
        {
            lock (connectedClients)
            {
                connectedClients.Remove(client);
            }

            OnClientDisconnected?.Invoke(client);
            client.Dispose();
        }

        /// <summary>
        /// Detiene el servidor
        /// </summary>
        public void Stop()
        {
            try
            {
                IsListening = false;
                cancellationTokenSource?.Cancel();

                listener?.Stop();

                lock (connectedClients)
                {
                    foreach (var client in connectedClients)
                    {
                        client.Dispose();
                    }
                    connectedClients.Clear();
                }

                acceptTask?.Wait(1000);
            }
            catch
            {
                // Ignorar errores durante parada
            }
        }

        public void Dispose()
        {
            Stop();
            cancellationTokenSource?.Dispose();
        }

        /// <summary>
        /// Test básico del servidor TCP
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de TCPServer...");

                // Test 1: Creación de servidor
                using (var server = new TCPServer())
                {
                    bool serverValid = server != null && !server.IsListening;
                    Console.WriteLine($"     Test 1 - Creación de servidor: {(serverValid ? "✅" : "❌")}");

                    // Test 2: Propiedades iniciales
                    bool propertiesValid = server.ListenPort == 0 && server.ConnectedClientsCount == 0;
                    Console.WriteLine($"     Test 2 - Propiedades iniciales: {(propertiesValid ? "✅" : "❌")}");

                    return serverValid && propertiesValid;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test TCPServer: {ex.Message}");
                return false;
            }
        }
    }
}