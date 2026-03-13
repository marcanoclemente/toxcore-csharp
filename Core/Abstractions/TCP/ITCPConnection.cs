// Core/Abstractions/TCP/ITCPConnection.cs - ACTUALIZADO
using System;
using System.Net;
using System.Threading.Tasks;

namespace Toxcore.Core.Abstractions.TCP
{
    /// <summary>
    /// Interfaz para conexiones TCP (cliente y servidor).
    /// </summary>
    public interface ITCPConnection : IDisposable
    {
        // Conexión
        Task<int> NewConnectionAsync(IPEndPoint relayEndpoint, byte[] relayPublicKey);

        // Envío
        bool SendData(int connectionId, byte[] data);
        bool SendDataPriority(int connectionId, byte[] data);

        // Estado
        byte GetConnectionStatus(int connectionId);
        void KillConnection(int connectionId);
        int ConnectionCount { get; }

        // CORRECCIÓN: Propiedades de puerto para servidor TCP
        ushort? ListeningPort { get; }
        bool IsListening { get; }

        // Ciclo principal
        void DoTcp();

        // Eventos
        event Action<int, byte[]> OnDataReceived;
        event Action<int> OnConnected;
        event Action<int> OnDisconnected;
    }

    // CORRECCIÓN: Interfaz auxiliar para proveer puerto
    public interface ITCPPortProvider
    {
        ushort? ListeningPort { get; }
    }
}