// Core/Abstractions/TCP/ITCPServer.cs - ACTUALIZADO
using System;
using System.Net;

namespace Toxcore.Core.Abstractions.TCP
{
    public interface ITCPServer : IDisposable
    {
        bool Start(IPAddress bindAddress, ushort port);
        void Stop();
        bool IsRunning { get; }
        IPEndPoint LocalEndPoint { get; }
        int ConnectionCount { get; }

        bool WritePacket(int connId, ReadOnlySpan<byte> data, bool priority);
        void DisconnectClient(int connId);

        event Action<int, IPEndPoint> OnClientConnected;
        event Action<int, byte[]> OnDataReceived;
        event Action<int> OnClientDisconnected;
    }
}