// Core/Abstractions/TCP/ITCPClient.cs - ACTUALIZADO
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ToxCore.Core.TCP;

namespace ToxCore.Core.Abstractions.TCP
{
    public interface ITCPClient : IDisposable
    {
        byte Status { get; }
        IPEndPoint RemoteEndPoint { get; }
        bool IsConnected { get; }
        TCPConnectionState ConnectionState { get; }

        Task<bool> ConnectAsync(IPEndPoint relayEndpoint, byte[] relayPublicKey, CancellationToken ct = default);
        bool WritePacket(ReadOnlySpan<byte> data, bool priority);
        int ReadPacket(Span<byte> buffer);
        void Disconnect();

        event Action<byte[]> OnDataReceived;
        event Action OnConnected;
        event Action OnDisconnected;
        event Action<Exception> OnError;
    }
}