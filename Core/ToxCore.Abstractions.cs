// ToxCore.Abstractions.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace ToxCore.Core
{
    // --------- DELEGADOS (fuera de interfaces) ---------
    public delegate void HandshakeInfoReadyDelegate(byte[] friendStaticPublic);

        
    // --------- INTERFACES DE RED ---------

    public interface IUdpSender
    {
        int Send(IPPort ep, byte[] data, int length);
    }

    public interface INetwork : IUdpSender, IDisposable
    {
        IPEndPoint LocalEndPoint { get; }
        bool IsRunning { get; }
        void Start();
        void Stop();
        event Action<IPEndPoint, byte[], int>? OnPacketReceived;
        event Action<Exception>? OnError;
    }

    /// <summary>
    /// Interfaz para componentes que exponen un puerto UDP local.
    /// </summary>
    public interface IUDPPortProvider
    {
        ushort LocalPort { get; }
    }


    // --------- ESTRUCTURAS DE RED ---------

    [Serializable]
    public struct IP4
    {
        public byte[] Data;
        public IP4(byte[] data)
        {
            Data = new byte[4];
            if (data?.Length >= 4) Buffer.BlockCopy(data, 0, Data, 0, 4);
        }
        public override string ToString() => $"{Data[0]}.{Data[1]}.{Data[2]}.{Data[3]}";
    }

    [Serializable]
    public struct IP6
    {
        public byte[] Data;
        public IP6(byte[] data)
        {
            Data = new byte[16];
            if (data?.Length >= 16) Buffer.BlockCopy(data, 0, Data, 0, 16);
        }
        public override string ToString() => new IPAddress(Data).ToString();
    }

    public struct IP
    {
        public byte[] Data;
        public byte IsIPv6;

        public IP(IP4 ip4)
        {
            Data = new byte[16];
            if (ip4.Data?.Length >= 4) Buffer.BlockCopy(ip4.Data, 0, Data, 0, 4);
            IsIPv6 = 0;
        }

        public IP(IP6 ip6)
        {
            Data = new byte[16];
            if (ip6.Data?.Length >= 16) Buffer.BlockCopy(ip6.Data, 0, Data, 0, 16);
            IsIPv6 = 1;
        }

        public IP(IPAddress address)
        {
            Data = new byte[16];
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                Buffer.BlockCopy(bytes, 0, Data, 0, 4);
                IsIPv6 = 0;
            }
            else
            {
                byte[] bytes = address.GetAddressBytes();
                Buffer.BlockCopy(bytes, 0, Data, 0, 16);
                IsIPv6 = 1;
            }
        }

        public IPAddress ToIPAddress()
        {
            if (IsIPv6 == 0)
            {
                byte[] ip4Bytes = new byte[4];
                Buffer.BlockCopy(Data, 0, ip4Bytes, 0, 4);
                return new IPAddress(ip4Bytes);
            }
            else
            {
                return new IPAddress(Data);
            }
        }
    }

    public struct IPPort
    {
        public IP IP;
        public ushort Port;

        public IPPort(IP ip, ushort port)
        {
            IP = ip;
            Port = port;
        }

        public IPPort(IPAddress ip, ushort port)
        {
            IP = new IP(ip);
            Port = port;
        }

        public override string ToString() => $"{IP.ToIPAddress()}:{Port}";
    }
}