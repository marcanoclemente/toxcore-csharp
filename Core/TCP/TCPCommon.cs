// Core/TCP/TCPCommon.cs - CORREGIDO
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using ToxCore.Core.Abstractions;
using ToxCore.Core.Abstractions.TCP;

namespace ToxCore.Core.TCP
{
    /// <summary>
    /// Funciones comunes compartidas entre TCP client y server.
    /// Traducción de TCP_common.c
    /// </summary>
    public static class TCPCommon
    {
        // Constantes de TCP_common.h
        public const int NumReservedPorts = 16;
        public const int NumClientConnections = 256 - NumReservedPorts;
        public const int TcpPingFrequency = 30; // segundos
        public const int TcpPingTimeout = 10; // segundos
        public const int MaxPacketSize = 2048;

        // Tamaños de handshake
        public const int TcpHandshakePlainSize = LibSodium.CRYPTO_PUBLIC_KEY_SIZE + LibSodium.CRYPTO_NONCE_SIZE; // 32 + 24 = 56
        public const int TcpServerHandshakeSize = LibSodium.CRYPTO_NONCE_SIZE + TcpHandshakePlainSize + LibSodium.CRYPTO_MAC_SIZE; // 24 + 56 + 16 = 96
        public const int TcpClientHandshakeSize = LibSodium.CRYPTO_PUBLIC_KEY_SIZE + TcpServerHandshakeSize; // 32 + 96 = 128

        public const int TcpMaxOobDataLength = 1024;

        /// <summary>
        /// Tipos de paquetes TCP.
        /// </summary>
        public enum TcpPacket : byte
        {
            RoutingRequest = 0,
            RoutingResponse = 1,
            ConnectionNotification = 2,
            DisconnectNotification = 3,
            Ping = 4,
            Pong = 5,
            OobSend = 6,
            OobRecv = 7,
            OnionRequest = 8,
            OnionResponse = 9,
            ForwardRequest = 10,
            Forwarding = 11
        }

        /// <summary>
        /// Convierte tipo de paquete a string para logging.
        /// </summary>
        public static string TcpPacketTypeToString(TcpPacket type)
        {
            return type switch
            {
                TcpPacket.RoutingRequest => "TCP_PACKET_ROUTING_REQUEST",
                TcpPacket.RoutingResponse => "TCP_PACKET_ROUTING_RESPONSE",
                TcpPacket.ConnectionNotification => "TCP_PACKET_CONNECTION_NOTIFICATION",
                TcpPacket.DisconnectNotification => "TCP_PACKET_DISCONNECT_NOTIFICATION",
                TcpPacket.Ping => "TCP_PACKET_PING",
                TcpPacket.Pong => "TCP_PACKET_PONG",
                TcpPacket.OobSend => "TCP_PACKET_OOB_SEND",
                TcpPacket.OobRecv => "TCP_PACKET_OOB_RECV",
                TcpPacket.OnionRequest => "TCP_PACKET_ONION_REQUEST",
                TcpPacket.OnionResponse => "TCP_PACKET_ONION_RESPONSE",
                TcpPacket.ForwardRequest => "TCP_PACKET_FORWARD_REQUEST",
                TcpPacket.Forwarding => "TCP_PACKET_FORWARDING",
                _ => ""
            };
        }

        /// <summary>
        /// Intenta convertir int a TcpPacket enum.
        /// </summary>
        public static bool TcpPacketFromInt(uint value, out TcpPacket outEnum)
        {
            outEnum = (TcpPacket)value;
            return value <= 11;
        }

        /// <summary>
        /// Incrementa nonce para paquetes TCP (24-byte little-endian).
        /// </summary>
        public static void IncrementNonce(byte[] nonce)
        {
            if (nonce == null || nonce.Length != LibSodium.CRYPTO_NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {LibSodium.CRYPTO_NONCE_SIZE} bytes", nameof(nonce));

            for (int i = 0; i < LibSodium.CRYPTO_NONCE_SIZE; i++)
            {
                if (++nonce[i] != 0)
                    break;
            }
        }
    }

    /// <summary>
    /// Lista de prioridad de paquetes TCP.
    /// </summary>
    public class TCPPriorityList
    {
        public TCPPriorityList Next { get; set; }
        public ushort Size { get; set; }
        public ushort Sent { get; set; }
        public byte[] Data { get; set; }
    }

    /// <summary>
    /// Conexión TCP con estado de cifrado.
    /// </summary>
    public class TCPConnectionState
    {
        public Socket Sock { get; set; }
        public IPEndPoint IpPort { get; set; }

        public byte[] SentNonce { get; set; } = new byte[LibSodium.CRYPTO_NONCE_SIZE];
        public byte[] SharedKey { get; set; } = new byte[LibSodium.CRYPTO_SHARED_KEY_SIZE];

        public byte[] LastPacket { get; set; } = new byte[2 + TCPCommon.MaxPacketSize];
        public ushort LastPacketLength { get; set; }
        public ushort LastPacketSent { get; set; }

        public TCPPriorityList PriorityQueueStart { get; set; }
        public TCPPriorityList PriorityQueueEnd { get; set; }

        public INetProfile NetProfile { get; set; }
    }

    /// <summary>
    /// Manejador de conexiones TCP con funciones de envío/recepción.
    /// </summary>
    public static class TCPConnectionHandler
    {
        /// <summary>
        /// Limpia la lista de prioridad de paquetes.
        /// </summary>
        public static void WipePriorityList(TCPPriorityList priorityQueueStart)
        {
            var current = priorityQueueStart;
            while (current != null)
            {
                var next = current.Next;
                current.Data = null;
                current.Next = null;
                current = next;
            }
        }

        /// <summary>
        /// Envía datos pendientes no prioritarios.
        /// </summary>
        public static int SendPendingDataNonpriority(TCPConnectionState con)
        {
            if (con.LastPacketLength == 0)
                return 0;

            var left = (ushort)(con.LastPacketLength - con.LastPacketSent);
            var dataToSend = new ReadOnlySpan<byte>(con.LastPacket, con.LastPacketSent, left);

            try
            {
                int sent = con.Sock.Send(dataToSend);

                if (sent <= 0)
                    return -1;

                if (sent == left)
                {
                    con.LastPacketLength = 0;
                    con.LastPacketSent = 0;
                    return 0;
                }

                con.LastPacketSent += (ushort)sent;
                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPCommon] Send pending data failed: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Envía datos pendientes (prioritarios y no prioritarios).
        /// </summary>
        public static int SendPendingData(TCPConnectionState con)
        {
            if (SendPendingDataNonpriority(con) == -1)
                return -1;

            var current = con.PriorityQueueStart;

            while (current != null)
            {
                var left = (ushort)(current.Size - current.Sent);
                var dataToSend = new ReadOnlySpan<byte>(current.Data, current.Sent, left);

                int sent;
                try
                {
                    sent = con.Sock.Send(dataToSend);
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[TCPCommon] Send priority data failed: {ex.Message}");
                    sent = 0;
                }

                if (sent != left)
                {
                    if (sent > 0)
                        current.Sent += (ushort)sent;

                    break;
                }

                var completed = current;
                current = current.Next;
                completed.Data = null;
                completed.Next = null;
            }

            con.PriorityQueueStart = current;
            if (current == null)
                con.PriorityQueueEnd = null;

            return current == null ? 0 : -1;
        }

        private static bool AddPriority(TCPConnectionState con, byte[] packet, ushort size, ushort sent)
        {
            var newList = new TCPPriorityList
            {
                Data = new byte[size],
                Size = size,
                Sent = sent,
                Next = null
            };

            Buffer.BlockCopy(packet, 0, newList.Data, 0, size);

            if (con.PriorityQueueEnd != null)
            {
                con.PriorityQueueEnd.Next = newList;
            }
            else
            {
                con.PriorityQueueStart = newList;
            }

            con.PriorityQueueEnd = newList;
            return true;
        }

        /// <summary>
        /// Escribe paquete a conexión TCP segura (cifrada).
        /// </summary>
        public static int WritePacketTcpSecureConnection(
            TCPConnectionState con,
            ReadOnlySpan<byte> data,
            ushort length,
            bool priority)
        {
            if (length + LibSodium.CRYPTO_MAC_SIZE > TCPCommon.MaxPacketSize)
            {
                Logger.Log.Error($"[TCPCommon] Packet too large: {length + LibSodium.CRYPTO_MAC_SIZE} > {TCPCommon.MaxPacketSize}");
                return -1;
            }

            bool sendPriority = true;

            if (SendPendingData(con) == -1)
            {
                if (priority)
                    sendPriority = false;
                else
                    return 0;
            }

            var packetSize = (ushort)(sizeof(ushort) + length + LibSodium.CRYPTO_MAC_SIZE);
            var packet = new byte[packetSize];

            packet[0] = (byte)((length + LibSodium.CRYPTO_MAC_SIZE) >> 8);
            packet[1] = (byte)((length + LibSodium.CRYPTO_MAC_SIZE) & 0xFF);

            var cipher = packet.AsSpan(2);
            if (!LibSodium.TryCryptoBoxEasyAfterNm(cipher.ToArray(), data.ToArray(), con.SentNonce, con.SharedKey))
            {
                Logger.Log.Error("[TCPCommon] Encryption failed");
                return -1;
            }

            Buffer.BlockCopy(cipher.ToArray(), 0, packet, 2, cipher.Length);

            if (priority)
            {
                int sent = sendPriority ? SendRaw(con.Sock, packet) : 0;

                if (sent < 0)
                    sent = 0;

                TCPCommon.IncrementNonce(con.SentNonce);

                if (sent == packetSize)
                    return 1;

                return AddPriority(con, packet, packetSize, (ushort)sent) ? 1 : 0;
            }
            else
            {
                int sent = SendRaw(con.Sock, packet);

                if (sent <= 0)
                    return 0;

                TCPCommon.IncrementNonce(con.SentNonce);

                if (sent == packetSize)
                    return 1;

                Buffer.BlockCopy(packet, 0, con.LastPacket, 0, packetSize);
                con.LastPacketLength = packetSize;
                con.LastPacketSent = (ushort)sent;
                return 1;
            }
        }

        /// <summary>
        /// Lee paquete TCP raw del socket.
        /// </summary>
        public static int ReadTcpPacket(
            Socket sock,
            Span<byte> data,
            ushort length,
            IPEndPoint ipPort)
        {
            if (sock.Available < length)
            {
                if (sock.Available > 0)
                {
                    Logger.Log.Trace($"[TCPCommon] recv buffer has {sock.Available} bytes, but requested {length} bytes");
                }
                return -1;
            }

            try
            {
                int received = sock.Receive(data.Slice(0, length));

                if (received != length)
                {
                    Logger.Log.Error($"[TCPCommon] FAIL recv packet: got {received}, expected {length}");
                    return -1;
                }

                return received;
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[TCPCommon] Receive error: {ex.Message}");
                return -1;
            }
        }

        private static ushort ReadTcpLength(Socket sock, IPEndPoint ipPort)
        {
            if (sock.Available >= sizeof(ushort))
            {
                var lengthBuf = new byte[sizeof(ushort)];

                try
                {
                    int received = sock.Receive(lengthBuf);

                    if (received != sizeof(ushort))
                    {
                        Logger.Log.Error("[TCPCommon] FAIL recv length");
                        return 0;
                    }

                    ushort length = (ushort)((lengthBuf[0] << 8) | lengthBuf[1]);

                    if (length > TCPCommon.MaxPacketSize)
                    {
                        Logger.Log.Error($"[TCPCommon] TCP packet too large: {length} > {TCPCommon.MaxPacketSize}");
                        return 0xFFFF;
                    }

                    return length;
                }
                catch (Exception ex)
                {
                    Logger.Log.Error($"[TCPCommon] Read length error: {ex.Message}");
                    return 0xFFFF;
                }
            }

            return 0;
        }

        /// <summary>
        /// Lee paquete cifrado de conexión TCP segura.
        /// </summary>
        public static int ReadPacketTcpSecureConnection(
            Socket sock,
            ref ushort nextPacketLength,
            byte[] sharedKey,
            byte[] recvNonce,
            Span<byte> data,
            ushort maxLen,
            IPEndPoint ipPort)
        {
            if (nextPacketLength == 0)
            {
                ushort len = ReadTcpLength(sock, ipPort);

                if (len == 0xFFFF)
                    return -1;

                if (len == 0)
                    return 0;

                nextPacketLength = len;
            }

            if (maxLen + LibSodium.CRYPTO_MAC_SIZE < nextPacketLength)
            {
                Logger.Log.Debug($"[TCPCommon] packet too large: max {maxLen}, got {nextPacketLength}");
                return -1;
            }

            var dataEncrypted = new byte[nextPacketLength];
            int lenPacket = ReadTcpPacket(sock, dataEncrypted, nextPacketLength, ipPort);

            if (lenPacket == -1)
                return 0;

            if (lenPacket != nextPacketLength)
            {
                Logger.Log.Warning($"[TCPCommon] invalid packet length: {lenPacket}, expected {nextPacketLength}");
                return 0;
            }

            nextPacketLength = 0;

            var plain = new byte[lenPacket - LibSodium.CRYPTO_MAC_SIZE];
            if (!LibSodium.TryCryptoBoxOpenEasyAfterNm(plain, dataEncrypted, recvNonce, sharedKey))
            {
                Logger.Log.Error("[TCPCommon] Decryption failed");
                return -1;
            }

            plain.AsSpan().CopyTo(data);

            TCPCommon.IncrementNonce(recvNonce);

            return plain.Length;
        }

        private static int SendRaw(Socket sock, byte[] data)
        {
            try
            {
                return sock.Send(data);
            }
            catch
            {
                return -1;
            }
        }
    }
}