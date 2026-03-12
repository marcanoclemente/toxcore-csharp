// Core/NetProfile.cs - CORREGIDO
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de estadísticas de tráfico de red.
    /// Traducción de net_profile.c
    /// </summary>
    public sealed class NetProfile : INetProfile, IDisposable
    {
        #region Estado Interno

        private readonly ConcurrentDictionary<byte, InternalPacketStats> _stats = new();
        private long _totalBytesSent;
        private long _totalBytesReceived;
        private long _totalPacketsSent;
        private long _totalPacketsReceived;

        #endregion

        #region INetProfile Implementation

        /// <summary>
        /// Registra un paquete enviado o recibido.
        /// </summary>
        public void RecordPacket(byte packetType, int size, PacketDirection direction)
        {
            var stats = _stats.GetOrAdd(packetType, _ => new InternalPacketStats { PacketType = packetType });

            if (direction == PacketDirection.Send)
            {
                // Usar lock en lugar de Interlocked porque no podemos usar ref en propiedades
                lock (stats)
                {
                    stats.BytesSent += size;
                    stats.PacketsSent++;
                }

                Interlocked.Add(ref _totalBytesSent, size);
                Interlocked.Increment(ref _totalPacketsSent);
            }
            else
            {
                lock (stats)
                {
                    stats.BytesReceived += size;
                    stats.PacketsReceived++;
                }

                Interlocked.Add(ref _totalBytesReceived, size);
                Interlocked.Increment(ref _totalPacketsReceived);
            }
        }

        /// <summary>
        /// Obtiene estadísticas de un tipo de paquete.
        /// </summary>
        public PacketStats GetStats(byte packetType)
        {
            if (_stats.TryGetValue(packetType, out var internalStats))
            {
                lock (internalStats)
                {
                    return new PacketStats
                    {
                        PacketType = internalStats.PacketType,
                        BytesSent = internalStats.BytesSent,
                        BytesReceived = internalStats.BytesReceived,
                        PacketsSent = internalStats.PacketsSent,
                        PacketsReceived = internalStats.PacketsReceived
                    };
                }
            }
            return null;
        }

        /// <summary>
        /// Obtiene todas las estadísticas.
        /// </summary>
        public IReadOnlyDictionary<byte, PacketStats> GetAllStats()
        {
            var result = new Dictionary<byte, PacketStats>();

            foreach (var kvp in _stats)
            {
                lock (kvp.Value)
                {
                    result[kvp.Key] = new PacketStats
                    {
                        PacketType = kvp.Value.PacketType,
                        BytesSent = kvp.Value.BytesSent,
                        BytesReceived = kvp.Value.BytesReceived,
                        PacketsSent = kvp.Value.PacketsSent,
                        PacketsReceived = kvp.Value.PacketsReceived
                    };
                }
            }

            return result;
        }

        /// <summary>
        /// Obtiene resumen global.
        /// </summary>
        public NetProfileSummary GetSummary()
        {
            return new NetProfileSummary
            {
                TotalBytesSent = Interlocked.Read(ref _totalBytesSent),
                TotalBytesReceived = Interlocked.Read(ref _totalBytesReceived),
                TotalPacketsSent = Interlocked.Read(ref _totalPacketsSent),
                TotalPacketsReceived = Interlocked.Read(ref _totalPacketsReceived),
                UniquePacketTypes = _stats.Count
            };
        }

        /// <summary>
        /// Resetea estadísticas.
        /// </summary>
        public void Reset()
        {
            _stats.Clear();
            Interlocked.Exchange(ref _totalBytesSent, 0);
            Interlocked.Exchange(ref _totalBytesReceived, 0);
            Interlocked.Exchange(ref _totalPacketsSent, 0);
            Interlocked.Exchange(ref _totalPacketsReceived, 0);
        }

        /// <summary>
        /// Imprime estadísticas al log.
        /// </summary>
        public void LogStats()
        {
            var summary = GetSummary();

            Logger.Log.Info($"[NetProfile] Total: {summary.TotalPacketsSent} pkt sent, {summary.TotalPacketsReceived} pkt recv");
            Logger.Log.Info($"[NetProfile] Bytes: {summary.TotalBytesSent} sent, {summary.TotalBytesReceived} recv");

            foreach (var kvp in _stats.OrderByDescending(x =>
            {
                lock (x.Value) return x.Value.TotalBytes;
            }))
            {
                PacketStats stats;
                lock (kvp.Value)
                {
                    stats = new PacketStats
                    {
                        PacketType = kvp.Value.PacketType,
                        BytesSent = kvp.Value.BytesSent,
                        BytesReceived = kvp.Value.BytesReceived,
                        PacketsSent = kvp.Value.PacketsSent,
                        PacketsReceived = kvp.Value.PacketsReceived
                    };
                }

                string typeName = GetPacketTypeName(kvp.Key);
                Logger.Log.Debug($"[NetProfile] 0x{kvp.Key:X2} ({typeName}): {stats.PacketsSent}/{stats.PacketsReceived} pkt, {stats.BytesSent}/{stats.BytesReceived} bytes");
            }
        }

        #endregion

        #region Utilidades

        private string GetPacketTypeName(byte type)
        {
            return type switch
            {
                0x00 => "PingReq",
                0x01 => "PingRes",
                0x02 => "GetNodes",
                0x04 => "SendNodes",
                0x18 => "CookieReq",
                0x19 => "CookieRes",
                0x1A => "CryptoHs",
                0x1B => "CryptoData",
                0x20 => "FriendReq",
                0x83 => "OnionAnnounceReq",
                0x84 => "OnionAnnounceRes",
                _ => "Unknown"
            };
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Reset();
            Logger.Log.Info("[NetProfile] Disposed");
        }

        #endregion

        #region Clase Interna para Estadísticas Thread-Safe

        /// <summary>
        /// Clase interna con campos (no propiedades) para permitir lock.
        /// </summary>
        private class InternalPacketStats
        {
            public byte PacketType;
            public long BytesSent;
            public long BytesReceived;
            public long PacketsSent;
            public long PacketsReceived;

            public long TotalBytes => BytesSent + BytesReceived;
            public long TotalPackets => PacketsSent + PacketsReceived;
        }

        #endregion
    }
}