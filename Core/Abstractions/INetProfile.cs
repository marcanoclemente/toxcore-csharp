// Core/Abstractions/INetProfile.cs
using System;
using System.Collections.Generic;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz de estadísticas de tráfico de red.
    /// Equivalente a la API pública de net_profile.h
    /// </summary>
    public interface INetProfile
    {
        /// <summary>
        /// Registra un paquete enviado o recibido.
        /// Equivalente a net_profile_add().
        /// </summary>
        void RecordPacket(byte packetType, int size, PacketDirection direction);

        /// <summary>
        /// Obtiene estadísticas de un tipo de paquete específico.
        /// </summary>
        PacketStats GetStats(byte packetType);

        /// <summary>
        /// Obtiene todas las estadísticas.
        /// </summary>
        IReadOnlyDictionary<byte, PacketStats> GetAllStats();

        /// <summary>
        /// Obtiene resumen global.
        /// </summary>
        NetProfileSummary GetSummary();

        /// <summary>
        /// Resetea todas las estadísticas.
        /// Equivalente a net_profile_reset().
        /// </summary>
        void Reset();

        /// <summary>
        /// Imprime estadísticas al log.
        /// </summary>
        void LogStats();
    }

    /// <summary>
    /// Dirección del paquete (envío o recepción).
    /// </summary>
    public enum PacketDirection
    {
        Send,
        Receive
    }

    /// <summary>
    /// Estadísticas de un tipo de paquete específico.
    /// </summary>
    public class PacketStats
    {
        public byte PacketType { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long PacketsSent { get; set; }
        public long PacketsReceived { get; set; }

        public long TotalBytes => BytesSent + BytesReceived;
        public long TotalPackets => PacketsSent + PacketsReceived;
    }

    /// <summary>
    /// Resumen global de estadísticas.
    /// </summary>
    public class NetProfileSummary
    {
        public long TotalBytesSent { get; set; }
        public long TotalBytesReceived { get; set; }
        public long TotalPacketsSent { get; set; }
        public long TotalPacketsReceived { get; set; }
        public int UniquePacketTypes { get; set; }

        public long TotalBytes => TotalBytesSent + TotalBytesReceived;
        public long TotalPackets => TotalPacketsSent + TotalPacketsReceived;
    }
}