// Core/Abstractions/INetworkCore.cs
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz del núcleo de networking UDP.
    /// Equivalente a la API pública de network.h / Networking_Core
    /// 
    /// Diseñada para ser implementada por NetworkCore y mockeada en tests.
    /// </summary>
    public interface INetworkCore : IDisposable
    {
        // ========== Propiedades de estado ==========

        /// <summary>
        /// Endpoint local al que está bind el socket.
        /// Equivalente a obtener la IP y puerto después del bind.
        /// </summary>
        IPEndPoint? LocalEndPoint { get; }

        /// <summary>
        /// Puerto en el que está escuchando (host byte order).
        /// Equivalente a net_port().
        /// </summary>
        ushort Port { get; }

        /// <summary>
        /// Familia de direcciones (IPv4/IPv6).
        /// Equivalente a net_family().
        /// </summary>
        System.Net.Sockets.AddressFamily Family { get; }

        /// <summary>
        /// Indica si el socket está activo y funcionando.
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Indica si es socket dual-stack (IPv4 e IPv6 simultáneos).
        /// </summary>
        bool IsDualStack { get; }

        // ========== Operaciones básicas de red ==========

        /// <summary>
        /// Envía un paquete a un destino específico.
        /// Equivalente a net_send_packet().
        /// </summary>
        /// <param name="destination">IP y puerto destino</param>
        /// <param name="packet">Datos a enviar (incluye byte de tipo)</param>
        /// <returns>Bytes enviados, o -1 en error</returns>
        int SendPacket(IPEndPoint destination, NetPacket packet);

        /// <summary>
        /// Envío legacy con buffer byte[].
        /// Equivalente a sendpacket() (deprecated en C pero útil para compat).
        /// </summary>
        int SendPacket(IPEndPoint destination, byte[] data, int length);

        // ========== Registro de handlers ==========

        /// <summary>
        /// Registra un callback para un tipo de paquete específico.
        /// Equivalente a networking_registerhandler().
        /// </summary>
        /// <param name="packetType">Primer byte del paquete (0x00-0xFF)</param>
        /// <param name="callback">Función a llamar cuando llegue ese tipo</param>
        /// <param name="state">Objeto de estado que se pasará al callback</param>
        void RegisterHandler(byte packetType, PacketHandlerCallback callback, object? state = null);

        /// <summary>
        /// Desregistra un handler.
        /// </summary>
        void UnregisterHandler(byte packetType);

        // ========== Ciclo de vida ==========

        /// <summary>
        /// Fuerza un poll manual (para modo síncrono).
        /// Equivalente a networking_poll().
        /// Nota: En implementaciones async, esto puede ser no-op si el loop corre automático.
        /// </summary>
        void Poll(object? userData = null);

        /// <summary>
        /// Inicializa el socket (equivalente a new_networking_ex).
        /// En C# típicamente se llama desde el constructor, pero expuesto aquí para reinicio.
        /// </summary>
        void Initialize(IPAddress? bindAddress = null, ushort portFrom = NetworkConstants.ToxPortRangeFrom, ushort portTo = NetworkConstants.ToxPortRangeTo);

        /// <summary>
        /// Cierra el socket y libera recursos.
        /// Equivalente a kill_networking().
        /// </summary>
        void Shutdown();
    }

    /// <summary>
    /// Constantes de networking del protocolo Tox.
    /// Extraídas de network.h para evitar duplicación.
    /// </summary>
    public static class NetworkConstants
    {
        public const int MaxUdpPacketSize = 2048;
        public const ushort ToxPortRangeFrom = 33445;
        public const ushort ToxPortRangeTo = 33545;
        public const ushort ToxPortDefault = ToxPortRangeFrom;

        public const int ToxInetAddrStrLen = 22;   // Para IPv4: xxx.xxx.xxx.xxx + null
        public const int ToxInet6AddrStrLen = 66;  // Para IPv6 full notation + null
        public const int IpNtoaLen = 96;           // Buffer size para mensajes de error + IP

        public const int SocketBufferSize = 1024 * 1024 * 2; // 2MB como en el C
    }

    /// <summary>
    /// Errores de conexión (para TCP principalmente, pero mantenido por compatibilidad).
    /// Equivalente a Net_Err_Connect.
    /// </summary>
    public enum NetErrConnect
    {
        Ok = 0,
        InvalidFamily = 1,
        Failed = 2
    }
}