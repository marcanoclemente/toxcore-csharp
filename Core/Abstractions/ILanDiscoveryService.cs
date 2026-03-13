// Core/Abstractions/ILanDiscoveryService.cs
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Servicio de descubrimiento LAN para ToxCore.
    /// Equivalente a LAN_discovery.h
    /// </summary>
    public interface ILanDiscoveryService
    {
        /// <summary>
        /// Inicializa el servicio y comienza el envío periódico.
        /// Equivalente a LANdiscovery_init.
        /// </summary>
        void Init();

        /// <summary>
        /// Detiene el servicio.
        /// Equivalente a LANdiscovery_kill.
        /// </summary>
        void Kill();

        /// <summary>
        /// Envía un paquete de descubrimiento LAN inmediatamente.
        /// Equivalente a send_LANdiscovery.
        /// </summary>
        /// <returns>true si se envió al menos a un destino, false si no hay interfaces válidas</returns>
        bool SendDiscovery();

        /// <summary>
        /// Verifica si una IP es local (LAN).
        /// Equivalente a LAN_ip / ip_is_local.
        /// </summary>
        bool IsLanIp(IPAddress ip);

        /// <summary>
        /// Habilita/deshabilita el envío periódico.
        /// </summary>
        bool Enabled { get; set; }
    }
}