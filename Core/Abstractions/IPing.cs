// Core/Abstractions/IPing.cs
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz del sistema de ping (ping.h).
    /// Separa Ping de DHT para evitar referencias circulares.
    /// Expone funcionalidad de PingArray para tracking de pings.
    /// </summary>
    public interface IPing
    {
        /// <summary>
        /// Agrega nodo a la lista de ping pendientes.
        /// </summary>
        int Add(byte[] publicKey, IPEndPoint ipPort);

        /// <summary>
        /// Itera enviando pings pendientes (llamar periódicamente).
        /// </summary>
        void Iterate();

        /// <summary>
        /// Envía ping request inmediato.
        /// </summary>
        void SendRequest(IPEndPoint ipPort, byte[] publicKey);

        /// <summary>
        /// Agrega datos al PingArray y retorna un ping_id único.
        /// Equivalente a ping_array_add.
        /// </summary>
        /// <param name="data">Datos a almacenar (se clonan).</param>
        /// <returns>ping_id (non-zero) en éxito, 0 en fallo.</returns>
        ulong AddToPingArray(byte[] data);

        /// <summary>
        /// Verifica si un ping_id es válido y no ha expirado.
        /// Equivalente a ping_array_check.
        /// </summary>
        /// <param name="pingId">ID del ping a verificar.</param>
        /// <param name="data">Buffer donde copiar los datos.</param>
        /// <returns>Longitud de datos copiados en éxito, -1 en fallo.</returns>
        int CheckPingArray(ulong pingId, byte[] data);
    }
}