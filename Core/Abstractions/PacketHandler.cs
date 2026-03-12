// Core/Abstractions/PacientHandler.cs
using System.Net;

namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Callback para manejo de paquetes entrantes.
    /// Equivalente a packet_handler_cb en network.h
    /// </summary>
    /// <param name="state">Objeto estado registrado (object en lugar de void* por seguridad de tipos)</param>
    /// <param name="source">Origen del paquete</param>
    /// <param name="packet">Datos del paquete (incluye el byte de tipo en [0])</param>
    /// <param name="userData">Datos de usuario del poll/contexto</param>
    /// <returns>
    /// En el C original retornaba int (0 éxito, -1 error), pero como es callback void 
    /// manejamos errores internamente o por excepciones controladas.
    /// </returns>
    public delegate void PacketHandlerCallback(
        object? state,
        IPEndPoint source,
        ReadOnlySpan<byte> packet,
        object? userData);
}