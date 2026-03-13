// Core/Abstractions/IForwarding.cs
using System;
using System.Net;

namespace Toxcore.Core.Abstractions
{
    /// <summary>
    /// Interfaz de sistema de reenvío de paquetes.
    /// </summary>
    public interface IForwarding : IDisposable
    {
        /// <summary>
        /// Solicita a un nodo que actúe como relay hacia un destino.
        /// </summary>
        uint RequestForwarding(IPEndPoint relay, byte[] targetPublicKey);

        /// <summary>
        /// Envía datos a través de un reenvío establecido.
        /// </summary>
        bool SendViaForwarding(uint forwardId, byte[] data);

        /// <summary>
        /// Cierra una conexión de reenvío.
        /// </summary>
        void CloseForwarding(uint forwardId);

        /// <summary>
        /// Habilita/deshabilita el modo relay.
        /// </summary>
        bool IsRelayEnabled { get; set; }

        /// <summary>
        /// Acepta una solicitud de reenvío entrante.
        /// </summary>
        bool AcceptForwarding(uint requestId, IPEndPoint clientEndpoint);

        /// <summary>
        /// Ciclo principal de mantenimiento.
        /// </summary>
        void DoForwarding();

        /// <summary>
        /// Evento cuando se reciben datos a través de reenvío.
        /// </summary>
        event Action<uint, byte[]> OnForwardedDataReceived;
    }
}