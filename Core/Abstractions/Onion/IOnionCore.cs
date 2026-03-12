// Core/Abstractions/Onion/IOnionCore.cs - COMPLETO Y CORREGIDO
using System;
using System.Net;

namespace ToxCore.Core.Abstractions.Onion
{
    /// <summary>
    /// Interfaz del núcleo de enrutamiento Onion.
    /// </summary>
    public interface IOnionCore : IDisposable
    {
        /// <summary>
        /// Envía un paquete a través de la red onion.
        /// </summary>
        bool SendOnionPacket(IPEndPoint[] path, byte[] destPublicKey, byte[] data, byte[] nonce);

        /// <summary>
        /// Envía una respuesta usando el reverse path (sendback).
        /// </summary>
        bool SendOnionResponse(IPEndPoint source, byte[] originalNonce, byte[] responseData);

        /// <summary>
        /// Establece el handler para datos onion recibidos.
        /// </summary>
        void SetOnionDataHandler(OnionDataHandler handler);

        /// <summary>
        /// Registra un handler para un tipo específico de paquete onion.
        /// </summary>
        void RegisterPacketHandler(byte packetType, OnionPacketHandler handler);

        /// <summary>
        /// Desregistra un handler de paquete.
        /// </summary>
        void UnregisterPacketHandler(byte packetType);

        /// <summary>
        /// Verifica si un endpoint es un nodo onion válido conocido.
        /// </summary>
        bool IsKnownOnionNode(IPEndPoint endpoint);

        /// <summary>
        /// Obtiene nodos candidatos para construir paths onion.
        /// </summary>
        IPEndPoint[] GetPathNodes(int count);

        /// <summary>
        /// Ciclo de mantenimiento del núcleo onion.
        /// </summary>
        void DoOnionCore();
    }

    /// <summary>
    /// Delegado para manejo de datos onion recibidos.
    /// </summary>
    public delegate void OnionDataHandler(IPEndPoint source, byte[] data, byte[] nonce);

    /// <summary>
    /// Handler específico para tipos de paquetes onion.
    /// </summary>
    public delegate void OnionPacketHandler(IPEndPoint source, byte[] data, byte[] senderPublicKey);
}