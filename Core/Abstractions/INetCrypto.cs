// Core/Abstractions/INetCrypto.cs - VERSIÓN COMPLETA
using System;
using System.Net;

namespace ToxCore.Core.Abstractions
{
    /// <summary>
    /// Interfaz completa de cifrado de conexiones de red (net_crypto.h).
    /// </summary>
    public interface INetCrypto : IDisposable
    {
        /// <summary>
        /// Establece conexión segura con un peer.
        /// Retorna true si se inició el handshake.
        /// </summary>
        bool EstablishSecureConnection(IPEndPoint endpoint, byte[] publicKey);

        /// <summary>
        /// Verifica si existe conexión segura establecida.
        /// </summary>
        bool IsConnectionSecure(IPEndPoint endpoint);

        /// <summary>
        /// Envía datos cifrados a través de una conexión establecida.
        /// </summary>
        int SendData(IPEndPoint endpoint, byte[] data);

        /// <summary>
        /// Obtiene shared key de una conexión.
        /// </summary>
        byte[] GetSharedKey(IPEndPoint endpoint);

        /// <summary>
        /// Cierra conexión segura por endpoint.
        /// </summary>
        void CloseConnection(IPEndPoint endpoint);

        /// <summary>
        /// Cierra conexión segura por ID.
        /// Equivalente a crypto_kill() en C.
        /// </summary>
        void CloseConnection(int connectionId);

        /// <summary>
        /// Ciclo de mantenimiento. Debe llamarse periódicamente.
        /// </summary>
        void DoNetCrypto();

        /// <summary>
        /// Obtiene endpoint para una public key.
        /// </summary>
        IPEndPoint GetEndpointForPublicKey(byte[] publicKey);

        /// <summary>
        /// Obtiene public key para un endpoint.
        /// </summary>
        byte[] GetPublicKeyForEndpoint(IPEndPoint endpoint);

        /// <summary>
        /// Obtiene ID de conexión para un endpoint.
        /// Equivalente a get_connection_id() en C.
        /// </summary>
        int GetConnectionId(IPEndPoint endpoint);

        /// <summary>
        /// Obtiene ID de conexión para una public key.
        /// </summary>
        int GetConnectionId(byte[] publicKey);

        /// <summary>
        /// Establece IP/Port directo para una conexión existente.
        /// Equivalente a set_direct_ip_port() en net_crypto.c
        /// 
        /// CRÍTICO: Permite actualizar la ruta de una conexión existente
        /// cuando descubrimos una mejor IP/Port (ej: vía DHT hole punching).
        /// </summary>
        /// <param name="connectionId">ID de la conexión</param>
        /// <param name="ipPort">Nuevo endpoint</param>
        /// <param name="redirect">Si es true, fuerza el cambio incluso si hay datos pendientes</param>
        /// <returns>true si se actualizó correctamente</returns>
        bool SetDirectIpPort(int connectionId, IPEndPoint ipPort, bool redirect);

        /// <summary>
        /// Registra un handler para un tipo específico de paquete.
        /// </summary>
        void RegisterPacketHandler(byte packetType, Action<IPEndPoint, byte[], int> handler);

        /// <summary>
        /// Desregistra un handler de paquete.
        /// </summary>
        void UnregisterPacketHandler(byte packetType);

        /// <summary>
        /// Evento: nueva conexión segura establecida.
        /// </summary>
        event Action<IPEndPoint, byte[]> OnConnectionSecured;

        /// <summary>
        /// Evento: datos recibidos de una conexión segura.
        /// </summary>
        event Action<IPEndPoint, byte[]> OnDataReceived;
    }
}