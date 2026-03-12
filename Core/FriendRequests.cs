// Core/FriendRequests.cs - ACTUALIZADO, NO SIMULADO
using System;
using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using ToxCore.Core.Abstractions;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación exacta de friend_requests.c
    /// Maneja solicitudes de amistad entrantes con sistema nospam.
    /// </summary>
    public sealed class FriendRequests : IFriendRequests, IDisposable
    {
        #region Constantes

        public const int MaxFriendRequestDataSize = 1024; // Ajustar según ONION_CLIENT_MAX_DATA_SIZE - 100
        public const int MaxReceivedStored = 32;

        #endregion

        #region Estado Interno

        private uint _nospam;

        private FriendRequestCallback _handleFriendRequest;
        private bool _handleFriendRequestIsSet;
        private object _handleFriendRequestObject;

        private FriendRequestFilterCallback _filterFunction;
        private object _filterFunctionUserdata;

        private readonly byte[][] _receivedRequests;
        private ushort _receivedRequestsIndex;

        private IFriendConnection _friendConnections;

        #endregion

        #region Constructor

        public FriendRequests()
        {
            _receivedRequests = new byte[MaxReceivedStored][];
            for (int i = 0; i < MaxReceivedStored; i++)
            {
                _receivedRequests[i] = new byte[LibSodium.CRYPTO_PUBLIC_KEY_SIZE];
            }
            _receivedRequestsIndex = 0;
            _nospam = 0;

            Logger.Log.Info("[FriendRequests] Initialized");
        }

        #endregion

        #region Nospam

        public void SetNospam(uint nospam)
        {
            _nospam = nospam;
            Logger.Log.Debug($"[FriendRequests] Nospam set to {nospam:X8}");
        }

        public uint GetNospam()
        {
            return _nospam;
        }

        #endregion

        #region Gestión de Solicitudes Recibidas

        private void AddToReceivedList(byte[] realPk)
        {
            if (_receivedRequestsIndex >= MaxReceivedStored)
            {
                _receivedRequestsIndex = 0;
            }

            Buffer.BlockCopy(realPk, 0, _receivedRequests[_receivedRequestsIndex], 0, LibSodium.CRYPTO_PUBLIC_KEY_SIZE);
            _receivedRequestsIndex++;
        }

        private bool RequestReceived(byte[] realPk)
        {
            for (int i = 0; i < MaxReceivedStored; i++)
            {
                if (_receivedRequests[i].AsSpan().SequenceEqual(realPk))
                {
                    return true;
                }
            }
            return false;
        }

        public int RemoveRequestReceived(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return -1;

            for (int i = 0; i < MaxReceivedStored; i++)
            {
                if (_receivedRequests[i].AsSpan().SequenceEqual(publicKey))
                {
                    CryptographicOperations.ZeroMemory(_receivedRequests[i]);
                    return 0;
                }
            }

            return -1;
        }

        #endregion

        #region Callbacks

        public void SetFriendRequestCallback(FriendRequestCallback callback, object obj)
        {
            _handleFriendRequest = callback;
            _handleFriendRequestIsSet = true;
            _handleFriendRequestObject = obj;

            Logger.Log.Info("[FriendRequests] Friend request callback registered");
        }

        public void SetFilterFunction(FriendRequestFilterCallback filterCallback, object userdata)
        {
            _filterFunction = filterCallback;
            _filterFunctionUserdata = userdata;

            Logger.Log.Info("[FriendRequests] Filter function set");
        }

        #endregion

        #region Inicialización

        public void Init(IFriendConnection friendConnections)
        {
            _friendConnections = friendConnections ?? throw new ArgumentNullException(nameof(friendConnections));

            // Registrar nuestro callback en FriendConnection
            // Esto hace que FriendConnection nos llame cuando reciba un paquete 0x20
            _friendConnections.SetFriendRequestCallback(HandleFriendRequestPacket, this);

            Logger.Log.Info("[FriendRequests] Initialized with FriendConnection");
        }

        #endregion

        #region Handler de Paquetes - NO SIMULADO

        /// <summary>
        /// Handler real de paquetes de solicitud de amistad.
        /// Llamado por FriendConnection cuando recibe packet 0x20.
        /// 
        /// Formato del paquete que recibimos:
        /// [nospam(4 bytes)][mensaje...]
        /// 
        /// La public key viene como parámetro separado desde FriendConnection.
        /// </summary>
        private void HandleFriendRequestPacket(object obj, byte[] publicKey, byte[] data,
                                       uint length, object userdata)
        {
            // 1. Verificar longitud mínima (1 byte ID + 4 bytes nospam)
            // y máxima según onion_client.h
            const int ONION_CLIENT_MAX_DATA_SIZE = 1633; // Ajusta según tu proyecto
            if (length <= 1 + sizeof(uint) || length > ONION_CLIENT_MAX_DATA_SIZE)
            {
                Logger.Log.Debug("[FriendRequests] Invalid packet length");
                return;
            }

            // 2. Verificar que tenemos callback registrado
            if (!_handleFriendRequestIsSet)
            {
                Logger.Log.Debug("[FriendRequests] No callback registered, ignoring request");
                return;
            }

            // 3. Verificar si ya recibimos de esta persona (anti-duplicado)
            if (RequestReceived(publicKey))
            {
                Logger.Log.Debug($"[FriendRequests] Duplicate request from {Logger.SafeKeyThumb(publicKey)}");
                return;
            }

            // 4. Extraer nospam del paquete (bytes 1-4, little-endian)
            // NOTA: El byte 0 es el packet ID, se salta como en el C original
            int offset = 1;
            uint packetNospam = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));

            // Verificar nospam
            if (packetNospam != _nospam)
            {
                Logger.Log.Debug($"[FriendRequests] Nospam mismatch from {Logger.SafeKeyThumb(publicKey)}: " +
                               $"received {packetNospam:X8}, expected {_nospam:X8}");
                return;
            }

            // 5. Aplicar filtro si existe
            if (_filterFunction != null)
            {
                int filterResult = _filterFunction(_filterFunctionUserdata, publicKey);
                if (filterResult != 0)
                {
                    Logger.Log.Info($"[FriendRequests] Request from {Logger.SafeKeyThumb(publicKey)} " +
                                  $"filtered out (result: {filterResult})");
                    return;
                }
            }

            // 6. Agregar a lista de recibidos (anti-duplicado futuro)
            AddToReceivedList(publicKey);

            // 7. Calcular longitud del mensaje (después de nospam, restando el byte inicial)
            uint messageLen = length - sizeof(uint) - 1; // -1 por el byte ID saltado
            if (messageLen > MaxFriendRequestDataSize)
            {
                Logger.Log.Warning($"[FriendRequests] Message too long from {Logger.SafeKeyThumb(publicKey)}: {messageLen}");
                messageLen = MaxFriendRequestDataSize;
            }

            // 8. Extraer mensaje
            byte[] message = new byte[messageLen + 1]; // +1 para null terminator como en C
            if (messageLen > 0)
            {
                Buffer.BlockCopy(data, offset + sizeof(uint), message, 0, (int)messageLen);
            }
            message[messageLen] = 0; // Null terminator

            Logger.Log.Info($"[FriendRequests] Valid friend request from {Logger.SafeKeyThumb(publicKey)}");

            // 9. Llamar callback registrado (típicamente Messenger o UI)
            try
            {
                _handleFriendRequest?.Invoke(
                    _handleFriendRequestObject,
                    publicKey,
                    message,
                    messageLen,
                    userdata
                );
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"[FriendRequests] Callback error: {ex.Message}");
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            // Limpiar arrays sensibles
            for (int i = 0; i < MaxReceivedStored; i++)
            {
                if (_receivedRequests[i] != null)
                {
                    CryptographicOperations.ZeroMemory(_receivedRequests[i]);
                }
            }

            Logger.Log.Info("[FriendRequests] Killed");
        }

        #endregion
    }
}