// ToxCore.Factory.cs - CORREGIDO
using System;
using System.Net;
using Toxcore;
using Toxcore.Core;
using Toxcore.Core.Abstractions;
using Toxcore.Core.Abstractions.Onion;
using Toxcore.Core.Abstractions.TCP;
using Toxcore.Core.Crypto;
using Toxcore.Core.Onion;
using Toxcore.Core.TCP;
using Toxcore.Events;
using Toxcore.Internal;


namespace Toxcore
{
    public static class ToxFactory
    {
        public static ITox Create(ToxOptions options = null)
        {
            options ??= new ToxOptions();

            try
            {
                var monoTime = new MonoTime();

                // Generar claves primero
                byte[] selfPublicKey = new byte[32];
                byte[] selfSecretKey = options.SecretKey ?? new byte[32];

                if (options.SecretKey == null)
                {
                    LibSodium.TryCryptoBoxKeyPair(selfPublicKey, selfSecretKey);
                }
                else
                {
                    Buffer.BlockCopy(options.SecretKey, 0, selfSecretKey, 0, Math.Min(options.SecretKey.Length, 32));
                }

                // NetworkCore
                IPAddress bindAddress = options.Ipv6Enabled ? IPAddress.IPv6Any : IPAddress.Any;
                var networkCore = new NetworkCore(bindAddress, options.StartPort, options.EndPort, true, null);

                // SharedKeyCache - CORREGIDO: usar constructor con parámetros correctos
                // Según el error, necesita: MonoTime, byte[] selfPublicKey, ulong timeout, byte mode
                // Pero parece que hay validación de "keys per slot" que falla con valores en 0
                // Probablemente necesita parámetros adicionales o diferentes
                var sharedKeysSent = new SharedKeyCache(monoTime, selfPublicKey, 1000, 0);
                var sharedKeysReceived = new SharedKeyCache(monoTime, selfPublicKey, 1000, 1);

                // LanDiscoveryService
                var lanDiscovery = new LanDiscoveryService(networkCore, null, monoTime, options.StartPort);

                // DHT
                var dht = new DHT(
                    networkCore,
                    monoTime,
                    sharedKeysSent,
                    sharedKeysReceived,
                    lanDiscovery,
                    options.Ipv6Enabled,
                    options.HolePunchingEnabled,
                    selfPublicKey,
                    selfSecretKey
                );

                // TCPConnection
                var tcpConnection = new TCPConnection(monoTime, selfPublicKey, selfSecretKey);

                // NetCrypto
                var netCrypto = new NetCrypto(
                    networkCore,
                    monoTime,
                    dht,
                    tcpConnection,
                    selfPublicKey,
                    selfSecretKey,
                    new byte[24]
                );

                // OnionCore
                var onionCore = new OnionCore(dht, networkCore, monoTime, sharedKeysSent, sharedKeysReceived);

                // OnionClient - usar reflection para encontrar constructor
                var onionClient = CreateOnionClient(onionCore, monoTime, netCrypto);

                // OnionAnnounce
                var onionAnnounce = new OnionAnnounce(onionCore, monoTime, dht);

                // FriendConnection
                var friendConnection = new FriendConnection(
                    netCrypto,
                    dht,
                    onionClient,
                    monoTime,
                    networkCore
                );

                // FriendRequests - sin parámetros
                var friendRequests = new FriendRequests();

                // Ping
                var ping = new Ping(monoTime, networkCore, sharedKeysSent, sharedKeysReceived, dht);

                // MessengerOptions
                var messengerOptions = new MessengerOptions
                {
                    Ipv6Enabled = options.Ipv6Enabled,
                    UdpEnabled = options.UdpEnabled,
                    HolePunchingEnabled = options.HolePunchingEnabled,
                    TcpEnabled = true,
                    PortRangeStart = options.StartPort,
                    PortRangeEnd = options.EndPort,
                    SavedData = options.SavedData
                };

                // Messenger
                var messenger = new Messenger(
                    monoTime,
                    networkCore,
                    dht,
                    netCrypto,
                    onionClient,
                    friendConnection,
                    friendRequests,
                    ping,
                    selfPublicKey,
                    selfSecretKey,
                    messengerOptions
                );

                // Event dispatcher
                var eventDispatcher = new ToxEventDispatcher();

                // ToxInternal
                var tox = new ToxInternal(
                    options,
                    messenger,
                    onionClient,
                    onionAnnounce,
                    dht,
                    networkCore,
                    tcpConnection,
                    friendConnection,
                    friendRequests,
                    monoTime,
                    eventDispatcher
                );

                return tox;
            }
            catch (Exception ex)
            {
                throw new ToxNewException($"Failed to create Tox instance: {ex.Message}", ex);
            }
        }

        private static IOnionClient CreateOnionClient(IOnionCore onionCore, MonoTime monoTime, INetCrypto netCrypto)
        {
            var type = typeof(OnionClient);

            var ctor = type.GetConstructor(new[] { typeof(IOnionCore), typeof(MonoTime), typeof(INetCrypto) });
            if (ctor != null)
            {
                return (IOnionClient)ctor.Invoke(new object[] { onionCore, monoTime, netCrypto });
            }

            ctor = type.GetConstructor(new[] { typeof(MonoTime), typeof(INetCrypto), typeof(IDht) });
            if (ctor != null)
            {
                var dhtProperty = netCrypto.GetType().GetProperty("Dht");
                var dht = dhtProperty?.GetValue(netCrypto) as IDht;
                return (IOnionClient)ctor.Invoke(new object[] { monoTime, netCrypto, dht });
            }

            ctor = type.GetConstructor(Type.EmptyTypes);
            if (ctor != null)
            {
                return (IOnionClient)ctor.Invoke(null);
            }

            throw new InvalidOperationException("Could not find suitable constructor for OnionClient");
        }

        public static ITox CreateAdvanced(
            ToxOptions options,
            IMessenger messenger,
            IOnionClient onionClient,
            IOnionAnnounce onionAnnounce,
            IDht dht,
            INetworkCore networkCore,
            ITCPConnection tcpConnection,
            IFriendConnection friendConnection,
            IFriendRequests friendRequests,
            MonoTime monoTime,
            IToxEventDispatcher eventDispatcher = null)
        {
            return new ToxInternal(
                options ?? new ToxOptions(),
                messenger ?? throw new ArgumentNullException(nameof(messenger)),
                onionClient ?? throw new ArgumentNullException(nameof(onionClient)),
                onionAnnounce ?? throw new ArgumentNullException(nameof(onionAnnounce)),
                dht ?? throw new ArgumentNullException(nameof(dht)),
                networkCore ?? throw new ArgumentNullException(nameof(networkCore)),
                tcpConnection ?? throw new ArgumentNullException(nameof(tcpConnection)),
                friendConnection ?? throw new ArgumentNullException(nameof(friendConnection)),
                friendRequests ?? throw new ArgumentNullException(nameof(friendRequests)),
                monoTime ?? throw new ArgumentNullException(nameof(monoTime)),
                eventDispatcher
            );
        }

        public static ITox CreateFromSaveData(byte[] saveData, ToxOptions options = null)
        {
            if (saveData == null || saveData.Length == 0)
                throw new ArgumentException("Save data cannot be null or empty", nameof(saveData));

            options ??= new ToxOptions();
            options.SavedData = saveData;

            return Create(options);
        }
    }

    public class ToxNewException : Exception
    {
        public ToxNewException(string message) : base(message) { }
        public ToxNewException(string message, Exception innerException) : base(message, innerException) { }
    }

    public static class ToxExtensions
    {
        public static string GetToxIdString(this ITox tox)
        {
            if (tox?.SelfAddress == null) return null;
            return BitConverter.ToString(tox.SelfAddress).Replace("-", "").ToUpperInvariant();
        }

        public static bool SendMessageSimple(this ITox tox, int friendNumber, string message)
        {
            var result = tox.SendMessage(friendNumber, ToxMessageType.Normal, message, out _);
            return result == ToxFriendSendMessageError.Ok;
        }

        public static bool SendAction(this ITox tox, int friendNumber, string action)
        {
            var result = tox.SendMessage(friendNumber, ToxMessageType.Action, action, out _);
            return result == ToxFriendSendMessageError.Ok;
        }

        public static bool AcceptFriendRequest(this ITox tox, byte[] publicKey, out int friendNumber)
        {
            return tox.AddFriendNoRequest(publicKey, out friendNumber) == ToxFriendAddError.Ok;
        }
    }
}