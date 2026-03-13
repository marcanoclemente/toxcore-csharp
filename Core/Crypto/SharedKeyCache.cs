using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using Toxcore.Core;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Implementación de caché de claves compartidas Curve25519.
    /// Traducción de shared_key_cache.c.
    /// </summary>
    public sealed class SharedKeyCache : ISharedKeyCache
    {
        private struct SharedKeyEntry
        {
            public byte[] PublicKey;
            public byte[] SharedKey;
            public ulong TimeLastRequested; // 0 = vacío
        }

        private readonly SharedKeyEntry[] _keys;
        private readonly byte[] _selfSecretKey;
        private readonly ulong _timeoutMs;
        private readonly MonoTime _monoTime;
        private readonly int _keysPerSlot; // CAMBIADO: de uint a int
        private readonly object _lock = new();

        public SharedKeyCache(
            MonoTime monoTime,
            byte[] selfSecretKey,
            ulong timeoutSeconds,
            byte keysPerSlot)
        {
            if (monoTime == null) throw new ArgumentNullException(nameof(monoTime));
            if (selfSecretKey == null || selfSecretKey.Length != LibSodium.CRYPTO_SECRET_KEY_SIZE)
                throw new ArgumentException("Invalid secret key");
            if (timeoutSeconds == 0) throw new ArgumentException("Timeout must be non-zero");
            if (keysPerSlot == 0) throw new ArgumentException("Keys per slot must be non-zero");

            _monoTime = monoTime;
            _selfSecretKey = (byte[])selfSecretKey.Clone();
            _timeoutMs = timeoutSeconds * 1000;
            _keysPerSlot = keysPerSlot; // Asignación directa a int

            // 256 slots * keys_per_slot
            _keys = new SharedKeyEntry[256 * keysPerSlot];
        }

        public byte[] Lookup(ReadOnlySpan<byte> publicKey)
        {
            if (publicKey.Length != LibSodium.CRYPTO_PUBLIC_KEY_SIZE)
                return null;

            // Usar byte 8 de la public key para el bucket (como en C)
            int bucketIdx = publicKey[8];
            int startIdx = bucketIdx * _keysPerSlot; // CORREGIDO: ambos son int

            ulong curTime = _monoTime.GetMilliseconds();
            byte[] found = null;

            lock (_lock)
            {
                // Búsqueda
                for (int i = 0; i < _keysPerSlot; i++)
                {
                    int idx = startIdx + i;
                    ref var entry = ref _keys[idx];

                    if (entry.TimeLastRequested == 0) continue; // Vacío

                    if (entry.PublicKey != null &&
                        publicKey.SequenceEqual(entry.PublicKey))
                    {
                        entry.TimeLastRequested = curTime;
                        found = (byte[])entry.SharedKey.Clone();
                        break;
                    }
                }

                // Housekeeping (limpiar expirados en este bucket)
                for (int i = 0; i < _keysPerSlot; i++)
                {
                    int idx = startIdx + i;
                    ref var entry = ref _keys[idx];

                    if (entry.TimeLastRequested == 0) continue;

                    if (entry.TimeLastRequested + _timeoutMs < curTime)
                    {
                        // Limpiar entrada expirada
                        entry.PublicKey = null;
                        entry.SharedKey = null;
                        entry.TimeLastRequested = 0;
                    }
                }

                // Si no encontrado, insertar
                if (found == null)
                {
                    // Buscar entrada LRU (menor timestamp)
                    int oldestIdx = -1;
                    ulong oldestTime = ulong.MaxValue;

                    for (int i = 0; i < _keysPerSlot; i++)
                    {
                        int idx = startIdx + i;
                        if (_keys[idx].TimeLastRequested < oldestTime)
                        {
                            oldestTime = _keys[idx].TimeLastRequested;
                            oldestIdx = idx;
                        }
                    }

                    if (oldestIdx >= 0)
                    {
                        ref var entry = ref _keys[oldestIdx];

                        // Computar shared key
                        var sharedKey = new byte[LibSodium.CRYPTO_SHARED_KEY_SIZE];
                        if (!LibSodium.TryCryptoBoxBeforeNm(sharedKey,
                            publicKey.ToArray(), _selfSecretKey))
                        {
                            return null;
                        }

                        entry.PublicKey = publicKey.ToArray();
                        entry.SharedKey = sharedKey;
                        entry.TimeLastRequested = curTime;

                        found = (byte[])sharedKey.Clone();
                    }
                }
            }

            return found;
        }

        public void Dispose()
        {
            lock (_lock)
            {
                // Limpiar material criptográfico
                for (int i = 0; i < _keys.Length; i++)
                {
                    if (_keys[i].SharedKey != null)
                        CryptographicOperations.ZeroMemory(_keys[i].SharedKey);
                    _keys[i].PublicKey = null;
                    _keys[i].SharedKey = null;
                }
            }

            CryptographicOperations.ZeroMemory(_selfSecretKey);
        }
    }
}