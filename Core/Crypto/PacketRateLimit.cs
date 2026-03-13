// Core/Crypto/PacketRateLimit.cs - CORREGIDO (manteniendo estructura original)
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Toxcore.Core;
using Toxcore.Core.Abstractions;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Rate limiting por endpoint para prevenir flooding.
    /// Implementación de token bucket para control de tráfico.
    /// CORREGIDO: Bug en cleanup de buckets llenos (FirstOrDefault con struct).
    /// </summary>
    public sealed class PacketRateLimit : IDisposable
    {
        // Constantes originales
        private readonly int _capacityBytes;
        private readonly long _refillIntervalTicks;
        private readonly int _maxBuckets;
        private readonly object _lock = new object();
        private readonly ConcurrentDictionary<EndPoint, Bucket> _buckets = new();

        private bool _disposed;

        private class Bucket
        {
            public long Tokens;
            public long LastRefill;
        }

        public PacketRateLimit(int capacityBytes, int refillIntervalMs, int maxBuckets)
        {
            _capacityBytes = capacityBytes;
            _refillIntervalTicks = TimeSpan.FromMilliseconds(refillIntervalMs).Ticks;
            _maxBuckets = maxBuckets;
        }

        /// <summary>
        /// true = paquete permitido; false = dropear.
        /// CORREGIDO: Limpieza segura del bucket más antiguo.
        /// </summary>
        public bool ShouldAllow(IPEndPoint remote, int bytes)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(PacketRateLimit));

            lock (_lock)
            {
                // Limpieza periódica
                CleanupIfNeeded();

                var ep = (EndPoint)remote;

                if (!_buckets.TryGetValue(ep, out var b))
                {
                    // Limitar número máximo de buckets
                    if (_buckets.Count >= _maxBuckets)
                    {
                        // CORREGIDO: Eliminar el bucket más antiguo de forma segura
                        CleanupOldestBucket();
                    }

                    b = new Bucket { Tokens = _capacityBytes, LastRefill = DateTime.UtcNow.Ticks };
                    _buckets[ep] = b;
                }

                // Refill lógico (igual que antes)
                var now = DateTime.UtcNow.Ticks;
                long elapsed = now - b.LastRefill;

                if (elapsed > _refillIntervalTicks)
                {
                    b.Tokens = _capacityBytes;
                    b.LastRefill = now;
                }
                else
                {
                    long refill = _capacityBytes * elapsed / _refillIntervalTicks;
                    b.Tokens = Math.Min(_capacityBytes, b.Tokens + refill);
                    b.LastRefill = now;
                }

                if (b.Tokens >= bytes)
                {
                    b.Tokens -= bytes;
                    return true;
                }

                return false;
            }
        }

        /// <summary>
        /// CORREGIDO: Limpieza segura del bucket más antiguo.
        /// </summary>
        private void CleanupOldestBucket()
        {
            // CORREGIDO: Usar OrderBy y verificar si hay elementos antes de FirstOrDefault
            var oldest = _buckets.OrderBy(kvp => kvp.Value.LastRefill).FirstOrDefault();

            // CORREGIDO: Verificación segura - verificar si el Key no es null
            if (oldest.Key != null)
            {
                _buckets.TryRemove(oldest.Key, out _);
            }
        }

        /// <summary>
        /// Limpieza periódica de buckets antiguos.
        /// </summary>
        private void CleanupIfNeeded()
        {
            // Implementación original o ajustada según necesites
            // Por ejemplo: remover buckets no usados en X tiempo
        }

        /// <summary>
        /// Libera recursos.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _disposed = true;

            lock (_lock)
            {
                _buckets.Clear();
            }

            Logger.Log.Info("[PacketRateLimit] Disposed");
        }
    }
}