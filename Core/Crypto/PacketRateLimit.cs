using System;
using System.Collections.Generic;
using System.Net;

namespace Toxcore.Core.Crypto
{
    /// <summary>
    /// Rate-limit UDP por IP + tamaño de paquete.
    /// Política: token-bucket 1 MiB / 60 s por IP.
    /// </summary>
    public sealed class PacketRateLimit
    {
        private readonly Dictionary<EndPoint, Bucket> _buckets = new();
        private readonly object _lock = new();
        private readonly long _capacityBytes;
        private readonly long _refillIntervalTicks;
        private readonly int _maxBuckets;
        private readonly TimeSpan _cleanupInterval;
        private DateTime _lastCleanup;

        public PacketRateLimit(int capacityMiB = 1, int refillSeconds = 60, int maxBuckets = 10000)
        {
            _capacityBytes = capacityMiB * 1024L * 1024L;
            _refillIntervalTicks = TimeSpan.TicksPerSecond * refillSeconds;
            _maxBuckets = maxBuckets;
            _cleanupInterval = TimeSpan.FromMinutes(5);
            _lastCleanup = DateTime.UtcNow;
        }

        /// <summary>
        /// true = paquete permitido; false = dropear.
        /// </summary>
        public bool ShouldAllow(IPEndPoint remote, int bytes)
        {
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
                        // Eliminar el bucket más antiguo
                        var oldest = _buckets.OrderBy(kvp => kvp.Value.LastRefill)
                                           .FirstOrDefault();
                        if (!oldest.Equals(default(KeyValuePair<EndPoint, Bucket>)))
                        {
                            _buckets.Remove(oldest.Key);
                        }
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

        private void CleanupIfNeeded()
        {
            if (DateTime.UtcNow - _lastCleanup < _cleanupInterval)
                return;

            var cutoff = DateTime.UtcNow.Ticks - 10 * _refillIntervalTicks;
            var toRemove = _buckets.Where(kvp => kvp.Value.LastRefill < cutoff)
                                   .Select(kvp => kvp.Key)
                                   .ToList();

            foreach (var key in toRemove)
            {
                _buckets.Remove(key);
            }

            _lastCleanup = DateTime.UtcNow;
        }

        private sealed class Bucket
        {
            public long Tokens;
            public long LastRefill;
        }
    }
}