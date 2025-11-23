using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ToxCore.Core;
using static ToxCore.Core.DHT;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de onion_announce.c - Anuncio de nodos en la red onion
    /// </summary>
    public class OnionAnnounce
    {
        private const string LOG_TAG = "ONION_ANNOUNCE";

        public const int ONION_ANNOUNCE_REQUEST_SIZE = 128;
        public const int ONION_ANNOUNCE_RESPONSE_SIZE = 64;
        public const int ONION_ANNOUNCE_MAX_ENTRIES = 10;
        public const int ONION_ANNOUNCE_TIMEOUT_MS = 300000; // 5 min

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OnionAnnounceEntry
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] PublicKey;
            public IPPort EndPoint;
            public long Timestamp;
            public bool IsActive;
        }

        private readonly List<OnionAnnounceEntry> _entries = new();
        private readonly object _lock = new object();

        public void AddEntry(byte[] publicKey, IPPort endPoint)
        {
            lock (_lock)
            {
                var existing = _entries.FirstOrDefault(e => ByteArraysEqual(e.PublicKey, publicKey));
                if (existing.IsActive)
                {
                    existing.Timestamp = DateTime.UtcNow.Ticks;
                    existing.EndPoint = endPoint;
                }
                else
                {
                    _entries.Add(new OnionAnnounceEntry
                    {
                        PublicKey = publicKey,
                        EndPoint = endPoint,
                        Timestamp = DateTime.UtcNow.Ticks,
                        IsActive = true
                    });
                }

                Cleanup();
            }
        }

        public List<OnionAnnounceEntry> GetClosest(byte[] targetId, int count = 4)
        {
            lock (_lock)
            {
                long cutoff = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * ONION_ANNOUNCE_TIMEOUT_MS;
                return _entries
                    .Where(e => e.IsActive && e.Timestamp > cutoff)
                    .OrderBy(e => KademliaDistance.Calculate(targetId, e.PublicKey), new KademliaDistanceComparer())
                    .Take(count)
                    .ToList();
            }
        }

        private void Cleanup()
        {
            long cutoff = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond * ONION_ANNOUNCE_TIMEOUT_MS;
            _entries.RemoveAll(e => e.Timestamp < cutoff);
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            return CryptoVerify.Verify(a, b);
        }
    }
}