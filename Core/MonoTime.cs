using System;
using System.Diagnostics;
using System.Threading;

namespace ToxCore.Core
{
    /// <summary>
    /// Delegado para callback de tiempo personalizado (para testing).
    /// Equivalente a mono_time_current_time_cb.
    /// </summary>
    public delegate ulong MonoTimeCurrentTimeCallback();

    /// <summary>
    /// Implementación de tiempo monotónico para toxcore.
    /// Traducción de mono_time.c - garantiza que el tiempo nunca retroceda,
    /// incluso si el usuario cambia el reloj del sistema.
    /// 
    /// Thread-safe mediante ReaderWriterLockSlim (equivalente a pthread_rwlock).
    /// </summary>
    public sealed class MonoTime : IDisposable
    {
        private ulong _curTime;      // Tiempo cacheado actual (ms desde Unix epoch)
        private readonly ulong _baseTime; // Offset para alinear con Unix epoch
        private MonoTimeCurrentTimeCallback _currentTimeCallback;
        private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);

        // Stopwatch proporciona tiempo monotónico de alta resolución en .NET
        private readonly Stopwatch _stopwatch;

        /// <summary>
        /// Crea una nueva instancia de tiempo monotónico.
        /// Equivalente a mono_time_new con callback por defecto.
        /// </summary>
        public MonoTime() : this(null!) { }

        /// <summary>
        /// Crea una nueva instancia con callback personalizado (para testing).
        /// </summary>
        public MonoTime(MonoTimeCurrentTimeCallback currentTimeCallback)
        {
            _stopwatch = new Stopwatch();
            _stopwatch.Start();

            SetCurrentTimeCallback(currentTimeCallback);

            // Calcular base_time como en C: max(1, time()) * 1000 - current_time_monotonic
            // Esto permite que GetMilliseconds() retorne tiempo Unix mientras es monotónico internamente
            long unixTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            ulong monotonicNow = CurrentTimeMonotonicInternal();

            _baseTime = Math.Max(1UL, (ulong)unixTimeMs) - monotonicNow;

            // Actualizar tiempo inicial
            Update();
        }

        /// <summary>
        /// Actualiza el tiempo cacheado. Llamar una vez por iteración (como tox_iterate).
        /// Equivalente a mono_time_update.
        /// </summary>
        public void Update()
        {
            ulong newTime = _baseTime + CurrentTimeMonotonicInternal();

            _lock.EnterWriteLock();
            try
            {
                _curTime = newTime;
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Obtiene el tiempo monotónico actual en milisegundos (desde Unix epoch).
        /// Equivalente a mono_time_get_ms.
        /// </summary>
        public ulong GetMilliseconds()
        {
            _lock.EnterReadLock();
            try
            {
                return _curTime;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        /// <summary>
        /// Obtiene el tiempo monotónico actual en segundos (desde Unix epoch).
        /// Equivalente a mono_time_get.
        /// </summary>
        public ulong GetSeconds()
        {
            return GetMilliseconds() / 1000UL;
        }

        /// <summary>
        /// Verifica si timestamp + timeout <= tiempo_actual.
        /// timeout en segundos.
        /// Equivalente a mono_time_is_timeout.
        /// </summary>
        public bool IsTimeout(ulong timestamp, ulong timeout)
        {
            return timestamp + timeout <= GetSeconds();
        }

        /// <summary>
        /// Verifica timeout en milisegundos.
        /// </summary>
        public bool IsTimeoutMs(ulong timestampMs, ulong timeoutMs)
        {
            return timestampMs + timeoutMs <= GetMilliseconds();
        }

        /// <summary>
        /// Obtiene tiempo monotónico relativo (no necesariamente Unix epoch).
        /// Útil para medir intervalos.
        /// Equivalente a current_time_monotonic.
        /// </summary>
        public ulong CurrentTimeMonotonic()
        {
            return CurrentTimeMonotonicInternal();
        }

        /// <summary>
        /// Cambia el callback de tiempo (para tests o fuzzing).
        /// Equivalente a mono_time_set_current_time_callback.
        /// </summary>
        public void SetCurrentTimeCallback(MonoTimeCurrentTimeCallback callback)
        {
            _currentTimeCallback = callback ?? DefaultTimeCallback;
        }

        private ulong DefaultTimeCallback()
        {
            // Stopwatch.ElapsedTicks es monotónico y de alta resolución
            // Convertimos a milisegundos manteniendo precisión
            return (ulong)(_stopwatch.Elapsed.TotalMilliseconds);
        }

        private ulong CurrentTimeMonotonicInternal()
        {
            return _currentTimeCallback();
        }

        public void Dispose()
        {
            _lock?.Dispose();
        }
    }
}