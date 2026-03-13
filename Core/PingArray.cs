using System;
using System.Buffers;
using System.Threading;
using Toxcore.Core.Crypto;

namespace Toxcore.Core
{
    /// <summary>
    /// Estructura interna equivalente a Ping_Array_Entry.
    /// Almacena datos asociados a un ping_id.
    /// </summary>
    internal struct PingEntry
    {
        public byte[] Data;
        public uint Length;
        public ulong PingTime;
        public ulong PingId;
    }

    /// <summary>
    /// Array circular eficiente para almacenar pings pendientes.
    /// Traducción de ping_array.c - usado por DHT para trackear requests de nodos.
    /// 
    /// Características:
    /// - Tamaño potencia de 2 (para máscara de bits eficiente)
    /// - Timeout automático de entradas viejas
    /// - IDs de ping generados criptográficamente (vía LibSodium)
    /// - Thread-safe para operaciones concurrentes (usando lock)
    /// </summary>
    public sealed class PingArray : IDisposable
    {
        private readonly PingEntry[] _entries;
        private readonly uint _totalSize;
        private readonly uint _timeout; // segundos
        private readonly MonoTime _monoTime;
        private readonly Func<ulong> _randomU64; // Fuente de random (por defecto LibSodium)

        private uint _lastDeleted;
        private uint _lastAdded;
        private readonly object _lock = new();

        /// <summary>
        /// Crea un nuevo PingArray.
        /// Equivalente a ping_array_new.
        /// </summary>
        /// <param name="monoTime">Instancia de tiempo monotónico.</param>
        /// <param name="size">Tamaño del array (debe ser potencia de 2).</param>
        /// <param name="timeout">Timeout en segundos para entradas.</param>
        /// <param name="randomProvider">Opcional: fuente de números aleatorios ulong. 
        /// Si es null, usa LibSodium vía RandomBytes.Generate().</param>
        public PingArray(MonoTime monoTime, uint size, uint timeout, Func<ulong> randomProvider = null!)
        {
            if (size == 0 || timeout == 0)
                throw new ArgumentException("Size and timeout must be non-zero");

            // Verificar potencia de 2: (size & (size - 1)) == 0
            if ((size & (size - 1)) != 0)
                throw new ArgumentException("Size must be a power of 2");

            _monoTime = monoTime ?? throw new ArgumentNullException(nameof(monoTime));
            _totalSize = size;
            _timeout = timeout;
            _entries = new PingEntry[size];

            // Por defecto usar LibSodium para random criptográfico seguro
            _randomU64 = randomProvider ?? (() =>
            {
                byte[] bytes = RandomBytes.Generate(8);
                return BitConverter.ToUInt64(bytes, 0);
            });

            _lastDeleted = 0;
            _lastAdded = 0;
        }

        /// <summary>
        /// Libera recursos.
        /// Equivalente a ping_array_kill.
        /// </summary>
        public void Dispose()
        {
            lock (_lock)
            {
                // Limpiar referencias para permitir GC
                for (int i = 0; i < _entries.Length; i++)
                {
                    _entries[i].Data = null!;
                }
            }
        }

        /// <summary>
        /// Agrega datos al array y retorna un ping_id único.
        /// Equivalente a ping_array_add.
        /// </summary>
        /// <param name="data">Datos a almacenar (se clonan).</param>
        /// <returns>ping_id (non-zero) en éxito, 0 en fallo.</returns>
        public ulong Add(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            lock (_lock)
            {
                return AddInternal(data);
            }
        }

        private ulong AddInternal(byte[] data)
        {
            ClearTimedOut();

            uint index = _lastAdded % _totalSize;

            // Si la entrada está ocupada (buffer circular lleno), avanzar deleted
            if (_entries[index].Data != null)
            {
                _lastDeleted = _lastAdded - _totalSize;
                ClearEntry(index);
            }

            // Copiar datos (en C usaba mem_balloc, aquí usamos Clone o ArrayPool)
            // Para datos pequeños (típico en DHT), Clone es suficiente y más simple
            _entries[index].Data = (byte[])data.Clone();
            _entries[index].Length = (uint)data.Length;
            _entries[index].PingTime = _monoTime.GetSeconds();

            _lastAdded++;

            // Generar ping_id: (random / size) * size + index
            // Esto asegura que el ID sea único y mapee de vuelta al índice
            ulong pingId = _randomU64();
            pingId /= _totalSize;
            pingId *= _totalSize;
            pingId += index;

            // Evitar ping_id = 0 (valor inválido)
            if (pingId == 0)
                pingId += _totalSize;

            _entries[index].PingId = pingId;
            return pingId;
        }

        /// <summary>
        /// Verifica si un ping_id es válido y no ha expirado.
        /// Si es válido, copia los datos al buffer proporcionado y limpia la entrada.
        /// Equivalente a ping_array_check.
        /// </summary>
        /// <param name="pingId">ID del ping a verificar.</param>
        /// <param name="data">Buffer donde copiar los datos.</param>
        /// <returns>Longitud de datos copiados en éxito, -1 en fallo.</returns>
        public int Check(ulong pingId, byte[] data)
        {
            if (pingId == 0 || data == null)
                return -1;

            lock (_lock)
            {
                return CheckInternal(pingId, data);
            }
        }

        private int CheckInternal(ulong pingId, byte[] data)
        {
            uint index = (uint)(pingId % _totalSize);

            // Verificar que el ID coincide (protección contra colisiones)
            if (_entries[index].PingId != pingId)
                return -1;

            // Verificar timeout
            if (_monoTime.IsTimeout(_entries[index].PingTime, _timeout))
                return -1;

            // Verificar que hay datos (sanity check)
            if (_entries[index].Data == null)
                return -1;

            // Verificar que el buffer destino es suficientemente grande
            if (_entries[index].Length > data.Length)
                return -1;

            int len = (int)_entries[index].Length;
            Buffer.BlockCopy(_entries[index].Data, 0, data, 0, len);

            // Limpiar entrada después de usar (como en el C original)
            ClearEntry(index);
            return len;
        }

        /// <summary>
        /// Limpia entradas que han expirado.
        /// Equivalente a ping_array_clear_timedout.
        /// </summary>
        private void ClearTimedOut()
        {
            while (_lastDeleted != _lastAdded)
            {
                uint index = _lastDeleted % _totalSize;

                // Si no ha hecho timeout, salir (las entradas están ordenadas por tiempo)
                if (!_monoTime.IsTimeout(_entries[index].PingTime, _timeout))
                    break;

                ClearEntry(index);
                _lastDeleted++;
            }
        }

        private void ClearEntry(uint index)
        {
            _entries[index].Data = null!;
            _entries[index].PingId = 0;
            _entries[index].Length = 0;
            _entries[index].PingTime = 0;
        }

        /// <summary>
        /// Número de entradas actualmente activas (no necesariamente timed-out).
        /// Útil para debugging.
        /// </summary>
        public uint Count
        {
            get
            {
                lock (_lock)
                {
                    return _lastAdded - _lastDeleted;
                }
            }
        }
    }
}