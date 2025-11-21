using System.Security.Cryptography;
using ToxCore.Core;

namespace ToxCore.FileTransfer
{
    /// <summary>
    /// Estados mejorados de transferencia de archivos
    /// </summary>
    public enum EnhancedFileTransferStatus
    {
        FILE_TRANSFER_STATUS_NONE,
        FILE_TRANSFER_STATUS_PAUSED,
        FILE_TRANSFER_STATUS_TRANSFERRING,
        FILE_TRANSFER_STATUS_COMPLETED,
        FILE_TRANSFER_STATUS_CANCELLED,
        FILE_TRANSFER_STATUS_ERROR,
        FILE_TRANSFER_STATUS_WAITING,
        FILE_TRANSFER_STATUS_HASH_VERIFYING,
        FILE_TRANSFER_STATUS_RESUMING
    }

    /// <summary>
    /// Control de transferencia mejorado
    /// </summary>
    public enum EnhancedFileControl
    {
        FILE_CONTROL_RESUME = 0,
        FILE_CONTROL_PAUSE = 1,
        FILE_CONTROL_CANCEL = 2,
        FILE_CONTROL_ACCEPT = 3,
        FILE_CONTROL_REJECT = 4,
        FILE_CONTROL_REQUEST_HASH = 5,
        FILE_CONTROL_SEND_HASH = 6,
        FILE_CONTROL_VERIFY_HASH = 7
    }

    public class TransferStatistics
    {
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public long BytesTransferred { get; set; }
        public double Progress { get; set; }
        public double Speed { get; set; }
        public EnhancedFileTransferStatus Status { get; set; }
        public TimeSpan EstimatedTimeRemaining { get; set; }
        public bool HashVerified { get; set; }

        public override string ToString()
        {
            return $"{FileName} - {Progress:F1}% ({Speed / 1024:F1} KB/s) - {Status}";
        }
    }


    /// <summary>
    /// Información completa de transferencia de archivo
    /// </summary>
    public class EnhancedFileTransfer
    {
        public int FriendNumber { get; set; }
        public int FileNumber { get; set; }
        public FileKind Kind { get; set; }
        public EnhancedFileTransferStatus Status { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public byte[] FileId { get; set; }
        public FileStream FileStream { get; set; }
        public long LastActivity { get; set; }
        public int TimeoutCounter { get; set; }
        public byte[] FileHash { get; set; }
        public byte[] ReceivedHash { get; set; }
        public bool HashVerified { get; set; }
        public int ChunkSize { get; set; }
        public int BandwidthLimit { get; set; } // KB/s
        public long TransferStartTime { get; set; }
        public double TransferSpeed { get; set; }
        public double ProgressPercentage => FileSize > 0 ? (double)(BytesSent + BytesReceived) / FileSize * 100.0 : 0.0;
        public TimeSpan EstimatedTimeRemaining
        {
            get
            {
                if (TransferSpeed <= 0) return TimeSpan.MaxValue;
                long remainingBytes = FileSize - (BytesSent + BytesReceived);
                return TimeSpan.FromSeconds(remainingBytes / TransferSpeed);
            }
        }

        // Para resumen de transferencias
        public List<FileSegment> TransferredSegments { get; set; }
        public Queue<FileSegment> PendingSegments { get; set; }

        public EnhancedFileTransfer(int friendNumber, int fileNumber)
        {
            FriendNumber = friendNumber;
            FileNumber = fileNumber;
            Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_NONE;
            FileId = new byte[32];
            FileHash = new byte[32]; // SHA256
            ReceivedHash = new byte[32];
            ChunkSize = 1024 * 16; // 16KB chunks por defecto
            BandwidthLimit = 0; // Sin límite por defecto
            TransferredSegments = new List<FileSegment>();
            PendingSegments = new Queue<FileSegment>();
            HashVerified = false;
            TransferStartTime = DateTime.UtcNow.Ticks;
        }

        public void UpdateTransferSpeed()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            double elapsedSeconds = (currentTime - TransferStartTime) / TimeSpan.TicksPerSecond;

            if (elapsedSeconds > 0)
            {
                TransferSpeed = (BytesSent + BytesReceived) / elapsedSeconds;
            }
        }
    }

    /// <summary>
    /// Segmento de archivo para transferencia
    /// </summary>
    public class FileSegment
    {
        public long StartPosition { get; set; }
        public int Length { get; set; }
        public byte[] Data { get; set; }
        public bool Transferred { get; set; }
        public long TransferTime { get; set; }

        public FileSegment(long start, int length)
        {
            StartPosition = start;
            Length = length;
            Data = new byte[length];
            Transferred = false;
        }
    }

    /// <summary>
    /// Callbacks mejorados para transferencia de archivos
    /// </summary>
    public class EnhancedFileTransferCallbacks
    {
        public delegate void FileReceiveCallback(EnhancedFileTransferManager manager, int friendNumber, int fileNumber,
            FileKind kind, long fileSize, string fileName, byte[] fileId, object userData);

        public delegate void FileChunkRequestCallback(EnhancedFileTransferManager manager, int friendNumber,
            int fileNumber, long position, int length, object userData);

        public delegate void FileChunkReceivedCallback(EnhancedFileTransferManager manager, int friendNumber,
            int fileNumber, long position, byte[] data, object userData);

        public delegate void FileTransferStatusChangedCallback(EnhancedFileTransferManager manager, int friendNumber,
            int fileNumber, EnhancedFileTransferStatus status, object userData);

        public delegate void FileTransferProgressCallback(EnhancedFileTransferManager manager, int friendNumber,
            int fileNumber, double progress, double speed, TimeSpan remaining, object userData);

        public delegate void FileHashVerifiedCallback(EnhancedFileTransferManager manager, int friendNumber,
            int fileNumber, bool verified, byte[] computedHash, object userData);

        public FileReceiveCallback OnFileReceive { get; set; }
        public FileChunkRequestCallback OnFileChunkRequest { get; set; }
        public FileChunkReceivedCallback OnFileChunkReceived { get; set; }
        public FileTransferStatusChangedCallback OnFileTransferStatusChanged { get; set; }
        public FileTransferProgressCallback OnFileTransferProgress { get; set; }
        public FileHashVerifiedCallback OnFileHashVerified { get; set; }
    }

    /// <summary>
    /// Gestor mejorado de transferencia de archivos
    /// </summary>
    public class EnhancedFileTransferManager : IDisposable
    {
        private const string LOG_TAG = "ENH_FILETRANSFER";

        // Constantes de configuración
        private const int MAX_CONCURRENT_TRANSFERS = 3;
        private const int DEFAULT_CHUNK_SIZE = 1024 * 16; // 16KB
        private const int MAX_CHUNK_SIZE = 1024 * 64; // 64KB
        private const int MIN_CHUNK_SIZE = 1024 * 4; // 4KB
        private const int TRANSFER_TIMEOUT_MS = 120000; // 2 minutos
        private const int HASH_VERIFICATION_TIMEOUT_MS = 30000; // 30 segundos
        private const int PROGRESS_UPDATE_INTERVAL_MS = 1000; // 1 segundo

        // Componentes
        private readonly Core.Tox _tox;
        private readonly EnhancedFileTransferCallbacks _callbacks;
        private readonly Dictionary<string, EnhancedFileTransfer> _activeTransfers;
        private readonly Dictionary<string, Timer> _progressTimers;
        private readonly object _transfersLock = new object();
        private readonly object _bandwidthLock = new object();
        private int _lastFileNumber;
        private bool _isRunning;
        private Thread _transferThread;
        private CancellationTokenSource _cancellationTokenSource;
        private long _totalBytesTransferred;
        private int _currentBandwidthUsage; // KB/s

        // Control de ancho de banda
        private readonly SemaphoreSlim _bandwidthSemaphore;
        private readonly int _maxBandwidth; // KB/s

        public EnhancedFileTransferCallbacks Callbacks => _callbacks;
        public bool IsRunning => _isRunning;
        public long TotalBytesTransferred => _totalBytesTransferred;

        public EnhancedFileTransferManager(Core.Tox tox, int maxBandwidth = 0)
        {
            _tox = tox ?? throw new ArgumentNullException(nameof(tox));
            _callbacks = new EnhancedFileTransferCallbacks();
            _activeTransfers = new Dictionary<string, EnhancedFileTransfer>();
            _progressTimers = new Dictionary<string, Timer>();
            _cancellationTokenSource = new CancellationTokenSource();
            _lastFileNumber = 0;
            _maxBandwidth = maxBandwidth;
            _bandwidthSemaphore = new SemaphoreSlim(maxBandwidth > 0 ? maxBandwidth : int.MaxValue, int.MaxValue);

            Logger.Log.Info($"[{LOG_TAG}] Enhanced File Transfer inicializado" +
                (maxBandwidth > 0 ? $" - Límite de ancho de banda: {maxBandwidth} KB/s" : ""));
        }

        /// <summary>
        /// Iniciar servicio de transferencia de archivos
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] Enhanced File Transfer ya está ejecutándose");
                return true;
            }

            try
            {
                _isRunning = true;
                _cancellationTokenSource = new CancellationTokenSource();

                // Iniciar hilo de transferencia
                _transferThread = new Thread(TransferWorker);
                _transferThread.IsBackground = true;
                _transferThread.Name = "EnhancedFileTransfer-Worker";
                _transferThread.Start();

                Logger.Log.Info($"[{LOG_TAG}] Servicio Enhanced File Transfer iniciado");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando Enhanced File Transfer: {ex.Message}");
                _isRunning = false;
                return false;
            }
        }

        /// <summary>
        /// Detener servicio de transferencia de archivos
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _isRunning = false;
                _cancellationTokenSource?.Cancel();

                // Pausar todas las transferencias activas
                lock (_transfersLock)
                {
                    foreach (var transfer in _activeTransfers.Values.ToList())
                    {
                        if (transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING)
                        {
                            transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_PAUSED;
                        }

                        transfer.FileStream?.Close();
                        transfer.FileStream?.Dispose();
                    }

                    _activeTransfers.Clear();
                }

                // Detener timers de progreso
                foreach (var timer in _progressTimers.Values)
                {
                    timer?.Dispose();
                }
                _progressTimers.Clear();

                _transferThread?.Join(2000);

                Logger.Log.Info($"[{LOG_TAG}] Servicio Enhanced File Transfer detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo Enhanced File Transfer: {ex.Message}");
            }
        }

        // ==================== API PÚBLICA MEJORADA ====================

        /// <summary>
        /// Enviar archivo con opciones avanzadas
        /// </summary>
        public int FileSend(int friendNumber, FileKind kind, string filePath,
            int chunkSize = 0, int bandwidthLimit = 0, bool enableHashVerification = true)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Archivo no existe: {filePath}");
                    return -1;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 1024L * 1024 * 1024 * 4) // 4GB límite
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Archivo demasiado grande: {fileInfo.Length} bytes");
                    return -1;
                }

                int fileNumber = _lastFileNumber++;
                var transfer = new EnhancedFileTransfer(friendNumber, fileNumber)
                {
                    Kind = kind,
                    FileSize = fileInfo.Length,
                    FileName = Path.GetFileName(filePath),
                    FilePath = filePath,
                    Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_WAITING,
                    ChunkSize = chunkSize > 0 ? Math.Min(chunkSize, MAX_CHUNK_SIZE) : DEFAULT_CHUNK_SIZE,
                    BandwidthLimit = bandwidthLimit
                };

                // Calcular hash del archivo
                if (enableHashVerification)
                {
                    transfer.FileHash = ComputeFileHash(filePath);
                }

                // Inicializar segmentos del archivo
                InitializeFileSegments(transfer);

                string transferKey = $"{friendNumber}_{fileNumber}";

                lock (_transfersLock)
                {
                    _activeTransfers[transferKey] = transfer;
                }

                // Iniciar timer de progreso
                StartProgressTimer(transfer);

                // Enviar solicitud de archivo
                byte[] fileRequest = CreateFileRequestPacket(transfer);
                int sent = _tox.Messenger.FriendConn.m_send_message(friendNumber, fileRequest, fileRequest.Length);

                if (sent > 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Envío de archivo iniciado: {filePath} ({fileInfo.Length} bytes) a friend {friendNumber}");
                    return fileNumber;
                }
                else
                {
                    lock (_transfersLock)
                    {
                        _activeTransfers.Remove(transferKey);
                    }
                    return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando envío de archivo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Enviar chunk de archivo con control de ancho de banda
        /// </summary>
        public async Task<bool> FileSendChunk(int friendNumber, int fileNumber, long position, byte[] data, int length)
        {
            if (!_isRunning) return false;

            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                EnhancedFileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer) ||
                        transfer.Status != EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING)
                    {
                        return false;
                    }
                }

                // Control de ancho de banda
                if (transfer.BandwidthLimit > 0)
                {
                    await _bandwidthSemaphore.WaitAsync();
                    try
                    {
                        // Simular limitación de ancho de banda
                        int delayMs = (length * 1000) / (transfer.BandwidthLimit * 1024);
                        if (delayMs > 0)
                        {
                            await Task.Delay(delayMs);
                        }
                    }
                    finally
                    {
                        _bandwidthSemaphore.Release();
                    }
                }

                // Crear paquete FILE_DATA mejorado
                byte[] packet = CreateEnhancedFileDataPacket(fileNumber, position, data, length);
                if (packet == null) return false;

                var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
                if (friend == null) return false;

                int sent = _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
                if (sent > 0)
                {
                    transfer.BytesSent += length;
                    transfer.LastActivity = DateTime.UtcNow.Ticks;
                    transfer.UpdateTransferSpeed();

                    // Marcar segmento como transferido
                    var segment = transfer.TransferredSegments.FirstOrDefault(s =>
                        s.StartPosition == position && s.Length == length);
                    if (segment != null)
                    {
                        segment.Transferred = true;
                        segment.TransferTime = DateTime.UtcNow.Ticks;
                    }

                    // Verificar si se completó la transferencia
                    if (transfer.BytesSent >= transfer.FileSize)
                    {
                        transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_HASH_VERIFYING;
                        Logger.Log.InfoF($"[{LOG_TAG}] Transferencia completada: {transfer.FileName}");

                        // Iniciar verificación de hash
                        if (transfer.FileHash != null && transfer.FileHash.Length > 0)
                        {
                            SendHashVerificationRequest(friendNumber, fileNumber);
                        }
                        else
                        {
                            transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED;
                            _callbacks.OnFileTransferStatusChanged?.Invoke(this, friendNumber, fileNumber,
                                EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED, null);
                        }
                    }

                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando chunk: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Control mejorado de transferencia
        /// </summary>
        public bool FileControl(int friendNumber, int fileNumber, EnhancedFileControl control)
        {
            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                EnhancedFileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                        return false;
                }

                bool success = ApplyEnhancedFileControl(transfer, control);
                if (!success) return false;

                // Enviar control al remitente
                SendEnhancedFileControl(friendNumber, fileNumber, control);

                Logger.Log.InfoF($"[{LOG_TAG}] Control de archivo {fileNumber}: {control}");

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en control de archivo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Reanudar transferencia desde el último punto
        /// </summary>
        public bool FileResume(int friendNumber, int fileNumber)
        {
            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                EnhancedFileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                        return false;
                }

                if (transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_PAUSED ||
                    transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_ERROR)
                {
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_RESUMING;

                    // Recalcular segmentos pendientes
                    RecalculatePendingSegments(transfer);

                    // Enviar solicitud de resumen
                    SendResumeRequest(friendNumber, fileNumber, transfer.BytesReceived);

                    Logger.Log.InfoF($"[{LOG_TAG}] Reanudando transferencia {fileNumber} desde byte {transfer.BytesReceived}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error reanudando transferencia: {ex.Message}");
                return false;
            }
        }

        // ==================== MANEJO DE PAQUETES MEJORADO ====================

        /// <summary>
        /// Manejar paquetes de transferencia de archivos mejorados
        /// </summary>
        public int HandleEnhancedFilePacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 5) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x50: // FILE_CONTROL_EXTENDED
                        return HandleEnhancedFileControl(friendNumber, packet, length);
                    case 0x51: // FILE_DATA_EXTENDED
                        return HandleEnhancedFileData(friendNumber, packet, length);
                    case 0x52: // FILE_REQUEST_EXTENDED
                        return HandleEnhancedFileRequest(friendNumber, packet, length);
                    case 0x53: // FILE_HASH_VERIFICATION
                        return HandleFileHashVerification(friendNumber, packet, length);
                    case 0x54: // FILE_RESUME_REQUEST
                        return HandleFileResumeRequest(friendNumber, packet, length);
                    case 0x55: // FILE_PROGRESS_UPDATE
                        return HandleFileProgressUpdate(friendNumber, packet, length);
                    default:
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete de archivo mejorado: {ex.Message}");
                return -1;
            }
        }

        private int HandleEnhancedFileRequest(int friendNumber, byte[] packet, int length)
        {
            if (length < 53) return -1;

            try
            {
                int fileNumber = BitConverter.ToInt32(packet, 1);
                long fileSize = BitConverter.ToInt64(packet, 5);

                byte[] fileId = new byte[32];
                Buffer.BlockCopy(packet, 13, fileId, 0, 32);

                int chunkSize = BitConverter.ToInt32(packet, 45);
                bool hasHash = packet[49] == 0x01;

                ushort fileNameLength = BitConverter.ToUInt16(packet, 50);
                string fileName = System.Text.Encoding.UTF8.GetString(packet, 52, fileNameLength);

                // Crear transferencia de recepción
                var transfer = new EnhancedFileTransfer(friendNumber, fileNumber)
                {
                    Kind = FileKind.TOX_FILE_KIND_DATA,
                    FileSize = fileSize,
                    FileName = fileName,
                    FileId = fileId,
                    ChunkSize = chunkSize,
                    Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_WAITING,
                    FilePath = Path.Combine(Path.GetTempPath(), $"tox_transfer_{fileNumber}_{fileName}")
                };

                string transferKey = $"{friendNumber}_{fileNumber}";

                lock (_transfersLock)
                {
                    _activeTransfers[transferKey] = transfer;
                }

                // Inicializar segmentos para recepción
                InitializeFileSegments(transfer);

                // Disparar callback
                _callbacks.OnFileReceive?.Invoke(this, friendNumber, fileNumber,
                    FileKind.TOX_FILE_KIND_DATA, fileSize, fileName, fileId, null);

                Logger.Log.InfoF($"[{LOG_TAG}] Solicitud de recepción de archivo: {fileName} ({fileSize} bytes)");

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando solicitud de archivo: {ex.Message}");
                return -1;
            }
        }

        private int HandleFileHashVerification(int friendNumber, byte[] packet, int length)
        {
            if (length < 37) return -1; // [type][file_number(4)][control(1)][hash(32)]

            int fileNumber = BitConverter.ToInt32(packet, 1);
            byte control = packet[5];
            byte[] hash = new byte[32];
            Buffer.BlockCopy(packet, 6, hash, 0, 32);

            string transferKey = $"{friendNumber}_{fileNumber}";
            EnhancedFileTransfer transfer;

            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    return -1;
            }

            if (control == 0x01) // Request hash
            {
                // Enviar nuestro hash
                SendFileHash(friendNumber, fileNumber, transfer.FileHash);
            }
            else if (control == 0x02) // Received hash
            {
                transfer.ReceivedHash = hash;
                VerifyFileHash(transfer);
            }

            return 0;
        }

        private int HandleFileResumeRequest(int friendNumber, byte[] packet, int length)
        {
            if (length < 13) return -1; // [type][file_number(4)][position(8)]

            int fileNumber = BitConverter.ToInt32(packet, 1);
            long resumePosition = BitConverter.ToInt64(packet, 5);

            string transferKey = $"{friendNumber}_{fileNumber}";
            EnhancedFileTransfer transfer;

            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    return -1;
            }

            // Ajustar la posición de reanudación
            transfer.BytesReceived = resumePosition;
            transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING;

            // Recalcular segmentos pendientes desde la posición de reanudación
            RecalculatePendingSegmentsFromPosition(transfer, resumePosition);

            Logger.Log.InfoF($"[{LOG_TAG}] Transferencia {fileNumber} reanudada desde posición {resumePosition}");

            return 0;
        }

        private int HandleFileProgressUpdate(int friendNumber, byte[] packet, int length)
        {
            if (length < 21) return -1; // [type][file_number(4)][progress(8)][speed(8)]

            int fileNumber = BitConverter.ToInt32(packet, 1);
            double progress = BitConverter.ToDouble(packet, 5);
            double speed = BitConverter.ToDouble(packet, 13);

            // Actualizar UI o estadísticas (opcional)
            // Podrías mantener estadísticas del peer remoto aquí

            return 0;
        }

        private void SendFileHash(int friendNumber, int fileNumber, byte[] hash)
        {
            if (hash == null) return;

            byte[] packet = new byte[38];
            packet[0] = 0x53; // FILE_HASH_VERIFICATION
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            packet[5] = 0x02; // Send hash
            Buffer.BlockCopy(hash, 0, packet, 6, 32);

            var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
            if (friend != null)
            {
                _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
            }
        }

        private void SendResumeRequest(int friendNumber, int fileNumber, long position)
        {
            byte[] packet = new byte[13];
            packet[0] = 0x54; // FILE_RESUME_REQUEST
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);

            var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
            if (friend != null)
            {
                _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
            }
        }

        private void SendProgressUpdate(int friendNumber, int fileNumber, double progress, double speed)
        {
            byte[] packet = new byte[21];
            packet[0] = 0x55; // FILE_PROGRESS_UPDATE
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(progress), 0, packet, 5, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(speed), 0, packet, 13, 8);

            var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
            if (friend != null)
            {
                _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
            }
        }

        private void RecalculatePendingSegmentsFromPosition(EnhancedFileTransfer transfer, long position)
        {
            transfer.PendingSegments.Clear();

            foreach (var segment in transfer.TransferredSegments)
            {
                if (segment.StartPosition >= position && !segment.Transferred)
                {
                    transfer.PendingSegments.Enqueue(segment);
                }
            }
        }

        // Método para aceptar una transferencia entrante
        public bool FileAccept(int friendNumber, int fileNumber, string savePath, int bandwidthLimit = 0)
        {
            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                EnhancedFileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer) ||
                        transfer.Status != EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_WAITING)
                    {
                        return false;
                    }

                    transfer.FilePath = savePath;
                    transfer.BandwidthLimit = bandwidthLimit;
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING;
                }

                // Iniciar timer de progreso
                StartProgressTimer(transfer);

                // Enviar aceptación
                SendEnhancedFileControl(friendNumber, fileNumber, EnhancedFileControl.FILE_CONTROL_ACCEPT);

                Logger.Log.InfoF($"[{LOG_TAG}] Transferencia {fileNumber} aceptada, guardando en: {savePath}");

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error aceptando transferencia: {ex.Message}");
                return false;
            }
        }

        // Método para obtener estadísticas de transferencia
        public TransferStatistics GetTransferStatistics(int friendNumber, int fileNumber)
        {
            string transferKey = $"{friendNumber}_{fileNumber}";

            lock (_transfersLock)
            {
                if (_activeTransfers.TryGetValue(transferKey, out var transfer))
                {
                    return new TransferStatistics
                    {
                        FileName = transfer.FileName,
                        FileSize = transfer.FileSize,
                        BytesTransferred = transfer.BytesSent + transfer.BytesReceived,
                        Progress = transfer.ProgressPercentage,
                        Speed = transfer.TransferSpeed,
                        Status = transfer.Status,
                        EstimatedTimeRemaining = transfer.EstimatedTimeRemaining,
                        HashVerified = transfer.HashVerified
                    };
                }
            }

            return null;
        }

        // Método para listar transferencias activas
        public List<EnhancedFileTransfer> GetActiveTransfers()
        {
            lock (_transfersLock)
            {
                return _activeTransfers.Values.ToList();
            }
        }




        private int HandleEnhancedFileControl(int friendNumber, byte[] packet, int length)
        {
            if (length < 6) return -1;

            int fileNumber = BitConverter.ToInt32(packet, 1);
            EnhancedFileControl control = (EnhancedFileControl)packet[5];

            string transferKey = $"{friendNumber}_{fileNumber}";
            EnhancedFileTransfer transfer;

            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    return -1;
            }

            return ApplyEnhancedFileControl(transfer, control) ? 0 : -1;
        }

        private int HandleEnhancedFileData(int friendNumber, byte[] packet, int length)
        {
            if (length < 25) return -1;

            int fileNumber = BitConverter.ToInt32(packet, 1);
            long position = BitConverter.ToInt64(packet, 5);
            int dataLength = BitConverter.ToInt32(packet, 13);
            uint sequence = BitConverter.ToUInt32(packet, 17);

            if (dataLength != length - 21)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Longitud de datos inconsistente en paquete de archivo");
                return -1;
            }

            byte[] data = new byte[dataLength];
            Buffer.BlockCopy(packet, 21, data, 0, dataLength);

            string transferKey = $"{friendNumber}_{fileNumber}";
            EnhancedFileTransfer transfer;

            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    return -1;
            }

            // Escribir datos en el archivo
            try
            {
                if (transfer.FileStream == null)
                {
                    transfer.FileStream = new FileStream(transfer.FilePath, FileMode.Create, FileAccess.Write);
                }

                transfer.FileStream.Seek(position, SeekOrigin.Begin);
                transfer.FileStream.Write(data, 0, dataLength);
                transfer.BytesReceived += dataLength;
                transfer.LastActivity = DateTime.UtcNow.Ticks;
                transfer.UpdateTransferSpeed();

                // Disparar callback de chunk recibido
                _callbacks.OnFileChunkReceived?.Invoke(this, friendNumber, fileNumber, position, data, null);

                // Verificar si se completó la recepción
                if (transfer.BytesReceived >= transfer.FileSize)
                {
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_HASH_VERIFYING;
                    transfer.FileStream?.Close();

                    // Verificar hash si está disponible
                    if (transfer.ReceivedHash != null && transfer.ReceivedHash.Length > 0)
                    {
                        VerifyFileHash(transfer);
                    }
                    else
                    {
                        transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED;
                        _callbacks.OnFileTransferStatusChanged?.Invoke(this, friendNumber, fileNumber,
                            EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED, null);
                    }

                    Logger.Log.InfoF($"[{LOG_TAG}] Recepción completada: {transfer.FileName}");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error escribiendo chunk de archivo: {ex.Message}");
                return -1;
            }
        }

        // ==================== MÉTODOS AUXILIARES MEJORADOS ====================

        private bool ApplyEnhancedFileControl(EnhancedFileTransfer transfer, EnhancedFileControl control)
        {
            switch (control)
            {
                case EnhancedFileControl.FILE_CONTROL_RESUME:
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING;
                    break;
                case EnhancedFileControl.FILE_CONTROL_PAUSE:
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_PAUSED;
                    break;
                case EnhancedFileControl.FILE_CONTROL_CANCEL:
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_CANCELLED;
                    CleanupTransfer(transfer);
                    break;
                case EnhancedFileControl.FILE_CONTROL_ACCEPT:
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING;
                    break;
                case EnhancedFileControl.FILE_CONTROL_REJECT:
                    transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_CANCELLED;
                    CleanupTransfer(transfer);
                    break;
                case EnhancedFileControl.FILE_CONTROL_REQUEST_HASH:
                    SendFileHash(transfer.FriendNumber, transfer.FileNumber, transfer.FileHash);
                    break;
                case EnhancedFileControl.FILE_CONTROL_VERIFY_HASH:
                    VerifyFileHash(transfer);
                    break;
                default:
                    return false;
            }

            _callbacks.OnFileTransferStatusChanged?.Invoke(this, transfer.FriendNumber, transfer.FileNumber, transfer.Status, null);
            return true;
        }

        private void InitializeFileSegments(EnhancedFileTransfer transfer)
        {
            transfer.TransferredSegments.Clear();
            transfer.PendingSegments.Clear();

            long position = 0;
            while (position < transfer.FileSize)
            {
                int chunkSize = (int)Math.Min(transfer.ChunkSize, transfer.FileSize - position);
                var segment = new FileSegment(position, chunkSize);
                transfer.TransferredSegments.Add(segment);
                transfer.PendingSegments.Enqueue(segment);
                position += chunkSize;
            }
        }

        private void RecalculatePendingSegments(EnhancedFileTransfer transfer)
        {
            transfer.PendingSegments.Clear();

            foreach (var segment in transfer.TransferredSegments)
            {
                if (!segment.Transferred)
                {
                    transfer.PendingSegments.Enqueue(segment);
                }
            }
        }

        private byte[] ComputeFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                return sha256.ComputeHash(stream);
            }
        }

        private void VerifyFileHash(EnhancedFileTransfer transfer)
        {
            try
            {
                byte[] computedHash = ComputeFileHash(transfer.FilePath);
                bool verified = computedHash.SequenceEqual(transfer.ReceivedHash);

                transfer.HashVerified = verified;
                transfer.Status = verified ?
                    EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED :
                    EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_ERROR;

                _callbacks.OnFileHashVerified?.Invoke(this, transfer.FriendNumber, transfer.FileNumber,
                    verified, computedHash, null);

                Logger.Log.InfoF($"[{LOG_TAG}] Verificación de hash {transfer.FileName}: {(verified ? "✅" : "❌")}");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error verificando hash: {ex.Message}");
                transfer.Status = EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_ERROR;
            }
        }

        private void CleanupTransfer(EnhancedFileTransfer transfer)
        {
            transfer.FileStream?.Close();
            transfer.FileStream?.Dispose();

            if (transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_CANCELLED)
            {
                // Eliminar archivo parcial si fue cancelado
                try
                {
                    if (File.Exists(transfer.FilePath))
                    {
                        File.Delete(transfer.FilePath);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] No se pudo eliminar archivo parcial: {ex.Message}");
                }
            }
        }

        // ==================== CREACIÓN DE PAQUETES MEJORADOS ====================

        private byte[] CreateFileRequestPacket(EnhancedFileTransfer transfer)
        {
            byte[] fileNameBytes = System.Text.Encoding.UTF8.GetBytes(transfer.FileName);
            byte[] packet = new byte[53 + fileNameBytes.Length];

            packet[0] = 0x52; // FILE_REQUEST_EXTENDED
            Buffer.BlockCopy(BitConverter.GetBytes(transfer.FileNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(transfer.FileSize), 0, packet, 5, 8);
            Buffer.BlockCopy(transfer.FileId, 0, packet, 13, 32);
            Buffer.BlockCopy(BitConverter.GetBytes(transfer.ChunkSize), 0, packet, 45, 4);
            packet[49] = (byte)(transfer.FileHash != null ? 0x01 : 0x00); // Hash flag
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)fileNameBytes.Length), 0, packet, 50, 2);
            Buffer.BlockCopy(fileNameBytes, 0, packet, 52, fileNameBytes.Length);

            return packet;
        }

        private byte[] CreateEnhancedFileDataPacket(int fileNumber, long position, byte[] data, int length)
        {
            byte[] packet = new byte[21 + length];
            packet[0] = 0x51; // FILE_DATA_EXTENDED
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(length), 0, packet, 13, 4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 17, 4); // Sequence
            Buffer.BlockCopy(data, 0, packet, 21, length);
            return packet;
        }

        private void SendEnhancedFileControl(int friendNumber, int fileNumber, EnhancedFileControl control)
        {
            byte[] packet = new byte[6];
            packet[0] = 0x50; // FILE_CONTROL_EXTENDED
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            packet[5] = (byte)control;

            var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
            if (friend != null)
            {
                _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
            }
        }

        private void SendHashVerificationRequest(int friendNumber, int fileNumber)
        {
            byte[] packet = new byte[6];
            packet[0] = 0x53; // FILE_HASH_VERIFICATION
            Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
            packet[5] = 0x01; // Request hash

            var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
            if (friend != null)
            {
                _tox.Messenger.Onion.onion_send_1(packet, packet.Length, friend.PublicKey);
            }
        }

        // ==================== WORKER PRINCIPAL ====================

        private void TransferWorker()
        {
            Logger.Log.Debug($"[{LOG_TAG}] Hilo Enhanced File Transfer iniciado");

            while (_isRunning && !_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    ProcessPendingTransfers();
                    CleanupCompletedTransfers();
                    Thread.Sleep(100); // Ejecutar cada 100ms
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] Error en worker: {ex.Message}");
                    }
                }
            }

            Logger.Log.Debug($"[{LOG_TAG}] Hilo Enhanced File Transfer finalizado");
        }

        private void ProcessPendingTransfers()
        {
            lock (_transfersLock)
            {
                var activeTransfers = _activeTransfers.Values
                    .Where(t => t.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING)
                    .Take(MAX_CONCURRENT_TRANSFERS) // Limitar transferencias concurrentes
                    .ToList();

                foreach (var transfer in activeTransfers)
                {
                    // Procesar siguiente segmento pendiente
                    if (transfer.PendingSegments.Count > 0)
                    {
                        var segment = transfer.PendingSegments.Dequeue();
                        if (!segment.Transferred)
                        {
                            // Leer datos del archivo y enviar
                            Task.Run(async () =>
                            {
                                try
                                {
                                    using (var fileStream = new FileStream(transfer.FilePath, FileMode.Open, FileAccess.Read))
                                    {
                                        fileStream.Seek(segment.StartPosition, SeekOrigin.Begin);
                                        byte[] buffer = new byte[segment.Length];
                                        int bytesRead = fileStream.Read(buffer, 0, segment.Length);

                                        if (bytesRead > 0)
                                        {
                                            await FileSendChunk(transfer.FriendNumber, transfer.FileNumber,
                                                segment.StartPosition, buffer, bytesRead);
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando segmento: {ex.Message}");
                                }
                            });
                        }
                    }
                }
            }
        }

        private void CleanupCompletedTransfers()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            List<string> transfersToRemove = new List<string>();

            lock (_transfersLock)
            {
                foreach (var kvp in _activeTransfers)
                {
                    var transfer = kvp.Value;
                    long timeSinceActivity = (currentTime - transfer.LastActivity) / TimeSpan.TicksPerMillisecond;

                    // Limpiar transferencias completadas o con timeout
                    if (transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED ||
                        transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_CANCELLED ||
                        transfer.Status == EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_ERROR ||
                        (timeSinceActivity > TRANSFER_TIMEOUT_MS &&
                         transfer.Status != EnhancedFileTransferStatus.FILE_TRANSFER_STATUS_PAUSED))
                    {
                        transfersToRemove.Add(kvp.Key);
                        CleanupTransfer(transfer);
                    }
                }

                foreach (string key in transfersToRemove)
                {
                    _activeTransfers.Remove(key);

                    // Detener timer de progreso
                    if (_progressTimers.ContainsKey(key))
                    {
                        _progressTimers[key]?.Dispose();
                        _progressTimers.Remove(key);
                    }
                }
            }

            if (transfersToRemove.Count > 0)
            {
                Logger.Log.DebugF($"[{LOG_TAG}] {transfersToRemove.Count} transferencias limpiadas");
            }
        }

        private void StartProgressTimer(EnhancedFileTransfer transfer)
        {
            string transferKey = $"{transfer.FriendNumber}_{transfer.FileNumber}";

            var timer = new Timer(state =>
            {
                if (_isRunning)
                {
                    transfer.UpdateTransferSpeed();
                    _callbacks.OnFileTransferProgress?.Invoke(this, transfer.FriendNumber, transfer.FileNumber,
                        transfer.ProgressPercentage, transfer.TransferSpeed, transfer.EstimatedTimeRemaining, null);
                }
            }, null, 0, PROGRESS_UPDATE_INTERVAL_MS);

            _progressTimers[transferKey] = timer;
        }

        /// <summary>
        /// Integración con el sistema de mensajes del Tox principal
        /// </summary>
        public int HandleToxPacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 1) return -1;

            byte packetType = packet[0];

            // Paquetes de file transfer mejorado (0x50-0x55)
            if (packetType >= 0x50 && packetType <= 0x55)
            {
                return HandleEnhancedFilePacket(friendNumber, packet, length);
            }

            return -1; // No es un paquete de file transfer
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource?.Dispose();
            _bandwidthSemaphore?.Dispose();

            foreach (var timer in _progressTimers.Values)
            {
                timer?.Dispose();
            }
        }
    }
}