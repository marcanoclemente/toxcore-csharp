using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ToxCore.Core;

namespace ToxCore.FileTransfer
{
    /// <summary>
    /// Estados de transferencia de archivos compatibles con toxcore
    /// </summary>
    public enum FileTransferStatus
    {
        FILE_TRANSFER_STATUS_NONE,
        FILE_TRANSFER_STATUS_PAUSED,
        FILE_TRANSFER_STATUS_TRANSFERRING,
        FILE_TRANSFER_STATUS_COMPLETED,
        FILE_TRANSFER_STATUS_CANCELLED,
        FILE_TRANSFER_STATUS_ERROR
    }

    /// <summary>
    /// Tipos de archivo compatibles
    /// </summary>
    public enum FileKind
    {
        TOX_FILE_KIND_DATA = 0,
        TOX_FILE_KIND_AVATAR = 1
    }

    /// <summary>
    /// Información de transferencia de archivo
    /// </summary>
    public class FileTransfer
    {
        public int FriendNumber { get; set; }
        public int FileNumber { get; set; }
        public FileKind Kind { get; set; }
        public FileTransferStatus Status { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public byte[] FileId { get; set; }
        public Stream FileStream { get; set; }
        public long LastActivity { get; set; }
        public int TimeoutCounter { get; set; }

        public FileTransfer(int friendNumber, int fileNumber)
        {
            FriendNumber = friendNumber;
            FileNumber = fileNumber;
            Status = FileTransferStatus.FILE_TRANSFER_STATUS_NONE;
            FileId = new byte[32];
            LastActivity = DateTime.UtcNow.Ticks;
        }

        public double Progress => FileSize > 0 ? (double)(BytesSent + BytesReceived) / FileSize * 100.0 : 0.0;
    }

    /// <summary>
    /// Callbacks para transferencia de archivos
    /// </summary>
    public class FileTransferCallbacks
    {
        public Action<int, int, FileKind, long, string, byte[], object> OnFileReceive;
        public Action<int, int, long, object> OnFileChunkRequest;
        public Action<int, int, long, byte[], object> OnFileChunkReceived;
        public Action<int, int, FileTransferStatus, object> OnFileTransferStatusChanged;
    }

    /// <summary>
    /// FileTransferManager - Gestor de transferencias de archivos como en toxcore
    /// </summary>
    public class FileTransferManager
    {
        private const string LOG_TAG = "FILETRANSFER";

        private readonly Messenger _messenger;
        private readonly Dictionary<string, FileTransfer> _activeTransfers;
        private readonly object _transfersLock = new object();
        private int _lastFileNumber;
        private readonly FileTransferCallbacks _callbacks;

        public FileTransferCallbacks Callbacks => _callbacks;

        public FileTransferManager(Messenger messenger)
        {
            _messenger = messenger;
            _activeTransfers = new Dictionary<string, FileTransfer>();
            _lastFileNumber = 0;
            _callbacks = new FileTransferCallbacks();
        }

        /// <summary>
        /// tox_file_send - Inicia envío de archivo a un amigo
        /// </summary>
        public int FileSend(int friendNumber, FileKind kind, long fileSize, string fileName, byte[] fileId = null)
        {
            try
            {
                if (!_messenger.FriendConn.Get_friend(friendNumber).HasValue)
                {
                    Logger.Log.ErrorF($"[{LOG_TAG}] Friend {friendNumber} no encontrado");
                    return -1;
                }

                int fileNumber = _lastFileNumber++;
                var transfer = new FileTransfer(friendNumber, fileNumber)
                {
                    Kind = kind,
                    FileSize = fileSize,
                    FileName = fileName,
                    Status = FileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING
                };

                if (fileId != null)
                {
                    Buffer.BlockCopy(fileId, 0, transfer.FileId, 0, Math.Min(fileId.Length, 32));
                }
                else
                {
                    // Generar fileId único si no se proporciona
                    RandomBytes.Generate(transfer.FileId);
                }

                string transferKey = $"{friendNumber}_{fileNumber}";

                lock (_transfersLock)
                {
                    _activeTransfers[transferKey] = transfer;
                }

                // Enviar control de archivo (FILE_CONTROL)
                SendFileControl(friendNumber, fileNumber, 0); // 0 = SEND

                Logger.Log.InfoF($"[{LOG_TAG}] Iniciando envío de archivo {fileName} ({fileSize} bytes) a friend {friendNumber}");

                return fileNumber;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando envío de archivo: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// tox_file_send_chunk - Envía chunk de archivo
        /// </summary>
        public bool FileSendChunk(int friendNumber, int fileNumber, long position, byte[] data, int length)
        {
            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                FileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] Transferencia no encontrada: {transferKey}");
                        return false;
                    }
                }

                if (transfer.Status != FileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING)
                {
                    Logger.Log.WarningF($"[{LOG_TAG}] Transferencia {transferKey} no está en estado de transferencia");
                    return false;
                }

                // Crear paquete FILE_DATA
                byte[] packet = CreateFileDataPacket(fileNumber, position, data, length);
                if (packet == null) return false;

                // Enviar a través de onion routing
                var friend = _messenger.FriendConn.Get_friend(friendNumber);
                if (!friend.HasValue) return false;

                int sent = _messenger.Onion.onion_send_1(packet, packet.Length, friend.Value.PublicKey);
                if (sent > 0)
                {
                    transfer.BytesSent += length;
                    transfer.LastActivity = DateTime.UtcNow.Ticks;

                    // Verificar si se completó la transferencia
                    if (transfer.BytesSent >= transfer.FileSize)
                    {
                        transfer.Status = FileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED;
                        Logger.Log.InfoF($"[{LOG_TAG}] Transferencia completada: {transfer.FileName}");

                        // Disparar callback de finalización
                        _callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, FileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED, null);
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
        /// tox_file_control - Control de transferencia (pausar, reanudar, cancelar)
        /// </summary>
        public bool FileControl(int friendNumber, int fileNumber, int control)
        {
            try
            {
                string transferKey = $"{friendNumber}_{fileNumber}";
                FileTransfer transfer;

                lock (_transfersLock)
                {
                    if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                        return false;
                }

                FileTransferStatus newStatus = transfer.Status;

                switch (control)
                {
                    case 0: // RESUME
                        newStatus = FileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING;
                        break;
                    case 1: // PAUSE
                        newStatus = FileTransferStatus.FILE_TRANSFER_STATUS_PAUSED;
                        break;
                    case 2: // CANCEL
                        newStatus = FileTransferStatus.FILE_TRANSFER_STATUS_CANCELLED;
                        break;
                    default:
                        return false;
                }

                transfer.Status = newStatus;
                transfer.LastActivity = DateTime.UtcNow.Ticks;

                // Enviar control al remitente
                SendFileControl(friendNumber, fileNumber, control);

                // Disparar callback
                _callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, newStatus, null);

                Logger.Log.InfoF($"[{LOG_TAG}] Control de archivo {fileNumber}: {control} -> {newStatus}");

                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en control de archivo: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Maneja paquetes de transferencia de archivos entrantes
        /// </summary>
        public int HandleFilePacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 5) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x50: // FILE_CONTROL
                        return HandleFileControl(friendNumber, packet, length);
                    case 0x51: // FILE_DATA
                        return HandleFileData(friendNumber, packet, length);
                    case 0x52: // FILE_REQUEST
                        return HandleFileRequest(friendNumber, packet, length);
                    default:
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete de archivo: {ex.Message}");
                return -1;
            }
        }

        private int HandleFileControl(int friendNumber, byte[] packet, int length)
        {
            if (length < 9) return -1; // [type][file_number(4)][control(4)]

            int fileNumber = BitConverter.ToInt32(packet, 1);
            int control = BitConverter.ToInt32(packet, 5);

            return FileControl(friendNumber, fileNumber, control) ? 0 : -1;
        }

        private int HandleFileData(int friendNumber, byte[] packet, int length)
        {
            if (length < 13) return -1; // [type][file_number(4)][position(8)] + data

            int fileNumber = BitConverter.ToInt32(packet, 1);
            long position = BitConverter.ToInt64(packet, 5);

            int dataLength = length - 13;
            byte[] data = new byte[dataLength];
            Buffer.BlockCopy(packet, 13, data, 0, dataLength);

            string transferKey = $"{friendNumber}_{fileNumber}";
            FileTransfer transfer;

            lock (_transfersLock)
            {
                if (!_activeTransfers.TryGetValue(transferKey, out transfer))
                    return -1;
            }

            // Procesar datos recibidos
            transfer.BytesReceived += dataLength;
            transfer.LastActivity = DateTime.UtcNow.Ticks;

            // Disparar callback de chunk recibido
            _callbacks.OnFileChunkReceived?.Invoke(friendNumber, fileNumber, position, data, null);

            // Verificar si se completó la recepción
            if (transfer.BytesReceived >= transfer.FileSize)
            {
                transfer.Status = FileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED;
                _callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, FileTransferStatus.FILE_TRANSFER_STATUS_COMPLETED, null);
                Logger.Log.InfoF($"[{LOG_TAG}] Recepción completada: {transfer.FileName}");
            }

            return 0;
        }

        private int HandleFileRequest(int friendNumber, byte[] packet, int length)
        {
            if (length < 45) return -1; // [type][file_number(4)][file_size(8)][file_id(32)] + filename

            int fileNumber = BitConverter.ToInt32(packet, 1);
            long fileSize = BitConverter.ToInt64(packet, 5);

            byte[] fileId = new byte[32];
            Buffer.BlockCopy(packet, 13, fileId, 0, 32);

            string fileName = System.Text.Encoding.UTF8.GetString(packet, 45, length - 45);

            // Disparar callback de archivo recibido
            _callbacks.OnFileReceive?.Invoke(friendNumber, fileNumber, FileKind.TOX_FILE_KIND_DATA, fileSize, fileName, fileId, null);

            Logger.Log.InfoF($"[{LOG_TAG}] Solicitud de archivo recibida: {fileName} ({fileSize} bytes)");

            return 0;
        }

        private byte[] CreateFileDataPacket(int fileNumber, long position, byte[] data, int length)
        {
            try
            {
                byte[] packet = new byte[13 + length];
                packet[0] = 0x51; // FILE_DATA type

                Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);
                Buffer.BlockCopy(data, 0, packet, 13, length);

                return packet;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error creando paquete FILE_DATA: {ex.Message}");
                return null;
            }
        }

        private void SendFileControl(int friendNumber, int fileNumber, int control)
        {
            try
            {
                byte[] packet = new byte[9];
                packet[0] = 0x50; // FILE_CONTROL type

                Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(control), 0, packet, 5, 4);

                var friend = _messenger.FriendConn.Get_friend(friendNumber);
                if (friend.HasValue)
                {
                    _messenger.Onion.onion_send_1(packet, packet.Length, friend.Value.PublicKey);
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando control de archivo: {ex.Message}");
            }
        }

        /// <summary>
        /// DoPeriodicWork - Mantenimiento de transferencias
        /// </summary>
        public void DoPeriodicWork()
        {
            try
            {
                long currentTime = DateTime.UtcNow.Ticks;
                List<string> transfersToRemove = new List<string>();

                lock (_transfersLock)
                {
                    foreach (var kvp in _activeTransfers)
                    {
                        var transfer = kvp.Value;
                        long timeSinceActivity = (currentTime - transfer.LastActivity) / TimeSpan.TicksPerMillisecond;

                        // Timeout después de 60 segundos de inactividad
                        if (timeSinceActivity > 60000 && transfer.Status == FileTransferStatus.FILE_TRANSFER_STATUS_TRANSFERRING)
                        {
                            transfer.Status = FileTransferStatus.FILE_TRANSFER_STATUS_ERROR;
                            transfersToRemove.Add(kvp.Key);

                            _callbacks.OnFileTransferStatusChanged?.Invoke(
                                transfer.FriendNumber, transfer.FileNumber,
                                FileTransferStatus.FILE_TRANSFER_STATUS_ERROR, null);

                            Logger.Log.WarningF($"[{LOG_TAG}] Timeout en transferencia: {transfer.FileName}");
                        }
                    }

                    // Remover transferencias completadas/error
                    foreach (var key in transfersToRemove)
                    {
                        _activeTransfers.Remove(key);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en trabajo periódico: {ex.Message}");
            }
        }
    }


}