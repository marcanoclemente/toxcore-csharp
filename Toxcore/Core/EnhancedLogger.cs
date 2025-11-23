using System.Collections.Concurrent;
using System.Text;
using System.Runtime.CompilerServices;

namespace ToxCore.Core
{
    /// <summary>
    /// Niveles de log mejorados con colores y categorías
    /// </summary>
    public enum EnhancedLogLevel
    {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        CRITICAL = 5,
        PERFORMANCE = 6,
        SECURITY = 7,
        NETWORK = 8
    }

    /// <summary>
    /// Categorías de log para filtrado
    /// </summary>
    public enum LogCategory
    {
        GENERAL,
        NETWORK,
        CRYPTO,
        DHT,
        MESSENGER,
        FILE_TRANSFER,
        GROUP_CHAT,
        AV,
        ONION,
        TCP,
        UDP,
        MEMORY,
        PERFORMANCE,
        SECURITY
    }

    /// <summary>
    /// Configuración del logger avanzado
    /// </summary>
    public class LoggerConfig
    {
        public string LogDirectory { get; set; } = "logs";
        public string FileNamePrefix { get; set; } = "tox";
        public bool EnableConsole { get; set; } = true;
        public bool EnableFileLogging { get; set; } = true;
        public bool EnableColors { get; set; } = true;
        public bool EnableTimestamps { get; set; } = true;
        public bool EnableCallerInfo { get; set; } = true;
        public int MaxFileSizeMB { get; set; } = 10;
        public int MaxFiles { get; set; } = 5;
        public EnhancedLogLevel MinLevel { get; set; } = EnhancedLogLevel.INFO;
        public LogCategory[] EnabledCategories { get; set; } = Enum.GetValues<LogCategory>();
        public bool AsyncLogging { get; set; } = true;
        public int QueueSize { get; set; } = 1000;
    }

    /// <summary>
    /// Entrada de log con información completa
    /// </summary>
    public struct LogEntry
    {
        public EnhancedLogLevel Level;
        public LogCategory Category;
        public string Message;
        public string File;
        public string Member;
        public int Line;
        public DateTime Timestamp;
        public Exception Exception;
        public string ThreadName;
        public long MemoryUsage;
    }

    /// <summary>
    /// Logger avanzado con múltiples destinos y características profesionales
    /// </summary>
    public class EnhancedLogger : IDisposable
    {
        private const string LOG_TAG = "ENH_LOGGER";

        // Componentes
        private readonly LoggerConfig _config;
        private readonly ConcurrentQueue<LogEntry> _logQueue;
        private readonly Thread _logWorker;
        private readonly CancellationTokenSource _cancellationTokenSource;
        private readonly object _fileLock = new object();
        private StreamWriter _currentFileWriter;
        private string _currentLogFile;
        private long _currentFileSize;
        private bool _isDisposed;
        private bool _isRunning;

        // Estadísticas
        private long _totalLogEntries;
        private long _droppedEntries;
        private DateTime _startTime;

        // Colores para consola (ANSI)
        private static readonly Dictionary<EnhancedLogLevel, string> _consoleColors = new()
        {
            [EnhancedLogLevel.TRACE] = "\x1b[37m",      // White
            [EnhancedLogLevel.DEBUG] = "\x1b[36m",      // Cyan
            [EnhancedLogLevel.INFO] = "\x1b[32m",       // Green
            [EnhancedLogLevel.WARNING] = "\x1b[33m",    // Yellow
            [EnhancedLogLevel.ERROR] = "\x1b[31m",      // Red
            [EnhancedLogLevel.CRITICAL] = "\x1b[35m",   // Magenta
            [EnhancedLogLevel.PERFORMANCE] = "\x1b[34m", // Blue
            [EnhancedLogLevel.SECURITY] = "\x1b[91m",   // Bright Red
            [EnhancedLogLevel.NETWORK] = "\x1b[94m"     // Bright Blue
        };

        private const string ResetColor = "\x1b[0m";

        // Categorías abreviadas
        private static readonly Dictionary<LogCategory, string> _categoryAbbr = new()
        {
            [LogCategory.GENERAL] = "GEN",
            [LogCategory.NETWORK] = "NET",
            [LogCategory.CRYPTO] = "CRY",
            [LogCategory.DHT] = "DHT",
            [LogCategory.MESSENGER] = "MSG",
            [LogCategory.FILE_TRANSFER] = "FIL",
            [LogCategory.GROUP_CHAT] = "GRP",
            [LogCategory.AV] = "AV",
            [LogCategory.ONION] = "ONI",
            [LogCategory.TCP] = "TCP",
            [LogCategory.UDP] = "UDP",
            [LogCategory.MEMORY] = "MEM",
            [LogCategory.PERFORMANCE] = "PER",
            [LogCategory.SECURITY] = "SEC"
        };

        public EnhancedLogger(LoggerConfig config = null)
        {
            _config = config ?? new LoggerConfig();
            _logQueue = new ConcurrentQueue<LogEntry>();
            _cancellationTokenSource = new CancellationTokenSource();

            InitializeLogging();

            if (_config.AsyncLogging)
            {
                _logWorker = new Thread(LogWorker);
                _logWorker.IsBackground = true;
                _logWorker.Name = "EnhancedLogger-Worker";
                _logWorker.Start();
            }

            _startTime = DateTime.UtcNow;
            LogInternal(EnhancedLogLevel.INFO, LogCategory.GENERAL,
                $"Enhanced Logger inicializado - Nivel: {_config.MinLevel}",
                "EnhancedLogger", ".ctor", 0);
        }

        /// <summary>
        /// Inicializar sistema de logging
        /// </summary>
        private void InitializeLogging()
        {
            try
            {
                if (_config.EnableFileLogging)
                {
                    // Crear directorio de logs
                    if (!Directory.Exists(_config.LogDirectory))
                    {
                        Directory.CreateDirectory(_config.LogDirectory);
                    }

                    // Crear archivo de log inicial
                    CreateNewLogFile();
                }

                _isRunning = true;
            }
            catch (Exception ex)
            {
                // Fallback a logging básico
                Console.WriteLine($"ERROR inicializando logger: {ex.Message}");
                _config.EnableFileLogging = false;
            }
        }

        /// <summary>
        /// Crear nuevo archivo de log
        /// </summary>
        private void CreateNewLogFile()
        {
            lock (_fileLock)
            {
                try
                {
                    _currentFileWriter?.Close();
                    _currentFileWriter?.Dispose();

                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    _currentLogFile = Path.Combine(_config.LogDirectory,
                        $"{_config.FileNamePrefix}_{timestamp}.log");

                    _currentFileWriter = new StreamWriter(_currentLogFile, true, Encoding.UTF8)
                    {
                        AutoFlush = true
                    };
                    _currentFileSize = 0;

                    // Escribir header del archivo
                    _currentFileWriter.WriteLine($"# ToxCore Log - Started {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    _currentFileWriter.WriteLine($"# Level: {_config.MinLevel}");
                    _currentFileWriter.WriteLine($"# Categories: {string.Join(", ", _config.EnabledCategories)}");
                    _currentFileWriter.WriteLine("# Fields: Timestamp|Level|Category|Thread|File:Line|Member|Message|Exception");
                    _currentFileWriter.WriteLine();

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"ERROR creando archivo de log: {ex.Message}");
                    _config.EnableFileLogging = false;
                }
            }
        }

        /// <summary>
        /// Log principal con información completa del caller
        /// </summary>
        public void Log(EnhancedLogLevel level, LogCategory category, string message,
            [CallerFilePath] string file = "",
            [CallerMemberName] string member = "",
            [CallerLineNumber] int line = 0)
        {
            if (!ShouldLog(level, category)) return;

            var entry = new LogEntry
            {
                Level = level,
                Category = category,
                Message = message,
                File = Path.GetFileName(file),
                Member = member,
                Line = line,
                Timestamp = DateTime.UtcNow,
                ThreadName = Thread.CurrentThread.Name ?? $"Thread_{Thread.CurrentThread.ManagedThreadId}",
                MemoryUsage = GC.GetTotalMemory(false)
            };

            if (_config.AsyncLogging)
            {
                // Logging asíncrono
                if (_logQueue.Count < _config.QueueSize)
                {
                    _logQueue.Enqueue(entry);
                    Interlocked.Increment(ref _totalLogEntries);
                }
                else
                {
                    Interlocked.Increment(ref _droppedEntries);
                    // Fallback síncrono para no perder logs críticos
                    if (level >= EnhancedLogLevel.ERROR)
                    {
                        ProcessLogEntrySync(entry);
                    }
                }
            }
            else
            {
                // Logging síncrono
                ProcessLogEntrySync(entry);
            }
        }

        /// <summary>
        /// Log con excepción
        /// </summary>
        public void LogException(EnhancedLogLevel level, LogCategory category, Exception exception, string context,
            [CallerFilePath] string file = "",
            [CallerMemberName] string member = "",
            [CallerLineNumber] int line = 0)
        {
            if (!ShouldLog(level, category)) return;

            string message = $"{context} - {exception.GetType().Name}: {exception.Message}";
            if (exception.InnerException != null)
            {
                message += $" -> {exception.InnerException.Message}";
            }

            var entry = new LogEntry
            {
                Level = level,
                Category = category,
                Message = message,
                File = Path.GetFileName(file),
                Member = member,
                Line = line,
                Timestamp = DateTime.UtcNow,
                Exception = exception,
                ThreadName = Thread.CurrentThread.Name ?? $"Thread_{Thread.CurrentThread.ManagedThreadId}",
                MemoryUsage = GC.GetTotalMemory(false)
            };

            if (_config.AsyncLogging)
            {
                _logQueue.Enqueue(entry);
            }
            else
            {
                ProcessLogEntrySync(entry);
            }
        }

        /// <summary>
        /// Verificar si se debe loguear
        /// </summary>
        private bool ShouldLog(EnhancedLogLevel level, LogCategory category)
        {
            return level >= _config.MinLevel &&
                   _config.EnabledCategories.Contains(category) &&
                   _isRunning;
        }

        /// <summary>
        /// Worker principal para logging asíncrono
        /// </summary>
        private void LogWorker()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested || !_logQueue.IsEmpty)
            {
                try
                {
                    if (_logQueue.TryDequeue(out LogEntry entry))
                    {
                        ProcessLogEntry(entry);
                    }
                    else
                    {
                        Thread.Sleep(10); // Pequeña pausa si no hay entries
                    }
                }
                catch (Exception ex)
                {
                    // Log de fallo del logger (usando Console como fallback)
                    Console.WriteLine($"LOGGER ERROR: {ex.Message}");
                    Thread.Sleep(100);
                }
            }
        }

        /// <summary>
        /// Procesar entrada de log
        /// </summary>
        private void ProcessLogEntry(LogEntry entry)
        {
            try
            {
                string formatted = FormatLogEntry(entry);

                if (_config.EnableConsole)
                {
                    WriteToConsole(entry, formatted);
                }

                if (_config.EnableFileLogging)
                {
                    WriteToFile(formatted);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR procesando log: {ex.Message}");
            }
        }

        /// <summary>
        /// Procesar entrada de log síncronamente
        /// </summary>
        private void ProcessLogEntrySync(LogEntry entry)
        {
            try
            {
                string formatted = FormatLogEntry(entry);

                if (_config.EnableConsole)
                {
                    WriteToConsole(entry, formatted);
                }

                if (_config.EnableFileLogging)
                {
                    WriteToFileSync(formatted);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR procesando log síncrono: {ex.Message}");
            }
        }

        /// <summary>
        /// Formatear entrada de log
        /// </summary>
        private string FormatLogEntry(LogEntry entry)
        {
            var sb = new StringBuilder();

            if (_config.EnableTimestamps)
            {
                sb.Append($"{entry.Timestamp:HH:mm:ss.fff}|");
            }

            sb.Append($"{entry.Level,-9}|");
            sb.Append($"{_categoryAbbr[entry.Category]}|");
            sb.Append($"{entry.ThreadName,-15}|");

            if (_config.EnableCallerInfo)
            {
                sb.Append($"{entry.File}:{entry.Line,-4}|");
                sb.Append($"{entry.Member,-20}|");
            }

            sb.Append(entry.Message);

            if (entry.Exception != null)
            {
                sb.Append($" | EXCEPTION: {entry.Exception}");
                if (entry.Exception.StackTrace != null)
                {
                    sb.Append($" | STACK: {entry.Exception.StackTrace}");
                }
            }

            // Agregar uso de memoria para logs de performance
            if (entry.Level == EnhancedLogLevel.PERFORMANCE)
            {
                sb.Append($" | MEM: {entry.MemoryUsage / 1024 / 1024}MB");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Escribir a consola con colores
        /// </summary>
        private void WriteToConsole(LogEntry entry, string formatted)
        {
            if (_config.EnableColors && _consoleColors.ContainsKey(entry.Level))
            {
                Console.WriteLine($"{_consoleColors[entry.Level]}{formatted}{ResetColor}");
            }
            else
            {
                Console.WriteLine(formatted);
            }
        }

        /// <summary>
        /// Escribir a archivo (thread-safe)
        /// </summary>
        private void WriteToFile(string formatted)
        {
            lock (_fileLock)
            {
                if (_currentFileWriter != null)
                {
                    _currentFileWriter.WriteLine(formatted);
                    _currentFileSize += formatted.Length + Environment.NewLine.Length;

                    // Rotar archivo si es muy grande
                    if (_currentFileSize > _config.MaxFileSizeMB * 1024 * 1024)
                    {
                        RotateLogFiles();
                    }
                }
            }
        }

        /// <summary>
        /// Escribir a archivo síncrono
        /// </summary>
        private void WriteToFileSync(string formatted)
        {
            try
            {
                lock (_fileLock)
                {
                    _currentFileWriter?.WriteLine(formatted);
                    _currentFileSize += formatted.Length + Environment.NewLine.Length;

                    if (_currentFileSize > _config.MaxFileSizeMB * 1024 * 1024)
                    {
                        RotateLogFiles();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR escribiendo a archivo: {ex.Message}");
            }
        }

        /// <summary>
        /// Rotar archivos de log
        /// </summary>
        private void RotateLogFiles()
        {
            try
            {
                CreateNewLogFile();
                CleanupOldLogs();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR rotando logs: {ex.Message}");
            }
        }

        /// <summary>
        /// Limpiar logs antiguos
        /// </summary>
        private void CleanupOldLogs()
        {
            try
            {
                var logFiles = Directory.GetFiles(_config.LogDirectory, $"{_config.FileNamePrefix}_*.log")
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.CreationTime)
                    .ToList();

                // Mantener solo los N archivos más recientes
                for (int i = _config.MaxFiles; i < logFiles.Count; i++)
                {
                    logFiles[i].Delete();
                }
            }
            catch (Exception ex)
            {
                LogInternal(EnhancedLogLevel.ERROR, LogCategory.GENERAL,
                    $"Error limpiando logs antiguos: {ex.Message}", "EnhancedLogger", "CleanupOldLogs", 0);
            }
        }

        /// <summary>
        /// Log interno del logger (evita recursión)
        /// </summary>
        private void LogInternal(EnhancedLogLevel level, LogCategory category, string message,
            string file, string member, int line)
        {
            var entry = new LogEntry
            {
                Level = level,
                Category = category,
                Message = message,
                File = file,
                Member = member,
                Line = line,
                Timestamp = DateTime.UtcNow,
                ThreadName = "Logger"
            };

            ProcessLogEntrySync(entry);
        }

        /// <summary>
        /// Obtener estadísticas del logger
        /// </summary>
        public LoggerStats GetStats()
        {
            return new LoggerStats
            {
                TotalEntries = _totalLogEntries,
                DroppedEntries = _droppedEntries,
                QueueSize = _logQueue.Count,
                Uptime = DateTime.UtcNow - _startTime,
                CurrentLogFile = _currentLogFile,
                CurrentFileSize = _currentFileSize
            };
        }

        /// <summary>
        /// Flushear logs pendientes
        /// </summary>
        public void Flush()
        {
            if (_config.AsyncLogging)
            {
                // Procesar cola restante
                while (!_logQueue.IsEmpty)
                {
                    if (_logQueue.TryDequeue(out LogEntry entry))
                    {
                        ProcessLogEntrySync(entry);
                    }
                }
            }

            lock (_fileLock)
            {
                _currentFileWriter?.Flush();
            }
        }

        public void Dispose()
        {
            if (_isDisposed) return;

            _isRunning = false;
            _cancellationTokenSource?.Cancel();

            // Esperar a que el worker termine
            if (_config.AsyncLogging)
            {
                _logWorker?.Join(2000);
            }

            // Flushear logs finales
            Flush();

            _cancellationTokenSource?.Dispose();

            lock (_fileLock)
            {
                _currentFileWriter?.Close();
                _currentFileWriter?.Dispose();
            }

            _isDisposed = true;

            LogInternal(EnhancedLogLevel.INFO, LogCategory.GENERAL,
                "Enhanced Logger detenido", "EnhancedLogger", "Dispose", 0);
        }

        // ==================== MÉTODOS DE CONVENIENCIA ====================

        public void Trace(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.TRACE, category, message, file, member, line);

        public void Debug(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.DEBUG, category, message, file, member, line);

        public void Info(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.INFO, category, message, file, member, line);

        public void Warning(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.WARNING, category, message, file, member, line);

        public void Error(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.ERROR, category, message, file, member, line);

        public void Critical(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.CRITICAL, category, message, file, member, line);

        public void Performance(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.PERFORMANCE, LogCategory.PERFORMANCE, message, file, member, line);

        public void Security(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.SECURITY, LogCategory.SECURITY, message, file, member, line);

        public void Network(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.NETWORK, LogCategory.NETWORK, message, file, member, line);
    }

    /// <summary>
    /// Estadísticas del logger
    /// </summary>
    public class LoggerStats
    {
        public long TotalEntries { get; set; }
        public long DroppedEntries { get; set; }
        public int QueueSize { get; set; }
        public TimeSpan Uptime { get; set; }
        public string CurrentLogFile { get; set; }
        public long CurrentFileSize { get; set; }

        public override string ToString()
        {
            return $"Logger Stats - Entries: {TotalEntries}, Dropped: {DroppedEntries}, " +
                   $"Queue: {QueueSize}, Uptime: {Uptime:hh\\:mm\\:ss}";
        }
    }

    /// <summary>
    /// Logger global para uso fácil en toda la aplicación
    /// </summary>
    public static class GlobalLogger
    {
        private static EnhancedLogger _instance;
        private static readonly object _lock = new object();

        public static void Initialize(LoggerConfig config = null)
        {
            lock (_lock)
            {
                _instance?.Dispose();
                _instance = new EnhancedLogger(config);
            }
        }

        public static void Log(EnhancedLogLevel level, LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
        {
            _instance?.Log(level, category, message, file, member, line);
        }

        public static void LogException(EnhancedLogLevel level, LogCategory category, Exception ex, string context,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
        {
            _instance?.LogException(level, category, ex, context, file, member, line);
        }

        // Métodos de conveniencia
        public static void Trace(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.TRACE, category, message, file, member, line);

        public static void Debug(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.DEBUG, category, message, file, member, line);

        public static void Info(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.INFO, category, message, file, member, line);

        public static void Warning(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.WARNING, category, message, file, member, line);

        public static void Error(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.ERROR, category, message, file, member, line);

        public static void Critical(LogCategory category, string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.CRITICAL, category, message, file, member, line);

        public static void Performance(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.PERFORMANCE, LogCategory.PERFORMANCE, message, file, member, line);

        public static void Security(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.SECURITY, LogCategory.SECURITY, message, file, member, line);

        public static void Network(string message,
            [CallerFilePath] string file = "", [CallerMemberName] string member = "", [CallerLineNumber] int line = 0)
            => Log(EnhancedLogLevel.NETWORK, LogCategory.NETWORK, message, file, member, line);

        public static void Dispose()
        {
            lock (_lock)
            {
                _instance?.Dispose();
                _instance = null;
            }
        }
    }
}
