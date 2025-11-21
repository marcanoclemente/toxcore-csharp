using System.Text;

namespace ToxCore.Core
{
    /// <summary>
    /// Niveles de log compatibles con toxcore
    /// </summary>
    public enum ToxLogLevel
    {
        TOX_LOG_LEVEL_TRACE,
        TOX_LOG_LEVEL_DEBUG,
        TOX_LOG_LEVEL_INFO,
        TOX_LOG_LEVEL_WARNING,
        TOX_LOG_LEVEL_ERROR
    }

    /// <summary>
    /// Callback para logging personalizado
    /// </summary>
    /// <param name="level">Nivel de log</param>
    /// <param name="file">Archivo origen</param>
    /// <param name="line">Línea origen</param>
    /// <param name="func">Función origen</param>
    /// <param name="message">Mensaje de log</param>
    /// <param name="userData">Datos de usuario</param>
    public delegate void ToxLogCallback(ToxLogLevel level, string file, int line, string func, string message, IntPtr userData);

    /// <summary>
    /// Implementación de logger compatible con logger.c de toxcore
    /// </summary>
    public static class Logger
    {
        private static ToxLogCallback _logCallback;
        private static IntPtr _userData;
        private static ToxLogLevel _minLevel = ToxLogLevel.TOX_LOG_LEVEL_INFO;
        private static readonly object _lockObject = new object();
        private static StreamWriter _fileWriter;
        private static string _logFilePath;

        // ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================

        /// <summary>
        /// tox_log_cb_register - Registrar callback de logging
        /// </summary>
        public static void tox_log_cb_register(ToxLogCallback callback, IntPtr userData)
        {
            lock (_lockObject)
            {
                _logCallback = callback;
                _userData = userData;
            }
        }

        /// <summary>
        /// tox_log_set_level - Establecer nivel mínimo de log
        /// </summary>
        public static void tox_log_set_level(ToxLogLevel level)
        {
            lock (_lockObject)
            {
                _minLevel = level;
            }
        }

        /// <summary>
        /// tox_log_get_level - Obtener nivel actual de log
        /// </summary>
        public static ToxLogLevel tox_log_get_level()
        {
            return _minLevel;
        }

        // ==================== FUNCIONES DE LOGGING PRINCIPALES ====================

        /// <summary>
        /// LOGGER_TRACE - Log nivel trace
        /// </summary>
        public static void LOGGER_TRACE(string file, int line, string func, string message)
        {
            LogInternal(ToxLogLevel.TOX_LOG_LEVEL_TRACE, file, line, func, message);
        }

        /// <summary>
        /// LOGGER_DEBUG - Log nivel debug
        /// </summary>
        public static void LOGGER_DEBUG(string file, int line, string func, string message)
        {
            LogInternal(ToxLogLevel.TOX_LOG_LEVEL_DEBUG, file, line, func, message);
        }

        /// <summary>
        /// LOGGER_INFO - Log nivel info
        /// </summary>
        public static void LOGGER_INFO(string file, int line, string func, string message)
        {
            LogInternal(ToxLogLevel.TOX_LOG_LEVEL_INFO, file, line, func, message);
        }

        /// <summary>
        /// LOGGER_WARNING - Log nivel warning
        /// </summary>
        public static void LOGGER_WARNING(string file, int line, string func, string message)
        {
            LogInternal(ToxLogLevel.TOX_LOG_LEVEL_WARNING, file, line, func, message);
        }

        /// <summary>
        /// LOGGER_ERROR - Log nivel error
        /// </summary>
        public static void LOGGER_ERROR(string file, int line, string func, string message)
        {
            LogInternal(ToxLogLevel.TOX_LOG_LEVEL_ERROR, file, line, func, message);
        }

        // ==================== FUNCIONES DE LOGGING CON FORMATO ====================

        /// <summary>
        /// LOGGER_TRACE_F - Log trace con formato
        /// </summary>
        public static void LOGGER_TRACE_F(string file, int line, string func, string format, params object[] args)
        {
            if (_minLevel <= ToxLogLevel.TOX_LOG_LEVEL_TRACE)
            {
                string message = string.Format(format, args);
                LogInternal(ToxLogLevel.TOX_LOG_LEVEL_TRACE, file, line, func, message);
            }
        }

        /// <summary>
        /// LOGGER_DEBUG_F - Log debug con formato
        /// </summary>
        public static void LOGGER_DEBUG_F(string file, int line, string func, string format, params object[] args)
        {
            if (_minLevel <= ToxLogLevel.TOX_LOG_LEVEL_DEBUG)
            {
                string message = string.Format(format, args);
                LogInternal(ToxLogLevel.TOX_LOG_LEVEL_DEBUG, file, line, func, message);
            }
        }

        /// <summary>
        /// LOGGER_INFO_F - Log info con formato
        /// </summary>
        public static void LOGGER_INFO_F(string file, int line, string func, string format, params object[] args)
        {
            if (_minLevel <= ToxLogLevel.TOX_LOG_LEVEL_INFO)
            {
                string message = string.Format(format, args);
                LogInternal(ToxLogLevel.TOX_LOG_LEVEL_INFO, file, line, func, message);
            }
        }

        /// <summary>
        /// LOGGER_WARNING_F - Log warning con formato
        /// </summary>
        public static void LOGGER_WARNING_F(string file, int line, string func, string format, params object[] args)
        {
            if (_minLevel <= ToxLogLevel.TOX_LOG_LEVEL_WARNING)
            {
                string message = string.Format(format, args);
                LogInternal(ToxLogLevel.TOX_LOG_LEVEL_WARNING, file, line, func, message);
            }
        }

        /// <summary>
        /// LOGGER_ERROR_F - Log error con formato
        /// </summary>
        public static void LOGGER_ERROR_F(string file, int line, string func, string format, params object[] args)
        {
            if (_minLevel <= ToxLogLevel.TOX_LOG_LEVEL_ERROR)
            {
                string message = string.Format(format, args);
                LogInternal(ToxLogLevel.TOX_LOG_LEVEL_ERROR, file, line, func, message);
            }
        }

        // ==================== FUNCIONES INTERNAS ====================

        private static void LogInternal(ToxLogLevel level, string file, int line, string func, string message)
        {
            if (level < _minLevel) return;

            lock (_lockObject)
            {
                // Llamar callback si está registrado
                if (_logCallback != null)
                {
                    try
                    {
                        _logCallback(level, file, line, func, message, _userData);
                    }
                    catch (Exception)
                    {
                        // Silenciar errores en callback
                    }
                }

                // Log a consola
                LogToConsole(level, file, line, func, message);

                // Log a archivo si está configurado
                LogToFile(level, file, line, func, message);
            }
        }

        private static void LogToConsole(ToxLogLevel level, string file, int line, string func, string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            string levelStr = GetLevelString(level);
            string fileName = Path.GetFileName(file);

            Console.WriteLine($"[{timestamp}] [{levelStr}] {fileName}:{line} ({func}) {message}");
        }

        private static void LogToFile(ToxLogLevel level, string file, int line, string func, string message)
        {
            if (_fileWriter != null)
            {
                try
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string levelStr = GetLevelString(level);
                    string fileName = Path.GetFileName(file);

                    _fileWriter.WriteLine($"[{timestamp}] [{levelStr}] {fileName}:{line} ({func}) {message}");
                    _fileWriter.Flush();
                }
                catch (Exception)
                {
                    // Silenciar errores de escritura de archivo
                }
            }
        }

        private static string GetLevelString(ToxLogLevel level)
        {
            switch (level)
            {
                case ToxLogLevel.TOX_LOG_LEVEL_TRACE: return "TRACE";
                case ToxLogLevel.TOX_LOG_LEVEL_DEBUG: return "DEBUG";
                case ToxLogLevel.TOX_LOG_LEVEL_INFO: return "INFO";
                case ToxLogLevel.TOX_LOG_LEVEL_WARNING: return "WARN";
                case ToxLogLevel.TOX_LOG_LEVEL_ERROR: return "ERROR";
                default: return "UNKNOWN";
            }
        }

        // ==================== FUNCIONES DE GESTIÓN DE ARCHIVOS ====================

        /// <summary>
        /// tox_log_enable_file_logging - Habilitar logging a archivo
        /// </summary>
        public static bool tox_log_enable_file_logging(string filePath)
        {
            lock (_lockObject)
            {
                try
                {
                    if (_fileWriter != null)
                    {
                        _fileWriter.Close();
                        _fileWriter = null;
                    }

                    _fileWriter = new StreamWriter(filePath, true, Encoding.UTF8);
                    _logFilePath = filePath;
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// tox_log_disable_file_logging - Deshabilitar logging a archivo
        /// </summary>
        public static void tox_log_disable_file_logging()
        {
            lock (_lockObject)
            {
                if (_fileWriter != null)
                {
                    _fileWriter.Close();
                    _fileWriter = null;
                    _logFilePath = null;
                }
            }
        }

        /// <summary>
        /// tox_log_get_file_path - Obtener ruta del archivo de log
        /// </summary>
        public static string tox_log_get_file_path()
        {
            return _logFilePath;
        }

        // ==================== MACROS COMPATIBLES (para uso en otros módulos) ====================

        /// <summary>
        /// Macros para facilitar el logging desde otros archivos
        /// </summary>
        public static class Log
        {
            public static void Trace(string message, [System.Runtime.CompilerServices.CallerFilePath] string file = "",
                                    [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
                                    [System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                LOGGER_TRACE(file, line, func, message);
            }

            public static void Debug(string message, [System.Runtime.CompilerServices.CallerFilePath] string file = "",
                                   [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
                                   [System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                LOGGER_DEBUG(file, line, func, message);
            }

            public static void Info(string message, [System.Runtime.CompilerServices.CallerFilePath] string file = "",
                                  [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
                                  [System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                LOGGER_INFO(file, line, func, message);
            }

            public static void Warning(string message, [System.Runtime.CompilerServices.CallerFilePath] string file = "",
                                     [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
                                     [System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                LOGGER_WARNING(file, line, func, message);
            }

            public static void Error(string message, [System.Runtime.CompilerServices.CallerFilePath] string file = "",
                                   [System.Runtime.CompilerServices.CallerLineNumber] int line = 0,
                                   [System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                LOGGER_ERROR(file, line, func, message);
            }

            public static void TraceF(string format, params object[] args)
            {
                LOGGER_TRACE_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);
            }

            public static void DebugF(string format, params object[] args)
            {
                LOGGER_DEBUG_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);
            }

            public static void InfoF(string format, params object[] args)
            {
                LOGGER_INFO_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);
            }

            public static void WarningF(string format, params object[] args)
            {
                LOGGER_WARNING_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);
            }

            public static void ErrorF(string format, params object[] args)
            {
                LOGGER_ERROR_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);
            }

            private static string GetCallerFile([System.Runtime.CompilerServices.CallerFilePath] string file = "")
            {
                return file;
            }

            private static int GetCallerLine([System.Runtime.CompilerServices.CallerLineNumber] int line = 0)
            {
                return line;
            }

            private static string GetCallerMethod([System.Runtime.CompilerServices.CallerMemberName] string func = "")
            {
                return func;
            }
        }
    }
}