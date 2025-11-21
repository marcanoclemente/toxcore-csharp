
namespace ToxCore.Core
{
    /// <summary>
    /// Sistema de TCP Forwarding a través de la red Tox
    /// </summary>
    public class TCPForwarding
    {
        private const string LOG_TAG = "TCP_FORWARDING";

        private readonly TCPTunnel _tunnel;
        private readonly Dictionary<int, ForwardingSession> _forwardingSessions;
        private readonly object _sessionsLock = new object();
        private int _lastSessionId;

        public TCPForwarding(TCPTunnel tunnel)
        {
            _tunnel = tunnel ?? throw new ArgumentNullException(nameof(tunnel));
            _forwardingSessions = new Dictionary<int, ForwardingSession>();
            _lastSessionId = 0;
        }

        /// <summary>
        /// Iniciar forwarding a través de un amigo
        /// </summary>
        public int StartForwarding(int friendNumber, IPPort targetEndPoint)
        {
            try
            {
                // Crear sesión de forwarding
                int sessionId = _lastSessionId++;
                var session = new ForwardingSession(sessionId, friendNumber, targetEndPoint);

                lock (_sessionsLock)
                {
                    _forwardingSessions[sessionId] = session;
                }

                // Iniciar tunnel
                int tunnelId = _tunnel.StartTunnel(friendNumber, targetEndPoint);
                if (tunnelId >= 0)
                {
                    session.TunnelId = tunnelId;
                    Logger.Log.InfoF($"[{LOG_TAG}] Forwarding iniciado: {sessionId} -> {targetEndPoint} via friend {friendNumber}");
                    return sessionId;
                }

                return -1;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando forwarding: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Enviar datos a través del forwarding
        /// </summary>
        public int SendForwardingData(int sessionId, byte[] data, int length)
        {
            try
            {
                ForwardingSession session;
                lock (_sessionsLock)
                {
                    if (!_forwardingSessions.TryGetValue(sessionId, out session))
                    {
                        return -1;
                    }
                }

                return _tunnel.SendTunnelData(session.TunnelId, data, length);
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando datos de forwarding: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// Cerrar sesión de forwarding
        /// </summary>
        public bool StopForwarding(int sessionId)
        {
            try
            {
                ForwardingSession session;
                lock (_sessionsLock)
                {
                    if (!_forwardingSessions.TryGetValue(sessionId, out session))
                    {
                        return false;
                    }
                    _forwardingSessions.Remove(sessionId);
                }

                _tunnel.CloseTunnel(session.TunnelId);
                Logger.Log.InfoF($"[{LOG_TAG}] Forwarding {sessionId} detenido");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo forwarding: {ex.Message}");
                return false;
            }
        }

        private class ForwardingSession
        {
            public int SessionId { get; }
            public int FriendNumber { get; }
            public IPPort TargetEndPoint { get; }
            public int TunnelId { get; set; }
            public long StartTime { get; }

            public ForwardingSession(int sessionId, int friendNumber, IPPort targetEndPoint)
            {
                SessionId = sessionId;
                FriendNumber = friendNumber;
                TargetEndPoint = targetEndPoint;
                StartTime = DateTime.UtcNow.Ticks;
                TunnelId = -1;
            }
        }
    }
}