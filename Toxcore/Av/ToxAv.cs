using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using ToxCore.Core;

namespace ToxCore.AV
{
    /// <summary>
    /// Codecs de audio y video soportados
    /// </summary>
    public enum ToxAvCodecType
    {
        TOXAV_CODEC_NONE = 0,
        TOXAV_CODEC_AUDIO_OPUS = 1,
        TOXAV_CODEC_VIDEO_VP8 = 2,
        TOXAV_CODEC_VIDEO_VP9 = 3,
        TOXAV_CODEC_VIDEO_H264 = 4
    }

    /// <summary>
    /// Estados de llamada
    /// </summary>
    public enum ToxAvCallState
    {
        TOXAV_CALL_STATE_NONE = 0,
        TOXAV_CALL_STATE_INVITING = 1,
        TOXAV_CALL_STATE_RINGING = 2,
        TOXAV_CALL_STATE_ACTIVE = 3,
        TOXAV_CALL_STATE_PAUSED = 4,
        TOXAV_CALL_STATE_ENDED = 5,
        TOXAV_CALL_STATE_ERROR = 6
    }

    /// <summary>
    /// Control de llamadas
    /// </summary>
    public enum ToxAvCallControl
    {
        TOXAV_CALL_CONTROL_RESUME = 0,
        TOXAV_CALL_CONTROL_PAUSE = 1,
        TOXAV_CALL_CONTROL_CANCEL = 2,
        TOXAV_CALL_CONTROL_MUTE_AUDIO = 3,
        TOXAV_CALL_CONTROL_UNMUTE_AUDIO = 4,
        TOXAV_CALL_CONTROL_HIDE_VIDEO = 5,
        TOXAV_CALL_CONTROL_SHOW_VIDEO = 6
    }

    /// <summary>
    /// Información de una llamada activa
    /// </summary>
    public class ToxAvCall
    {
        public int FriendNumber { get; set; }
        public ToxAvCallState State { get; set; }
        public bool AudioEnabled { get; set; }
        public bool VideoEnabled { get; set; }
        public long StartTime { get; set; }
        public uint CallId { get; set; }
        public bool AudioMuted { get; set; }
        public bool VideoHidden { get; set; }
        public int AudioBitrate { get; set; }
        public int VideoBitrate { get; set; }
        public uint AudioSampleRate { get; set; }
        public byte AudioChannels { get; set; }
        public uint VideoWidth { get; set; }
        public uint VideoHeight { get; set; }
        public uint VideoFps { get; set; }

        public ToxAvCall(int friendNumber, uint callId)
        {
            FriendNumber = friendNumber;
            CallId = callId;
            State = ToxAvCallState.TOXAV_CALL_STATE_NONE;
            AudioEnabled = false;
            VideoEnabled = false;
            StartTime = DateTime.UtcNow.Ticks;
            AudioBitrate = 64000; // 64 kbps por defecto
            VideoBitrate = 500000; // 500 kbps por defecto
            AudioSampleRate = 48000; // 48 kHz
            AudioChannels = 1; // Mono
            VideoWidth = 640;
            VideoHeight = 480;
            VideoFps = 30;
        }
    }

    /// <summary>
    /// Frame de audio
    /// </summary>
    public class AudioFrame
    {
        public byte[] Samples { get; set; }
        public uint SampleCount { get; set; }
        public byte Channels { get; set; }
        public uint SamplingRate { get; set; }
        public long Timestamp { get; set; }

        public AudioFrame(uint sampleCount, byte channels, uint samplingRate)
        {
            SampleCount = sampleCount;
            Channels = channels;
            SamplingRate = samplingRate;
            Samples = new byte[sampleCount * channels * 2]; // 16-bit samples
            Timestamp = DateTime.UtcNow.Ticks;
        }
    }

    /// <summary>
    /// Frame de video
    /// </summary>
    public class VideoFrame
    {
        public byte[] Data { get; set; }
        public uint Width { get; set; }
        public uint Height { get; set; }
        public long Timestamp { get; set; }
        public uint StrideY { get; set; }
        public uint StrideU { get; set; }
        public uint StrideV { get; set; }

        public VideoFrame(uint width, uint height)
        {
            Width = width;
            Height = height;
            // YUV420 format
            Data = new byte[width * height * 3 / 2];
            StrideY = width;
            StrideU = width / 2;
            StrideV = width / 2;
            Timestamp = DateTime.UtcNow.Ticks;
        }
    }

    /// <summary>
    /// Callbacks de ToxAV
    /// </summary>
    public class ToxAvCallbacks
    {
        public delegate void CallCallback(ToxAv toxAv, int friendNumber, bool audio, bool video, object userData);
        public delegate void CallStateCallback(ToxAv toxAv, int friendNumber, ToxAvCallState state, object userData);
        public delegate void AudioReceiveCallback(ToxAv toxAv, int friendNumber, AudioFrame frame, object userData);
        public delegate void VideoReceiveCallback(ToxAv toxAv, int friendNumber, VideoFrame frame, object userData);
        public delegate void AudioBitrateCallback(ToxAv toxAv, int friendNumber, uint bitrate, object userData);
        public delegate void VideoBitrateCallback(ToxAv toxAv, int friendNumber, uint bitrate, object userData);

        public CallCallback OnCall { get; set; }
        public CallStateCallback OnCallState { get; set; }
        public AudioReceiveCallback OnAudioReceive { get; set; }
        public VideoReceiveCallback OnVideoReceive { get; set; }
        public AudioBitrateCallback OnAudioBitrate { get; set; }
        public VideoBitrateCallback OnVideoBitrate { get; set; }
    }

    /// <summary>
    /// Implementación principal de ToxAV - Audio/Video sobre Tox
    /// </summary>
    public class ToxAv : IDisposable
    {
        private const string LOG_TAG = "TOXAV";

        // Constantes de configuración
        public const uint DEFAULT_AUDIO_BITRATE = 64000; // 64 kbps
        public const uint DEFAULT_VIDEO_BITRATE = 500000; // 500 kbps
        public const uint DEFAULT_AUDIO_SAMPLE_RATE = 48000; // 48 kHz
        public const byte DEFAULT_AUDIO_CHANNELS = 1; // Mono
        public const uint DEFAULT_VIDEO_WIDTH = 640;
        public const uint DEFAULT_VIDEO_HEIGHT = 480;
        public const uint DEFAULT_VIDEO_FPS = 30;

        // Jitter buffer y timing
        private const int JITTER_BUFFER_MAX_PACKETS = 100;
        private const int AUDIO_FRAME_DURATION_MS = 20; // 20ms frames for Opus
        private const int VIDEO_FRAME_DURATION_MS = 33; // ~30fps

        // Componentes
        private readonly Core.Tox _tox;
        private readonly ToxAvCallbacks _callbacks;
        private readonly Dictionary<int, ToxAvCall> _activeCalls;
        private readonly Dictionary<int, JitterBuffer> _audioJitterBuffers;
        private readonly Dictionary<int, JitterBuffer> _videoJitterBuffers;
        private readonly object _callsLock = new object();
        private uint _nextCallId = 1;
        private bool _isRunning;
        private Thread _avThread;
        private CancellationTokenSource _cancellationTokenSource;

        // Codecs (en una implementación real usaríamos librerías como Opus, VP8)
        private ToxAvCodecType _audioCodec = ToxAvCodecType.TOXAV_CODEC_AUDIO_OPUS;
        private ToxAvCodecType _videoCodec = ToxAvCodecType.TOXAV_CODEC_VIDEO_VP8;

        public ToxAvCallbacks Callbacks => _callbacks;
        public bool IsRunning => _isRunning;

        public ToxAv(Core.Tox tox)
        {
            _tox = tox ?? throw new ArgumentNullException(nameof(tox));
            _callbacks = new ToxAvCallbacks();
            _activeCalls = new Dictionary<int, ToxAvCall>();
            _audioJitterBuffers = new Dictionary<int, JitterBuffer>();
            _videoJitterBuffers = new Dictionary<int, JitterBuffer>();
            _cancellationTokenSource = new CancellationTokenSource();

            Logger.Log.Info($"[{LOG_TAG}] ToxAV inicializado");
        }

        /// <summary>
        /// Iniciar servicio de audio/video
        /// </summary>
        public bool Start()
        {
            if (_isRunning)
            {
                Logger.Log.Warning($"[{LOG_TAG}] ToxAV ya está ejecutándose");
                return true;
            }

            try
            {
                _isRunning = true;
                _cancellationTokenSource = new CancellationTokenSource();

                // Iniciar hilo de procesamiento AV
                _avThread = new Thread(AvWorker);
                _avThread.IsBackground = true;
                _avThread.Name = "ToxAV-Worker";
                _avThread.Start();

                Logger.Log.Info($"[{LOG_TAG}] Servicio ToxAV iniciado");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando ToxAV: {ex.Message}");
                _isRunning = false;
                return false;
            }
        }

        /// <summary>
        /// Detener servicio de audio/video
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            try
            {
                _isRunning = false;
                _cancellationTokenSource?.Cancel();

                // Terminar todas las llamadas activas
                lock (_callsLock)
                {
                    foreach (var call in _activeCalls.Values.ToList())
                    {
                        CallControl(call.FriendNumber, ToxAvCallControl.TOXAV_CALL_CONTROL_CANCEL);
                    }
                    _activeCalls.Clear();
                    _audioJitterBuffers.Clear();
                    _videoJitterBuffers.Clear();
                }

                _avThread?.Join(2000);

                Logger.Log.Info($"[{LOG_TAG}] Servicio ToxAV detenido");
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error deteniendo ToxAV: {ex.Message}");
            }
        }

        // ==================== API PÚBLICA PRINCIPAL ====================

        /// <summary>
        /// toxav_call - Iniciar llamada a un amigo
        /// </summary>
        public bool Call(int friendNumber, bool audio, bool video)
        {
            if (!_isRunning)
            {
                Logger.Log.Error($"[{LOG_TAG}] No se puede iniciar llamada - ToxAV no iniciado");
                return false;
            }

            try
            {
                lock (_callsLock)
                {
                    if (_activeCalls.ContainsKey(friendNumber))
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Ya existe una llamada activa con friend {friendNumber}");
                        return false;
                    }

                    var call = new ToxAvCall(friendNumber, _nextCallId++)
                    {
                        AudioEnabled = audio,
                        VideoEnabled = video,
                        State = ToxAvCallState.TOXAV_CALL_STATE_INVITING
                    };

                    _activeCalls[friendNumber] = call;

                    // Crear jitter buffers
                    _audioJitterBuffers[friendNumber] = new JitterBuffer(JITTER_BUFFER_MAX_PACKETS);
                    _videoJitterBuffers[friendNumber] = new JitterBuffer(JITTER_BUFFER_MAX_PACKETS);
                }

                // Enviar paquete de invitación de llamada
                byte[] callPacket = CreateCallPacket(audio, video);
                int sent = _tox.Messenger.FriendConn.m_send_message(friendNumber, callPacket, callPacket.Length);

                if (sent > 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Llamada iniciada a friend {friendNumber} - Audio: {audio}, Video: {video}");
                    return true;
                }
                else
                {
                    lock (_callsLock)
                    {
                        _activeCalls.Remove(friendNumber);
                        _audioJitterBuffers.Remove(friendNumber);
                        _videoJitterBuffers.Remove(friendNumber);
                    }
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error iniciando llamada: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_answer - Responder a una llamada entrante
        /// </summary>
        public bool Answer(int friendNumber, bool audio, bool video)
        {
            try
            {
                ToxAvCall call;
                lock (_callsLock)
                {
                    if (!_activeCalls.TryGetValue(friendNumber, out call))
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] No hay llamada entrante de friend {friendNumber}");
                        return false;
                    }

                    if (call.State != ToxAvCallState.TOXAV_CALL_STATE_RINGING)
                    {
                        Logger.Log.WarningF($"[{LOG_TAG}] Llamada no está en estado ringing: {call.State}");
                        return false;
                    }

                    call.AudioEnabled = audio;
                    call.VideoEnabled = video;
                    call.State = ToxAvCallState.TOXAV_CALL_STATE_ACTIVE;
                }

                // Enviar paquete de respuesta
                byte[] answerPacket = CreateAnswerPacket(audio, video);
                int sent = _tox.Messenger.FriendConn.m_send_message(friendNumber, answerPacket, answerPacket.Length);

                if (sent > 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Llamada respondida - Audio: {audio}, Video: {video}");
                    _callbacks.OnCallState?.Invoke(this, friendNumber, ToxAvCallState.TOXAV_CALL_STATE_ACTIVE, null);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error respondiendo llamada: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_call_control - Control de llamada (pausar, reanudar, cancelar)
        /// </summary>
        public bool CallControl(int friendNumber, ToxAvCallControl control)
        {
            try
            {
                ToxAvCall call;
                lock (_callsLock)
                {
                    if (!_activeCalls.TryGetValue(friendNumber, out call))
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] No hay llamada activa con friend {friendNumber}");
                        return false;
                    }
                }

                // Aplicar control localmente
                bool success = ApplyCallControl(call, control);
                if (!success) return false;

                // Enviar control al peer remoto
                byte[] controlPacket = CreateControlPacket(control);
                int sent = _tox.Messenger.FriendConn.m_send_message(friendNumber, controlPacket, controlPacket.Length);

                if (sent > 0)
                {
                    Logger.Log.InfoF($"[{LOG_TAG}] Control de llamada enviado: {control}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error en control de llamada: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_audio_send_frame - Enviar frame de audio
        /// </summary>
        public bool SendAudioFrame(int friendNumber, AudioFrame frame)
        {
            if (!_isRunning) return false;

            try
            {
                ToxAvCall call;
                lock (_callsLock)
                {
                    if (!_activeCalls.TryGetValue(friendNumber, out call) ||
                        call.State != ToxAvCallState.TOXAV_CALL_STATE_ACTIVE ||
                        !call.AudioEnabled ||
                        call.AudioMuted)
                    {
                        return false;
                    }
                }

                // Codificar audio (en implementación real usaríamos Opus)
                byte[] encodedAudio = EncodeAudio(frame);
                if (encodedAudio == null) return false;

                // Crear paquete RTP de audio
                byte[] audioPacket = CreateAudioPacket(call.CallId, encodedAudio, frame.Timestamp);
                if (audioPacket == null) return false;

                // Enviar a través de onion routing
                var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
                if (friend == null) return false;

                int sent = _tox.Messenger.Onion.onion_send_1(audioPacket, audioPacket.Length, friend.PublicKey);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando frame de audio: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_video_send_frame - Enviar frame de video
        /// </summary>
        public bool SendVideoFrame(int friendNumber, VideoFrame frame)
        {
            if (!_isRunning) return false;

            try
            {
                ToxAvCall call;
                lock (_callsLock)
                {
                    if (!_activeCalls.TryGetValue(friendNumber, out call) ||
                        call.State != ToxAvCallState.TOXAV_CALL_STATE_ACTIVE ||
                        !call.VideoEnabled ||
                        call.VideoHidden)
                    {
                        return false;
                    }
                }

                // Codificar video (en implementación real usaríamos VP8/VP9)
                byte[] encodedVideo = EncodeVideo(frame);
                if (encodedVideo == null) return false;

                // Crear paquete RTP de video
                byte[] videoPacket = CreateVideoPacket(call.CallId, encodedVideo, frame.Timestamp);
                if (videoPacket == null) return false;

                // Enviar a través de onion routing
                var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
                if (friend == null) return false;

                int sent = _tox.Messenger.Onion.onion_send_1(videoPacket, videoPacket.Length, friend.PublicKey);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando frame de video: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_set_audio_bitrate - Configurar bitrate de audio
        /// </summary>
        public bool SetAudioBitrate(int friendNumber, uint bitrate)
        {
            try
            {
                lock (_callsLock)
                {
                    if (_activeCalls.TryGetValue(friendNumber, out var call))
                    {
                        call.AudioBitrate = (int)bitrate;
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error configurando bitrate de audio: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// toxav_set_video_bitrate - Configurar bitrate de video
        /// </summary>
        public bool SetVideoBitrate(int friendNumber, uint bitrate)
        {
            try
            {
                lock (_callsLock)
                {
                    if (_activeCalls.TryGetValue(friendNumber, out var call))
                    {
                        call.VideoBitrate = (int)bitrate;
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error configurando bitrate de video: {ex.Message}");
                return false;
            }
        }

        // ==================== MANEJO DE PAQUETES AV ====================

        /// <summary>
        /// Manejar paquetes de audio/video
        /// </summary>
        public int HandleAvPacket(int friendNumber, byte[] packet, int length)
        {
            if (packet == null || length < 5) return -1;

            try
            {
                byte packetType = packet[0];

                switch (packetType)
                {
                    case 0x60: // CALL_INVITE
                        return HandleCallInvite(friendNumber, packet, length);
                    case 0x61: // CALL_ANSWER
                        return HandleCallAnswer(friendNumber, packet, length);
                    case 0x62: // CALL_CONTROL
                        return HandleCallControl(friendNumber, packet, length);
                    case 0x63: // AUDIO_FRAME
                        return HandleAudioFrame(friendNumber, packet, length);
                    case 0x64: // VIDEO_FRAME
                        return HandleVideoFrame(friendNumber, packet, length);
                    case 0x65: // CODEC_CONTROL
                        return HandleCodecControl(friendNumber, packet, length);
                    default:
                        return -1;
                }
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando paquete AV: {ex.Message}");
                return -1;
            }
        }

        private int HandleCallInvite(int friendNumber, byte[] packet, int length)
        {
            if (length < 3) return -1;

            bool audio = (packet[1] & 0x01) != 0;
            bool video = (packet[1] & 0x02) != 0;
            uint callId = BitConverter.ToUInt32(packet, 2);

            lock (_callsLock)
            {
                // Si ya existe una llamada, rechazar la nueva
                if (_activeCalls.ContainsKey(friendNumber))
                {
                    // Enviar rechazo automático
                    CallControl(friendNumber, ToxAvCallControl.TOXAV_CALL_CONTROL_CANCEL);
                    return -1;
                }

                var call = new ToxAvCall(friendNumber, callId)
                {
                    AudioEnabled = audio,
                    VideoEnabled = video,
                    State = ToxAvCallState.TOXAV_CALL_STATE_RINGING
                };

                _activeCalls[friendNumber] = call;
                _audioJitterBuffers[friendNumber] = new JitterBuffer(JITTER_BUFFER_MAX_PACKETS);
                _videoJitterBuffers[friendNumber] = new JitterBuffer(JITTER_BUFFER_MAX_PACKETS);
            }

            Logger.Log.InfoF($"[{LOG_TAG}] Llamada entrante de friend {friendNumber} - Audio: {audio}, Video: {video}");

            // Disparar callback
            _callbacks.OnCall?.Invoke(this, friendNumber, audio, video, null);

            return 0;
        }

        private int HandleCallAnswer(int friendNumber, byte[] packet, int length)
        {
            if (length < 3) return -1;

            bool audio = (packet[1] & 0x01) != 0;
            bool video = (packet[1] & 0x02) != 0;

            lock (_callsLock)
            {
                if (_activeCalls.TryGetValue(friendNumber, out var call))
                {
                    call.AudioEnabled = audio;
                    call.VideoEnabled = video;
                    call.State = ToxAvCallState.TOXAV_CALL_STATE_ACTIVE;
                }
            }

            Logger.Log.InfoF($"[{LOG_TAG}] Llamada aceptada por friend {friendNumber}");

            _callbacks.OnCallState?.Invoke(this, friendNumber, ToxAvCallState.TOXAV_CALL_STATE_ACTIVE, null);

            return 0;
        }

        private int HandleCallControl(int friendNumber, byte[] packet, int length)
        {
            if (length < 2) return -1;

            ToxAvCallControl control = (ToxAvCallControl)packet[1];

            lock (_callsLock)
            {
                if (_activeCalls.TryGetValue(friendNumber, out var call))
                {
                    ApplyCallControl(call, control);
                }
            }

            return 0;
        }

        private int HandleCodecControl(int friendNumber, byte[] packet, int length)
        {
            if (length < 3) return -1;

            try
            {
                byte controlType = packet[1];
                uint value = BitConverter.ToUInt32(packet, 2);

                lock (_callsLock)
                {
                    if (_activeCalls.TryGetValue(friendNumber, out var call))
                    {
                        switch (controlType)
                        {
                            case 0x01: // Audio bitrate change
                                call.AudioBitrate = (int)value;
                                _callbacks.OnAudioBitrate?.Invoke(this, friendNumber, value, null);
                                Logger.Log.DebugF($"[{LOG_TAG}] Bitrate de audio cambiado: {value} bps");
                                break;

                            case 0x02: // Video bitrate change
                                call.VideoBitrate = (int)value;
                                _callbacks.OnVideoBitrate?.Invoke(this, friendNumber, value, null);
                                Logger.Log.DebugF($"[{LOG_TAG}] Bitrate de video cambiado: {value} bps");
                                break;

                            case 0x03: // Audio codec change
                                _audioCodec = (ToxAvCodecType)value;
                                Logger.Log.DebugF($"[{LOG_TAG}] Codec de audio cambiado: {_audioCodec}");
                                break;

                            case 0x04: // Video codec change
                                _videoCodec = (ToxAvCodecType)value;
                                Logger.Log.DebugF($"[{LOG_TAG}] Codec de video cambiado: {_videoCodec}");
                                break;

                            case 0x05: // Audio sample rate change
                                call.AudioSampleRate = value;
                                Logger.Log.DebugF($"[{LOG_TAG}] Sample rate de audio cambiado: {value} Hz");
                                break;

                            case 0x06: // Video resolution change
                                call.VideoWidth = value;
                                call.VideoHeight = BitConverter.ToUInt32(packet, 6);
                                Logger.Log.DebugF($"[{LOG_TAG}] Resolución de video cambiada: {value}x{call.VideoHeight}");
                                break;

                            default:
                                Logger.Log.WarningF($"[{LOG_TAG}] Tipo de control de codec desconocido: 0x{controlType:X2}");
                                return -1;
                        }
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error manejando control de codec: {ex.Message}");
                return -1;
            }
        }

        /// <summary>
        /// toxav_send_codec_control - Enviar control de codec al peer remoto
        /// </summary>
        public bool SendCodecControl(int friendNumber, byte controlType, uint value, uint additionalValue = 0)
        {
            try
            {
                byte[] controlPacket = CreateCodecControlPacket(controlType, value, additionalValue);
                if (controlPacket == null) return false;

                var friend = _tox.Messenger.FriendConn.Get_friend(friendNumber);
                if (friend == null) return false;

                int sent = _tox.Messenger.Onion.onion_send_1(controlPacket, controlPacket.Length, friend.PublicKey);
                return sent > 0;
            }
            catch (Exception ex)
            {
                Logger.Log.ErrorF($"[{LOG_TAG}] Error enviando control de codec: {ex.Message}");
                return false;
            }
        }

        private byte[] CreateCodecControlPacket(byte controlType, uint value, uint additionalValue = 0)
        {
            int packetSize = (controlType == 0x06) ? 10 : 6; // Para cambio de resolución necesita 2 valores
            byte[] packet = new byte[packetSize];

            packet[0] = 0x65; // CODEC_CONTROL
            packet[1] = controlType;
            Buffer.BlockCopy(BitConverter.GetBytes(value), 0, packet, 2, 4);

            if (controlType == 0x06) // Video resolution change
            {
                Buffer.BlockCopy(BitConverter.GetBytes(additionalValue), 0, packet, 6, 4);
            }

            return packet;
        }

        // <summary>
        /// Enviar cambio de bitrate de audio
        /// </summary>
        public bool SendAudioBitrateChange(int friendNumber, uint bitrate)
        {
            return SendCodecControl(friendNumber, 0x01, bitrate);
        }

        /// <summary>
        /// Enviar cambio de bitrate de video
        /// </summary>
        public bool SendVideoBitrateChange(int friendNumber, uint bitrate)
        {
            return SendCodecControl(friendNumber, 0x02, bitrate);
        }

        /// <summary>
        /// Enviar cambio de codec de audio
        /// </summary>
        public bool SendAudioCodecChange(int friendNumber, ToxAvCodecType codec)
        {
            return SendCodecControl(friendNumber, 0x03, (uint)codec);
        }

        /// <summary>
        /// Enviar cambio de codec de video
        /// </summary>
        public bool SendVideoCodecChange(int friendNumber, ToxAvCodecType codec)
        {
            return SendCodecControl(friendNumber, 0x04, (uint)codec);
        }

        /// <summary>
        /// Enviar cambio de sample rate de audio
        /// </summary>
        public bool SendAudioSampleRateChange(int friendNumber, uint sampleRate)
        {
            return SendCodecControl(friendNumber, 0x05, sampleRate);
        }

        /// <summary>
        /// Enviar cambio de resolución de video
        /// </summary>
        public bool SendVideoResolutionChange(int friendNumber, uint width, uint height)
        {
            return SendCodecControl(friendNumber, 0x06, width, height);
        }


        private int HandleAudioFrame(int friendNumber, byte[] packet, int length)
        {
            if (length < 20) return -1; // header + timestamp mínimo

            uint callId = BitConverter.ToUInt32(packet, 1);
            long timestamp = BitConverter.ToInt64(packet, 5);
            uint sequence = BitConverter.ToUInt32(packet, 13);

            int audioDataLength = length - 17;
            byte[] audioData = new byte[audioDataLength];
            Buffer.BlockCopy(packet, 17, audioData, 0, audioDataLength);

            // Agregar al jitter buffer
            lock (_callsLock)
            {
                if (_audioJitterBuffers.TryGetValue(friendNumber, out var jitterBuffer))
                {
                    jitterBuffer.AddPacket(sequence, timestamp, audioData);
                }
            }

            return 0;
        }

        private int HandleVideoFrame(int friendNumber, byte[] packet, int length)
        {
            if (length < 25) return -1; // header + metadata mínimo

            uint callId = BitConverter.ToUInt32(packet, 1);
            long timestamp = BitConverter.ToInt64(packet, 5);
            uint sequence = BitConverter.ToUInt32(packet, 13);
            uint width = BitConverter.ToUInt32(packet, 17);
            uint height = BitConverter.ToUInt32(packet, 21);

            int videoDataLength = length - 25;
            byte[] videoData = new byte[videoDataLength];
            Buffer.BlockCopy(packet, 25, videoData, 0, videoDataLength);

            // Agregar al jitter buffer
            lock (_callsLock)
            {
                if (_videoJitterBuffers.TryGetValue(friendNumber, out var jitterBuffer))
                {
                    jitterBuffer.AddPacket(sequence, timestamp, videoData);
                }
            }

            return 0;
        }

        // ==================== MÉTODOS AUXILIARES ====================

        private bool ApplyCallControl(ToxAvCall call, ToxAvCallControl control)
        {
            switch (control)
            {
                case ToxAvCallControl.TOXAV_CALL_CONTROL_RESUME:
                    call.State = ToxAvCallState.TOXAV_CALL_STATE_ACTIVE;
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_PAUSE:
                    call.State = ToxAvCallState.TOXAV_CALL_STATE_PAUSED;
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_CANCEL:
                    call.State = ToxAvCallState.TOXAV_CALL_STATE_ENDED;
                    // Limpiar recursos
                    _audioJitterBuffers.Remove(call.FriendNumber);
                    _videoJitterBuffers.Remove(call.FriendNumber);
                    _activeCalls.Remove(call.FriendNumber);
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_MUTE_AUDIO:
                    call.AudioMuted = true;
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_UNMUTE_AUDIO:
                    call.AudioMuted = false;
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_HIDE_VIDEO:
                    call.VideoHidden = true;
                    break;
                case ToxAvCallControl.TOXAV_CALL_CONTROL_SHOW_VIDEO:
                    call.VideoHidden = false;
                    break;
                default:
                    return false;
            }

            _callbacks.OnCallState?.Invoke(this, call.FriendNumber, call.State, null);
            return true;
        }

        // ==================== CREACIÓN DE PAQUETES ====================

        private byte[] CreateCallPacket(bool audio, bool video)
        {
            byte[] packet = new byte[6];
            packet[0] = 0x60; // CALL_INVITE
            packet[1] = (byte)((audio ? 0x01 : 0x00) | (video ? 0x02 : 0x00));
            Buffer.BlockCopy(BitConverter.GetBytes(_nextCallId), 0, packet, 2, 4);
            return packet;
        }

        private byte[] CreateAnswerPacket(bool audio, bool video)
        {
            byte[] packet = new byte[3];
            packet[0] = 0x61; // CALL_ANSWER
            packet[1] = (byte)((audio ? 0x01 : 0x00) | (video ? 0x02 : 0x00));
            return packet;
        }

        private byte[] CreateControlPacket(ToxAvCallControl control)
        {
            byte[] packet = new byte[2];
            packet[0] = 0x62; // CALL_CONTROL
            packet[1] = (byte)control;
            return packet;
        }

        private byte[] CreateAudioPacket(uint callId, byte[] audioData, long timestamp)
        {
            byte[] packet = new byte[17 + audioData.Length];
            packet[0] = 0x63; // AUDIO_FRAME
            Buffer.BlockCopy(BitConverter.GetBytes(callId), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, packet, 5, 8);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 13, 4); // sequence
            Buffer.BlockCopy(audioData, 0, packet, 17, audioData.Length);
            return packet;
        }

        private byte[] CreateVideoPacket(uint callId, byte[] videoData, long timestamp)
        {
            byte[] packet = new byte[25 + videoData.Length];
            packet[0] = 0x64; // VIDEO_FRAME
            Buffer.BlockCopy(BitConverter.GetBytes(callId), 0, packet, 1, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, packet, 5, 8);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 13, 4); // sequence
            // Incluir dimensiones del video
            Buffer.BlockCopy(BitConverter.GetBytes(DEFAULT_VIDEO_WIDTH), 0, packet, 17, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(DEFAULT_VIDEO_HEIGHT), 0, packet, 21, 4);
            Buffer.BlockCopy(videoData, 0, packet, 25, videoData.Length);
            return packet;
        }

        // ==================== CODECS (STUBS - en implementación real usar librerías) ====================

        private byte[] EncodeAudio(AudioFrame frame)
        {
            // STUB - En implementación real usar Opus codec
            // Por ahora simplemente devolvemos los samples sin comprimir
            return frame.Samples;
        }

        private byte[] EncodeVideo(VideoFrame frame)
        {
            // STUB - En implementación real usar VP8/VP9 codec
            // Por ahora simplemente devolvemos los datos YUV sin comprimir
            return frame.Data;
        }

        private AudioFrame DecodeAudio(byte[] encodedAudio, uint sampleRate, byte channels)
        {
            // STUB - Decodificar audio
            var frame = new AudioFrame((uint)encodedAudio.Length / 2, channels, sampleRate);
            Buffer.BlockCopy(encodedAudio, 0, frame.Samples, 0, encodedAudio.Length);
            return frame;
        }

        private VideoFrame DecodeVideo(byte[] encodedVideo, uint width, uint height)
        {
            // STUB - Decodificar video
            var frame = new VideoFrame(width, height);
            Buffer.BlockCopy(encodedVideo, 0, frame.Data, 0, Math.Min(encodedVideo.Length, frame.Data.Length));
            return frame;
        }

        // ==================== WORKER PRINCIPAL ====================

        private void AvWorker()
        {
            Logger.Log.Debug($"[{LOG_TAG}] Hilo AV iniciado");

            while (_isRunning && !_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    ProcessJitterBuffers();
                    Thread.Sleep(10); // 10ms para no consumir demasiada CPU
                }
                catch (Exception ex)
                {
                    if (_isRunning) // Solo loguear si todavía estamos ejecutándonos
                    {
                        Logger.Log.ErrorF($"[{LOG_TAG}] Error en worker AV: {ex.Message}");
                    }
                }
            }

            Logger.Log.Debug($"[{LOG_TAG}] Hilo AV finalizado");
        }

        private void ProcessJitterBuffers()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            lock (_callsLock)
            {
                foreach (var kvp in _audioJitterBuffers)
                {
                    int friendNumber = kvp.Key;
                    var jitterBuffer = kvp.Value;

                    // Procesar paquetes de audio listos
                    var audioPacket = jitterBuffer.GetNextPacket(currentTime);
                    while (audioPacket != null)
                    {
                        try
                        {
                            // Obtener configuración de audio de la llamada
                            uint sampleRate = DEFAULT_AUDIO_SAMPLE_RATE;
                            byte channels = DEFAULT_AUDIO_CHANNELS;

                            if (_activeCalls.TryGetValue(friendNumber, out var call))
                            {
                                sampleRate = call.AudioSampleRate;
                                channels = call.AudioChannels;
                            }

                            // Decodificar y disparar callback
                            var audioFrame = DecodeAudio(audioPacket.Data, sampleRate, channels);
                            _callbacks.OnAudioReceive?.Invoke(this, friendNumber, audioFrame, null);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando frame de audio: {ex.Message}");
                        }

                        // Obtener siguiente paquete
                        audioPacket = jitterBuffer.GetNextPacket(currentTime);
                    }
                }

                foreach (var kvp in _videoJitterBuffers)
                {
                    int friendNumber = kvp.Key;
                    var jitterBuffer = kvp.Value;

                    // Procesar paquetes de video listos
                    var videoPacket = jitterBuffer.GetNextPacket(currentTime);
                    while (videoPacket != null)
                    {
                        try
                        {
                            // Obtener configuración de video de la llamada
                            uint width = DEFAULT_VIDEO_WIDTH;
                            uint height = DEFAULT_VIDEO_HEIGHT;

                            if (_activeCalls.TryGetValue(friendNumber, out var call))
                            {
                                width = call.VideoWidth;
                                height = call.VideoHeight;
                            }

                            // Decodificar y disparar callback
                            var videoFrame = DecodeVideo(videoPacket.Data, width, height);
                            _callbacks.OnVideoReceive?.Invoke(this, friendNumber, videoFrame, null);
                        }
                        catch (Exception ex)
                        {
                            Logger.Log.ErrorF($"[{LOG_TAG}] Error procesando frame de video: {ex.Message}");
                        }

                        // Obtener siguiente paquete
                        videoPacket = jitterBuffer.GetNextPacket(currentTime);
                    }
                }
            }
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource?.Dispose();
        }
    }

    // ==================== CLASES AUXILIARES ====================

    /// <summary>
    /// Jitter Buffer para manejar paquetes RTP
    /// </summary>
    public class JitterBuffer
    {
        private readonly SortedDictionary<uint, JitterPacket> _packets;
        private readonly int _maxPackets;
        private uint _expectedSequence;
        private readonly object _lock = new object();

        public JitterBuffer(int maxPackets)
        {
            _packets = new SortedDictionary<uint, JitterPacket>();
            _maxPackets = maxPackets;
            _expectedSequence = 0;
        }

        public void AddPacket(uint sequence, long timestamp, byte[] data)
        {
            lock (_lock)
            {
                // Limpiar buffer si está lleno
                if (_packets.Count >= _maxPackets)
                {
                    var firstKey = _packets.Keys.First();
                    _packets.Remove(firstKey);
                }

                _packets[sequence] = new JitterPacket
                {
                    Sequence = sequence,
                    Timestamp = timestamp,
                    Data = data
                };
            }
        }

        public JitterPacket GetNextPacket(long currentTime)
        {
            lock (_lock)
            {
                if (_packets.Count == 0) return null;

                // Buscar el siguiente paquete en secuencia
                if (_packets.TryGetValue(_expectedSequence, out var packet))
                {
                    _packets.Remove(_expectedSequence);
                    _expectedSequence++;
                    return packet;
                }

                // Si no encontramos el esperado, buscar el más antiguo
                var oldestSequence = _packets.Keys.First();
                if (_packets.TryGetValue(oldestSequence, out packet))
                {
                    _packets.Remove(oldestSequence);
                    _expectedSequence = oldestSequence + 1;
                    return packet;
                }

                return null;
            }
        }
    }

    public class JitterPacket
    {
        public uint Sequence { get; set; }
        public long Timestamp { get; set; }
        public byte[] Data { get; set; }
    }
}