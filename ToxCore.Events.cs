// ToxCore.Events.cs - Sistema de Eventos Desacoplado
// Propósito: Reemplazar callbacks sueltos con sistema de eventos tipado y thread-safe
// Equivalente a: tox_dispatch.c + tox_events.c (simplificado para C#)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Toxcore;
using Toxcore.Core.Abstractions;

namespace Toxcore.Events
{
    /// <summary>
    /// Interfaz para el dispatcher de eventos Tox.
    /// Permite desacoplar la recepción de red del procesamiento de eventos.
    /// </summary>
    public interface IToxEventDispatcher : IDisposable
    {
        void EnqueueEvent(ToxEventBase eventData);
        void RegisterHandler<T>(Action<T> handler) where T : ToxEventBase;
        void UnregisterHandler<T>(Action<T> handler) where T : ToxEventBase;
        void DispatchEvents();
        Task DispatchEventsAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Clase base para todos los eventos Tox internos.
    /// </summary>
    public abstract record ToxEventBase
    {
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
        public ulong MonotonicTime { get; init; }
    }

    // Eventos internos (mapean 1:1 con los de la API pública)
    public record InternalFriendRequestEvent(byte[] PublicKey, byte[] Message, uint Length) : ToxEventBase;
    public record InternalFriendMessageEvent(int FriendNumber, ToxMessageType Type, byte[] Message, uint Length, uint MessageId) : ToxEventBase;
    public record InternalFriendNameChangeEvent(int FriendNumber, byte[] Name, uint Length) : ToxEventBase;
    public record InternalFriendStatusMessageChangeEvent(int FriendNumber, byte[] Message, uint Length) : ToxEventBase;
    public record InternalFriendStatusChangeEvent(int FriendNumber, ToxUserStatus Status) : ToxEventBase;
    public record InternalFriendConnectionStatusChangeEvent(int FriendNumber, ToxConnectionStatus Status) : ToxEventBase;
    public record InternalSelfConnectionStatusChangeEvent(ToxConnectionStatus Status) : ToxEventBase;
    public record InternalFriendTypingEvent(int FriendNumber, bool IsTyping) : ToxEventBase;

    /// <summary>
    /// Implementación del dispatcher usando Channel<T> para thread-safety.
    /// </summary>
    public sealed class ToxEventDispatcher : IToxEventDispatcher
    {
        private readonly Channel<ToxEventBase> _eventChannel;
        private readonly Dictionary<Type, List<Delegate>> _handlers = new();
        private readonly object _handlerLock = new();
        private bool _disposed;

        public ToxEventDispatcher(int capacity = 1000)
        {
            _eventChannel = Channel.CreateBounded<ToxEventBase>(new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = false
            });
        }

        /// <summary>
        /// Encola un evento desde cualquier thread (thread-safe).
        /// </summary>
        public void EnqueueEvent(ToxEventBase eventData)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ToxEventDispatcher));
            if (eventData == null) return;

            _eventChannel.Writer.TryWrite(eventData);
        }

        /// <summary>
        /// Registra un handler para un tipo específico de evento.
        /// </summary>
        public void RegisterHandler<T>(Action<T> handler) where T : ToxEventBase
        {
            if (handler == null) throw new ArgumentNullException(nameof(handler));

            lock (_handlerLock)
            {
                if (!_handlers.TryGetValue(typeof(T), out var list))
                {
                    list = new List<Delegate>();
                    _handlers[typeof(T)] = list;
                }
                list.Add(handler);
            }
        }

        /// <summary>
        /// Desregistra un handler previamente registrado.
        /// </summary>
        public void UnregisterHandler<T>(Action<T> handler) where T : ToxEventBase
        {
            if (handler == null) return;

            lock (_handlerLock)
            {
                if (_handlers.TryGetValue(typeof(T), out var list))
                {
                    list.Remove(handler);
                }
            }
        }

        /// <summary>
        /// Procesa todos los eventos pendientes (síncrono).
        /// Debe llamarse desde el thread de Iterate().
        /// </summary>
        public void DispatchEvents()
        {
            if (_disposed) return;

            while (_eventChannel.Reader.TryRead(out var evt))
            {
                DispatchSingleEvent(evt);
            }
        }

        /// <summary>
        /// Procesa eventos de forma asíncrona (para uso con async/await).
        /// </summary>
        public async Task DispatchEventsAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed) return;

            await foreach (var evt in _eventChannel.Reader.ReadAllAsync(cancellationToken))
            {
                DispatchSingleEvent(evt);
            }
        }

        private void DispatchSingleEvent(ToxEventBase evt)
        {
            List<Delegate> handlers;

            lock (_handlerLock)
            {
                if (!_handlers.TryGetValue(evt.GetType(), out handlers) || handlers.Count == 0)
                    return;

                // Crear copia para evitar lock durante invocación
                handlers = new List<Delegate>(handlers);
            }

            foreach (var handler in handlers)
            {
                try
                {
                    handler.DynamicInvoke(evt);
                }
                catch (Exception ex)
                {
                    // Loggear pero no detener otros handlers
                    System.Diagnostics.Debug.WriteLine($"[ToxEventDispatcher] Handler error: {ex.Message}");
                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _eventChannel.Writer.Complete();

            lock (_handlerLock)
            {
                _handlers.Clear();
            }
        }
    }

    /// <summary>
    /// Bridge entre eventos internos y eventos públicos de ITox.
    /// Conecta el dispatcher con los EventHandler<> de la API pública.
    /// </summary>
    public sealed class ToxEventBridge : IDisposable
    {
        private readonly IToxEventDispatcher _dispatcher;

        // Delegados públicos que expone el bridge para que ToxInternal los use
        public event EventHandler<ToxFriendRequestEventArgs> OnFriendRequest;
        public event EventHandler<ToxFriendMessageEventArgs> OnFriendMessage;
        public event EventHandler<ToxFriendNameChangeEventArgs> OnFriendNameChange;
        public event EventHandler<ToxFriendStatusMessageChangeEventArgs> OnFriendStatusMessageChange;
        public event EventHandler<ToxFriendStatusChangeEventArgs> OnFriendStatusChange;
        public event EventHandler<ToxFriendConnectionStatusChangeEventArgs> OnFriendConnectionStatusChange;
        public event EventHandler<ToxSelfConnectionStatusChangeEventArgs> OnSelfConnectionStatusChange;
        public event EventHandler<ToxFriendTypingEventArgs> OnFriendTyping;

        public ToxEventBridge(IToxEventDispatcher dispatcher)
        {
            _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            RegisterInternalHandlers();
        }

        private void RegisterInternalHandlers()
        {
            _dispatcher.RegisterHandler<InternalFriendRequestEvent>(OnInternalFriendRequest);
            _dispatcher.RegisterHandler<InternalFriendMessageEvent>(OnInternalFriendMessage);
            _dispatcher.RegisterHandler<InternalFriendNameChangeEvent>(OnInternalFriendNameChange);
            _dispatcher.RegisterHandler<InternalFriendStatusMessageChangeEvent>(OnInternalFriendStatusMessageChange);
            _dispatcher.RegisterHandler<InternalFriendStatusChangeEvent>(OnInternalFriendStatusChange);
            _dispatcher.RegisterHandler<InternalFriendConnectionStatusChangeEvent>(OnInternalFriendConnectionStatusChange);
            _dispatcher.RegisterHandler<InternalSelfConnectionStatusChangeEvent>(OnInternalSelfConnectionStatusChange);
            _dispatcher.RegisterHandler<InternalFriendTypingEvent>(OnInternalFriendTyping);
        }

        private void OnInternalFriendRequest(InternalFriendRequestEvent e)
        {
            var msg = e.Message != null ? System.Text.Encoding.UTF8.GetString(e.Message, 0, (int)Math.Min(e.Length, e.Message.Length)) : string.Empty;
            OnFriendRequest?.Invoke(this, new ToxFriendRequestEventArgs(e.PublicKey, msg));
        }

        private void OnInternalFriendMessage(InternalFriendMessageEvent e)
        {
            var msg = e.Message != null ? System.Text.Encoding.UTF8.GetString(e.Message, 0, (int)Math.Min(e.Length, e.Message.Length)) : string.Empty;
            OnFriendMessage?.Invoke(this, new ToxFriendMessageEventArgs(e.FriendNumber, e.Type, msg, e.MessageId));
        }

        private void OnInternalFriendNameChange(InternalFriendNameChangeEvent e)
        {
            var name = e.Name != null ? System.Text.Encoding.UTF8.GetString(e.Name, 0, (int)Math.Min(e.Length, e.Name.Length)) : string.Empty;
            OnFriendNameChange?.Invoke(this, new ToxFriendNameChangeEventArgs(e.FriendNumber, name));
        }

        private void OnInternalFriendStatusMessageChange(InternalFriendStatusMessageChangeEvent e)
        {
            var msg = e.Message != null ? System.Text.Encoding.UTF8.GetString(e.Message, 0, (int)Math.Min(e.Length, e.Message.Length)) : string.Empty;
            OnFriendStatusMessageChange?.Invoke(this, new ToxFriendStatusMessageChangeEventArgs(e.FriendNumber, msg));
        }

        private void OnInternalFriendStatusChange(InternalFriendStatusChangeEvent e)
        {
            OnFriendStatusChange?.Invoke(this, new ToxFriendStatusChangeEventArgs(e.FriendNumber, e.Status));
        }

        private void OnInternalFriendConnectionStatusChange(InternalFriendConnectionStatusChangeEvent e)
        {
            OnFriendConnectionStatusChange?.Invoke(this, new ToxFriendConnectionStatusChangeEventArgs(e.FriendNumber, e.Status));
        }

        private void OnInternalSelfConnectionStatusChange(InternalSelfConnectionStatusChangeEvent e)
        {
            OnSelfConnectionStatusChange?.Invoke(this, new ToxSelfConnectionStatusChangeEventArgs(e.Status));
        }

        private void OnInternalFriendTyping(InternalFriendTypingEvent e)
        {
            OnFriendTyping?.Invoke(this, new ToxFriendTypingEventArgs(e.FriendNumber, e.IsTyping));
        }

        public void Dispose()
        {
            // Los handlers se limpian automáticamente cuando el dispatcher se dispone
        }
    }
}