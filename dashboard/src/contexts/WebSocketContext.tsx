/**
 * Live connection to the monitoring stream.
 *
 * The backend exposes a plain WebSocket at `/ws/monitor` - not a Socket.IO
 * server - so this uses the native `WebSocket` API. It wraps it in a small
 * event emitter (`on` / `off` / `emit`) so components subscribe to named events
 * rather than parsing frames themselves.
 *
 * Wire protocol
 * -------------
 *   server -> client   {"type": "alert", "data": {...}, "timestamp": ..., "message_id": ...}
 *   client -> server   {"action": "subscribe", "topic": "security_alerts"}
 *   heartbeat          the literal string "ping", answered with "pong"
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import toast from 'react-hot-toast';

type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

type EventHandler = (payload: any) => void;

/** Minimal emitter surface, so pages keep using `socket.on(...)`. */
export interface MonitorSocket {
  on: (event: string, handler: EventHandler) => void;
  off: (event: string, handler: EventHandler) => void;
  emit: (action: string, payload?: Record<string, unknown>) => void;
}

interface WebSocketContextType {
  socket: MonitorSocket | null;
  isConnected: boolean;
  lastMessage: any;
  connectionStatus: ConnectionStatus;
  subscribe: (topic: string, filters?: Record<string, unknown>) => void;
  unsubscribe: (topic: string) => void;
  sendMessage: (action: string, data?: Record<string, unknown>) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

/**
 * Server message types mapped to the event names components listen for.
 * Anything not listed here is dispatched under its own `type`.
 */
const EVENT_ALIASES: Record<string, string> = {
  alert: 'new_alert',
  interaction: 'new_interaction',
  user_activity: 'user_activity',
  system_status: 'system_status',
  system_alert: 'system_alert',
  platform_stats: 'stats_update',
  risk_trend: 'stats_update',
};

const MAX_RECONNECT_ATTEMPTS = 6;
const HEARTBEAT_INTERVAL_MS = 25_000;

/** Derive the socket URL from configuration, falling back to the page origin. */
function resolveSocketUrl(): string {
  const explicit = import.meta.env.VITE_WS_URL;
  if (explicit) return explicit;

  const apiUrl = import.meta.env.VITE_API_URL;
  if (apiUrl) {
    return `${apiUrl.replace(/^http/, 'ws').replace(/\/$/, '')}/ws/monitor`;
  }

  // Same-origin: the dev server proxies /ws to the backend.
  const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${scheme}://${window.location.host}/ws/monitor`;
}

interface WebSocketProviderProps {
  children: React.ReactNode;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({ children }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected');

  const socketRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Map<string, Set<EventHandler>>>(new Map());
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Topics are replayed after a reconnect so subscriptions survive an outage.
  const topicsRef = useRef<Map<string, Record<string, unknown> | undefined>>(new Map());
  const shuttingDown = useRef(false);

  const dispatch = useCallback((event: string, payload: any) => {
    handlersRef.current.get(event)?.forEach((handler) => {
      try {
        handler(payload);
      } catch (error) {
        // One bad listener must not stop the others from running.
        console.error(`WebSocket handler for "${event}" threw:`, error);
      }
    });
  }, []);

  const send = useCallback((payload: Record<string, unknown>) => {
    const socket = socketRef.current;
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(payload));
      return true;
    }
    return false;
  }, []);

  const connect = useCallback(() => {
    if (shuttingDown.current) return;

    setConnectionStatus('connecting');

    let socket: WebSocket;
    try {
      socket = new WebSocket(resolveSocketUrl());
    } catch {
      // An invalid URL throws synchronously; surface it as a failed connection
      // rather than letting it escape the provider.
      setConnectionStatus('error');
      return;
    }

    socketRef.current = socket;

    socket.onopen = () => {
      setIsConnected(true);
      setConnectionStatus('connected');

      if (reconnectAttempts.current > 0) {
        toast.success('Real-time monitoring reconnected');
      }
      reconnectAttempts.current = 0;

      // Restore subscriptions the previous connection held.
      topicsRef.current.forEach((filters, topic) => {
        send({ action: 'subscribe', topic, filters });
      });

      heartbeatTimer.current = setInterval(() => {
        if (socketRef.current?.readyState === WebSocket.OPEN) {
          socketRef.current.send('ping');
        }
      }, HEARTBEAT_INTERVAL_MS);
    };

    socket.onmessage = (event) => {
      if (event.data === 'pong') return;

      let message: any;
      try {
        message = JSON.parse(event.data);
      } catch {
        console.warn('Ignoring non-JSON WebSocket frame');
        return;
      }

      setLastMessage(message);

      const type: string = message?.type ?? 'message';
      dispatch(EVENT_ALIASES[type] ?? type, message?.data ?? message);
      dispatch('message', message);
    };

    socket.onerror = () => {
      setConnectionStatus('error');
    };

    socket.onclose = () => {
      setIsConnected(false);
      socketRef.current = null;

      if (heartbeatTimer.current) {
        clearInterval(heartbeatTimer.current);
        heartbeatTimer.current = null;
      }

      if (shuttingDown.current) {
        setConnectionStatus('disconnected');
        return;
      }

      if (reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
        setConnectionStatus('error');
        toast.error('Lost the monitoring connection. Reload the page to retry.');
        return;
      }

      // Exponential backoff, capped, so a backend restart does not turn into a
      // reconnect storm from every open dashboard.
      const delay = Math.min(1_000 * 2 ** reconnectAttempts.current, 30_000);
      reconnectAttempts.current += 1;
      setConnectionStatus('disconnected');
      reconnectTimer.current = setTimeout(connect, delay);
    };
  }, [dispatch, send]);

  useEffect(() => {
    shuttingDown.current = false;
    connect();

    return () => {
      shuttingDown.current = true;

      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (heartbeatTimer.current) clearInterval(heartbeatTimer.current);

      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [connect]);

  const subscribe = useCallback(
    (topic: string, filters?: Record<string, unknown>) => {
      topicsRef.current.set(topic, filters);
      send({ action: 'subscribe', topic, filters });
    },
    [send]
  );

  const unsubscribe = useCallback(
    (topic: string) => {
      topicsRef.current.delete(topic);
      send({ action: 'unsubscribe', topic });
    },
    [send]
  );

  const sendMessage = useCallback(
    (action: string, data?: Record<string, unknown>) => {
      send({ action, ...data });
    },
    [send]
  );

  const socket = useMemo<MonitorSocket>(
    () => ({
      on: (event, handler) => {
        const handlers = handlersRef.current.get(event) ?? new Set<EventHandler>();
        handlers.add(handler);
        handlersRef.current.set(event, handlers);
      },
      off: (event, handler) => {
        handlersRef.current.get(event)?.delete(handler);
      },
      emit: (action, payload) => {
        // `emit('subscribe', { topic })` is the idiom the pages already use.
        if (action === 'subscribe' && typeof payload?.topic === 'string') {
          subscribe(payload.topic, payload.filters as Record<string, unknown> | undefined);
          return;
        }
        if (action === 'unsubscribe' && typeof payload?.topic === 'string') {
          unsubscribe(payload.topic);
          return;
        }
        send({ action, ...payload });
      },
    }),
    [send, subscribe, unsubscribe]
  );

  const value = useMemo<WebSocketContextType>(
    () => ({
      socket,
      isConnected,
      lastMessage,
      connectionStatus,
      subscribe,
      unsubscribe,
      sendMessage,
    }),
    [socket, isConnected, lastMessage, connectionStatus, subscribe, unsubscribe, sendMessage]
  );

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>;
};
