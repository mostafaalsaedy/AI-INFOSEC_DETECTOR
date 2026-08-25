/**
 * Live feed of events arriving over the monitoring WebSocket.
 *
 * Purely in-memory and capped: this is a "what is happening right now" panel,
 * not a log. History lives in the Sessions and Alerts pages.
 */

import React, { useEffect, useRef, useState } from 'react';
import { Chip, List, ListItem, ListItemText, Typography } from '@mui/material';

import { useWebSocket } from '../../contexts/WebSocketContext';
import { RISK_COLORS } from '../../theme/vizPalette';

/** Keeping the feed short bounds memory and keeps the panel readable. */
const MAX_EVENTS = 25;

interface ActivityEvent {
  id: string;
  kind: 'alert' | 'interaction' | 'session' | 'system';
  label: string;
  detail?: string;
  severity?: string;
  receivedAt: Date;
}

const KIND_LABEL: Record<ActivityEvent['kind'], string> = {
  alert: 'Alert',
  interaction: 'Interaction',
  session: 'Session',
  system: 'System',
};

const RealtimeActivity: React.FC = () => {
  const { socket, isConnected } = useWebSocket();
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const counter = useRef(0);

  useEffect(() => {
    if (!socket) return undefined;

    const push = (event: Omit<ActivityEvent, 'id' | 'receivedAt'>) => {
      counter.current += 1;
      const entry: ActivityEvent = {
        ...event,
        id: `${Date.now()}-${counter.current}`,
        receivedAt: new Date(),
      };

      setEvents((current) => [entry, ...current].slice(0, MAX_EVENTS));
    };

    const handleAlert = (payload: any) => {
      push({
        kind: 'alert',
        label: payload?.title ?? 'Security alert raised',
        detail: payload?.platform,
        severity: payload?.severity,
      });
    };

    const handleInteraction = (payload: any) => {
      push({
        kind: 'interaction',
        label: `Interaction on ${payload?.platform ?? 'an AI platform'}`,
        detail:
          typeof payload?.risk_score === 'number'
            ? `risk ${payload.risk_score.toFixed(0)}`
            : undefined,
        severity: payload?.risk_level,
      });
    };

    const handleActivity = (payload: any) => {
      push({
        kind: 'session',
        label: payload?.message ?? 'Session activity',
        detail: payload?.session_id,
      });
    };

    const handleSystem = (payload: any) => {
      push({
        kind: 'system',
        label: payload?.message ?? 'System status changed',
        detail: payload?.status?.status,
      });
    };

    socket.on('new_alert', handleAlert);
    socket.on('new_interaction', handleInteraction);
    socket.on('user_activity', handleActivity);
    socket.on('system_alert', handleSystem);

    socket.emit('subscribe', { topic: 'security_alerts' });
    socket.emit('subscribe', { topic: 'user_activity' });

    return () => {
      socket.off('new_alert', handleAlert);
      socket.off('new_interaction', handleInteraction);
      socket.off('user_activity', handleActivity);
      socket.off('system_alert', handleSystem);
    };
  }, [socket]);

  if (!isConnected) {
    return (
      <Typography variant="body2" color="text.secondary" sx={{ py: 3, textAlign: 'center' }}>
        Not connected to the monitoring stream. Live events will appear once the
        connection is restored.
      </Typography>
    );
  }

  if (events.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary" sx={{ py: 3, textAlign: 'center' }}>
        Connected and waiting for activity…
      </Typography>
    );
  }

  return (
    <List
      dense
      disablePadding
      sx={{ maxHeight: 320, overflowY: 'auto' }}
      aria-live="polite"
      aria-label="Live monitoring activity"
    >
      {events.map((event) => (
        <ListItem key={event.id} disableGutters sx={{ gap: 1.5, alignItems: 'flex-start' }}>
          <Chip
            size="small"
            label={KIND_LABEL[event.kind]}
            variant="outlined"
            sx={{
              flexShrink: 0,
              minWidth: 92,
              borderColor: event.severity
                ? RISK_COLORS[event.severity] ?? 'divider'
                : 'divider',
              color: event.severity ? RISK_COLORS[event.severity] ?? 'text.secondary' : 'text.secondary',
            }}
          />

          <ListItemText
            primary={event.label}
            primaryTypographyProps={{ variant: 'body2' }}
            secondary={[event.detail, event.receivedAt.toLocaleTimeString()]
              .filter(Boolean)
              .join(' · ')}
            secondaryTypographyProps={{ variant: 'caption' }}
          />
        </ListItem>
      ))}
    </List>
  );
};

export default RealtimeActivity;
