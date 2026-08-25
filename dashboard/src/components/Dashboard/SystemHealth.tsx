/**
 * Health of each backend dependency.
 *
 * Every tile carries an icon and a written status alongside its colour, so a
 * degraded service is legible without relying on hue.
 */

import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  IconButton,
  Skeleton,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  HelpOutline as HelpOutlineIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';

import { STATUS_COLORS } from '../../theme/vizPalette';

interface SystemStatus {
  status: string;
  services: Record<string, string>;
  uptime?: number;
  version?: string;
}

interface SystemHealthProps {
  systemStatus?: SystemStatus;
  loading?: boolean;
  onRefresh?: () => void;
}

const SERVICE_LABELS: Record<string, string> = {
  database: 'Database',
  ml_analyzer: 'ML analyzer',
  redis: 'Redis',
  celery: 'Task queue',
  websocket: 'WebSocket',
};

const statusPresentation = (value: string) => {
  switch (value) {
    case 'healthy':
      return { color: STATUS_COLORS.good, icon: <CheckCircleIcon fontSize="small" /> };
    case 'degraded':
      return { color: STATUS_COLORS.warning, icon: <WarningIcon fontSize="small" /> };
    case 'unhealthy':
      return { color: STATUS_COLORS.critical, icon: <ErrorIcon fontSize="small" /> };
    default:
      return { color: '#6b6b6b', icon: <HelpOutlineIcon fontSize="small" /> };
  }
};

const formatUptime = (seconds?: number): string | null => {
  if (!seconds || seconds < 0) return null;

  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
};

const SystemHealth: React.FC<SystemHealthProps> = ({
  systemStatus,
  loading = false,
  onRefresh,
}) => {
  const overall = statusPresentation(systemStatus?.status ?? 'unknown');
  const uptime = formatUptime(systemStatus?.uptime);
  const services = Object.entries(systemStatus?.services ?? {});

  return (
    <Card>
      <CardContent>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 2,
            mb: 2,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, minWidth: 0 }}>
            <Typography variant="h6" component="h2">
              System Health
            </Typography>

            {!loading && (
              <Chip
                size="small"
                icon={overall.icon}
                label={systemStatus?.status ?? 'unknown'}
                variant="outlined"
                sx={{ textTransform: 'capitalize', borderColor: overall.color, color: overall.color }}
              />
            )}
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexShrink: 0 }}>
            {systemStatus?.version && (
              <Typography variant="caption" color="text.secondary">
                v{systemStatus.version}
              </Typography>
            )}
            {uptime && (
              <Typography variant="caption" color="text.secondary">
                up {uptime}
              </Typography>
            )}
            {onRefresh && (
              <Tooltip title="Re-check services">
                <IconButton size="small" onClick={onRefresh} aria-label="Re-check services">
                  <RefreshIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
          </Box>
        </Box>

        {loading ? (
          <Skeleton variant="rounded" height={64} />
        ) : services.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No service status reported. The API may be unreachable.
          </Typography>
        ) : (
          <Box
            sx={{
              display: 'grid',
              gap: 1.5,
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            }}
          >
            {services.map(([name, value]) => {
              const presentation = statusPresentation(value);

              return (
                <Box
                  key={name}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 1.25,
                    p: 1.5,
                    borderRadius: 1.5,
                    border: '1px solid',
                    borderColor: 'divider',
                  }}
                >
                  <Box sx={{ color: presentation.color, display: 'flex' }}>
                    {presentation.icon}
                  </Box>

                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" noWrap>
                      {SERVICE_LABELS[name] ?? name}
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: presentation.color, textTransform: 'capitalize' }}
                    >
                      {value}
                    </Typography>
                  </Box>
                </Box>
              );
            })}
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default SystemHealth;
