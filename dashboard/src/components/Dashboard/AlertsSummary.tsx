/**
 * Compact feed of the most recent security alerts.
 *
 * Severity is shown as a labelled chip rather than a coloured dot, so it reads
 * correctly for colour-blind users and in a screen reader.
 */

import React from 'react';
import {
  Box,
  Chip,
  List,
  ListItemButton,
  ListItemText,
  Skeleton,
  Typography,
} from '@mui/material';
import { formatDistanceToNow } from 'date-fns';
import { useNavigate } from 'react-router-dom';

import { useApiQuery } from '../../hooks/useApi';
import { RISK_COLORS } from '../../theme/vizPalette';

interface AlertRow {
  id: number;
  title: string;
  severity: string;
  status: string;
  created_at: string;
  platform?: string | null;
}

interface AlertListResponse {
  alerts: AlertRow[];
  total_count: number;
}

interface AlertsSummaryProps {
  limit?: number;
}

const relativeTime = (value: string): string => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'unknown time';
  return `${formatDistanceToNow(parsed)} ago`;
};

const AlertsSummary: React.FC<AlertsSummaryProps> = ({ limit = 5 }) => {
  const navigate = useNavigate();

  const { data, isLoading, isError } = useApiQuery<AlertListResponse>(
    `/api/v1/alerts/?per_page=${limit}&sort=created_desc`,
    { refetchInterval: 30_000 }
  );

  if (isLoading) {
    return (
      <Box>
        {Array.from({ length: limit }).map((_, index) => (
          <Skeleton key={index} variant="rounded" height={52} sx={{ mb: 1 }} />
        ))}
      </Box>
    );
  }

  if (isError) {
    return (
      <Typography variant="body2" color="text.secondary" sx={{ py: 3, textAlign: 'center' }}>
        Alerts are unavailable right now.
      </Typography>
    );
  }

  const alerts = data?.alerts ?? [];

  if (alerts.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary" sx={{ py: 3, textAlign: 'center' }}>
        No alerts have been raised. Nothing needs your attention.
      </Typography>
    );
  }

  return (
    <List disablePadding>
      {alerts.map((alert) => (
        <ListItemButton
          key={alert.id}
          onClick={() => navigate(`/alerts?alert=${alert.id}`)}
          sx={{ borderRadius: 1.5, mb: 0.5, gap: 1.5 }}
        >
          <ListItemText
            primary={alert.title}
            primaryTypographyProps={{ variant: 'body2', noWrap: true }}
            secondary={[alert.platform, relativeTime(alert.created_at)]
              .filter(Boolean)
              .join(' · ')}
            secondaryTypographyProps={{ variant: 'caption' }}
          />

          <Chip
            size="small"
            label={alert.severity}
            sx={{
              flexShrink: 0,
              textTransform: 'capitalize',
              borderColor: RISK_COLORS[alert.severity] ?? 'divider',
              color: RISK_COLORS[alert.severity] ?? 'text.secondary',
            }}
            variant="outlined"
          />
        </ListItemButton>
      ))}
    </List>
  );
};

export default AlertsSummary;
