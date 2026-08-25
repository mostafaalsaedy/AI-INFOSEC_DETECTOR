/**
 * A single headline metric.
 *
 * Shows a skeleton rather than a zero while loading: "0 alerts" and "not
 * loaded yet" mean very different things on a security dashboard.
 */

import React from 'react';
import { Box, Card, CardContent, Chip, Skeleton, Typography, alpha } from '@mui/material';
import { TrendingUp as TrendingUpIcon } from '@mui/icons-material';

export type StatsCardColor =
  | 'primary'
  | 'secondary'
  | 'success'
  | 'error'
  | 'warning'
  | 'info';

interface StatsCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color?: StatsCardColor;
  loading?: boolean;
  /** Short delta label, e.g. "+12". */
  trend?: string;
  subtitle?: string;
}

const StatsCard: React.FC<StatsCardProps> = ({
  title,
  value,
  icon,
  color = 'primary',
  loading = false,
  trend,
  subtitle,
}) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom noWrap>
            {title}
          </Typography>

          {loading ? (
            <Skeleton variant="text" width={96} height={44} />
          ) : (
            <Typography variant="h4" component="p" sx={{ fontWeight: 600 }}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </Typography>
          )}

          {subtitle && !loading && (
            <Typography variant="caption" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>

        <Box
          sx={(theme) => ({
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 48,
            height: 48,
            borderRadius: 2,
            flexShrink: 0,
            color: `${color}.main`,
            // alpha() tints the surface without washing out the icon on top.
            backgroundColor: alpha(theme.palette[color].main, 0.15),
          })}
        >
          {icon}
        </Box>
      </Box>

      {trend && !loading && (
        <Chip
          size="small"
          icon={<TrendingUpIcon />}
          label={trend}
          color={color}
          variant="outlined"
          sx={{ mt: 1.5 }}
        />
      )}
    </CardContent>
  </Card>
);

export default StatsCard;
