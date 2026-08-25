/**
 * Mean risk score over the last 24 hours.
 *
 * Deliberately a single measure on a single axis. Plotting interaction volume
 * on a second y-axis would let the two lines cross wherever the scales happen
 * to put them, which invents a correlation that is not in the data - so volume
 * appears as context inside the tooltip instead.
 */

import React from 'react';
import { Box, Skeleton, Typography } from '@mui/material';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { useApiQuery } from '../../hooks/useApi';
import {
  SERIES_COLORS,
  TOOLTIP_STYLE,
  VIZ_AXIS_TEXT,
  VIZ_GRID,
  riskScoreLabel,
} from '../../theme/vizPalette';

interface TrendPoint {
  period: string;
  interactions: number;
  mean_risk_score: number;
  high_risk_count: number;
}

interface RiskTrendResponse {
  series?: TrendPoint[];
  trend_data?: TrendPoint[];
}

const LINE_COLOR = SERIES_COLORS[0];

const formatPeriod = (period: string): string => {
  // Buckets arrive as "YYYY-MM-DDTHH:00" (hourly) or "YYYY-MM-DD" (daily).
  const time = period.split('T')[1];
  return time ? time.slice(0, 5) : period.slice(5);
};

const TrendTooltip: React.FC<{
  active?: boolean;
  payload?: Array<{ payload: TrendPoint }>;
}> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;

  const point = payload[0].payload;

  return (
    <Box sx={{ ...TOOLTIP_STYLE.contentStyle, p: 1.25, minWidth: 168 }}>
      <Typography variant="caption" sx={{ color: VIZ_AXIS_TEXT, display: 'block' }}>
        {point.period}
      </Typography>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {point.mean_risk_score.toFixed(1)} mean risk
        <Typography component="span" variant="caption" sx={{ ml: 0.75, color: VIZ_AXIS_TEXT }}>
          {riskScoreLabel(point.mean_risk_score)}
        </Typography>
      </Typography>
      <Typography variant="caption" sx={{ color: VIZ_AXIS_TEXT, display: 'block' }}>
        {point.interactions.toLocaleString()} interactions ·{' '}
        {point.high_risk_count.toLocaleString()} high risk
      </Typography>
    </Box>
  );
};

const RiskTrendChart: React.FC = () => {
  const { data, isLoading, isError } = useApiQuery<RiskTrendResponse>(
    '/api/v1/analytics/trends?metric=risk_score&time_range=24h&granularity=hour',
    { refetchInterval: 60_000 }
  );

  if (isLoading) {
    return <Skeleton variant="rounded" height={280} />;
  }

  if (isError) {
    return (
      <Box sx={{ height: 280, display: 'grid', placeItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          Risk trend data is unavailable right now.
        </Typography>
      </Box>
    );
  }

  const points = data?.series ?? data?.trend_data ?? [];

  if (points.length === 0) {
    return (
      <Box sx={{ height: 280, display: 'grid', placeItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          No interactions recorded in the last 24 hours.
        </Typography>
      </Box>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
        <defs>
          <linearGradient id="riskTrendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={LINE_COLOR} stopOpacity={0.32} />
            <stop offset="100%" stopColor={LINE_COLOR} stopOpacity={0.02} />
          </linearGradient>
        </defs>

        <CartesianGrid stroke={VIZ_GRID} strokeDasharray="3 3" vertical={false} />

        <XAxis
          dataKey="period"
          tickFormatter={formatPeriod}
          tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
          axisLine={{ stroke: VIZ_GRID }}
          tickLine={false}
          minTickGap={24}
        />

        <YAxis
          domain={[0, 100]}
          tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
          axisLine={false}
          tickLine={false}
          width={44}
        />

        <Tooltip content={<TrendTooltip />} cursor={{ stroke: VIZ_GRID, strokeWidth: 1 }} />

        <Area
          type="monotone"
          dataKey="mean_risk_score"
          name="Mean risk score"
          stroke={LINE_COLOR}
          strokeWidth={2}
          fill="url(#riskTrendFill)"
          activeDot={{ r: 4, strokeWidth: 2, stroke: '#1e1e1e' }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
};

export default RiskTrendChart;
