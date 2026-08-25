/**
 * Interaction volume per AI platform.
 *
 * A horizontal bar chart rather than a pie: platform names are long, and
 * comparing bar lengths is far more accurate than comparing wedge angles.
 * Values are labelled directly, so the chart is readable without the legend
 * and without relying on colour.
 */

import React from 'react';
import { Box, Skeleton, Typography } from '@mui/material';
import {
  Bar,
  BarChart,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { useApiQuery } from '../../hooks/useApi';
import {
  TOOLTIP_STYLE,
  VIZ_AXIS_TEXT,
  seriesColor,
} from '../../theme/vizPalette';

interface PlatformAnalyticsResponse {
  total_usage: Record<string, number>;
  risk_correlation: Record<string, number>;
}

interface PlatformRow {
  platform: string;
  interactions: number;
  meanRisk: number;
}

/** Show the busiest platforms individually; the tail becomes one "Other" bar. */
const MAX_BARS = 6;

const PlatformTooltip: React.FC<{
  active?: boolean;
  payload?: Array<{ payload: PlatformRow }>;
}> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;

  const row = payload[0].payload;

  return (
    <Box sx={{ ...TOOLTIP_STYLE.contentStyle, p: 1.25 }}>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {row.platform}
      </Typography>
      <Typography variant="caption" sx={{ color: VIZ_AXIS_TEXT, display: 'block' }}>
        {row.interactions.toLocaleString()} interactions
      </Typography>
      {row.meanRisk > 0 && (
        <Typography variant="caption" sx={{ color: VIZ_AXIS_TEXT, display: 'block' }}>
          Mean risk score {row.meanRisk.toFixed(1)}
        </Typography>
      )}
    </Box>
  );
};

const PlatformUsage: React.FC = () => {
  const { data, isLoading, isError } = useApiQuery<PlatformAnalyticsResponse>(
    '/api/v1/analytics/platforms?time_range=7d',
    { refetchInterval: 60_000 }
  );

  if (isLoading) {
    return <Skeleton variant="rounded" height={280} />;
  }

  if (isError) {
    return (
      <Box sx={{ height: 280, display: 'grid', placeItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          Platform data is unavailable right now.
        </Typography>
      </Box>
    );
  }

  const usage = data?.total_usage ?? {};
  const risk = data?.risk_correlation ?? {};

  const ranked: PlatformRow[] = Object.entries(usage)
    .map(([platform, interactions]) => ({
      platform,
      interactions,
      meanRisk: risk[platform] ?? 0,
    }))
    .sort((a, b) => b.interactions - a.interactions);

  if (ranked.length === 0) {
    return (
      <Box sx={{ height: 280, display: 'grid', placeItems: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          No platform activity in the last 7 days.
        </Typography>
      </Box>
    );
  }

  const head = ranked.slice(0, MAX_BARS);
  const tail = ranked.slice(MAX_BARS);

  const rows =
    tail.length > 0
      ? [
          ...head,
          {
            platform: `Other (${tail.length})`,
            interactions: tail.reduce((sum, row) => sum + row.interactions, 0),
            meanRisk: 0,
          },
        ]
      : head;

  return (
    <ResponsiveContainer width="100%" height={Math.max(220, rows.length * 44)}>
      <BarChart
        data={rows}
        layout="vertical"
        margin={{ top: 4, right: 48, bottom: 4, left: 4 }}
        barCategoryGap={6}
      >
        <XAxis type="number" hide />

        <YAxis
          type="category"
          dataKey="platform"
          width={104}
          tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
          axisLine={false}
          tickLine={false}
        />

        <Tooltip content={<PlatformTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />

        <Bar dataKey="interactions" radius={[0, 4, 4, 0]} maxBarSize={22}>
          {rows.map((row, index) => (
            <Cell key={row.platform} fill={seriesColor(index)} />
          ))}
          <LabelList
            dataKey="interactions"
            position="right"
            formatter={(value: number) => value.toLocaleString()}
            style={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
};

export default PlatformUsage;
