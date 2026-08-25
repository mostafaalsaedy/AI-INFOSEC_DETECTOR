/**
 * Analytics workspace: risk distribution, platform comparison and alert trends
 * over a selectable window.
 *
 * Each measure gets its own chart on its own axis. Overlaying risk scores and
 * interaction counts on shared axes would make their crossings look meaningful
 * when they are an artefact of the scales.
 */

import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  MenuItem,
  Skeleton,
  TextField,
  Typography,
} from '@mui/material';
import { Helmet } from 'react-helmet-async';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { useApiQuery } from '../../hooks/useApi';
import {
  RISK_COLORS,
  SERIES_COLORS,
  TOOLTIP_STYLE,
  VIZ_AXIS_TEXT,
  VIZ_GRID,
  seriesColor,
} from '../../theme/vizPalette';

const TIME_RANGES = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
] as const;

const RISK_ORDER = ['low', 'medium', 'high', 'critical'] as const;

interface RiskAnalytics {
  total_interactions: number;
  risk_distribution: Record<string, number>;
  platform_breakdown: Record<string, number>;
  trend_data: Array<{
    period: string;
    interactions: number;
    mean_risk_score: number;
    high_risk_count: number;
  }>;
  top_risk_patterns: Array<{ pattern: string; count: number; mean_risk_score: number }>;
  summary_stats: Record<string, number>;
}

interface AlertAnalytics {
  total_alerts: number;
  alerts_by_severity: Record<string, number>;
  alert_trends: Array<{ period: string; count: number }>;
  false_positive_rate: number;
  top_alert_types: Array<{ alert_type: string; count: number; share_percent: number }>;
}

const ChartCard: React.FC<{
  title: string;
  description?: string;
  loading?: boolean;
  empty?: boolean;
  emptyMessage?: string;
  children: React.ReactNode;
}> = ({ title, description, loading, empty, emptyMessage, children }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Typography variant="h6" component="h2">
        {title}
      </Typography>
      {description && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
          {description}
        </Typography>
      )}

      {loading ? (
        <Skeleton variant="rounded" height={260} />
      ) : empty ? (
        <Box sx={{ height: 260, display: 'grid', placeItems: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            {emptyMessage ?? 'No data for this period.'}
          </Typography>
        </Box>
      ) : (
        children
      )}
    </CardContent>
  </Card>
);

const Analytics: React.FC = () => {
  const [timeRange, setTimeRange] = useState<string>('7d');

  const { data: risk, isLoading: riskLoading } = useApiQuery<RiskAnalytics>(
    `/api/v1/analytics/risk?time_range=${timeRange}`
  );

  const { data: alerts, isLoading: alertsLoading } = useApiQuery<AlertAnalytics>(
    `/api/v1/analytics/alerts?time_range=${timeRange}`
  );

  const riskDistribution = RISK_ORDER.map((level) => ({
    level,
    label: level.charAt(0).toUpperCase() + level.slice(1),
    count: risk?.risk_distribution?.[level] ?? 0,
  }));

  const platformRows = Object.entries(risk?.platform_breakdown ?? {})
    .map(([platform, interactions]) => ({ platform, interactions }))
    .sort((a, b) => b.interactions - a.interactions)
    .slice(0, 8);

  const alertTrend = alerts?.alert_trends ?? [];
  const riskPatterns = (risk?.top_risk_patterns ?? []).slice(0, 8);

  return (
    <>
      <Helmet>
        <title>Analytics · InfoSec AI Monitor</title>
      </Helmet>

      <Box sx={{ p: 3 }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 2,
            mb: 3,
          }}
        >
          <Box>
            <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
              Analytics
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {risk
                ? `${risk.total_interactions.toLocaleString()} interactions · ${
                    alerts?.total_alerts.toLocaleString() ?? 0
                  } alerts`
                : 'Loading…'}
            </Typography>
          </Box>

          <TextField
            select
            size="small"
            label="Time range"
            value={timeRange}
            onChange={(event) => setTimeRange(event.target.value)}
            sx={{ minWidth: 180 }}
          >
            {TIME_RANGES.map((range) => (
              <MenuItem key={range.value} value={range.value}>
                {range.label}
              </MenuItem>
            ))}
          </TextField>
        </Box>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <ChartCard
              title="Risk distribution"
              description="Interactions by assessed risk level"
              loading={riskLoading}
              empty={riskDistribution.every((row) => row.count === 0)}
            >
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={riskDistribution} margin={{ top: 8, right: 8, left: -16 }}>
                  <CartesianGrid stroke={VIZ_GRID} strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={{ stroke: VIZ_GRID }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                    width={48}
                  />
                  <Tooltip {...TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="count" name="Interactions" radius={[4, 4, 0, 0]} maxBarSize={64}>
                    {riskDistribution.map((row) => (
                      <Cell key={row.level} fill={RISK_COLORS[row.level]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </Grid>

          <Grid item xs={12} md={6}>
            <ChartCard
              title="Platform activity"
              description="Interactions per AI platform"
              loading={riskLoading}
              empty={platformRows.length === 0}
            >
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={platformRows}
                  layout="vertical"
                  margin={{ top: 4, right: 24, left: 4 }}
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
                  <Tooltip {...TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="interactions" name="Interactions" radius={[0, 4, 4, 0]} maxBarSize={22}>
                    {platformRows.map((row, index) => (
                      <Cell key={row.platform} fill={seriesColor(index)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </Grid>

          <Grid item xs={12}>
            <ChartCard
              title="Alerts over time"
              description={
                alerts
                  ? `False positive rate ${alerts.false_positive_rate.toFixed(1)}%`
                  : undefined
              }
              loading={alertsLoading}
              empty={alertTrend.length === 0}
              emptyMessage="No alerts were raised in this period."
            >
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={alertTrend} margin={{ top: 8, right: 8, left: -16 }}>
                  <CartesianGrid stroke={VIZ_GRID} strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="period"
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={{ stroke: VIZ_GRID }}
                    tickLine={false}
                    minTickGap={24}
                  />
                  <YAxis
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                    width={48}
                    allowDecimals={false}
                  />
                  <Tooltip {...TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ color: VIZ_AXIS_TEXT, fontSize: 12 }} />
                  <Line
                    type="monotone"
                    dataKey="count"
                    name="Alerts raised"
                    stroke={SERIES_COLORS[1]}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </ChartCard>
          </Grid>

          <Grid item xs={12} md={6}>
            <ChartCard
              title="Most frequent risk patterns"
              description="Detection rules that fired most often"
              loading={riskLoading}
              empty={riskPatterns.length === 0}
            >
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={riskPatterns}
                  layout="vertical"
                  margin={{ top: 4, right: 24, left: 4 }}
                  barCategoryGap={6}
                >
                  <XAxis type="number" hide />
                  <YAxis
                    type="category"
                    dataKey="pattern"
                    width={128}
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip {...TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar
                    dataKey="count"
                    name="Occurrences"
                    fill={SERIES_COLORS[2]}
                    radius={[0, 4, 4, 0]}
                    maxBarSize={22}
                  />
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </Grid>

          <Grid item xs={12} md={6}>
            <ChartCard
              title="Alert types"
              description="Share of alerts by detection type"
              loading={alertsLoading}
              empty={(alerts?.top_alert_types?.length ?? 0) === 0}
            >
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={alerts?.top_alert_types?.slice(0, 8) ?? []}
                  layout="vertical"
                  margin={{ top: 4, right: 24, left: 4 }}
                  barCategoryGap={6}
                >
                  <XAxis type="number" hide />
                  <YAxis
                    type="category"
                    dataKey="alert_type"
                    width={128}
                    tick={{ fill: VIZ_AXIS_TEXT, fontSize: 12 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip {...TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar
                    dataKey="count"
                    name="Alerts"
                    fill={SERIES_COLORS[4]}
                    radius={[0, 4, 4, 0]}
                    maxBarSize={22}
                  />
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>
          </Grid>
        </Grid>
      </Box>
    </>
  );
};

export default Analytics;
