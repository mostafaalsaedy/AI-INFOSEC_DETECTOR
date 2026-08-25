import React, { useEffect, useState } from 'react';
import { 
  Grid, 
  Card, 
  CardContent, 
  Typography, 
  Box, 
  Chip,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  TrendingUp as TrendingUpIcon,
  People as PeopleIcon,
  Computer as ComputerIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  OpenInNew as OpenInNewIcon
} from '@mui/icons-material';
import { Helmet } from 'react-helmet-async';

import { useWebSocket } from '../../contexts/WebSocketContext';
import { useApiQuery } from '../../hooks/useApi';
import StatsCard from '../../components/Dashboard/StatsCard';
import RiskTrendChart from '../../components/Dashboard/RiskTrendChart';
import AlertsSummary from '../../components/Dashboard/AlertsSummary';
import PlatformUsage from '../../components/Dashboard/PlatformUsage';
import RealtimeActivity from '../../components/Dashboard/RealtimeActivity';
import SystemHealth from '../../components/Dashboard/SystemHealth';

interface DashboardStats {
  total_interactions: number;
  total_alerts: number;
  active_sessions: number;
  high_risk_interactions: number;
  platforms_monitored: number;
  avg_risk_score: number;
  alerts_last_24h: number;
  users_active_today: number;
}

interface SystemStatus {
  status: string;
  services: {
    database: string;
    ml_analyzer: string;
    redis: string;
    celery: string;
  };
  uptime: number;
  version: string;
}

const Dashboard: React.FC = () => {
  const { socket, isConnected } = useWebSocket();
  const [realtimeStats, setRealtimeStats] = useState<Partial<DashboardStats>>({});
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  // API queries for dashboard data
  const { data: dashboardStats, isLoading: statsLoading, refetch: refetchStats } = useApiQuery<DashboardStats>(
    '/api/v1/dashboard/overview',
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  );

  const { data: systemStatus, isLoading: systemLoading } = useApiQuery<SystemStatus>(
    '/api/v1/health',
    {
      refetchInterval: 15000, // Refetch every 15 seconds
    }
  );

  // WebSocket event listeners
  useEffect(() => {
    if (!socket) return;

    const handleStatsUpdate = (data: Partial<DashboardStats>) => {
      setRealtimeStats(prev => ({ ...prev, ...data }));
      setLastUpdated(new Date());
    };

    const handleNewAlert = (_alert: any) => {
      setRealtimeStats(prev => ({
        ...prev,
        total_alerts: (prev.total_alerts || 0) + 1,
        alerts_last_24h: (prev.alerts_last_24h || 0) + 1,
      }));
    };

    const handleNewInteraction = (_interaction: any) => {
      setRealtimeStats(prev => ({
        ...prev,
        total_interactions: (prev.total_interactions || 0) + 1,
      }));
    };

    // Subscribe to WebSocket events
    socket.on('stats_update', handleStatsUpdate);
    socket.on('new_alert', handleNewAlert);
    socket.on('new_interaction', handleNewInteraction);

    // Subscribe to relevant topics
    socket.emit('subscribe', { topic: 'system_status' });
    socket.emit('subscribe', { topic: 'platform_stats' });

    return () => {
      socket.off('stats_update', handleStatsUpdate);
      socket.off('new_alert', handleNewAlert);
      socket.off('new_interaction', handleNewInteraction);
    };
  }, [socket]);

  // Merge API data with realtime updates
  const currentStats = {
    ...dashboardStats,
    ...realtimeStats,
  };

  const handleRefresh = () => {
    refetchStats();
    setLastUpdated(new Date());
  };

  const getRiskLevelColor = (score: number): 'success' | 'warning' | 'error' => {
    if (score < 30) return 'success';
    if (score < 70) return 'warning';
    return 'error';
  };

  const getRiskLevelText = (score: number): string => {
    if (score < 30) return 'Low Risk';
    if (score < 70) return 'Medium Risk';
    return 'High Risk';
  };

  return (
    <>
      <Helmet>
        <title>Dashboard - InfoSec AI Monitor</title>
      </Helmet>

      <Box sx={{ p: 3 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
            Security Dashboard
          </Typography>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip
              icon={isConnected ? <SecurityIcon /> : <WarningIcon />}
              label={isConnected ? 'Live Monitoring' : 'Disconnected'}
              color={isConnected ? 'success' : 'error'}
              variant="outlined"
            />
            
            <Typography variant="body2" color="text.secondary">
              Last updated: {lastUpdated.toLocaleTimeString()}
            </Typography>
            
            <Tooltip title="Refresh Data">
              <IconButton onClick={handleRefresh} size="small">
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Stats Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <StatsCard
              title="Total Interactions"
              value={currentStats.total_interactions || 0}
              icon={<ComputerIcon />}
              color="primary"
              loading={statsLoading}
              trend={realtimeStats.total_interactions ? '+' + realtimeStats.total_interactions : undefined}
            />
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <StatsCard
              title="Security Alerts"
              value={currentStats.total_alerts || 0}
              icon={<WarningIcon />}
              color="error"
              loading={statsLoading}
              trend={realtimeStats.total_alerts ? '+' + realtimeStats.total_alerts : undefined}
            />
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <StatsCard
              title="Active Sessions"
              value={currentStats.active_sessions || 0}
              icon={<PeopleIcon />}
              color="info"
              loading={statsLoading}
            />
          </Grid>
          
          <Grid item xs={12} sm={6} md={3}>
            <StatsCard
              title="Avg Risk Score"
              value={`${(currentStats.avg_risk_score || 0).toFixed(1)}%`}
              icon={<TrendingUpIcon />}
              color={getRiskLevelColor(currentStats.avg_risk_score || 0)}
              loading={statsLoading}
              subtitle={getRiskLevelText(currentStats.avg_risk_score || 0)}
            />
          </Grid>
        </Grid>

        {/* System Health */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12}>
            <SystemHealth 
              systemStatus={systemStatus} 
              loading={systemLoading}
              onRefresh={() => window.location.reload()}
            />
          </Grid>
        </Grid>

        {/* Main Content */}
        <Grid container spacing={3}>
          {/* Risk Trend Chart */}
          <Grid item xs={12} lg={8}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" component="h2">
                    Risk Trends (24 Hours)
                  </Typography>
                  <Tooltip title="View Detailed Analytics">
                    <IconButton size="small" onClick={() => window.open('/analytics', '_blank')}>
                      <OpenInNewIcon />
                    </IconButton>
                  </Tooltip>
                </Box>
                <RiskTrendChart />
              </CardContent>
            </Card>
          </Grid>

          {/* Platform Usage */}
          <Grid item xs={12} lg={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" component="h2" sx={{ mb: 2 }}>
                  Platform Usage
                </Typography>
                <PlatformUsage />
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Alerts */}
          <Grid item xs={12} lg={6}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" component="h2">
                    Recent Security Alerts
                  </Typography>
                  <Tooltip title="View All Alerts">
                    <IconButton size="small" onClick={() => window.open('/alerts', '_blank')}>
                      <OpenInNewIcon />
                    </IconButton>
                  </Tooltip>
                </Box>
                <AlertsSummary limit={5} />
              </CardContent>
            </Card>
          </Grid>

          {/* Real-time Activity */}
          <Grid item xs={12} lg={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" component="h2" sx={{ mb: 2 }}>
                  Real-time Activity
                </Typography>
                <RealtimeActivity />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Quick Actions */}
        <Grid container spacing={3} sx={{ mt: 2 }}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" component="h2" sx={{ mb: 2 }}>
                  Quick Actions
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Chip 
                    icon={<SecurityIcon />}
                    label="Generate Security Report" 
                    clickable 
                    color="primary"
                    onClick={() => window.open('/analytics?report=security', '_blank')}
                  />
                  <Chip 
                    icon={<PeopleIcon />}
                    label="Export User Sessions" 
                    clickable 
                    color="secondary"
                    onClick={() => window.open('/sessions?export=csv', '_blank')}
                  />
                  <Chip 
                    icon={<TimelineIcon />}
                    label="Risk Analysis Report" 
                    clickable 
                    color="info"
                    onClick={() => window.open('/analytics?report=risk', '_blank')}
                  />
                  <Chip 
                    icon={<WarningIcon />}
                    label="Alert Summary" 
                    clickable 
                    color="warning"
                    onClick={() => window.open('/alerts?summary=true', '_blank')}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </>
  );
};

export default Dashboard;