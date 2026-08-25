/**
 * User Sessions Page
 * Monitor and analyze user AI platform interaction sessions
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Divider,
  Tooltip,
  CircularProgress,
  Alert,
  Snackbar,
  Stack,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Refresh,
  FilterList,
  Download,
  Visibility,
  Schedule,
  Computer,
  Warning,
  CheckCircle,
  Timeline,
  Chat,
  LocationOn,
} from '@mui/icons-material';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFnsV3';
import { format, formatDistanceToNow, differenceInMinutes } from 'date-fns';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie } from 'recharts';

// Types
interface UserSession {
  session_id: string;
  user_id?: string;
  started_at: string;
  ended_at?: string;
  duration_minutes?: number;
  platform: string;
  user_agent: string;
  ip_address?: string;
  location?: {
    city: string;
    country: string;
    timezone: string;
  };
  interaction_count: number;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  total_risk_score: number;
  avg_risk_score: number;
  alerts_generated: number;
  consent_status: 'given' | 'pending' | 'withdrawn';
  privacy_flags: string[];
  is_active: boolean;
}

interface SessionInteraction {
  id: number;
  timestamp: string;
  platform: string;
  interaction_type: 'prompt' | 'response';
  content_length: number;
  risk_level: string;
  risk_score: number;
  risk_flags: string[];
  ml_predictions?: Record<string, any>;
}

interface SessionFilters {
  platform?: string;
  risk_level?: string;
  consent_status?: string;
  is_active?: boolean;
  started_after?: Date;
  started_before?: Date;
  min_duration?: number;
  max_duration?: number;
  search?: string;
}

interface SessionStats {
  total_sessions: number;
  active_sessions: number;
  avg_session_duration: number;
  total_interactions: number;
  by_platform: Record<string, number>;
  by_risk_level: Record<string, number>;
  hourly_activity: Array<{hour: number, count: number}>;
}

// Platform colors
const PLATFORM_COLORS = {
  chatgpt: '#10a37f',
  claude: '#ff6b35',
  bard: '#4285f4',
  copilot: '#0078d4',
  other: '#666666'
};

// Risk level colors
const RISK_COLORS = {
  low: '#4caf50',
  medium: '#ff9800', 
  high: '#f44336',
  critical: '#d32f2f'
};

const Sessions: React.FC = () => {
  // State management
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [stats, setStats] = useState<SessionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters] = useState<SessionFilters>({});
  
  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  
  // Dialog states
  const [detailsDialog, setDetailsDialog] = useState<{open: boolean, session?: UserSession}>({open: false});
  const [interactionsDialog, setInteractionsDialog] = useState<{open: boolean, sessionId?: string}>({open: false});
  const [, setFilterDialog] = useState(false);
  const [, setExportDialog] = useState(false);
  
  // Session interactions
  const [sessionInteractions, setSessionInteractions] = useState<SessionInteraction[]>([]);
  const [interactionsLoading, setInteractionsLoading] = useState(false);
  
  // Notifications
  const [snackbar, setSnackbar] = useState<{open: boolean, message: string, severity: 'success' | 'error'}>({
    open: false,
    message: '',
    severity: 'success'
  });
  
  // Auto-refresh
  const [autoRefresh] = useState(true);
  
  // Fetch sessions with current filters and pagination
  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true);
      
      const params = new URLSearchParams({
        page: (page + 1).toString(),
        per_page: rowsPerPage.toString(),
        sort: 'started_desc'
      });
      
      // Add filters
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== '') {
          if (value instanceof Date) {
            params.append(key, value.toISOString());
          } else {
            params.append(key, String(value));
          }
        }
      });
      
      const response = await fetch(`/api/v1/sessions?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setSessions(data.sessions);
      setTotalCount(data.total_count);
      setError(null);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch sessions');
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage, filters]);
  
  // Fetch session statistics
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/sessions/stats', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch session statistics:', err);
    }
  }, []);
  
  // Fetch session interactions
  const fetchSessionInteractions = useCallback(async (sessionId: string) => {
    try {
      setInteractionsLoading(true);
      
      const response = await fetch(`/api/v1/sessions/${sessionId}/interactions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch interactions: ${response.statusText}`);
      }
      
      const data = await response.json();
      setSessionInteractions(data.interactions || []);
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to fetch interactions',
        severity: 'error'
      });
    } finally {
      setInteractionsLoading(false);
    }
  }, []);
  
  // Initial data loading
  useEffect(() => {
    fetchSessions();
    fetchStats();
  }, [fetchSessions, fetchStats]);
  
  // Auto-refresh every 60 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    
    const interval = setInterval(() => {
      fetchSessions();
      fetchStats();
    }, 60000);
    
    return () => clearInterval(interval);
  }, [autoRefresh, fetchSessions, fetchStats]);
  
  // Handle session termination
  const handleTerminateSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/v1/sessions/${sessionId}/terminate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to terminate session: ${response.statusText}`);
      }
      
      await fetchSessions();
      setSnackbar({
        open: true,
        message: 'Session terminated successfully',
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to terminate session',
        severity: 'error'
      });
    }
  };
  
  // Render risk level chip
  const renderRiskChip = (riskLevel: string) => {
    const color = RISK_COLORS[riskLevel as keyof typeof RISK_COLORS] || '#666666';
    return (
      <Chip
        label={riskLevel.toUpperCase()}
        size="small"
        sx={{
          backgroundColor: color + '20',
          color: color,
          fontWeight: 'bold'
        }}
      />
    );
  };
  
  // Render platform chip
  const renderPlatformChip = (platform: string) => {
    const color = PLATFORM_COLORS[platform as keyof typeof PLATFORM_COLORS] || '#666666';
    return (
      <Chip
        label={platform.toUpperCase()}
        size="small"
        sx={{
          backgroundColor: color + '20',
          color: color,
          fontWeight: 'bold'
        }}
      />
    );
  };
  
  // Render session duration
  const renderDuration = (startedAt: string, endedAt?: string) => {
    const start = new Date(startedAt);
    const end = endedAt ? new Date(endedAt) : new Date();
    const minutes = differenceInMinutes(end, start);
    
    if (minutes < 60) {
      return `${minutes}m`;
    } else {
      const hours = Math.floor(minutes / 60);
      const remainingMinutes = minutes % 60;
      return `${hours}h ${remainingMinutes}m`;
    }
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ p: 3 }}>
        {/* Page Header */}
        <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h4" component="h1" gutterBottom>
            User Sessions
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<Refresh />}
              onClick={() => {
                fetchSessions();
                fetchStats();
              }}
            >
              Refresh
            </Button>
            <Button
              variant="outlined"
              startIcon={<FilterList />}
              onClick={() => setFilterDialog(true)}
            >
              Filters
            </Button>
            <Button
              variant="outlined"
              startIcon={<Download />}
              onClick={() => setExportDialog(true)}
            >
              Export
            </Button>
          </Box>
        </Box>

        {/* Statistics Cards */}
        {stats && (
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Total Sessions
                  </Typography>
                  <Typography variant="h4">
                    {stats.total_sessions.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Active Sessions
                  </Typography>
                  <Typography variant="h4" color="primary">
                    {stats.active_sessions.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Avg Duration
                  </Typography>
                  <Typography variant="h4">
                    {Math.round(stats.avg_session_duration)}m
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Total Interactions
                  </Typography>
                  <Typography variant="h4">
                    {stats.total_interactions.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        )}

        {/* Analytics Charts */}
        {stats && (
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={8}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Hourly Activity
                  </Typography>
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={stats.hourly_activity}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="hour" />
                      <YAxis />
                      <RechartsTooltip />
                      <Area type="monotone" dataKey="count" stroke="#1976d2" fill="#1976d2" fillOpacity={0.3} />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Platform Distribution
                  </Typography>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie
                        data={Object.entries(stats.by_platform).map(([platform, count]) => ({
                          name: platform,
                          value: count,
                          fill: PLATFORM_COLORS[platform as keyof typeof PLATFORM_COLORS] || '#666666'
                        }))}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        dataKey="value"
                        label={({name, percent}) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                      </Pie>
                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        )}

        {/* Error Display */}
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Sessions Table */}
        <Card>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Session</TableCell>
                  <TableCell>Platform</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Interactions</TableCell>
                  <TableCell>Risk Level</TableCell>
                  <TableCell>Avg Risk Score</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : sessions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} align="center" sx={{ py: 4 }}>
                      No sessions found
                    </TableCell>
                  </TableRow>
                ) : (
                  sessions.map((session) => (
                    <TableRow key={session.session_id} hover>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2" noWrap>
                            {session.session_id.substring(0, 12)}...
                          </Typography>
                          {session.location && (
                            <Typography variant="caption" color="textSecondary">
                              <LocationOn sx={{ fontSize: 12, mr: 0.5 }} />
                              {session.location.city}, {session.location.country}
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        {renderPlatformChip(session.platform)}
                      </TableCell>
                      <TableCell>
                        <Tooltip title={format(new Date(session.started_at), 'PPpp')}>
                          <Typography variant="body2">
                            {formatDistanceToNow(new Date(session.started_at), { addSuffix: true })}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {renderDuration(session.started_at, session.ended_at)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Chat sx={{ fontSize: 16, color: 'text.secondary' }} />
                          <Typography variant="body2">
                            {session.interaction_count}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {renderRiskChip(session.risk_level)}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body2">
                            {session.avg_risk_score.toFixed(1)}
                          </Typography>
                          <LinearProgress
                            variant="determinate"
                            value={session.avg_risk_score}
                            sx={{ 
                              width: 40, 
                              height: 4,
                              bgcolor: 'grey.200',
                              '& .MuiLinearProgress-bar': {
                                bgcolor: session.avg_risk_score > 70 ? '#f44336' : 
                                        session.avg_risk_score > 40 ? '#ff9800' : '#4caf50'
                              }
                            }}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {session.is_active ? (
                            <>
                              <CheckCircle sx={{ fontSize: 16, color: 'success.main' }} />
                              <Typography variant="body2" color="success.main">
                                Active
                              </Typography>
                            </>
                          ) : (
                            <>
                              <Schedule sx={{ fontSize: 16, color: 'text.secondary' }} />
                              <Typography variant="body2" color="text.secondary">
                                Ended
                              </Typography>
                            </>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={1}>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => setDetailsDialog({open: true, session})}
                            >
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="View Interactions">
                            <IconButton
                              size="small"
                              onClick={() => {
                                setInteractionsDialog({open: true, sessionId: session.session_id});
                                fetchSessionInteractions(session.session_id);
                              }}
                            >
                              <Timeline />
                            </IconButton>
                          </Tooltip>
                          {session.is_active && (
                            <Tooltip title="Terminate Session">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleTerminateSession(session.session_id)}
                              >
                                <Warning />
                              </IconButton>
                            </Tooltip>
                          )}
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
          
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={totalCount}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={(_, newPage) => setPage(newPage)}
            onRowsPerPageChange={(event) => {
              setRowsPerPage(parseInt(event.target.value, 10));
              setPage(0);
            }}
          />
        </Card>

        {/* Session Details Dialog */}
        <Dialog
          open={detailsDialog.open}
          onClose={() => setDetailsDialog({open: false})}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            Session Details
          </DialogTitle>
          <DialogContent>
            {detailsDialog.session && (
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="h6">
                    Session {detailsDialog.session.session_id}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Platform</Typography>
                  {renderPlatformChip(detailsDialog.session.platform)}
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Risk Level</Typography>
                  {renderRiskChip(detailsDialog.session.risk_level)}
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Started</Typography>
                  <Typography variant="body2">
                    {format(new Date(detailsDialog.session.started_at), 'PPpp')}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Duration</Typography>
                  <Typography variant="body2">
                    {renderDuration(detailsDialog.session.started_at, detailsDialog.session.ended_at)}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Interactions</Typography>
                  <Typography variant="body2">
                    {detailsDialog.session.interaction_count}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Alerts Generated</Typography>
                  <Typography variant="body2">
                    {detailsDialog.session.alerts_generated}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Average Risk Score</Typography>
                  <Typography variant="body2">
                    {detailsDialog.session.avg_risk_score.toFixed(1)}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Total Risk Score</Typography>
                  <Typography variant="body2">
                    {detailsDialog.session.total_risk_score.toFixed(1)}
                  </Typography>
                </Grid>
                
                {detailsDialog.session.location && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Location</Typography>
                    <Typography variant="body2">
                      {detailsDialog.session.location.city}, {detailsDialog.session.location.country}
                      <br />
                      Timezone: {detailsDialog.session.location.timezone}
                    </Typography>
                  </Grid>
                )}
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2">User Agent</Typography>
                  <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                    {detailsDialog.session.user_agent}
                  </Typography>
                </Grid>
                
                {detailsDialog.session.privacy_flags.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Privacy Flags</Typography>
                    <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                      {detailsDialog.session.privacy_flags.map((flag, index) => (
                        <Chip key={index} label={flag} size="small" variant="outlined" />
                      ))}
                    </Stack>
                  </Grid>
                )}
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDetailsDialog({open: false})}>
              Close
            </Button>
          </DialogActions>
        </Dialog>

        {/* Session Interactions Dialog */}
        <Dialog
          open={interactionsDialog.open}
          onClose={() => setInteractionsDialog({open: false})}
          maxWidth="lg"
          fullWidth
        >
          <DialogTitle>
            Session Interactions
          </DialogTitle>
          <DialogContent>
            {interactionsLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <CircularProgress />
              </Box>
            ) : (
              <List>
                {sessionInteractions.map((interaction, index) => (
                  <React.Fragment key={interaction.id}>
                    <ListItem>
                      <ListItemIcon>
                        {interaction.interaction_type === 'prompt' ? <Chat /> : <Computer />}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="subtitle2">
                              {interaction.interaction_type === 'prompt' ? 'User Prompt' : 'AI Response'}
                            </Typography>
                            {renderRiskChip(interaction.risk_level)}
                            <Typography variant="caption" color="textSecondary">
                              {format(new Date(interaction.timestamp), 'HH:mm:ss')}
                            </Typography>
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="body2">
                              Length: {interaction.content_length} characters
                            </Typography>
                            <Typography variant="body2">
                              Risk Score: {interaction.risk_score.toFixed(1)}
                            </Typography>
                            {interaction.risk_flags.length > 0 && (
                              <Stack direction="row" spacing={0.5} sx={{ mt: 1 }}>
                                {interaction.risk_flags.map((flag, flagIndex) => (
                                  <Chip key={flagIndex} label={flag} size="small" variant="outlined" />
                                ))}
                              </Stack>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                    {index < sessionInteractions.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setInteractionsDialog({open: false})}>
              Close
            </Button>
          </DialogActions>
        </Dialog>

        {/* Snackbar for notifications */}
        <Snackbar
          open={snackbar.open}
          autoHideDuration={6000}
          onClose={() => setSnackbar({...snackbar, open: false})}
        >
          <Alert severity={snackbar.severity}>
            {snackbar.message}
          </Alert>
        </Snackbar>
      </Box>
    </LocalizationProvider>
  );
};

export default Sessions;