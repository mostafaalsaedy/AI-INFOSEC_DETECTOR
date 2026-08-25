/**
 * Alerts Management Page
 * Comprehensive security alerts dashboard with advanced filtering and management
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
  Checkbox,
  Toolbar,
  Tooltip,
  Badge,
  CircularProgress,
  Alert,
  Snackbar,
  Paper,
  Stack,
} from '@mui/material';
import {
  Refresh,
  FilterList,
  Download,
  Visibility,
  Check,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Notifications,
} from '@mui/icons-material';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFnsV3';
import { format as formatDate, formatDistanceToNow } from 'date-fns';

// Types
interface SecurityAlert {
  id: number;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'active' | 'acknowledged' | 'resolved' | 'false_positive';
  created_at: string;
  updated_at?: string;
  confidence_score: number;
  risk_score?: number;
  platform?: string;
  evidence?: Record<string, any>;
  related_interactions: number[];
  resolution_notes?: string;
  assigned_to?: string;
}

interface AlertFilters {
  status: string;
  severity: string;
  platform?: string;
  assigned_to?: string;
  created_after?: Date;
  created_before?: Date;
  search?: string;
}

interface AlertStats {
  total_alerts: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_platform: Record<string, number>;
  resolution_metrics: Record<string, number>;
}

// Severity colors and icons
const SEVERITY_CONFIG = {
  low: { color: '#4caf50', icon: <InfoIcon />, label: 'Low' },
  medium: { color: '#ff9800', icon: <WarningIcon />, label: 'Medium' },
  high: { color: '#f44336', icon: <ErrorIcon />, label: 'High' },
  critical: { color: '#d32f2f', icon: <ErrorIcon />, label: 'Critical' }
};

// Status colors and labels
const STATUS_CONFIG = {
  active: { color: '#f44336', label: 'Active' },
  acknowledged: { color: '#ff9800', label: 'Acknowledged' },
  resolved: { color: '#4caf50', label: 'Resolved' },
  false_positive: { color: '#9e9e9e', label: 'False Positive' }
};

const Alerts: React.FC = () => {
  // State management
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([]);
  const [filters] = useState<AlertFilters>({
    status: 'all',
    severity: 'all'
  });
  
  // Pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  
  // Dialog states
  const [detailsDialog, setDetailsDialog] = useState<{open: boolean, alert?: SecurityAlert}>({open: false});
  const [, setFilterDialog] = useState(false);
  
  // Form states
  const [snackbar, setSnackbar] = useState<{open: boolean, message: string, severity: 'success' | 'error'}>({
    open: false,
    message: '',
    severity: 'success'
  });
  
  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  // Fetch alerts with current filters and pagination
  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      
      const params = new URLSearchParams({
        page: (page + 1).toString(),
        per_page: rowsPerPage.toString(),
        status: filters.status,
        severity: filters.severity,
        sort: 'created_desc'
      });
      
      if (filters.platform) params.append('platform', filters.platform);
      if (filters.assigned_to) params.append('assigned_to', filters.assigned_to);
      if (filters.search) params.append('search', filters.search);
      if (filters.created_after) params.append('created_after', filters.created_after.toISOString());
      if (filters.created_before) params.append('created_before', filters.created_before.toISOString());
      
      const response = await fetch(`/api/v1/alerts?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setAlerts(data.alerts);
      setTotalCount(data.total_count);
      setError(null);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, [page, rowsPerPage, filters]);
  
  // Fetch alert statistics
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/alerts/stats', {
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
      console.error('Failed to fetch alert statistics:', err);
    }
  }, []);
  
  // Initial data loading
  useEffect(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts, fetchStats]);
  
  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    
    const interval = setInterval(() => {
      fetchAlerts();
      fetchStats();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [autoRefresh, fetchAlerts, fetchStats]);
  
  // Handle alert selection
  const handleSelectAlert = (alertId: number) => {
    setSelectedAlerts(prev => 
      prev.includes(alertId)
        ? prev.filter(id => id !== alertId)
        : [...prev, alertId]
    );
  };
  
  const handleSelectAllAlerts = () => {
    if (selectedAlerts.length === alerts.length) {
      setSelectedAlerts([]);
    } else {
      setSelectedAlerts(alerts.map(alert => alert.id));
    }
  };
  
  // Handle alert update
  const handleUpdateAlert = async (alertId: number, updateData: any) => {
    try {
      const response = await fetch(`/api/v1/alerts/${alertId}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(updateData)
      });
      
      if (!response.ok) {
        throw new Error(`Failed to update alert: ${response.statusText}`);
      }
      
      await fetchAlerts();
      setSnackbar({
        open: true,
        message: 'Alert updated successfully',
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to update alert',
        severity: 'error'
      });
    }
  };
  
  // Handle bulk actions
  const handleBulkAction = async (action: string, parameters?: any) => {
    try {
      const response = await fetch('/api/v1/alerts/bulk-action', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          alert_ids: selectedAlerts,
          action,
          parameters
        })
      });
      
      if (!response.ok) {
        throw new Error(`Bulk action failed: ${response.statusText}`);
      }
      
      const result = await response.json();
      await fetchAlerts();
      setSelectedAlerts([]);
      
      setSnackbar({
        open: true,
        message: `Bulk action completed: ${result.processed_count} alerts updated`,
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Bulk action failed',
        severity: 'error'
      });
    }
  };
  
  // Handle export
  const handleExport = async (exportFormat: string) => {
    try {
      const params = new URLSearchParams({
        format: exportFormat,
        ...Object.fromEntries(Object.entries(filters).map(([k, v]) => [k, String(v)]))
      });
      
      const response = await fetch(`/api/v1/alerts/export?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`
        }
      });
      
      if (!response.ok) {
        throw new Error(`Export failed: ${response.statusText}`);
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const stamp = formatDate(new Date(), 'yyyy-MM-dd');
      link.download = `alerts-export-${exportFormat}-${stamp}.${exportFormat}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      setSnackbar({
        open: true,
        message: 'Export completed successfully',
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Export failed',
        severity: 'error'
      });
    }
  };
  
  // Render severity chip
  const renderSeverityChip = (severity: string) => {
    const config = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG];
    return (
      <Chip
        icon={config.icon}
        label={config.label}
        size="small"
        sx={{
          backgroundColor: config.color + '20',
          color: config.color,
          fontWeight: 'bold'
        }}
      />
    );
  };
  
  // Render status chip
  const renderStatusChip = (status: string) => {
    const config = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG];
    return (
      <Chip
        label={config.label}
        size="small"
        sx={{
          backgroundColor: config.color + '20',
          color: config.color,
          fontWeight: 'bold'
        }}
      />
    );
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ p: 3 }}>
        {/* Page Header */}
        <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Security Alerts
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Auto-refresh">
              <IconButton
                color={autoRefresh ? 'primary' : 'default'}
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                <Badge variant="dot" color="success" invisible={!autoRefresh}>
                  <Notifications />
                </Badge>
              </IconButton>
            </Tooltip>
            <Button
              variant="outlined"
              startIcon={<Refresh />}
              onClick={() => {
                fetchAlerts();
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
              onClick={() => handleExport('csv')}
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
                    Total Alerts
                  </Typography>
                  <Typography variant="h4">
                    {stats.total_alerts.toLocaleString()}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Active Alerts
                  </Typography>
                  <Typography variant="h4" color="error">
                    {stats.by_status.active || 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Critical Alerts
                  </Typography>
                  <Typography variant="h4" color="error">
                    {stats.by_severity.critical || 0}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Resolution Rate
                  </Typography>
                  <Typography variant="h4" color="success.main">
                    {((stats.by_status.resolved || 0) / stats.total_alerts * 100).toFixed(1)}%
                  </Typography>
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

        {/* Bulk Actions Toolbar */}
        {selectedAlerts.length > 0 && (
          <Paper elevation={1} sx={{ p: 2, mb: 2 }}>
            <Toolbar sx={{ pl: 0 }}>
              <Typography variant="h6" sx={{ flex: '1 1 100%' }}>
                {selectedAlerts.length} alert{selectedAlerts.length !== 1 ? 's' : ''} selected
              </Typography>
              <Stack direction="row" spacing={1}>
                <Button
                  size="small"
                  onClick={() => handleBulkAction('acknowledge')}
                >
                  Acknowledge
                </Button>
                <Button
                  size="small"
                  onClick={() => handleBulkAction('resolve')}
                >
                  Resolve
                </Button>
                <Button
                  size="small"
                  onClick={() => handleBulkAction('false_positive')}
                >
                  Mark False Positive
                </Button>
                <Button
                  size="small"
                  onClick={() => handleBulkAction('assign')}
                >
                  Assign
                </Button>
              </Stack>
            </Toolbar>
          </Paper>
        )}

        {/* Alerts Table */}
        <Card>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      indeterminate={selectedAlerts.length > 0 && selectedAlerts.length < alerts.length}
                      checked={alerts.length > 0 && selectedAlerts.length === alerts.length}
                      onChange={handleSelectAllAlerts}
                    />
                  </TableCell>
                  <TableCell>Alert</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Platform</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : alerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                      No alerts found
                    </TableCell>
                  </TableRow>
                ) : (
                  alerts.map((alert) => (
                    <TableRow
                      key={alert.id}
                      hover
                      selected={selectedAlerts.includes(alert.id)}
                    >
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={selectedAlerts.includes(alert.id)}
                          onChange={() => handleSelectAlert(alert.id)}
                        />
                      </TableCell>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2" noWrap>
                            {alert.title}
                          </Typography>
                          <Typography variant="body2" color="textSecondary" noWrap>
                            {alert.description}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {renderSeverityChip(alert.severity)}
                      </TableCell>
                      <TableCell>
                        {renderStatusChip(alert.status)}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={alert.platform || 'Unknown'}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title={formatDate(new Date(alert.created_at), 'PPpp')}>
                          <Typography variant="body2">
                            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {alert.confidence_score.toFixed(1)}%
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={1}>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => setDetailsDialog({open: true, alert})}
                            >
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          {alert.status === 'active' && (
                            <Tooltip title="Acknowledge">
                              <IconButton
                                size="small"
                                onClick={() => handleUpdateAlert(alert.id, {status: 'acknowledged'})}
                              >
                                <Check />
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

        {/* Alert Details Dialog */}
        <Dialog
          open={detailsDialog.open}
          onClose={() => setDetailsDialog({open: false})}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            Alert Details
            {detailsDialog.alert && (
              <Box sx={{ mt: 1 }}>
                {renderSeverityChip(detailsDialog.alert.severity)}
                <Box component="span" sx={{ mx: 1 }} />
                {renderStatusChip(detailsDialog.alert.status)}
              </Box>
            )}
          </DialogTitle>
          <DialogContent>
            {detailsDialog.alert && (
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="h6">{detailsDialog.alert.title}</Typography>
                  <Typography variant="body1" sx={{ mt: 1 }}>
                    {detailsDialog.alert.description}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Created</Typography>
                  <Typography variant="body2">
                    {formatDate(new Date(detailsDialog.alert.created_at), 'PPpp')}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="subtitle2">Confidence Score</Typography>
                  <Typography variant="body2">
                    {detailsDialog.alert.confidence_score.toFixed(1)}%
                  </Typography>
                </Grid>
                {detailsDialog.alert.risk_score && (
                  <Grid item xs={6}>
                    <Typography variant="subtitle2">Risk Score</Typography>
                    <Typography variant="body2">
                      {detailsDialog.alert.risk_score.toFixed(1)}
                    </Typography>
                  </Grid>
                )}
                {detailsDialog.alert.platform && (
                  <Grid item xs={6}>
                    <Typography variant="subtitle2">Platform</Typography>
                    <Typography variant="body2">
                      {detailsDialog.alert.platform}
                    </Typography>
                  </Grid>
                )}
                {detailsDialog.alert.evidence && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Evidence</Typography>
                    <Paper variant="outlined" sx={{ p: 2, mt: 1, bgcolor: 'grey.50' }}>
                      <pre style={{ margin: 0, fontSize: '0.875rem' }}>
                        {JSON.stringify(detailsDialog.alert.evidence, null, 2)}
                      </pre>
                    </Paper>
                  </Grid>
                )}
                {detailsDialog.alert.resolution_notes && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2">Resolution Notes</Typography>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      {detailsDialog.alert.resolution_notes}
                    </Typography>
                  </Grid>
                )}
              </Grid>
            )}
          </DialogContent>
          <DialogActions>
            {detailsDialog.alert?.status === 'active' && (
              <>
                <Button
                  onClick={() => {
                    if (detailsDialog.alert) {
                      handleUpdateAlert(detailsDialog.alert.id, {status: 'acknowledged'});
                      setDetailsDialog({open: false});
                    }
                  }}
                  color="primary"
                >
                  Acknowledge
                </Button>
                <Button
                  onClick={() => {
                    if (detailsDialog.alert) {
                      handleUpdateAlert(detailsDialog.alert.id, {status: 'resolved'});
                      setDetailsDialog({open: false});
                    }
                  }}
                  color="success"
                >
                  Resolve
                </Button>
              </>
            )}
            <Button onClick={() => setDetailsDialog({open: false})}>
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

export default Alerts;