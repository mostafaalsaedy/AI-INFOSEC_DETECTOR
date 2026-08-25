/**
 * Settings Page
 * System configuration, user preferences, and administrative settings
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Switch,
  TextField,
  Button,
  Tabs,
  Tab,
  Grid,
  FormControl,
  FormControlLabel,
  InputLabel,
  Select,
  MenuItem,
  Slider,
  Alert,
  Snackbar,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stack
} from '@mui/material';
import {
  Save,
  Restore,
  Security,
  Notifications,
  Analytics,
  Api,
  Delete,
  Add,
  ExpandMore,
  Warning,
  Visibility,
  VisibilityOff
} from '@mui/icons-material';

// Types
interface SystemSettings {
  security: {
    ml_analysis_enabled: boolean;
    real_time_monitoring: boolean;
    auto_alert_generation: boolean;
    risk_threshold_low: number;
    risk_threshold_medium: number;
    risk_threshold_high: number;
    data_retention_days: number;
    session_timeout_minutes: number;
    max_failed_login_attempts: number;
    require_2fa: boolean;
  };
  notifications: {
    email_enabled: boolean;
    slack_enabled: boolean;
    webhook_enabled: boolean;
    sms_enabled: boolean;
    email_recipients: string[];
    slack_webhook_url: string;
    webhook_url: string;
    notification_frequency: 'immediate' | 'hourly' | 'daily';
    severity_threshold: 'low' | 'medium' | 'high' | 'critical';
  };
  privacy: {
    gdpr_compliance: boolean;
    ccpa_compliance: boolean;
    consent_required: boolean;
    data_anonymization: boolean;
    retention_policy_enabled: boolean;
    auto_deletion_enabled: boolean;
    privacy_audit_logging: boolean;
  };
  ml_models: {
    anomaly_detection_enabled: boolean;
    risk_classification_enabled: boolean;
    transformer_analysis_enabled: boolean;
    auto_retraining: boolean;
    retraining_frequency_days: number;
    confidence_threshold: number;
    batch_size: number;
    max_training_samples: number;
  };
  api: {
    rate_limiting_enabled: boolean;
    rate_limit_requests_per_hour: number;
    api_key_rotation_days: number;
    cors_enabled: boolean;
    allowed_origins: string[];
    request_logging: boolean;
    response_caching: boolean;
    cache_ttl_seconds: number;
  };
}

interface ApiKey {
  id: string;
  name: string;
  key_preview: string;
  created_at: string;
  last_used: string | null;
  expires_at: string | null;
  permissions: string[];
  is_active: boolean;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
};

const Settings: React.FC = () => {
  // State management
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  
  // Form states
  const [hasChanges, setHasChanges] = useState(false);
  
  // Dialog states
  const [apiKeyDialog, setApiKeyDialog] = useState<{open: boolean, editing?: ApiKey}>({open: false});
  const [deleteDialog, setDeleteDialog] = useState<{open: boolean, apiKey?: ApiKey}>({open: false});
  
  // Notifications
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'success'
  });
  
  // New API Key form
  const [newApiKey, setNewApiKey] = useState({
    name: '',
    permissions: [] as string[],
    expires_days: 365
  });
  
  // Password visibility
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  
  // Fetch settings
  const fetchSettings = async () => {
    try {
      setLoading(true);
      
      const response = await fetch('/api/v1/settings', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch settings: ${response.statusText}`);
      }
      
      const data = await response.json();
      setSettings(data.settings);
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to fetch settings',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };
  
  // Fetch API keys
  const fetchApiKeys = async () => {
    try {
      const response = await fetch('/api/v1/settings/api-keys', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setApiKeys(data.api_keys);
      }
    } catch (err) {
      console.error('Failed to fetch API keys:', err);
    }
  };
  
  // Save settings
  const saveSettings = async () => {
    try {
      setSaving(true);
      
      const response = await fetch('/api/v1/settings', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ settings })
      });
      
      if (!response.ok) {
        throw new Error(`Failed to save settings: ${response.statusText}`);
      }
      
      setHasChanges(false);
      setSnackbar({
        open: true,
        message: 'Settings saved successfully',
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to save settings',
        severity: 'error'
      });
    } finally {
      setSaving(false);
    }
  };
  
  // Update setting value
  const updateSetting = (section: keyof SystemSettings, key: string, value: any) => {
    if (!settings) return;
    
    setSettings(prev => ({
      ...prev!,
      [section]: {
        ...prev![section],
        [key]: value
      }
    }));
    setHasChanges(true);
  };
  
  // Create API key
  const createApiKey = async () => {
    try {
      const response = await fetch('/api/v1/settings/api-keys', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newApiKey)
      });
      
      if (!response.ok) {
        throw new Error(`Failed to create API key: ${response.statusText}`);
      }
      
      const data = await response.json();
      await fetchApiKeys();
      setApiKeyDialog({open: false});
      setNewApiKey({name: '', permissions: [], expires_days: 365});
      
      setSnackbar({
        open: true,
        message: `API key created: ${data.api_key}`,
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to create API key',
        severity: 'error'
      });
    }
  };
  
  // Delete API key
  const deleteApiKey = async (apiKeyId: string) => {
    try {
      const response = await fetch(`/api/v1/settings/api-keys/${apiKeyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to delete API key: ${response.statusText}`);
      }
      
      await fetchApiKeys();
      setDeleteDialog({open: false});
      
      setSnackbar({
        open: true,
        message: 'API key deleted successfully',
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to delete API key',
        severity: 'error'
      });
    }
  };
  
  // Test notification
  const testNotification = async (type: string) => {
    try {
      const response = await fetch(`/api/v1/settings/test-notification/${type}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('api_token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Test failed: ${response.statusText}`);
      }
      
      setSnackbar({
        open: true,
        message: `Test ${type} notification sent successfully`,
        severity: 'success'
      });
      
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : `Failed to send test ${type}`,
        severity: 'error'
      });
    }
  };
  
  // Initial data loading
  useEffect(() => {
    fetchSettings();
    fetchApiKeys();
  }, []);
  
  if (loading || !settings) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Typography>Loading settings...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Page Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1">
          System Settings
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<Restore />}
            onClick={fetchSettings}
          >
            Reset
          </Button>
          <Button
            variant="contained"
            startIcon={<Save />}
            onClick={saveSettings}
            disabled={!hasChanges || saving}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
        </Box>
      </Box>

      {/* Changes Indicator */}
      {hasChanges && (
        <Alert severity="info" sx={{ mb: 2 }}>
          You have unsaved changes. Click &quot;Save Changes&quot; to apply them.
        </Alert>
      )}

      {/* Settings Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs
          value={tabValue}
          onChange={(_, newValue) => setTabValue(newValue)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Security" icon={<Security />} />
          <Tab label="Notifications" icon={<Notifications />} />
          <Tab label="Privacy & Compliance" icon={<Warning />} />
          <Tab label="ML Models" icon={<Analytics />} />
          <Tab label="API Configuration" icon={<Api />} />
          <Tab label="API Keys" icon={<Security />} />
        </Tabs>
      </Paper>

      {/* Security Settings */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h5" gutterBottom>
              Security Configuration
            </Typography>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Analysis & Monitoring
                </Typography>
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.security.ml_analysis_enabled}
                      onChange={(e) => updateSetting('security', 'ml_analysis_enabled', e.target.checked)}
                    />
                  }
                  label="ML Risk Analysis"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.security.real_time_monitoring}
                      onChange={(e) => updateSetting('security', 'real_time_monitoring', e.target.checked)}
                    />
                  }
                  label="Real-time Monitoring"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.security.auto_alert_generation}
                      onChange={(e) => updateSetting('security', 'auto_alert_generation', e.target.checked)}
                    />
                  }
                  label="Automatic Alert Generation"
                />
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Thresholds
                </Typography>
                
                <Box sx={{ mb: 2 }}>
                  <Typography gutterBottom>Low Risk Threshold: {settings.security.risk_threshold_low}</Typography>
                  <Slider
                    value={settings.security.risk_threshold_low}
                    onChange={(_, value) => updateSetting('security', 'risk_threshold_low', value)}
                    min={0}
                    max={100}
                    marks={[{value: 0, label: '0'}, {value: 100, label: '100'}]}
                  />
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography gutterBottom>Medium Risk Threshold: {settings.security.risk_threshold_medium}</Typography>
                  <Slider
                    value={settings.security.risk_threshold_medium}
                    onChange={(_, value) => updateSetting('security', 'risk_threshold_medium', value)}
                    min={0}
                    max={100}
                    marks={[{value: 0, label: '0'}, {value: 100, label: '100'}]}
                  />
                </Box>
                
                <Box sx={{ mb: 2 }}>
                  <Typography gutterBottom>High Risk Threshold: {settings.security.risk_threshold_high}</Typography>
                  <Slider
                    value={settings.security.risk_threshold_high}
                    onChange={(_, value) => updateSetting('security', 'risk_threshold_high', value)}
                    min={0}
                    max={100}
                    marks={[{value: 0, label: '0'}, {value: 100, label: '100'}]}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Session & Authentication
                </Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={4}>
                    <TextField
                      label="Data Retention (days)"
                      type="number"
                      value={settings.security.data_retention_days}
                      onChange={(e) => updateSetting('security', 'data_retention_days', parseInt(e.target.value))}
                      fullWidth
                    />
                  </Grid>
                  
                  <Grid item xs={12} sm={4}>
                    <TextField
                      label="Session Timeout (minutes)"
                      type="number"
                      value={settings.security.session_timeout_minutes}
                      onChange={(e) => updateSetting('security', 'session_timeout_minutes', parseInt(e.target.value))}
                      fullWidth
                    />
                  </Grid>
                  
                  <Grid item xs={12} sm={4}>
                    <TextField
                      label="Max Failed Login Attempts"
                      type="number"
                      value={settings.security.max_failed_login_attempts}
                      onChange={(e) => updateSetting('security', 'max_failed_login_attempts', parseInt(e.target.value))}
                      fullWidth
                    />
                  </Grid>
                </Grid>
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.security.require_2fa}
                      onChange={(e) => updateSetting('security', 'require_2fa', e.target.checked)}
                    />
                  }
                  label="Require Two-Factor Authentication"
                  sx={{ mt: 2 }}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Notifications Settings */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h5" gutterBottom>
              Notification Configuration
            </Typography>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Channels
                </Typography>
                
                <Stack spacing={2}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications.email_enabled}
                        onChange={(e) => updateSetting('notifications', 'email_enabled', e.target.checked)}
                      />
                    }
                    label="Email Notifications"
                  />
                  
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications.slack_enabled}
                        onChange={(e) => updateSetting('notifications', 'slack_enabled', e.target.checked)}
                      />
                    }
                    label="Slack Notifications"
                  />
                  
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications.webhook_enabled}
                        onChange={(e) => updateSetting('notifications', 'webhook_enabled', e.target.checked)}
                      />
                    }
                    label="Webhook Notifications"
                  />
                  
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications.sms_enabled}
                        onChange={(e) => updateSetting('notifications', 'sms_enabled', e.target.checked)}
                      />
                    }
                    label="SMS Notifications"
                  />
                </Stack>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Settings
                </Typography>
                
                <Stack spacing={2}>
                  <FormControl fullWidth>
                    <InputLabel>Notification Frequency</InputLabel>
                    <Select
                      value={settings.notifications.notification_frequency}
                      onChange={(e) => updateSetting('notifications', 'notification_frequency', e.target.value)}
                    >
                      <MenuItem value="immediate">Immediate</MenuItem>
                      <MenuItem value="hourly">Hourly Digest</MenuItem>
                      <MenuItem value="daily">Daily Digest</MenuItem>
                    </Select>
                  </FormControl>
                  
                  <FormControl fullWidth>
                    <InputLabel>Severity Threshold</InputLabel>
                    <Select
                      value={settings.notifications.severity_threshold}
                      onChange={(e) => updateSetting('notifications', 'severity_threshold', e.target.value)}
                    >
                      <MenuItem value="low">Low</MenuItem>
                      <MenuItem value="medium">Medium</MenuItem>
                      <MenuItem value="high">High</MenuItem>
                      <MenuItem value="critical">Critical Only</MenuItem>
                    </Select>
                  </FormControl>
                </Stack>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Channel Configuration
                </Typography>
                
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography>Email Configuration</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TextField
                      label="Email Recipients (comma-separated)"
                      value={settings.notifications.email_recipients.join(', ')}
                      onChange={(e) => updateSetting('notifications', 'email_recipients', e.target.value.split(',').map(s => s.trim()))}
                      fullWidth
                      multiline
                      rows={2}
                      sx={{ mb: 1 }}
                    />
                    <Button size="small" onClick={() => testNotification('email')}>
                      Test Email
                    </Button>
                  </AccordionDetails>
                </Accordion>
                
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography>Slack Configuration</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TextField
                      label="Slack Webhook URL"
                      value={settings.notifications.slack_webhook_url}
                      onChange={(e) => updateSetting('notifications', 'slack_webhook_url', e.target.value)}
                      fullWidth
                      type={showSecrets.slack ? 'text' : 'password'}
                      InputProps={{
                        endAdornment: (
                          <IconButton
                            onClick={() => setShowSecrets(prev => ({...prev, slack: !prev.slack}))}
                            edge="end"
                          >
                            {showSecrets.slack ? <VisibilityOff /> : <Visibility />}
                          </IconButton>
                        )
                      }}
                      sx={{ mb: 1 }}
                    />
                    <Button size="small" onClick={() => testNotification('slack')}>
                      Test Slack
                    </Button>
                  </AccordionDetails>
                </Accordion>
                
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography>Webhook Configuration</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TextField
                      label="Webhook URL"
                      value={settings.notifications.webhook_url}
                      onChange={(e) => updateSetting('notifications', 'webhook_url', e.target.value)}
                      fullWidth
                      sx={{ mb: 1 }}
                    />
                    <Button size="small" onClick={() => testNotification('webhook')}>
                      Test Webhook
                    </Button>
                  </AccordionDetails>
                </Accordion>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* API Keys Tab */}
      <TabPanel value={tabValue} index={5}>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h5">
            API Keys Management
          </Typography>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setApiKeyDialog({open: true})}
          >
            Create API Key
          </Button>
        </Box>
        
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Key Preview</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Last Used</TableCell>
                <TableCell>Expires</TableCell>
                <TableCell>Permissions</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apiKeys.map((apiKey) => (
                <TableRow key={apiKey.id}>
                  <TableCell>{apiKey.name}</TableCell>
                  <TableCell>
                    <code>{apiKey.key_preview}</code>
                  </TableCell>
                  <TableCell>{new Date(apiKey.created_at).toLocaleDateString()}</TableCell>
                  <TableCell>
                    {apiKey.last_used ? new Date(apiKey.last_used).toLocaleDateString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    {apiKey.expires_at ? new Date(apiKey.expires_at).toLocaleDateString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap">
                      {apiKey.permissions.map(permission => (
                        <Chip key={permission} label={permission} size="small" />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={apiKey.is_active ? 'Active' : 'Inactive'}
                      color={apiKey.is_active ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => setDeleteDialog({open: true, apiKey})}
                    >
                      <Delete />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* API Key Creation Dialog */}
      <Dialog open={apiKeyDialog.open} onClose={() => setApiKeyDialog({open: false})} maxWidth="sm" fullWidth>
        <DialogTitle>Create API Key</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="API Key Name"
              value={newApiKey.name}
              onChange={(e) => setNewApiKey(prev => ({...prev, name: e.target.value}))}
              fullWidth
            />
            
            <TextField
              label="Expires in (days)"
              type="number"
              value={newApiKey.expires_days}
              onChange={(e) => setNewApiKey(prev => ({...prev, expires_days: parseInt(e.target.value)}))}
              fullWidth
            />
            
            <FormControl fullWidth>
              <InputLabel>Permissions</InputLabel>
              <Select
                multiple
                value={newApiKey.permissions}
                onChange={(e) => setNewApiKey(prev => ({...prev, permissions: e.target.value as string[]}))}
                renderValue={(selected) => (
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {selected.map((value) => (
                      <Chip key={value} label={value} size="small" />
                    ))}
                  </Box>
                )}
              >
                <MenuItem value="read">Read Access</MenuItem>
                <MenuItem value="write">Write Access</MenuItem>
                <MenuItem value="admin">Admin Access</MenuItem>
                <MenuItem value="export">Export Data</MenuItem>
                <MenuItem value="settings">Manage Settings</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApiKeyDialog({open: false})}>Cancel</Button>
          <Button
            variant="contained"
            onClick={createApiKey}
            disabled={!newApiKey.name}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete API Key Dialog */}
      <Dialog open={deleteDialog.open} onClose={() => setDeleteDialog({open: false})}>
        <DialogTitle>Delete API Key</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the API key &quot;{deleteDialog.apiKey?.name}&quot;?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialog({open: false})}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => deleteDialog.apiKey && deleteApiKey(deleteDialog.apiKey.id)}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
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
  );
};

export default Settings;