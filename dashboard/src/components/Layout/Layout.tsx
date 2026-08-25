/**
 * Application shell: navigation rail, top bar and content area.
 *
 * The drawer is permanent on desktop and temporary on mobile, so the same
 * navigation works on a SOC wall display and on a phone.
 */

import React, { useState } from 'react';
import {
  AppBar,
  Avatar,
  Box,
  Chip,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Toolbar,
  Tooltip,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import {
  Analytics as AnalyticsIcon,
  Dashboard as DashboardIcon,
  Devices as DevicesIcon,
  Logout as LogoutIcon,
  Menu as MenuIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Warning as WarningIcon,
  WifiOff as WifiOffIcon,
  Wifi as WifiIcon,
} from '@mui/icons-material';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../../contexts/AuthContext';
import { useWebSocket } from '../../contexts/WebSocketContext';

const DRAWER_WIDTH = 248;

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  /** Permission required to see this entry, if any. */
  requires?: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/dashboard', icon: <DashboardIcon /> },
  { label: 'Alerts', path: '/alerts', icon: <WarningIcon /> },
  { label: 'Sessions', path: '/sessions', icon: <DevicesIcon /> },
  { label: 'Analytics', path: '/analytics', icon: <AnalyticsIcon /> },
  { label: 'Settings', path: '/settings', icon: <SettingsIcon />, requires: 'admin' },
];

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const theme = useTheme();
  const isDesktop = useMediaQuery(theme.breakpoints.up('md'));
  const navigate = useNavigate();
  const location = useLocation();

  const { user, logout, can } = useAuth();
  const { isConnected, connectionStatus } = useWebSocket();

  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuAnchor, setUserMenuAnchor] = useState<HTMLElement | null>(null);

  const visibleItems = NAV_ITEMS.filter(
    (item) => !item.requires || can(item.requires)
  );

  const currentItem = visibleItems.find((item) =>
    location.pathname.startsWith(item.path)
  );

  const handleNavigate = (path: string) => {
    navigate(path);
    if (!isDesktop) {
      setMobileOpen(false);
    }
  };

  const drawerContent = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar sx={{ gap: 1.5, px: 2.5 }}>
        <SecurityIcon color="primary" />
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle1" noWrap sx={{ fontWeight: 600, lineHeight: 1.2 }}>
            InfoSec AI
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap>
            Monitor
          </Typography>
        </Box>
      </Toolbar>

      <Divider />

      <List sx={{ px: 1.5, py: 2, flexGrow: 1 }}>
        {visibleItems.map((item) => {
          const selected = location.pathname.startsWith(item.path);

          return (
            <ListItemButton
              key={item.path}
              selected={selected}
              onClick={() => handleNavigate(item.path)}
              sx={{ borderRadius: 1.5, mb: 0.5 }}
            >
              <ListItemIcon sx={{ minWidth: 40 }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{ fontWeight: selected ? 600 : 400 }}
              />
            </ListItemButton>
          );
        })}
      </List>

      <Divider />

      <Box sx={{ p: 2 }}>
        <Tooltip title={`Realtime connection: ${connectionStatus}`}>
          <Chip
            size="small"
            icon={isConnected ? <WifiIcon /> : <WifiOffIcon />}
            label={isConnected ? 'Live' : 'Offline'}
            color={isConnected ? 'success' : 'default'}
            variant="outlined"
            sx={{ width: '100%' }}
          />
        </Tooltip>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', width: '100%' }}>
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { md: `${DRAWER_WIDTH}px` },
          borderBottom: '1px solid',
          borderColor: 'divider',
          backgroundColor: 'background.paper',
          backgroundImage: 'none',
        }}
      >
        <Toolbar sx={{ gap: 2 }}>
          <IconButton
            edge="start"
            onClick={() => setMobileOpen(true)}
            sx={{ display: { md: 'none' } }}
            aria-label="Open navigation"
          >
            <MenuIcon />
          </IconButton>

          <Typography variant="h6" component="h1" sx={{ flexGrow: 1, fontWeight: 600 }}>
            {currentItem?.label ?? 'InfoSec AI Monitor'}
          </Typography>

          {user && (
            <>
              <Tooltip title={`${user.name} · ${user.role}`}>
                <IconButton
                  onClick={(event) => setUserMenuAnchor(event.currentTarget)}
                  size="small"
                  aria-label="Account menu"
                >
                  <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
                    {user.name.charAt(0).toUpperCase()}
                  </Avatar>
                </IconButton>
              </Tooltip>

              <Menu
                anchorEl={userMenuAnchor}
                open={Boolean(userMenuAnchor)}
                onClose={() => setUserMenuAnchor(null)}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                transformOrigin={{ vertical: 'top', horizontal: 'right' }}
              >
                <Box sx={{ px: 2, py: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {user.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {user.email}
                  </Typography>
                </Box>

                <Divider />

                <MenuItem
                  onClick={() => {
                    setUserMenuAnchor(null);
                    logout();
                  }}
                >
                  <ListItemIcon>
                    <LogoutIcon fontSize="small" />
                  </ListItemIcon>
                  Sign out
                </MenuItem>
              </Menu>
            </>
          )}
        </Toolbar>
      </AppBar>

      <Box
        component="nav"
        sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
          }}
        >
          {drawerContent}
        </Drawer>

        <Drawer
          variant="permanent"
          open
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
          }}
        >
          {drawerContent}
        </Drawer>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          minHeight: '100vh',
        }}
      >
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
};

export default Layout;
