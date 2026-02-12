import { useState } from 'react';
import { useRouter } from 'next/router';
import Link from 'next/link';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  IconButton,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Divider,
  Avatar,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Security,
  Dashboard as DashboardIcon,
  Dns as DnsIcon,
  BugReport as BugReportIcon,
  Storage as StorageIcon,
  Group as GroupIcon,
  History as HistoryIcon,
  Link as LinkIcon,
  Logout as LogoutIcon,
} from '@mui/icons-material';
import authService from '../lib/services/authService';

const drawerWidth = 240;

const Layout = ({ children }) => {
  const router = useRouter();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems = [
    { path: '/', label: 'Dashboard', icon: <DashboardIcon /> },
    { path: '/assets', label: 'Assets', icon: <StorageIcon /> },
    { path: '/scans', label: 'Scans', icon: <DnsIcon /> },
    { path: '/vulnerabilities', label: 'Vulnérabilités', icon: <BugReportIcon /> },
    { path: '/scripts', label: 'Scripts', icon: <Security /> },
    { path: '/groups', label: 'Groupes', icon: <GroupIcon /> },
    { path: '/analysis-history', label: 'Historique IA', icon: <HistoryIcon /> },
    { path: '/webhooks', label: 'Webhooks', icon: <LinkIcon /> },
  ];

  const handleToggleDrawer = () => {
    setMobileOpen((prev) => !prev);
  };

  const handleLogout = () => {
    authService.logout();
  };

  const isActive = (path) => {
    if (path === '/') {
      return router.pathname === '/';
    }
    return router.pathname === path || router.pathname.startsWith(`${path}/`);
  };

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Toolbar>
        <Security sx={{ mr: 1 }} />
        <Box>
          <Typography variant="subtitle1" noWrap>
            CyberSec AI
          </Typography>
          <Typography variant="caption" color="text.secondary" noWrap>
            Vulnerability Agent
          </Typography>
        </Box>
      </Toolbar>
      <Divider />
      <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
        <List>
          {navItems.map((item) => (
            <Link key={item.path} href={item.path} passHref legacyBehavior>
              <ListItemButton
                component="a"
                selected={isActive(item.path)}
                sx={{
                  '&.Mui-selected': {
                    backgroundColor: theme.palette.action.selected,
                  },
                }}
                onClick={() => {
                  if (isMobile) {
                    setMobileOpen(false);
                  }
                }}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            </Link>
          ))}
        </List>
      </Box>
      <Divider />
      <List>
        <ListItemButton onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon />
          </ListItemIcon>
          <ListItemText primary="Logout" />
        </ListItemButton>
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          zIndex: (t) => t.zIndex.drawer + 1,
        }}
      >
        <Toolbar>
          {isMobile && (
            <IconButton
              color="inherit"
              edge="start"
              onClick={handleToggleDrawer}
              sx={{ mr: 2 }}
            >
              <MenuIcon />
            </IconButton>
          )}
          {!isMobile && (
            <Security sx={{ mr: 1 }} />
          )}
          <Typography variant="h6" noWrap sx={{ flexGrow: 1 }}>
            CyberSec AI
          </Typography>
          <Avatar sx={{ width: 32, height: 32 }}>
            {/** Placeholder pour l'utilisateur connecté */}
            U
          </Avatar>
        </Toolbar>
      </AppBar>

      <Box
        component="nav"
        sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}
        aria-label="navigation principale"
      >
        {isMobile ? (
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={handleToggleDrawer}
            ModalProps={{
              keepMounted: true,
            }}
            sx={{
              display: { xs: 'block', md: 'none' },
              '& .MuiDrawer-paper': { width: drawerWidth },
            }}
          >
            {drawer}
          </Drawer>
        ) : (
          <Drawer
            variant="permanent"
            open
            sx={{
              display: { xs: 'none', md: 'block' },
              '& .MuiDrawer-paper': {
                width: drawerWidth,
                boxSizing: 'border-box',
              },
            }}
          >
            {drawer}
          </Drawer>
        )}
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          bgcolor: 'background.default',
          minHeight: '100vh',
          p: 3,
          mt: 8,
        }}
      >
        {children}
      </Box>
    </Box>
  );
};

export default Layout;
