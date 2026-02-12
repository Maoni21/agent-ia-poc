import { useRouter } from 'next/router';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Button,
  Container,
} from '@mui/material';
import { Security } from '@mui/icons-material';
import Link from 'next/link';

const Layout = ({ children }) => {
  const router = useRouter();

  const navItems = [
    { path: '/', label: 'Dashboard' },
    { path: '/assets', label: 'Assets' },
    { path: '/scans', label: 'Scans' },
    { path: '/vulnerabilities', label: 'Vulnérabilités' },
    { path: '/scripts', label: 'Scripts' },
    { path: '/groups', label: 'Groupes' },
    { path: '/analysis-history', label: 'Historique IA' },
     { path: '/webhooks', label: 'Webhooks' },
  ];

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Security sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            CyberSec AI
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {navItems.map((item) => (
              <Link key={item.path} href={item.path} passHref legacyBehavior>
                <Button
                  color="inherit"
                  variant={router.pathname === item.path ? 'outlined' : 'text'}
                  sx={{ textTransform: 'none' }}
                >
                  {item.label}
                </Button>
              </Link>
            ))}
          </Box>
        </Toolbar>
      </AppBar>
      
      <Box component="main" sx={{ flexGrow: 1, bgcolor: 'background.default' }}>
        {children}
      </Box>
      
      <Box
        component="footer"
        sx={{
          py: 2,
          px: 2,
          mt: 'auto',
          backgroundColor: (theme) =>
            theme.palette.mode === 'light'
              ? theme.palette.grey[200]
              : theme.palette.grey[800],
        }}
      >
        <Container maxWidth="lg">
          <Typography variant="body2" color="text.secondary" align="center">
            © 2025 CyberSec AI - Agent IA de Cybersécurité v2.0.0
          </Typography>
        </Container>
      </Box>
    </Box>
  );
};

export default Layout;
