import { ThemeProvider, CssBaseline } from '@mui/material';
import { createTheme } from '@mui/material/styles';
import { CacheProvider } from '@emotion/react';
import createEmotionCache from '../lib/createEmotionCache';
import '../styles/globals.css';
import ProtectedRoute from '../components/ProtectedRoute';

const clientSideEmotionCache = createEmotionCache();

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

// Routes publiques (sans auth)
const publicRoutes = ['/login', '/register'];

function MyApp({ Component, pageProps, emotionCache = clientSideEmotionCache, router }) {
  const isPublic = publicRoutes.includes(router?.pathname);

  const content = isPublic ? (
    <Component {...pageProps} />
  ) : (
    <ProtectedRoute>
      <Component {...pageProps} />
    </ProtectedRoute>
  );

  return (
    <CacheProvider value={emotionCache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {content}
      </ThemeProvider>
    </CacheProvider>
  );
}

export default MyApp;
