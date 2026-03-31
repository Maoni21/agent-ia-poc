import '../styles/globals.css';
import { ThemeProvider } from '../components/theme-provider';
import ProtectedRoute from '../components/ProtectedRoute';
import AppLayout from '../components/layout/AppLayout';

// Routes publiques (sans auth ni layout)
const publicRoutes = ['/login', '/register'];

function MyApp({ Component, pageProps, router }) {
  const isPublic = publicRoutes.includes(router?.pathname);

  const content = isPublic ? (
    <Component {...pageProps} />
  ) : (
    <ProtectedRoute>
      <AppLayout>
        <Component {...pageProps} />
      </AppLayout>
    </ProtectedRoute>
  );

  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      {content}
    </ThemeProvider>
  );
}

export default MyApp;
