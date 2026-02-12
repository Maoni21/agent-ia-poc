import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import authService from '../lib/services/authService';

/**
 * Protège une page : si l'utilisateur n'est pas authentifié,
 * on le redirige vers /login.
 */
export default function ProtectedRoute({ children }) {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    if (!authService.isAuthenticated()) {
      router.replace('/login');
    } else {
      setChecking(false);
    }
  }, [router]);

  if (checking) {
    return null; // ou un spinner
  }

  return children;
}

