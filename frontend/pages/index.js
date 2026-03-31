import Head from 'next/head';
import { useEffect, useState } from 'react';
import Dashboard from '../components/Dashboard';
import assetsService from '../lib/services/assetsService';

export default function HomePage() {
  const [showAssetDialog, setShowAssetDialog] = useState(false);

  useEffect(() => {
    const checkAssets = async () => {
      try {
        const data = await assetsService.getAssets();
        const hasAssets = Array.isArray(data) && data.length > 0;
        if (hasAssets) {
          localStorage.setItem('has_assets', 'true');
        }
      } catch {
        // en cas d'erreur API, on ne bloque pas le dashboard
      }
    };
    checkAssets();
  }, []);

  return (
    <>
      <Head>
        <title>CyberSec AI - Dashboard</title>
      </Head>
      <Dashboard />
    </>
  );
}
