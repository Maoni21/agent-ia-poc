import Head from 'next/head';
import { useEffect, useState } from 'react';
import { Container } from '@mui/material';
import Layout from '../components/Layout';
import Dashboard from '../components/Dashboard';
import WelcomeWizard from '../components/WelcomeWizard';
import AssetCreateDialog from '../components/AssetCreateDialog';
import assetsService from '../lib/services/assetsService';

export default function HomePage() {
  const [showWizard, setShowWizard] = useState(false);
  const [showAssetDialog, setShowAssetDialog] = useState(false);

  useEffect(() => {
    const wizardCompleted = localStorage.getItem('welcome_wizard_completed');

    const checkAssets = async () => {
      try {
        const data = await assetsService.getAssets();
        const hasAssets = Array.isArray(data) && data.length > 0;
        if (hasAssets) {
          localStorage.setItem('has_assets', 'true');
        }
        const storedHasAssets = localStorage.getItem('has_assets');
        if (!wizardCompleted && !storedHasAssets && !hasAssets) {
          setShowWizard(true);
        }
      } catch {
        // en cas d'erreur API, on ne bloque pas le dashboard
      }
    };

    checkAssets();
  }, []);

  const handleWizardComplete = () => {
    setShowWizard(false);
    setShowAssetDialog(true);
  };

  const handleAssetCreated = () => {
    setShowAssetDialog(false);
    localStorage.setItem('has_assets', 'true');
  };

  return (
    <>
      <Head>
        <title>CyberSec AI - Dashboard</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Dashboard />
        </Container>
      </Layout>

      <WelcomeWizard
        open={showWizard}
        onClose={() => setShowWizard(false)}
        onComplete={handleWizardComplete}
      />

      <AssetCreateDialog
        open={showAssetDialog}
        onClose={() => setShowAssetDialog(false)}
        onSuccess={handleAssetCreated}
        isFirstAsset
      />
    </>
  );
}
