import Head from 'next/head';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import {
  Box,
  Container,
  Typography,
  Paper,
  TextField,
  MenuItem,
  Button,
  CircularProgress,
  Alert,
} from '@mui/material';
import Layout from '../../components/Layout';
import assetsService from '../../lib/services/assetsService';
import scansService from '../../lib/services/scansService';

export default function NewScanPage() {
  const router = useRouter();
  const [assets, setAssets] = useState([]);
  const [assetId, setAssetId] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loadingAssets, setLoadingAssets] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadAssets = async () => {
      setLoadingAssets(true);
      setError(null);
      try {
        const data = await assetsService.getAssets();
        setAssets(data || []);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement des assets');
      } finally {
        setLoadingAssets(false);
      }
    };

    loadAssets();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!assetId) return;

    setSubmitting(true);
    setError(null);
    try {
      const result = await scansService.createScan({
        asset_id: assetId,
        scan_type: scanType,
      });

      const newId = result.id || result.scan_id;
      if (newId) {
        router.push(`/scans/${newId}`);
      } else {
        throw new Error("L'API n'a pas renvoyé d'identifiant de scan");
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la création du scan');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <Head>
        <title>Nouveau scan - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="md">
          <Box sx={{ mt: 4, mb: 3 }}>
            <Typography variant="h4" gutterBottom>
              Nouveau scan
            </Typography>
          </Box>

          <Paper sx={{ p: 3 }}>
            {error && (
              <Alert
                severity="error"
                sx={{ mb: 2 }}
                onClose={() => setError(null)}
              >
                {error}
              </Alert>
            )}

            <Box
              component="form"
              noValidate
              autoComplete="off"
              onSubmit={handleSubmit}
            >
              <TextField
                select
                fullWidth
                label="Asset"
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                margin="normal"
                required
                disabled={loadingAssets || submitting}
                helperText="Choisissez l'asset à scanner"
              >
                {loadingAssets ? (
                  <MenuItem disabled>
                    <CircularProgress size={16} sx={{ mr: 1 }} />
                    Chargement des assets...
                  </MenuItem>
                ) : assets.length === 0 ? (
                  <MenuItem disabled>Aucun asset disponible</MenuItem>
                ) : (
                  assets.map((asset) => (
                    <MenuItem key={asset.id} value={asset.id}>
                      {asset.hostname || asset.ip_address} ({asset.ip_address})
                    </MenuItem>
                  ))
                )}
              </TextField>

              <TextField
                select
                fullWidth
                label="Type de scan"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                margin="normal"
                required
                disabled={submitting}
                helperText="Type de scan à exécuter"
              >
                <MenuItem value="quick">Rapide</MenuItem>
                <MenuItem value="full">Complet</MenuItem>
                <MenuItem value="stealth">Furtif</MenuItem>
                <MenuItem value="compliance">Conformité</MenuItem>
              </TextField>

              <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                <Button
                  variant="text"
                  onClick={() => router.push('/scans')}
                  disabled={submitting}
                >
                  Annuler
                </Button>
                <Button
                  type="submit"
                  variant="contained"
                  disabled={!assetId || submitting}
                >
                  {submitting ? (
                    <CircularProgress size={20} sx={{ mr: 1 }} />
                  ) : null}
                  Lancer le scan
                </Button>
              </Box>
            </Box>
          </Paper>
        </Container>
      </Layout>
    </>
  );
}

