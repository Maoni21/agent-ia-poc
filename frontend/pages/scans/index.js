import Head from 'next/head';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import {
  Box,
  Container,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  IconButton,
  CircularProgress,
  Alert,
} from '@mui/material';
import { Add, Refresh, Visibility } from '@mui/icons-material';
import Layout from '../../components/Layout';
import scansService from '../../lib/services/scansService';
import assetsService from '../../lib/services/assetsService';

export default function ScansListPage() {
  const router = useRouter();
  const [scans, setScans] = useState([]);
  const [assetsById, setAssetsById] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAssets = async () => {
    try {
      const data = await assetsService.getAssets();
      const map = {};
      (data || []).forEach((asset) => {
        map[asset.id] = asset;
      });
      setAssetsById(map);
    } catch (err) {
      // On loggue seulement, ce n'est pas bloquant pour la liste des scans
      console.warn('Erreur chargement assets pour la liste des scans:', err);
    }
  };

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await scansService.getScans({ limit: 100 });
      setScans(data || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
    loadScans();
  }, []);

  const getStatusColor = (status) => {
    switch ((status || '').toLowerCase()) {
      case 'completed':
        return 'success';
      case 'running':
      case 'queued':
        return 'info';
      case 'failed':
      case 'cancelled':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatDate = (value) => {
    if (!value) return '-';
    try {
      const d = new Date(value);
      return d.toLocaleString('fr-FR');
    } catch {
      return value;
    }
  };

  const handleView = (scanId) => {
    router.push(`/scans/${scanId}`);
  };

  const handleNewScan = () => {
    router.push('/scans/new');
  };

  return (
    <>
      <Head>
        <title>Scans - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="lg">
          <Box sx={{ mt: 4, mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h4">Scans</Typography>
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={handleNewScan}
            >
              Nouveau scan
            </Button>
          </Box>

          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Liste des scans</Typography>
              <IconButton onClick={loadScans} disabled={loading}>
                <Refresh />
              </IconButton>
            </Box>

            {loading && scans.length === 0 && (
              <Box display="flex" justifyContent="center" p={3}>
                <CircularProgress />
              </Box>
            )}

            {error && scans.length === 0 && (
              <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                {error}
              </Alert>
            )}

            {!loading && scans.length === 0 && !error && (
              <Alert severity="info">
                Aucun scan trouvé. Cliquez sur &quot;Nouveau scan&quot; pour en créer un.
              </Alert>
            )}

            {scans.length > 0 && (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Asset</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Statut</TableCell>
                      <TableCell>Début</TableCell>
                      <TableCell>Vulnérabilités</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scans.map((scan) => {
                      const asset = assetsById[scan.asset_id];
                      return (
                        <TableRow
                          key={scan.id}
                          hover
                          sx={{ cursor: 'pointer' }}
                          onClick={() => handleView(scan.id)}
                        >
                          <TableCell>
                            {asset
                              ? `${asset.hostname || asset.ip_address} (${asset.ip_address})`
                              : scan.asset_id}
                          </TableCell>
                          <TableCell>{scan.scan_type}</TableCell>
                          <TableCell>
                            <Chip
                              label={scan.status}
                              color={getStatusColor(scan.status)}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>{formatDate(scan.started_at || scan.created_at)}</TableCell>
                          <TableCell>{scan.vulnerabilities_found ?? '-'}</TableCell>
                          <TableCell align="right">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleView(scan.id);
                              }}
                            >
                              <Visibility fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paper>
        </Container>
      </Layout>
    </>
  );
}

