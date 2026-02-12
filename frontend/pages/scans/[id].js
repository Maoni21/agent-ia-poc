import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import Layout from '../../components/Layout';
import scansService from '../../lib/services/scansService';

const WS_BASE =
  typeof window !== 'undefined'
    ? (process.env.NEXT_PUBLIC_WS_URL || process.env.REACT_APP_WS_URL || 'ws://localhost:8000')
    : '';

export default function ScanDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(null);

  useEffect(() => {
    if (!id) return;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await scansService.getScan(id);
        setScan(data);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement du scan');
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [id]);

  useEffect(() => {
    if (!id) return;

    // WebSocket temps réel basé sur /ws/scans/{id}
    const url = `${WS_BASE}/ws/scans/${id}`;
    let ws;

    try {
      ws = new WebSocket(url);
    } catch (e) {
      console.warn('WebSocket non disponible:', e);
      return;
    }

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const data = payload.data || payload;
        setProgress({
          progress: data.progress ?? 0,
          status: data.status || '',
          currentStep: data.current_step || '',
          message: data.message || '',
        });

        if (['completed', 'failed', 'cancelled'].includes((data.status || '').toLowerCase())) {
          // Recharger les détails à la fin
          scansService
            .getScan(id)
            .then(setScan)
            .catch(() => {});
        }
      } catch (e) {
        console.warn('Message WebSocket invalide:', e);
      }
    };

    ws.onerror = () => {
      // On se contente de logguer
      console.warn('Erreur WebSocket pour le scan', id);
    };

    return () => {
      if (ws) {
        ws.close(1000, 'Page fermée');
      }
    };
  }, [id]);

  const severityChartData = useMemo(() => {
    if (!scan) return [];
    const entries = [
      { label: 'CRITICAL', value: scan.critical_count || 0, color: '#DC2626' },
      { label: 'HIGH', value: scan.high_count || 0, color: '#F97316' },
      { label: 'MEDIUM', value: scan.medium_count || 0, color: '#FACC15' },
      { label: 'LOW', value: scan.low_count || 0, color: '#22C55E' },
      { label: 'INFO', value: scan.info_count || 0, color: '#9CA3AF' },
    ];
    return entries.filter((e) => e.value > 0);
  }, [scan]);

  const formatDate = (value) => {
    if (!value) return '-';
    try {
      const d = new Date(value);
      return d.toLocaleString('fr-FR');
    } catch {
      return value;
    }
  };

  return (
    <>
      <Head>
        <title>Détails du scan - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="lg">
          <Box sx={{ mt: 4, mb: 3 }}>
            <Typography variant="h4" gutterBottom>
              Détails du scan
            </Typography>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : !scan ? (
            <Alert severity="info">Scan introuvable.</Alert>
          ) : (
            <>
              {progress && (
                <Paper sx={{ p: 2, mb: 2 }}>
                  <Box
                    display="flex"
                    justifyContent="space-between"
                    alignItems="center"
                    mb={1}
                  >
                    <Typography variant="subtitle1" fontWeight="bold">
                      {progress.currentStep || 'Progression du scan'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {progress.progress ?? 0}%
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      backgroundColor: 'action.hover',
                      overflow: 'hidden',
                      mb: 1,
                    }}
                  >
                    <Box
                      sx={{
                        width: `${progress.progress ?? 0}%`,
                        height: '100%',
                        backgroundColor: 'primary.main',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {progress.message || 'Traitement en cours...'}
                  </Typography>
                </Paper>
              )}

              <Paper sx={{ p: 2, mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Informations générales
                </Typography>
                <Typography variant="body2">
                  <strong>ID :</strong> {scan.id}
                </Typography>
                <Typography variant="body2">
                  <strong>Type :</strong> {scan.scan_type}
                </Typography>
                <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <strong>Statut :</strong>
                  <Chip label={scan.status} size="small" />
                </Typography>
                <Typography variant="body2">
                  <strong>Début :</strong> {formatDate(scan.started_at || scan.created_at)}
                </Typography>
                <Typography variant="body2">
                  <strong>Fin :</strong> {formatDate(scan.completed_at)}
                </Typography>
                <Typography variant="body2">
                  <strong>Vulnérabilités trouvées :</strong>{' '}
                  {scan.vulnerabilities_found ?? 0}
                </Typography>
              </Paper>

              <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 3, mb: 3 }}>
                <Paper sx={{ p: 2, flex: 1 }}>
                  <Typography variant="h6" gutterBottom>
                    Distribution par sévérité
                  </Typography>
                  {severityChartData.length === 0 ? (
                    <Typography variant="body2" color="text.secondary">
                      Aucune vulnérabilité détectée pour ce scan.
                    </Typography>
                  ) : (
                    <ResponsiveContainer width="100%" height={260}>
                      <PieChart>
                        <Pie
                          data={severityChartData}
                          dataKey="value"
                          nameKey="label"
                          outerRadius={90}
                          label
                        >
                          {severityChartData.map((entry, index) => (
                            <Cell key={index} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  )}
                </Paper>

                <Paper sx={{ p: 2, flex: 1 }}>
                  <Typography variant="h6" gutterBottom>
                    Vulnérabilités
                  </Typography>
                  {(!scan.vulnerabilities || scan.vulnerabilities.length === 0) ? (
                    <Typography variant="body2" color="text.secondary">
                      Aucune vulnérabilité associée à ce scan.
                    </Typography>
                  ) : (
                    <Box sx={{ maxHeight: 260, overflowY: 'auto' }}>
                      {scan.vulnerabilities.map((vuln) => (
                        <Box key={vuln.id} sx={{ mb: 1.5 }}>
                          <Typography variant="subtitle2">
                            {vuln.title || vuln.cve_id}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {vuln.severity} — CVSS:{' '}
                            {vuln.cvss_score != null ? vuln.cvss_score : '-'}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  )}
                </Paper>
              </Box>
            </>
          )}
        </Container>
      </Layout>
    </>
  );
}

