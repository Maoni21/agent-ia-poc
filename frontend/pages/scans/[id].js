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
  Checkbox,
  Button,
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
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import groupsService from '../../lib/services/groupsService';

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
  const [selectedVulnIds, setSelectedVulnIds] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    if (!id) return;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await scansService.getScan(id);
        setScan(data);
        setSelectedVulnIds([]);
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

  const getVulnSeverityColors = (severity) => {
    const sev = (severity || '').toUpperCase();
    switch (sev) {
      case 'CRITICAL':
        return { border: '#DC2626', bg: '#FEF2F2' };
      case 'HIGH':
        return { border: '#EA580C', bg: '#FFF7ED' };
      case 'MEDIUM':
        return { border: '#D97706', bg: '#FFFBEB' };
      case 'LOW':
        return { border: '#16A34A', bg: '#ECFDF3' };
      case 'INFO':
      default:
        return { border: '#6B7280', bg: '#F3F4F6' };
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

  const toggleVulnSelection = (vulnId, checked) => {
    setSelectedVulnIds((prev) => {
      if (checked) {
        if (prev.includes(vulnId)) return prev;
        return [...prev, vulnId];
      }
      return prev.filter((id) => id !== vulnId);
    });
  };

  const handleSelectAll = () => {
    if (!scan?.vulnerabilities || scan.vulnerabilities.length === 0) return;
    setSelectedVulnIds(scan.vulnerabilities.map((v) => v.id));
  };

  const handleClearSelection = () => {
    setSelectedVulnIds([]);
  };

  const handleAnalyzeSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.analyzeVulnerability(vulnId),
      );
      await Promise.all(promises);
      // Recharger le scan pour rafraîchir les indicateurs IA
      try {
        const refreshed = await scansService.getScan(id);
        setScan(refreshed);
      } catch {
        // silencieux si le refresh échoue
      }
      alert(
        `Analyse IA terminée pour ${selectedVulnIds.length} vulnérabilité(s).`,
      );
    } catch (err) {
      alert(
        "Erreur lors de l'analyse IA: " + (err.message || 'inconnue'),
      );
    } finally {
      setActionLoading(false);
    }
  };

  const handleCorrectSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.generateScript(vulnId, {
          target_system: 'ubuntu-22.04',
          script_type: 'bash',
        }),
      );
      const results = await Promise.all(promises);
      alert(
        `Scripts de remédiation générés pour ${results.length} vulnérabilité(s).`,
      );
      // eslint-disable-next-line no-console
      console.log('Scripts générés pour la sélection:', results);
    } catch (err) {
      alert(
        'Erreur lors de la génération de scripts: ' +
          (err.message || 'inconnue'),
      );
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateGroupFromSelection = async () => {
    if (selectedVulnIds.length === 0) return;

    const name = window.prompt(
      'Nom du groupe de vulnérabilités :',
      `Scan ${id} - ${selectedVulnIds.length} vulnérabilités`,
    );
    if (!name) return;

    const description =
      window.prompt('Description du groupe (optionnel) :', '') || '';

    try {
      setActionLoading(true);
      await groupsService.createGroup({
        name,
        description,
        vulnerabilityIds: selectedVulnIds,
      });
      alert('Groupe de vulnérabilités créé avec succès.');
    } catch (err) {
      alert(
        'Erreur lors de la création du groupe: ' +
          (err.message || 'inconnue'),
      );
    } finally {
      setActionLoading(false);
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

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, mb: 3 }}>
                <Paper sx={{ p: 2 }}>
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

                <Paper sx={{ p: 2, minHeight: 260 }}>
                  <Typography variant="h6" gutterBottom>
                    Vulnérabilités
                  </Typography>
                {(!scan.vulnerabilities || scan.vulnerabilities.length === 0) ? (
                    <Typography variant="body2" color="text.secondary">
                      Aucune vulnérabilité associée à ce scan.
                    </Typography>
                  ) : (
                  <>
                    <Box
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        mb: 1.5,
                        flexWrap: 'wrap',
                        gap: 1,
                      }}
                    >
                      <Typography variant="body2" color="text.secondary">
                        Sélection : {selectedVulnIds.length} /{' '}
                        {scan.vulnerabilities.length}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Button
                          size="small"
                          variant="text"
                          onClick={handleSelectAll}
                          disabled={actionLoading}
                        >
                          Tout sélectionner
                        </Button>
                        <Button
                          size="small"
                          variant="text"
                          onClick={handleClearSelection}
                          disabled={actionLoading || selectedVulnIds.length === 0}
                        >
                          Vider
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          onClick={handleAnalyzeSelected}
                          disabled={
                            actionLoading || selectedVulnIds.length === 0
                          }
                        >
                          Analyser IA
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          color="success"
                          onClick={handleCorrectSelected}
                          disabled={
                            actionLoading || selectedVulnIds.length === 0
                          }
                        >
                          Scripts de remédiation
                        </Button>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={handleCreateGroupFromSelection}
                          disabled={
                            actionLoading || selectedVulnIds.length === 0
                          }
                        >
                          Créer un groupe
                        </Button>
                      </Box>
                    </Box>

                    <Box sx={{ maxHeight: 420, overflowY: 'auto' }}>
                      {scan.vulnerabilities.map((vuln) => {
                        const colors = getVulnSeverityColors(vuln.severity);
                        return (
                          <Box
                            key={vuln.id}
                            sx={{
                              mb: 1.5,
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: 1,
                            }}
                          >
                            <Checkbox
                              size="small"
                              checked={selectedVulnIds.includes(vuln.id)}
                              onChange={(e) =>
                                toggleVulnSelection(vuln.id, e.target.checked)
                              }
                            />
                            <Box
                              sx={{
                                flex: 1,
                                borderRadius: 1,
                                borderLeft: '4px solid',
                                borderLeftColor: colors.border,
                                backgroundColor: colors.bg,
                                px: 1.5,
                                py: 0.75,
                              }}
                            >
                              <Box
                                sx={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  alignItems: 'center',
                                  mb: 0.25,
                                }}
                              >
                                <Typography variant="subtitle2">
                                  {vuln.title || vuln.cve_id}
                                </Typography>
                                {vuln.ai_priority_score != null && (
                                  <Typography
                                    variant="caption"
                                    sx={{ fontWeight: 600 }}
                                  >
                                    IA&nbsp;score: {vuln.ai_priority_score}/10
                                  </Typography>
                                )}
                              </Box>
                              <Typography variant="caption" color="text.secondary">
                                {vuln.severity} — CVSS:{' '}
                                {vuln.cvss_score != null ? vuln.cvss_score : '-'}
                                {vuln.ai_analyzed && vuln.ai_priority_score == null && (
                                  <> • Analysée par IA</>
                                )}
                              </Typography>
                            </Box>
                          </Box>
                        );
                      })}
                    </Box>
                  </>
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

