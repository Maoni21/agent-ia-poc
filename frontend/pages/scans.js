import Head from 'next/head';
import { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Box,
  Paper,
  Tabs,
  Tab,
  Alert,
  CircularProgress,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import Layout from '../components/Layout';
import ScanForm from '../components/ScanForm';
import ScanList from '../components/ScanList';
import ProgressBar from '../components/ProgressBar';
import VulnerabilityCard from '../components/VulnerabilityCard';
import scanService from '../lib/services/scanService';
import vulnerabilityService from '../lib/services/vulnerabilityService';
import WebSocketService from '../lib/services/wsService';
import scanDashboardService from '../lib/services/scanDashboardService';

export default function ScanPage() {
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [scanDetails, setScanDetails] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [progress, setProgress] = useState(null);
  const [wsService, setWsService] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [upgradePlanOpen, setUpgradePlanOpen] = useState(false);
  const [upgradePlan, setUpgradePlan] = useState(null);
  const [loadingUpgradePlan, setLoadingUpgradePlan] = useState(false);

  // Nettoyer le WebSocket lors du démontage
  useEffect(() => {
    return () => {
      if (wsService) {
        wsService.close();
      }
    };
  }, [wsService]);

  const handleScanStarted = (scanId) => {
    setSelectedScanId(scanId);
    setTabValue(1);
    setRefreshTrigger(prev => prev + 1);
    connectWebSocket(scanId);
    loadScanDetails(scanId);
  };

  const connectWebSocket = (scanId) => {
    if (wsService) {
      wsService.close();
    }

    const ws = new WebSocketService(
      scanId,
      (data) => {
        setProgress({
          progress: data.progress || 0,
          currentStep: data.current_step || 'En cours...',
          message: data.message || '',
          estimatedTime: data.estimated_time_remaining,
        });
        
        if (data.status === 'completed') {
          setTimeout(() => {
            loadScanDetails(scanId);
            setRefreshTrigger(prev => prev + 1);
          }, 2000);
        }
      },
      (error) => {
        console.error('WebSocket error:', error);
      },
      () => {
        console.log('WebSocket fermé');
      }
    );

    setWsService(ws);
  };

  const loadScanDetails = async (scanId) => {
    setLoading(true);
    setError(null);
    
    try {
      const statusData = await scanService.getScan(scanId);
      setScanDetails(statusData);
      
      if (statusData.status === 'completed') {
        try {
          // Récupérer directement le workflow complet via l'API v2
          const results = await scanService.getScanResults(scanId);
          const vulns = [];
          if (results.analysis_result?.vulnerabilities) {
            vulns.push(...results.analysis_result.vulnerabilities);
          } else if (results.scan_result?.vulnerabilities) {
            vulns.push(...results.scan_result.vulnerabilities);
          }
          setVulnerabilities(vulns);
        } catch (err) {
          console.warn('Impossible de charger les résultats:', err);
          setVulnerabilities([]);
        }
      } else {
        setVulnerabilities([]);
      }
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des détails');
      console.error('Erreur chargement détails:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleScanSelect = (scanId) => {
    setSelectedScanId(scanId);
    setTabValue(2);
    loadScanDetails(scanId);
    
    if (scanDetails?.status === 'running' || scanDetails?.status === 'pending') {
      connectWebSocket(scanId);
    }
  };

  const handleAnalyzeVulnerability = async (vulnerabilityId) => {
    try {
      const result = await vulnerabilityService.analyzeVulnerabilities(
        [vulnerabilityId],
        scanDetails?.target || 'Unknown System'
      );
      alert('Analyse terminée ! Consultez les résultats dans la console.');
      console.log('Résultat analyse:', result);
    } catch (err) {
      alert('Erreur lors de l\'analyse: ' + err.message);
    }
  };

  const handleGenerateScript = async (vulnerabilityId) => {
    try {
      const result = await vulnerabilityService.generateScripts(
        [vulnerabilityId],
        scanDetails?.target || 'ubuntu',
        'bash'
      );
      alert('Script généré ! Consultez les résultats dans la console.');
      console.log('Résultat génération:', result);
    } catch (err) {
      alert('Erreur lors de la génération: ' + err.message);
    }
  };

  const handleGenerateUpgradePlan = async () => {
    if (!selectedScanId) return;
    setUpgradePlanOpen(true);
    setUpgradePlan(null);
    setLoadingUpgradePlan(true);
    try {
      const plan = await scanDashboardService.generateUpgradePlan(selectedScanId);
      setUpgradePlan(plan);
    } catch (err) {
      alert('Erreur lors de la génération du plan de mises à jour: ' + (err.message || 'inconnue'));
    } finally {
      setLoadingUpgradePlan(false);
    }
  };

  return (
    <>
      <Head>
        <title>CyberSec AI - Gestion des scans</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Gestion des scans
          </Typography>

          <Paper sx={{ mt: 3 }}>
            <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
              <Tab label="Nouveau scan" />
              <Tab label="Liste des scans" />
              <Tab label="Détails" disabled={!selectedScanId} />
            </Tabs>

            <Box sx={{ p: 3 }}>
              {tabValue === 0 && (
                <ScanForm onScanStarted={handleScanStarted} />
              )}

              {tabValue === 1 && (
                <ScanList
                  onScanSelect={handleScanSelect}
                  refreshTrigger={refreshTrigger}
                />
              )}

              {tabValue === 2 && selectedScanId && (
                <Box>
                  {error && (
                    <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                      {error}
                    </Alert>
                  )}

                  {loading && (
                    <Box display="flex" justifyContent="center" p={3}>
                      <CircularProgress />
                    </Box>
                  )}

                  {!loading && scanDetails && (
                    <>
                      {progress && (
                        <ProgressBar
                          progress={progress.progress}
                          currentStep={progress.currentStep}
                          message={progress.message}
                          estimatedTime={progress.estimatedTime}
                        />
                      )}

                      <Paper sx={{ p: 2, mb: 2 }}>
                        <Typography variant="h6" gutterBottom>
                          Détails du scan
                        </Typography>
                        <Typography variant="body2">
                          <strong>ID:</strong> {scanDetails.scan_id}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Cible:</strong> {scanDetails.target || scanDetails.target}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Statut:</strong> {scanDetails.status}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Progression:</strong> {scanDetails.progress || 0}%
                        </Typography>
                        <Box mt={2}>
                          <Button variant="contained" onClick={handleGenerateUpgradePlan}>
                            Générer un plan de mises à jour
                          </Button>
                        </Box>
                      </Paper>

                      {vulnerabilities.length > 0 && (
                        <Box>
                          <Typography variant="h6" gutterBottom>
                            Vulnérabilités détectées ({vulnerabilities.length})
                          </Typography>
                          {vulnerabilities.map((vuln, index) => (
                            <VulnerabilityCard
                              key={vuln.vulnerability_id || vuln.id || index}
                              vulnerability={vuln}
                              onAnalyze={handleAnalyzeVulnerability}
                              onGenerateScript={handleGenerateScript}
                            />
                          ))}
                        </Box>
                      )}
                    </>
                  )}
                </Box>
              )}
            </Box>
          </Paper>
        </Container>
      </Layout>

      <Dialog
        open={upgradePlanOpen}
        onClose={() => {
          setUpgradePlanOpen(false);
          setUpgradePlan(null);
        }}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Plan de mises à jour</DialogTitle>
        <DialogContent dividers>
          {loadingUpgradePlan ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : !upgradePlan ? (
            <Typography variant="body2" color="text.secondary">
              Aucun plan disponible pour le moment.
            </Typography>
          ) : (
            <Box>
              {upgradePlan.summary && (
                <Box mb={2}>
                  <Typography variant="subtitle1" gutterBottom>
                    Résumé
                  </Typography>
                  <pre style={{ whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(upgradePlan.summary, null, 2)}
                  </pre>
                </Box>
              )}
              {Array.isArray(upgradePlan.upgrade_plan) && (
                <Box>
                  <Typography variant="subtitle1" gutterBottom>
                    Étapes
                  </Typography>
                  <pre style={{ whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(upgradePlan.upgrade_plan, null, 2)}
                  </pre>
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setUpgradePlanOpen(false);
              setUpgradePlan(null);
            }}
          >
            Fermer
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
