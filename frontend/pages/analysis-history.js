import Head from 'next/head';
import { useEffect, useState } from 'react';
import {
  Container,
  Typography,
  Box,
  Paper,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
} from '@mui/material';
import Layout from '../components/Layout';
import analysisHistoryService from '../lib/services/analysisHistoryService';

export default function AnalysisHistoryPage() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [details, setDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const loadAnalyses = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await analysisHistoryService.listAnalyses(50);
      setAnalyses(data.analyses || []);
    } catch (err) {
      setError(err.message || "Erreur lors du chargement de l'historique IA");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalyses();
  }, []);

  const openDetails = async (analysis) => {
    setSelected(analysis);
    setDetails(null);
    setLoadingDetails(true);
    try {
      const data = await analysisHistoryService.getAnalysisDetails(analysis.analysis_id);
      setDetails(data);
    } catch (err) {
      alert(err.message || "Erreur lors du chargement des détails de l'analyse");
    } finally {
      setLoadingDetails(false);
    }
  };

  return (
    <>
      <Head>
        <title>CyberSec AI - Historique des analyses IA</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Historique des analyses IA
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          <Paper sx={{ p: 2 }}>
            {loading ? (
              <Box display="flex" justifyContent="center" p={3}>
                <CircularProgress />
              </Box>
            ) : analyses.length === 0 ? (
              <Alert severity="info">Aucune analyse IA enregistrée pour le moment.</Alert>
            ) : (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Analysis ID</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Vulnérabilités</TableCell>
                    <TableCell>Modèle IA</TableCell>
                    <TableCell>Score de confiance</TableCell>
                    <TableCell>Date</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {analyses.map((analysis) => (
                    <TableRow
                      key={analysis.analysis_id}
                      hover
                      sx={{ cursor: 'pointer' }}
                      onClick={() => openDetails(analysis)}
                    >
                      <TableCell>{analysis.analysis_id}</TableCell>
                      <TableCell>{analysis.target_system}</TableCell>
                      <TableCell>{analysis.vulnerability_count}</TableCell>
                      <TableCell>{analysis.ai_model_used}</TableCell>
                      <TableCell>{analysis.confidence_score}</TableCell>
                      <TableCell>{analysis.analyzed_at}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>

          <Dialog
            open={Boolean(selected)}
            onClose={() => {
              setSelected(null);
              setDetails(null);
            }}
            fullWidth
            maxWidth="md"
          >
            <DialogTitle>Détails de l'analyse</DialogTitle>
            <DialogContent dividers>
              {loadingDetails ? (
                <Box display="flex" justifyContent="center" p={3}>
                  <CircularProgress />
                </Box>
              ) : !details ? (
                <Typography variant="body2" color="text.secondary">
                  Sélectionnez une analyse pour afficher les détails.
                </Typography>
              ) : (
                <Box>
                  <Typography variant="subtitle1" gutterBottom>
                    Cible: {details.target_system}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Vulnérabilités analysées: {details.vulnerability_ids?.length || 0}
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    Score de confiance: {details.confidence_score}
                  </Typography>

                  {details.analysis_summary && (
                    <Box mt={2}>
                      <Typography variant="subtitle2">Résumé de l'analyse</Typography>
                      <pre style={{ whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(details.analysis_summary, null, 2)}
                      </pre>
                    </Box>
                  )}

                  {details.remediation_plan && (
                    <Box mt={2}>
                      <Typography variant="subtitle2">Plan de remédiation</Typography>
                      <pre style={{ whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(details.remediation_plan, null, 2)}
                      </pre>
                    </Box>
                  )}
                </Box>
              )}
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => {
                  setSelected(null);
                  setDetails(null);
                }}
              >
                Fermer
              </Button>
            </DialogActions>
          </Dialog>
        </Container>
      </Layout>
    </>
  );
}

