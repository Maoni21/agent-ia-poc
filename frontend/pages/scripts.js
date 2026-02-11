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
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';
import Layout from '../components/Layout';
import scriptsService from '../lib/services/scriptsService';

export default function ScriptsPage() {
  const [scripts, setScripts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadScripts = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await scriptsService.getScripts({ limit: 100 });
        setScripts(data.scripts || []);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement des scripts');
      } finally {
        setLoading(false);
      }
    };

    loadScripts();
  }, []);

  return (
    <>
      <Head>
        <title>CyberSec AI - Scripts de remédiation</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Scripts de remédiation
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
            ) : scripts.length === 0 ? (
              <Alert severity="info">Aucun script généré pour le moment.</Alert>
            ) : (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Script ID</TableCell>
                    <TableCell>Vulnérabilité</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Système cible</TableCell>
                    <TableCell>Statut</TableCell>
                    <TableCell>Risque</TableCell>
                    <TableCell>Généré le</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scripts.map((script) => (
                    <TableRow key={script.script_id}>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {script.script_id}
                        </Typography>
                      </TableCell>
                      <TableCell>{script.vulnerability_id}</TableCell>
                      <TableCell>{script.script_type}</TableCell>
                      <TableCell>{script.target_system}</TableCell>
                      <TableCell>
                        <Chip
                          label={script.validation_status || 'pending'}
                          size="small"
                          color={
                            script.validation_status === 'approved'
                              ? 'success'
                              : script.validation_status === 'reject'
                              ? 'error'
                              : 'warning'
                          }
                        />
                      </TableCell>
                      <TableCell>{script.risk_level || 'medium'}</TableCell>
                      <TableCell>{script.generated_at || '-'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>
        </Container>
      </Layout>
    </>
  );
}

