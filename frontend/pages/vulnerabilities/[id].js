import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  CircularProgress,
  Alert,
  Button,
  TextField,
} from '@mui/material';
import Layout from '../../components/Layout';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import scriptsService from '../../lib/services/scriptsService';
import { api } from '../../lib/services/api';

const severityColor = (severity) => {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'error';
    case 'HIGH':
      return 'warning';
    case 'MEDIUM':
      return 'info';
    case 'LOW':
      return 'success';
    default:
      return 'default';
  }
};

export default function VulnerabilityDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [vuln, setVuln] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [scriptGenerating, setScriptGenerating] = useState(false);
  const [scriptLoading, setScriptLoading] = useState(false);
  const [scriptError, setScriptError] = useState(null);
  const [script, setScript] = useState(null);

  const [sshHost, setSshHost] = useState('');
  const [sshUser, setSshUser] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [executing, setExecuting] = useState(false);

  const loadVuln = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get(`/api/v1/vulnerabilities/${id}`);
      setVuln(data.data || data); // intercepteur Axios peut wrapper
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement de la vulnérabilité');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVuln();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const handleAnalyze = async () => {
    if (!id) return;
    setAnalyzing(true);
    try {
      const result = await vulnerabilitiesService.analyzeVulnerability(id);
      // Recharger la vuln pour récupérer ai_analysis / ai_priority_score
      await loadVuln();
      alert('Analyse IA terminée.');
      console.log('Analyse IA', result);
    } catch (err) {
      alert('Erreur lors de lanalyse IA: ' + (err.message || 'inconnue'));
    } finally {
      setAnalyzing(false);
    }
  };

  const handleGenerateScript = async () => {
    if (!id) return;
    setScriptGenerating(true);
    setScriptError(null);
    try {
      const result = await vulnerabilitiesService.generateScript(id, {
        target_system: 'ubuntu-22.04',
        script_type: 'bash',
      });
      if (result.script_id) {
        // Charger les détails du script
        const scriptDetails = await scriptsService.getScript(result.script_id);
        setScript(scriptDetails);
      }
    } catch (err) {
      setScriptError(err.message || 'Erreur lors de la génération du script');
    } finally {
      setScriptGenerating(false);
    }
  };

  const handleApproveScript = async () => {
    if (!script?.id) return;
    setScriptLoading(true);
    setScriptError(null);
    try {
      await api.put(`/api/v1/remediation-scripts/${script.id}/approve`);
      const refreshed = await scriptsService.getScript(script.id);
      setScript(refreshed);
      alert('Script approuvé.');
    } catch (err) {
      setScriptError(err.message || 'Erreur lors de lapprobation du script');
    } finally {
      setScriptLoading(false);
    }
  };

  const handleExecuteScript = async () => {
    if (!script?.id) return;
    if (!sshHost || !sshUser || !sshPassword) {
      alert('Veuillez renseigner host, username et password SSH.');
      return;
    }
    setExecuting(true);
    setScriptError(null);
    try {
      await api.post(`/api/v1/remediation-scripts/${script.id}/execute`, {
        host: sshHost,
        username: sshUser,
        password: sshPassword,
      });
      alert('Exécution du script lancée.');
    } catch (err) {
      setScriptError(err.message || 'Erreur lors de lexécution du script');
    } finally {
      setExecuting(false);
    }
  };

  const formatScore = (val) => {
    if (val == null) return '-';
    const n = typeof val === 'number' ? val : parseFloat(val);
    if (Number.isNaN(n)) return String(val);
    return n.toFixed(1);
  };

  return (
    <>
      <Head>
        <title>Détails vulnérabilité - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="md" sx={{ mt: 4, mb: 4 }}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : !vuln ? (
            <Alert severity="info">Vulnérabilité introuvable.</Alert>
          ) : (
            <>
              <Paper sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>
                  {vuln.title || vuln.name}
                </Typography>

                <Box display="flex" flexWrap="wrap" gap={1} mb={1}>
                  <Chip
                    label={vuln.severity}
                    color={severityColor(vuln.severity)}
                    size="small"
                  />
                  {vuln.cvss_score != null && (
                    <Chip
                      label={`CVSS ${formatScore(vuln.cvss_score)}`}
                      size="small"
                      variant="outlined"
                    />
                  )}
                  <Chip
                    label={vuln.status || 'open'}
                    size="small"
                    variant="outlined"
                  />
                </Box>

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {vuln.cve_id && (
                    <>
                      <strong>CVE :</strong> {vuln.cve_id}
                      <br />
                    </>
                  )}
                  <strong>ID :</strong> {vuln.id}
                </Typography>

                <Typography variant="body1" sx={{ mt: 2 }}>
                  {vuln.description || 'Aucune description disponible.'}
                </Typography>

                <Box sx={{ mt: 2 }}>
                  {vuln.service && (
                    <Typography variant="body2" color="text.secondary">
                      <strong>Service :</strong> {vuln.service} ({vuln.port ?? 'n/a'}/{vuln.protocol || 'tcp'})
                    </Typography>
                  )}
                  {vuln.affected_package && (
                    <Typography variant="body2" color="text.secondary">
                      <strong>Package :</strong> {vuln.affected_package}{' '}
                      {vuln.affected_version && `(${vuln.affected_version})`}
                    </Typography>
                  )}
                </Box>
              </Paper>

              <Paper sx={{ p: 3, mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Analyse IA
                </Typography>
                {vuln.ai_analysis ? (
                  <Box sx={{ mb: 2 }}>
                    <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>
                      {JSON.stringify(vuln.ai_analysis, null, 2)}
                    </pre>
                    {vuln.ai_priority_score != null && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>Priority score :</strong> {vuln.ai_priority_score}/10
                      </Typography>
                    )}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Aucune analyse IA enregistrée pour le moment.
                  </Typography>
                )}

                <Button
                  variant="contained"
                  onClick={handleAnalyze}
                  disabled={analyzing}
                >
                  {analyzing ? 'Analyse en cours...' : 'Analyser avec IA'}
                </Button>
              </Paper>

              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Script de remédiation
                </Typography>

                {scriptError && (
                  <Alert
                    severity="error"
                    sx={{ mb: 2 }}
                    onClose={() => setScriptError(null)}
                  >
                    {scriptError}
                  </Alert>
                )}

                {!script ? (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Aucun script généré pour cette vulnérabilité.
                    </Typography>
                    <Button
                      variant="contained"
                      onClick={handleGenerateScript}
                      disabled={scriptGenerating}
                    >
                      {scriptGenerating ? 'Génération...' : 'Générer un script de correction'}
                    </Button>
                  </Box>
                ) : (
                  <>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      <strong>Type :</strong> {script.script_type} •{' '}
                      <strong>OS cible :</strong> {script.target_os}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      <strong>Statut :</strong> {script.execution_status}
                    </Typography>

                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Script
                      </Typography>
                      <pre
                        style={{
                          background: '#111827',
                          color: '#e5e7eb',
                          padding: '12px',
                          borderRadius: 4,
                          fontSize: 12,
                          overflowX: 'auto',
                        }}
                      >
                        {script.script_content || '# (vide)'}
                      </pre>
                    </Box>

                    {script.rollback_script && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>
                          Rollback script
                        </Typography>
                        <pre
                          style={{
                            background: '#111827',
                            color: '#e5e7eb',
                            padding: '12px',
                            borderRadius: 4,
                            fontSize: 12,
                            overflowX: 'auto',
                          }}
                        >
                          {script.rollback_script}
                        </pre>
                      </Box>
                    )}

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 2 }}>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button
                          variant="outlined"
                          onClick={handleApproveScript}
                          disabled={scriptLoading || script.execution_status === 'approved'}
                        >
                          Approuver le script
                        </Button>
                        <Button
                          variant="contained"
                          color="success"
                          onClick={handleExecuteScript}
                          disabled={executing}
                        >
                          {executing ? 'Exécution...' : 'Approuver & Exécuter (SSH)'}
                        </Button>
                      </Box>

                      <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <TextField
                          label="SSH host"
                          size="small"
                          value={sshHost}
                          onChange={(e) => setSshHost(e.target.value)}
                        />
                        <TextField
                          label="SSH username"
                          size="small"
                          value={sshUser}
                          onChange={(e) => setSshUser(e.target.value)}
                        />
                        <TextField
                          label="SSH password"
                          size="small"
                          type="password"
                          value={sshPassword}
                          onChange={(e) => setSshPassword(e.target.value)}
                        />
                      </Box>
                    </Box>
                  </>
                )}
              </Paper>
            </>
          )}
        </Container>
      </Layout>
    </>
  );
}

