import Head from 'next/head';
import { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Box,
  Paper,
  TextField,
  InputAdornment,
  CircularProgress,
  Alert,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Button,
} from '@mui/material';
import { Search, Download } from '@mui/icons-material';
import Layout from '../components/Layout';
import VulnerabilityCard from '../components/VulnerabilityCard';
import vulnerabilitiesService from '../lib/services/vulnerabilitiesService';
import analysisService from '../lib/services/analysisService';

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulnerabilities, setFilteredVulnerabilities] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [falsePositiveFilter, setFalsePositiveFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadVulnerabilities = async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await vulnerabilitiesService.getVulnerabilities({
        limit: 200,
        severity: severityFilter || undefined,
        search: searchTerm || undefined,
      });
      const vulns = data.vulnerabilities || [];
      setVulnerabilities(vulns);
      setFilteredVulnerabilities(applyFalsePositiveFilter(vulns, falsePositiveFilter));
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des vulnérabilités');
      console.error('Erreur chargement vulnérabilités:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVulnerabilities();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severityFilter]);

  useEffect(() => {
    // Filtrage client sur la base de la liste actuelle
    let base = [...vulnerabilities];

    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      base = base.filter(
        (vuln) =>
          vuln.name?.toLowerCase().includes(term) ||
          vuln.vulnerability_id?.toLowerCase().includes(term) ||
          vuln.description?.toLowerCase().includes(term),
      );
    }

    setFilteredVulnerabilities(applyFalsePositiveFilter(base, falsePositiveFilter));
  }, [searchTerm, falsePositiveFilter, vulnerabilities]);

  const applyFalsePositiveFilter = (list, fpFilter) => {
    if (!fpFilter) return list;
    if (fpFilter === 'false_positive') {
      return list.filter((v) => v.is_false_positive);
    }
    if (fpFilter === 'true_positive') {
      return list.filter((v) => v.is_false_positive === false);
    }
    return list;
  };

  const handleAnalyzeAll = async () => {
    if (filteredVulnerabilities.length === 0) return;
    const ids = filteredVulnerabilities
      .map((v) => v.vulnerability_id)
      .filter(Boolean);
    try {
      const result = await analysisService.analyzeSelected({
        vulnerabilityIds: ids,
        targetSystem: 'Unknown System',
      });
      alert(
        `Analyse lancée / terminée.\nAnalysis ID: ${result.analysis_id || 'n/a'}\n${
          result.message || ''
        }`,
      );
    } catch (err) {
      alert('Erreur lors de l’analyse: ' + (err.message || 'inconnue'));
    }
  };

  const handleCorrectAll = async () => {
    if (filteredVulnerabilities.length === 0) return;
    const ids = filteredVulnerabilities
      .map((v) => v.vulnerability_id)
      .filter(Boolean);
    try {
      const result = await analysisService.correctSelected({
        vulnerabilityIds: ids,
        targetSystem: 'ubuntu',
      });
      alert(result.message || 'Génération de scripts terminée (voir console).');
      console.log('Scripts générés:', result);
    } catch (err) {
      alert('Erreur lors de la génération de scripts: ' + (err.message || 'inconnue'));
    }
  };

  const handleExportCsv = async () => {
    try {
      await vulnerabilitiesService.exportCsv({
        severity: severityFilter || undefined,
      });
    } catch (err) {
      alert('Erreur lors de lexport CSV: ' + (err.message || 'inconnue'));
    }
  };

  return (
    <>
      <Head>
        <title>CyberSec AI - Vulnérabilités</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            Vulnérabilités détectées
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          <Paper sx={{ p: 2, mb: 3 }}>
            <Box display="flex" flexDirection={{ xs: 'column', md: 'row' }} gap={2}>
              <TextField
                fullWidth
                placeholder="Rechercher une vulnérabilité..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Search />
                    </InputAdornment>
                  ),
                }}
              />

              <FormControl sx={{ minWidth: 160 }}>
                <InputLabel>Sévérité</InputLabel>
                <Select
                  value={severityFilter}
                  label="Sévérité"
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <MenuItem value="">Toutes</MenuItem>
                  <MenuItem value="CRITICAL">Critique</MenuItem>
                  <MenuItem value="HIGH">Élevée</MenuItem>
                  <MenuItem value="MEDIUM">Moyenne</MenuItem>
                  <MenuItem value="LOW">Faible</MenuItem>
                </Select>
              </FormControl>

              <FormControl sx={{ minWidth: 180 }}>
                <InputLabel>Faux positifs</InputLabel>
                <Select
                  value={falsePositiveFilter}
                  label="Faux positifs"
                  onChange={(e) => setFalsePositiveFilter(e.target.value)}
                >
                  <MenuItem value="">Tous</MenuItem>
                  <MenuItem value="false_positive">Faux positifs</MenuItem>
                  <MenuItem value="true_positive">Vrais positifs</MenuItem>
                </Select>
              </FormControl>

              <Box display="flex" gap={1} alignItems="center">
                <Button variant="outlined" startIcon={<Download />} onClick={handleExportCsv}>
                  Export CSV
                </Button>
                <Button variant="contained" onClick={handleAnalyzeAll}>
                  Analyser (sélection filtrée)
                </Button>
                <Button variant="contained" color="success" onClick={handleCorrectAll}>
                  Générer scripts (filtrés)
                </Button>
              </Box>
            </Box>
          </Paper>

          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {filteredVulnerabilities.length} vulnérabilité(s) trouvée(s)
              </Typography>

              {filteredVulnerabilities.length === 0 ? (
                <Alert severity="info">
                  Aucune vulnérabilité trouvée. Lancez un scan pour commencer.
                </Alert>
              ) : (
                filteredVulnerabilities.map((vuln, index) => (
                  <VulnerabilityCard
                    key={vuln.vulnerability_id || vuln.id || index}
                    vulnerability={vuln}
                  />
                ))
              )}
            </Box>
          )}
        </Container>
      </Layout>
    </>
  );
}
