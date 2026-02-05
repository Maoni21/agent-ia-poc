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
} from '@mui/material';
import { Search } from '@mui/icons-material';
import Layout from '../components/Layout';
import VulnerabilityCard from '../components/VulnerabilityCard';
import scanService from '../lib/services/scanService';
import vulnerabilityService from '../lib/services/vulnerabilityService';

export default function VulnerabilitiesPage() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulnerabilities, setFilteredVulnerabilities] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadAllVulnerabilities();
  }, []);

  useEffect(() => {
    if (!searchTerm.trim()) {
      setFilteredVulnerabilities(vulnerabilities);
    } else {
      const filtered = vulnerabilities.filter(
        (vuln) =>
          vuln.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          vuln.vulnerability_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          vuln.description?.toLowerCase().includes(searchTerm.toLowerCase())
      );
      setFilteredVulnerabilities(filtered);
    }
  }, [searchTerm, vulnerabilities]);

  const loadAllVulnerabilities = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const data = await scanService.getScans(100);
      const scans = data.scans || [];
      const allVulns = [];
      
      for (const scan of scans) {
        if (scan.status === 'completed') {
          try {
            const results = await scanService.getScanResults(scan.scan_id);
            
            if (results.analysis_result?.vulnerabilities) {
              allVulns.push(...results.analysis_result.vulnerabilities);
            } else if (results.scan_result?.vulnerabilities) {
              allVulns.push(...results.scan_result.vulnerabilities);
            }
          } catch (err) {
            console.warn(`Impossible de charger les résultats pour ${scan.scan_id}:`, err);
          }
        }
      }
      
      const uniqueVulns = [];
      const seenIds = new Set();
      
      for (const vuln of allVulns) {
        const id = vuln.vulnerability_id || vuln.id;
        if (id && !seenIds.has(id)) {
          seenIds.add(id);
          uniqueVulns.push(vuln);
        }
      }
      
      setVulnerabilities(uniqueVulns);
      setFilteredVulnerabilities(uniqueVulns);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des vulnérabilités');
      console.error('Erreur chargement vulnérabilités:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeVulnerability = async (vulnerabilityId) => {
    try {
      const result = await vulnerabilityService.analyzeVulnerabilities(
        [vulnerabilityId],
        'Unknown System'
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
        'ubuntu',
        'bash'
      );
      alert('Script généré ! Consultez les résultats dans la console.');
      console.log('Résultat génération:', result);
    } catch (err) {
      alert('Erreur lors de la génération: ' + err.message);
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
                    onAnalyze={handleAnalyzeVulnerability}
                    onGenerateScript={handleGenerateScript}
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
