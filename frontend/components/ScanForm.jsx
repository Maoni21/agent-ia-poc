import React, { useState } from 'react';
import {
  Box,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Paper,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import { PlayArrow } from '@mui/icons-material';
import scanService from '../lib/services/scanService';

const ScanForm = ({ onScanStarted }) => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [workflowType, setWorkflowType] = useState('full');
  const [scriptType, setScriptType] = useState('bash');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // Valider la cible
      if (!target || target.trim() === '') {
        throw new Error('Veuillez entrer une adresse IP ou un domaine');
      }

      // Lancer le scan
      const result = await scanService.startScan(
        target.trim(),
        scanType,
        workflowType,
        scriptType
      );

      if (result.success && result.scan_id) {
        // Notifier le parent que le scan a démarré
        if (onScanStarted) {
          onScanStarted(result.scan_id, result);
        }
        
        // Réinitialiser le formulaire
        setTarget('');
      } else {
        throw new Error(result.message || 'Erreur lors du lancement du scan');
      }
    } catch (err) {
      setError(err.message || 'Une erreur est survenue');
      console.error('Erreur lancement scan:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
      <Typography variant="h5" gutterBottom>
        Lancer un nouveau scan
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Box component="form" onSubmit={handleSubmit}>
        <TextField
          fullWidth
          label="Cible (IP ou domaine)"
          placeholder="192.168.1.1 ou example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          margin="normal"
          required
          disabled={loading}
          helperText="Entrez l'adresse IP ou le nom de domaine à scanner"
        />

        <FormControl fullWidth margin="normal">
          <InputLabel>Type de scan</InputLabel>
          <Select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            label="Type de scan"
            disabled={loading}
          >
            <MenuItem value="quick">Rapide (2-3 min)</MenuItem>
            <MenuItem value="full">Complet (5-10 min)</MenuItem>
            <MenuItem value="stealth">Furtif (lent)</MenuItem>
            <MenuItem value="aggressive">Agressif (avec scripts vuln)</MenuItem>
          </Select>
        </FormControl>

        <FormControl fullWidth margin="normal">
          <InputLabel>Type de workflow</InputLabel>
          <Select
            value={workflowType}
            onChange={(e) => setWorkflowType(e.target.value)}
            label="Type de workflow"
            disabled={loading}
          >
            <MenuItem value="scan_only">Scan uniquement</MenuItem>
            <MenuItem value="scan_and_analyze">Scan + Analyse IA</MenuItem>
            <MenuItem value="full">Workflow complet (Scan + Analyse + Scripts)</MenuItem>
          </Select>
        </FormControl>

        <FormControl fullWidth margin="normal">
          <InputLabel>Type de script</InputLabel>
          <Select
            value={scriptType}
            onChange={(e) => setScriptType(e.target.value)}
            label="Type de script"
            disabled={loading}
          >
            <MenuItem value="bash">Bash</MenuItem>
            <MenuItem value="ansible">Ansible</MenuItem>
          </Select>
        </FormControl>

        <Button
          type="submit"
          variant="contained"
          color="primary"
          size="large"
          fullWidth
          disabled={loading || !target.trim()}
          startIcon={loading ? <CircularProgress size={20} /> : <PlayArrow />}
          sx={{ mt: 2 }}
        >
          {loading ? 'Lancement...' : 'Lancer le scan'}
        </Button>
      </Box>
    </Paper>
  );
};

export default ScanForm;
