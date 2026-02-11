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
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  CircularProgress,
} from '@mui/material';
import Layout from '../components/Layout';
import groupsService from '../lib/services/groupsService';

export default function GroupsPage() {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [vulnIdsText, setVulnIdsText] = useState('');
  const [saving, setSaving] = useState(false);

  const loadGroups = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await groupsService.listGroups();
      setGroups(data.groups || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des groupes');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGroups();
  }, []);

  const handleCreateGroup = async () => {
    setSaving(true);
    try {
      const vulnerabilityIds = vulnIdsText
        .split(/[,\s]+/)
        .map((id) => id.trim())
        .filter(Boolean);

      await groupsService.createGroup({
        name,
        description,
        vulnerabilityIds,
      });

      setDialogOpen(false);
      setName('');
      setDescription('');
      setVulnIdsText('');
      await loadGroups();
    } catch (err) {
      alert(err.message || "Erreur lors de la création du groupe");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteGroup = async (groupId) => {
    if (!window.confirm('Supprimer ce groupe ?')) return;
    try {
      await groupsService.deleteGroup(groupId);
      await loadGroups();
    } catch (err) {
      alert(err.message || "Erreur lors de la suppression du groupe");
    }
  };

  const handleAnalyzeGroup = async (groupId) => {
    try {
      const result = await groupsService.analyzeGroup(groupId);
      alert(
        `Analyse lancée / terminée.\nAnalysis ID: ${result.analysis_id || 'n/a'}\n${result.message || ''}`,
      );
    } catch (err) {
      alert(err.message || "Erreur lors de l'analyse du groupe");
    }
  };

  return (
    <>
      <Head>
        <title>CyberSec AI - Groupes de vulnérabilités</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h4" gutterBottom>
              Groupes de vulnérabilités
            </Typography>
            <Button variant="contained" onClick={() => setDialogOpen(true)}>
              Nouveau groupe
            </Button>
          </Box>

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
            ) : groups.length === 0 ? (
              <Alert severity="info">Aucun groupe créé pour le moment.</Alert>
            ) : (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Nom</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Vulnérabilités</TableCell>
                    <TableCell>Créé le</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {groups.map((group) => (
                    <TableRow key={group.group_id}>
                      <TableCell>{group.name}</TableCell>
                      <TableCell>{group.description}</TableCell>
                      <TableCell>{group.vulnerability_count}</TableCell>
                      <TableCell>{group.created_at}</TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          onClick={() => handleAnalyzeGroup(group.group_id)}
                          sx={{ mr: 1 }}
                        >
                          Analyser avec IA
                        </Button>
                        <Button
                          size="small"
                          color="error"
                          onClick={() => handleDeleteGroup(group.group_id)}
                        >
                          Supprimer
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>

          <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} fullWidth maxWidth="sm">
            <DialogTitle>Nouveau groupe de vulnérabilités</DialogTitle>
            <DialogContent dividers>
              <TextField
                fullWidth
                label="Nom du groupe"
                margin="normal"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <TextField
                fullWidth
                label="Description"
                margin="normal"
                multiline
                minRows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
              <TextField
                fullWidth
                label="IDs de vulnérabilités (CVE...)"
                helperText="Séparés par des virgules ou espaces (ex: CVE-2023-1234, CVE-2024-5678)"
                margin="normal"
                multiline
                minRows={2}
                value={vulnIdsText}
                onChange={(e) => setVulnIdsText(e.target.value)}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDialogOpen(false)}>Annuler</Button>
              <Button onClick={handleCreateGroup} disabled={saving || !name.trim()}>
                Créer
              </Button>
            </DialogActions>
          </Dialog>
        </Container>
      </Layout>
    </>
  );
}

