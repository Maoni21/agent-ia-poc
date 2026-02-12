import { useEffect, useState } from 'react';
import Head from 'next/head';
import {
  Box,
  Container,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Chip,
  Stack,
} from '@mui/material';
import { Add, Edit, Delete } from '@mui/icons-material';
import Layout from '../components/Layout';
import assetsService from '../lib/services/assetsService';

const ASSET_TYPES = [
  { value: 'server', label: 'Serveur' },
  { value: 'workstation', label: 'Poste de travail' },
  { value: 'network_device', label: 'Équipement réseau' },
  { value: 'container', label: 'Conteneur' },
  { value: 'cloud_instance', label: 'Instance cloud' },
];

const ENVIRONMENTS = [
  { value: 'production', label: 'Production' },
  { value: 'staging', label: 'Staging' },
  { value: 'development', label: 'Développement' },
  { value: 'test', label: 'Test' },
];

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [form, setForm] = useState({
    hostname: '',
    ip_address: '',
    asset_type: 'server',
    environment: '',
    tags: '',
  });

  const loadAssets = async () => {
    setLoading(true);
    try {
      const data = await assetsService.getAssets();
      setAssets(data);
    } catch (err) {
      console.error('Erreur chargement assets', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const openCreateDialog = () => {
    setEditingAsset(null);
    setForm({
      hostname: '',
      ip_address: '',
      asset_type: 'server',
      environment: '',
      tags: '',
    });
    setDialogOpen(true);
  };

  const openEditDialog = (asset) => {
    setEditingAsset(asset);
    setForm({
      hostname: asset.hostname || '',
      ip_address: asset.ip_address || '',
      asset_type: asset.asset_type || 'server',
      environment: asset.environment || '',
      tags: (asset.tags || []).join(', '),
    });
    setDialogOpen(true);
  };

  const handleDelete = async (asset) => {
    if (!window.confirm(`Supprimer l'asset ${asset.hostname || asset.ip_address} ?`)) {
      return;
    }
    try {
      await assetsService.deleteAsset(asset.id);
      await loadAssets();
    } catch (err) {
      console.error('Erreur suppression asset', err);
    }
  };

  const handleFormChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const payload = {
      hostname: form.hostname || null,
      ip_address: form.ip_address,
      asset_type: form.asset_type,
      environment: form.environment || null,
      tags: form.tags
        ? form.tags.split(',').map((t) => t.trim()).filter(Boolean)
        : [],
    };

    try {
      if (editingAsset) {
        await assetsService.updateAsset(editingAsset.id, payload);
      } else {
        await assetsService.createAsset(payload);
      }
      setDialogOpen(false);
      await loadAssets();
    } catch (err) {
      alert(err?.message || "Erreur lors de l'enregistrement de l'asset");
    }
  };

  return (
    <>
      <Head>
        <title>Assets - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h4" component="h1">
              Assets
            </Typography>
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={openCreateDialog}
            >
              Ajouter un asset
            </Button>
          </Box>

          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Hostname</TableCell>
                  <TableCell>IP</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Environnement</TableCell>
                  <TableCell>Tags</TableCell>
                  <TableCell>Dernier vu</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {!loading && assets.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      Aucun asset pour le moment.
                    </TableCell>
                  </TableRow>
                )}
                {assets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell>{asset.hostname || '-'}</TableCell>
                    <TableCell>{asset.ip_address}</TableCell>
                    <TableCell>{asset.asset_type}</TableCell>
                    <TableCell>{asset.environment || '-'}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap">
                        {(asset.tags || []).map((tag) => (
                          <Chip key={tag} label={tag} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      {asset.last_seen
                        ? new Date(asset.last_seen).toLocaleString()
                        : '-'}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" onClick={() => openEditDialog(asset)}>
                        <Edit fontSize="small" />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDelete(asset)}
                      >
                        <Delete fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} fullWidth maxWidth="sm">
            <DialogTitle>
              {editingAsset ? "Modifier l'asset" : 'Ajouter un asset'}
            </DialogTitle>
            <DialogContent>
              <Box
                component="form"
                sx={{ mt: 1 }}
                onSubmit={handleSubmit}
              >
                <TextField
                  margin="normal"
                  fullWidth
                  label="Hostname"
                  name="hostname"
                  value={form.hostname}
                  onChange={handleFormChange}
                />
                <TextField
                  margin="normal"
                  required
                  fullWidth
                  label="Adresse IP"
                  name="ip_address"
                  value={form.ip_address}
                  onChange={handleFormChange}
                />
                <TextField
                  select
                  margin="normal"
                  fullWidth
                  label="Type d'asset"
                  name="asset_type"
                  value={form.asset_type}
                  onChange={handleFormChange}
                >
                  {ASSET_TYPES.map((opt) => (
                    <MenuItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </MenuItem>
                  ))}
                </TextField>
                <TextField
                  select
                  margin="normal"
                  fullWidth
                  label="Environnement"
                  name="environment"
                  value={form.environment}
                  onChange={handleFormChange}
                >
                  <MenuItem value="">
                    <em>Non défini</em>
                  </MenuItem>
                  {ENVIRONMENTS.map((opt) => (
                    <MenuItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </MenuItem>
                  ))}
                </TextField>
                <TextField
                  margin="normal"
                  fullWidth
                  label="Tags (séparés par des virgules)"
                  name="tags"
                  value={form.tags}
                  onChange={handleFormChange}
                />
              </Box>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDialogOpen(false)}>Annuler</Button>
              <Button onClick={handleSubmit} variant="contained">
                Enregistrer
              </Button>
            </DialogActions>
          </Dialog>
        </Container>
      </Layout>
    </>
  );
}

