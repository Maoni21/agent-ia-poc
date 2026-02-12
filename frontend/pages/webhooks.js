import { useEffect, useState } from 'react';
import Head from 'next/head';
import {
  Box,
  Container,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormGroup,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import { Delete, Add } from '@mui/icons-material';
import Layout from '../components/Layout';
import webhooksService from '../lib/services/webhooksService';

const AVAILABLE_EVENTS = [
  { id: 'scan_completed', label: 'Scan terminé' },
  { id: 'critical_vulnerability', label: 'Vulnérabilité critique' },
  { id: 'remediation_completed', label: 'Remédiation terminée' },
];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [selectedEvents, setSelectedEvents] = useState(['scan_completed']);

  const loadWebhooks = async () => {
    try {
      const data = await webhooksService.getWebhooks();
      setWebhooks(data);
    } catch (err) {
      console.error('Erreur chargement webhooks', err);
    }
  };

  useEffect(() => {
    loadWebhooks();
  }, []);

  const handleToggleEvent = (eventId) => {
    setSelectedEvents((prev) =>
      prev.includes(eventId)
        ? prev.filter((e) => e !== eventId)
        : [...prev, eventId]
    );
  };

  const handleCreate = async () => {
    try {
      await webhooksService.createWebhook({
        url,
        events: selectedEvents,
      });
      setDialogOpen(false);
      setUrl('');
      setSelectedEvents(['scan_completed']);
      await loadWebhooks();
    } catch (err) {
      alert(err?.message || 'Erreur création webhook');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Supprimer ce webhook ?')) return;
    try {
      await webhooksService.deleteWebhook(id);
      await loadWebhooks();
    } catch (err) {
      alert(err?.message || 'Erreur suppression webhook');
    }
  };

  return (
    <>
      <Head>
        <title>Webhooks - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h4">Webhooks</Typography>
            <Button
              variant="contained"
              startIcon={<Add />}
              onClick={() => setDialogOpen(true)}
            >
              Ajouter un webhook
            </Button>
          </Box>

          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>URL</TableCell>
                  <TableCell>Événements</TableCell>
                  <TableCell>Actif</TableCell>
                  <TableCell>Dernière livraison</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {webhooks.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center">
                      Aucun webhook configuré.
                    </TableCell>
                  </TableRow>
                )}
                {webhooks.map((wh) => (
                  <TableRow key={wh.id}>
                    <TableCell>{wh.url}</TableCell>
                    <TableCell>{(wh.events || []).join(', ')}</TableCell>
                    <TableCell>{wh.is_active ? 'Oui' : 'Non'}</TableCell>
                    <TableCell>
                      {wh.last_delivery_at
                        ? new Date(wh.last_delivery_at).toLocaleString()
                        : '-'}
                    </TableCell>
                    <TableCell align="right">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDelete(wh.id)}
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
            <DialogTitle>Ajouter un webhook</DialogTitle>
            <DialogContent>
              <TextField
                fullWidth
                margin="normal"
                label="URL du webhook"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <Typography variant="subtitle1" sx={{ mt: 2 }}>
                Événements
              </Typography>
              <FormGroup>
                {AVAILABLE_EVENTS.map((ev) => (
                  <FormControlLabel
                    key={ev.id}
                    control={
                      <Checkbox
                        checked={selectedEvents.includes(ev.id)}
                        onChange={() => handleToggleEvent(ev.id)}
                      />
                    }
                    label={ev.label}
                  />
                ))}
              </FormGroup>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDialogOpen(false)}>Annuler</Button>
              <Button variant="contained" onClick={handleCreate}>
                Enregistrer
              </Button>
            </DialogActions>
          </Dialog>
        </Container>
      </Layout>
    </>
  );
}

