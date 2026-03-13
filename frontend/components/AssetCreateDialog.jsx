import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  MenuItem,
  Alert,
  Box,
  Typography,
  Tooltip,
  IconButton,
  InputAdornment,
} from '@mui/material';
import { HelpOutline, CheckCircle } from '@mui/icons-material';
import assetsService from '../lib/services/assetsService';

export default function AssetCreateDialog({
  open,
  onClose,
  onSuccess,
  isFirstAsset = false,
}) {
  const [form, setForm] = useState({
    ip_address: '',
    hostname: '',
    asset_type: 'server',
    environment: 'production',
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const validateIP = (ip) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipv4Regex.test(ip);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));

    if (name === 'ip_address') {
      if (value && !validateIP(value)) {
        setErrors((prev) => ({ ...prev, ip_address: 'Format IP invalide' }));
      } else {
        setErrors((prev) => {
          const { ip_address, ...rest } = prev;
          return rest;
        });
      }
    }
  };

  const handleSubmit = async () => {
    if (!validateIP(form.ip_address)) {
      setErrors({ ip_address: 'Adresse IP invalide (ex: 192.168.1.10)' });
      return;
    }

    setLoading(true);
    try {
      await assetsService.createAsset(form);
      if (onSuccess) onSuccess();
      setForm({
        ip_address: '',
        hostname: '',
        asset_type: 'server',
        environment: 'production',
      });
    } catch (err) {
      // eslint-disable-next-line no-alert
      alert(
        "Erreur lors de la création de l'asset: " +
          (err?.message || 'inconnue'),
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    if (onClose) onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>Ajouter un asset</DialogTitle>
      <DialogContent dividers>
        {isFirstAsset && (
          <Alert severity="info" sx={{ mb: 2 }}>
            C&apos;est votre premier asset : commencez par un serveur de test.
          </Alert>
        )}

        <TextField
          fullWidth
          margin="normal"
          label="Adresse IP"
          name="ip_address"
          value={form.ip_address}
          onChange={handleChange}
          error={Boolean(errors.ip_address)}
          helperText={errors.ip_address || 'Ex: 192.168.1.10'}
          InputProps={{
            endAdornment: (
              <InputAdornment position="end">
                {form.ip_address && !errors.ip_address && (
                  <CheckCircle color="success" fontSize="small" />
                )}
              </InputAdornment>
            ),
          }}
        />

        <TextField
          fullWidth
          margin="normal"
          label="Nom de l’asset"
          name="hostname"
          value={form.hostname}
          onChange={handleChange}
          helperText="Ex: Serveur Web Production, Base MySQL Dev…"
        />

        <TextField
          select
          fullWidth
          margin="normal"
          label="Type d’asset"
          name="asset_type"
          value={form.asset_type}
          onChange={handleChange}
        >
          <MenuItem value="server">Serveur</MenuItem>
          <MenuItem value="database">Base de données</MenuItem>
          <MenuItem value="network_device">Équipement réseau</MenuItem>
          <MenuItem value="container">Container</MenuItem>
          <MenuItem value="cloud_instance">Instance cloud</MenuItem>
        </TextField>

        <TextField
          select
          fullWidth
          margin="normal"
          label="Environnement"
          name="environment"
          value={form.environment}
          onChange={handleChange}
        >
          <MenuItem value="production">Production</MenuItem>
          <MenuItem value="staging">Staging</MenuItem>
          <MenuItem value="development">Développement</MenuItem>
          <MenuItem value="test">Test</MenuItem>
        </TextField>

        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
          <Tooltip title="Besoin d'aide ?">
            <IconButton size="small">
              <HelpOutline fontSize="small" />
            </IconButton>
          </Tooltip>
          <Typography variant="caption" color="text.secondary">
            Utilisez une IP accessible depuis le serveur où tourne l&apos;agent.
          </Typography>
        </Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Annuler
        </Button>
        <Button variant="contained" onClick={handleSubmit} disabled={loading}>
          Créer l&apos;asset
        </Button>
      </DialogActions>
    </Dialog>
  );
}

