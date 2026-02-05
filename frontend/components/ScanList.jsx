import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Typography,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  Visibility,
  Download,
  Refresh,
} from '@mui/icons-material';
import scanService from '../lib/services/scanService';

const ScanList = ({ onScanSelect, refreshTrigger }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchScans = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const data = await scanService.getScans(50);
      setScans(data.scans || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des scans');
      console.error('Erreur chargement scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    
    // Rafraîchir toutes les 5 secondes pour les scans en cours
    const interval = setInterval(() => {
      fetchScans();
    }, 5000);
    
    return () => clearInterval(interval);
  }, [refreshTrigger]);

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'success';
      case 'running':
      case 'pending':
        return 'info';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleString('fr-FR');
    } catch {
      return dateString;
    }
  };

  const handleViewScan = (scanId) => {
    if (onScanSelect) {
      onScanSelect(scanId);
    }
  };

  const handleDownloadPDF = async (scanId, e) => {
    e.stopPropagation();
    try {
      await scanService.downloadPDF(scanId);
    } catch (err) {
      console.error('Erreur téléchargement PDF:', err);
      alert('Erreur lors du téléchargement du PDF');
    }
  };

  if (loading && scans.length === 0) {
    return (
      <Box display="flex" justifyContent="center" p={3}>
        <CircularProgress />
      </Box>
    );
  }

  if (error && scans.length === 0) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Paper elevation={3} sx={{ p: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5">Liste des scans</Typography>
        <IconButton onClick={fetchScans} disabled={loading}>
          <Refresh />
        </IconButton>
      </Box>

      {scans.length === 0 ? (
        <Alert severity="info">Aucun scan trouvé. Lancez un nouveau scan pour commencer.</Alert>
      ) : (
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Cible</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Statut</TableCell>
                <TableCell>Progression</TableCell>
                <TableCell>Vulnérabilités</TableCell>
                <TableCell>Date de début</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.map((scan) => (
                <TableRow
                  key={scan.scan_id}
                  hover
                  onClick={() => handleViewScan(scan.scan_id)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {scan.scan_id.substring(0, 8)}...
                    </Typography>
                  </TableCell>
                  <TableCell>{scan.target || 'N/A'}</TableCell>
                  <TableCell>{scan.scan_type || scan.workflow_type || 'N/A'}</TableCell>
                  <TableCell>
                    <Chip
                      label={scan.status || 'unknown'}
                      color={getStatusColor(scan.status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {scan.progress !== undefined ? `${scan.progress}%` : 'N/A'}
                  </TableCell>
                  <TableCell>
                    {scan.vulnerabilities_found !== undefined
                      ? scan.vulnerabilities_found
                      : 'N/A'}
                  </TableCell>
                  <TableCell>{formatDate(scan.started_at)}</TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={() => handleViewScan(scan.scan_id)}
                      title="Voir les détails"
                    >
                      <Visibility />
                    </IconButton>
                    {scan.status === 'completed' && (
                      <IconButton
                        size="small"
                        onClick={(e) => handleDownloadPDF(scan.scan_id, e)}
                        title="Télécharger le PDF"
                      >
                        <Download />
                      </IconButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Paper>
  );
};

export default ScanList;
