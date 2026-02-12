import { api } from './api';

// Service pour les scans basés sur l'API v1 (PostgreSQL + Celery)
export const scansService = {
  // Créer un nouveau scan pour un asset donné
  createScan: async ({ asset_id, scan_type = 'full' }) => {
    const response = await api.post('/api/v1/scans', {
      asset_id,
      scan_type,
    });
    return response.data;
  },

  // Liste des scans de l'organisation courante
  getScans: async ({ limit = 50, offset = 0 } = {}) => {
    const response = await api.get('/api/v1/scans', {
      params: {
        limit,
        offset,
      },
    });
    return response.data;
  },

  // Détails d'un scan + vulnérabilités associées
  getScan: async (scanId) => {
    const response = await api.get(`/api/v1/scans/${scanId}`);
    return response.data;
  },
};

export default scansService;

