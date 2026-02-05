import { api } from './api';

export const scanService = {
  // Lancer un nouveau scan
  startScan: async (target, scanType = 'full', workflowType = 'full', scriptType = 'bash') => {
    const response = await api.post('/api/v2/scans/launch', {
      target,
      scan_type: scanType,
      workflow_type: workflowType,
      script_type: scriptType,
    });
    return response.data;
  },

  // Récupérer tous les scans
  getScans: async (limit = 50) => {
    const response = await api.get('/api/v2/scans', {
      params: { limit },
    });
    return response.data;
  },

  // Récupérer un scan spécifique
  getScan: async (scanId) => {
    const response = await api.get(`/api/v2/scans/${scanId}/status`);
    return response.data;
  },

  // Récupérer les résultats d'un scan
  getScanResults: async (scanId) => {
    const response = await api.get(`/api/v2/scans/${scanId}/results`);
    return response.data;
  },

  // Télécharger le rapport PDF
  downloadPDF: async (scanId) => {
    const response = await api.get(`/api/v2/scans/${scanId}/pdf`, {
      responseType: 'blob',
    });
    
    // Créer un lien de téléchargement
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `rapport_${scanId}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
    
    return response.data;
  },
};

export default scanService;
