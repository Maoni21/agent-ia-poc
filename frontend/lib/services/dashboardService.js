import { api } from './api';

export const dashboardService = {
  // Statistiques générales (endpoint existant)
  getStats: async () => {
    const response = await api.get('/api/v1/dashboard/stats');
    return response.data;
  },

  // Score de sécurité global 0-100 avec trending
  getSecurityScore: async () => {
    const response = await api.get('/api/v1/dashboard/security-score');
    return response.data;
  },

  // Top N assets les plus à risque
  getTopRiskyAssets: async (limit = 10) => {
    const response = await api.get('/api/v1/dashboard/top-risky-assets', {
      params: { limit },
    });
    return response.data;
  },

  // Tendances des vulnérabilités par sévérité sur N jours
  getVulnerabilityTrends: async (days = 30) => {
    const response = await api.get('/api/v1/dashboard/vulnerability-trends', {
      params: { days },
    });
    return response.data;
  },

  // Répartition par sévérité (pie chart)
  getSeverityDistribution: async () => {
    const response = await api.get('/api/v1/dashboard/severity-distribution');
    return response.data;
  },

  // Top CVEs classés par nombre d'assets affectés
  getTopVulnerabilitiesByAssets: async (limit = 10) => {
    const response = await api.get('/api/v1/dashboard/top-vulnerabilities-by-assets', {
      params: { limit },
    });
    return response.data;
  },
};

export default dashboardService;
