import { api } from './api';

export const dashboardService = {
  // Statistiques globales du dashboard
  getOverview: async () => {
    const response = await api.get('/api/v1/stats/overview');
    return response.data;
  },

  // Distribution des vulnérabilités par sévérité
  getSeverityDistribution: async () => {
    const response = await api.get('/api/v1/stats/severity-distribution');
    return response.data;
  },

  // Timeline des vulnérabilités (30 derniers jours)
  getTimeline: async () => {
    const response = await api.get('/api/v1/stats/timeline');
    return response.data;
  },

  // Top vulnérabilités critiques
  getTopVulnerabilities: async (limit = 10) => {
    const response = await api.get('/api/v1/stats/top-vulnerabilities', {
      params: { limit },
    });
    return response.data;
  },
};

export default dashboardService;

