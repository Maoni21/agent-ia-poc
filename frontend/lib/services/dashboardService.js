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

  // Statut de conformité (PCI DSS, ISO 27001, SOC 2, GDPR)
  getComplianceStatus: async () => {
    const response = await api.get('/api/v1/dashboard/compliance-status');
    return response.data;
  },

  // MTTR (Mean Time to Remediate) + benchmarks industrie
  getMTTR: async () => {
    const response = await api.get('/api/v1/dashboard/mttr');
    return response.data;
  },

  // Projets de remédiation
  getRemediationProjects: async () => {
    const response = await api.get('/api/v1/remediation-projects');
    return response.data;
  },

  createRemediationProject: async (data) => {
    const response = await api.post('/api/v1/remediation-projects', data);
    return response.data;
  },

  updateRemediationProject: async (id, data) => {
    const response = await api.put(`/api/v1/remediation-projects/${id}`, data);
    return response.data;
  },

  deleteRemediationProject: async (id) => {
    await api.delete(`/api/v1/remediation-projects/${id}`);
  },
};

export default dashboardService;
