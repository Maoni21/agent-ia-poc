import { api } from './api';

// Service complémentaire pour les fonctionnalités avancées de scan du dashboard (upgrade plan, vulnérabilités par scan)
export const scanDashboardService = {
  // Vulnérabilités pour un scan précis (utilise /api/scans/{scan_id}/vulnerabilities de dashboard_api.py)
  getScanVulnerabilities: async (scanId, limit = 500) => {
    const response = await api.get(`/api/scans/${scanId}/vulnerabilities`, {
      params: { limit },
    });
    return response.data;
  },

  // Plan de mises à jour optimisé pour un scan
  generateUpgradePlan: async (scanId) => {
    const response = await api.post(`/api/scans/${scanId}/upgrade-plan`);
    return response.data;
  },
};

export default scanDashboardService;

