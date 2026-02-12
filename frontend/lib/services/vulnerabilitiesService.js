import { api } from './api';

// Service dédié aux vulnérabilités
export const vulnerabilitiesService = {
  // Liste des vulnérabilités (adaptera l'URL quand un endpoint dédié existera)
  getVulnerabilities: async ({ limit = 100, severity, status, search } = {}) => {
    const response = await api.get('/api/v1/vulnerabilities', {
      params: {
        limit,
        severity: severity || undefined,
        status: status || undefined,
        search: search || undefined,
      },
    });
    return response.data;
  },

  // Analyse IA d'une vulnérabilité
  analyzeVulnerability: async (vulnerabilityId) => {
    const response = await api.post(
      `/api/v1/vulnerabilities/${vulnerabilityId}/analyze`
    );
    return response.data;
  },

  // Génération de script pour une vulnérabilité
  generateScript: async (vulnerabilityId, { target_system, script_type } = {}) => {
    const response = await api.post(
      `/api/v1/vulnerabilities/${vulnerabilityId}/generate-script`,
      {
        target_system,
        script_type,
      }
    );
    return response.data;
  },
};

export default vulnerabilitiesService;

