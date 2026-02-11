import { api } from './api';

// Service pour les appels d'analyse et de correction avancés exposés par dashboard_api.py
export const analysisService = {
  // Analyse d'une sélection de vulnérabilités
  analyzeSelected: async ({ vulnerabilityIds, targetSystem, businessContext }) => {
    const response = await api.post('/api/analyze/selected', {
      vulnerability_ids: vulnerabilityIds,
      target_system: targetSystem || 'Unknown System',
      business_context: businessContext || null,
    });
    return response.data;
  },

  // Génération de scripts de correction pour une sélection
  correctSelected: async ({ vulnerabilityIds, targetSystem }) => {
    const response = await api.post('/api/correct/selected', {
      vulnerability_ids: vulnerabilityIds,
      target_system: targetSystem || 'ubuntu',
    });
    return response.data;
  },
};

export default analysisService;

