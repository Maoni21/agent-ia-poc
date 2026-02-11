import { api } from './api';

export const analysisHistoryService = {
  // Liste des dernières analyses IA
  listAnalyses: async (limit = 20) => {
    const response = await api.get('/api/analysis-history', {
      params: { limit },
    });
    return response.data;
  },

  // Détails d'une analyse IA
  getAnalysisDetails: async (analysisId) => {
    const response = await api.get(`/api/analysis-history/${analysisId}`);
    return response.data;
  },
};

export default analysisHistoryService;

