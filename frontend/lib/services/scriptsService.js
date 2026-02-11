import { api } from './api';

export const scriptsService = {
  // Liste des scripts de remédiation
  getScripts: async ({ limit = 50, status } = {}) => {
    const response = await api.get('/api/scripts', {
      params: {
        limit,
        status: status || undefined,
      },
    });
    return response.data;
  },
};

export default scriptsService;

