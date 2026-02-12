import { api } from './api';

export const scriptsService = {
  // Récupère un script de remédiation par ID
  getScript: async (id) => {
    const response = await api.get(`/api/v1/remediation-scripts/${id}`);
    return response.data;
  },
};

export default scriptsService;


