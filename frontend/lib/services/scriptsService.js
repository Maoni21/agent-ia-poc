import { api } from './api';

export const scriptsService = {
  // Liste tous les scripts générés (RemediationScript — flux individuel par vulnérabilité)
  getScripts: async ({ limit = 200, offset = 0, status } = {}) => {
    const params = new URLSearchParams({ limit, offset });
    if (status) params.append('execution_status', status);
    const response = await api.get(`/api/v1/remediation-scripts?${params}`);
    return response.data;
  },

  // Détail d'un script individuel (ancien flux, par vulnérabilité)
  getScript: async (id) => {
    const response = await api.get(`/api/v1/remediation-scripts/${id}`);
    return response.data;
  },

  // Détail d'un script d'exécution (nouveau flux, RemediationExecution)
  getExecutionScript: async (id) => {
    const response = await api.get(`/api/v1/scripts/${id}`);
    return response.data;
  },
};

export default scriptsService;
