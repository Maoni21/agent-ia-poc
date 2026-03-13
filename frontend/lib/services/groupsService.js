import { api } from './api';

export const groupsService = {
  // Liste des groupes
  listGroups: async () => {
    const response = await api.get('/api/v1/vulnerability-groups');
    return response.data;
  },

  // Détails d'un groupe
  getGroup: async (groupId) => {
    const response = await api.get(`/api/v1/vulnerability-groups/${groupId}`);
    return response.data;
  },

  // Création d'un groupe
  createGroup: async ({ name, description, vulnerabilityIds }) => {
    const response = await api.post('/api/v1/vulnerability-groups', {
      name,
      description,
      vulnerability_ids: vulnerabilityIds,
    });
    return response.data;
  },

  // Mise à jour d'un groupe
  updateGroup: async (groupId, { name, description, vulnerabilityIds }) => {
    const response = await api.put(`/api/v1/vulnerability-groups/${groupId}`, {
      name,
      description,
      vulnerability_ids: vulnerabilityIds,
    });
    return response.data;
  },

  // Suppression d'un groupe
  deleteGroup: async (groupId) => {
    const response = await api.delete(`/api/v1/vulnerability-groups/${groupId}`);
    return response.data;
  },

  // Analyse IA d'un groupe complet
  analyzeGroup: async (groupId, targetSystem) => {
    const response = await api.post(`/api/v1/analyze/group/${groupId}`, null, {
      params: {
        target_system: targetSystem || undefined,
      },
    });
    return response.data;
  },
};

export default groupsService;

