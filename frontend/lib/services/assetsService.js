import api from './api';

export const assetsService = {
  getAssets: async () => {
    const res = await api.get('/api/v1/assets');
    return res.data;
  },

  getAsset: async (id) => {
    const res = await api.get(`/api/v1/assets/${id}`);
    return res.data;
  },

  createAsset: async (data) => {
    const res = await api.post('/api/v1/assets', data);
    return res.data;
  },

  updateAsset: async (id, data) => {
    const res = await api.put(`/api/v1/assets/${id}`, data);
    return res.data;
  },

  deleteAsset: async (id) => {
    await api.delete(`/api/v1/assets/${id}`);
  },
};

export default assetsService;

