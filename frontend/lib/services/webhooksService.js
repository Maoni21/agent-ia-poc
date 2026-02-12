import api from './api';

export const webhooksService = {
  getWebhooks: async () => {
    const res = await api.get('/api/v1/webhooks');
    return res.data;
  },

  createWebhook: async (data) => {
    const res = await api.post('/api/v1/webhooks', data);
    return res.data;
  },

  deleteWebhook: async (id) => {
    await api.delete(`/api/v1/webhooks/${id}`);
  },
};

export default webhooksService;

