import { api } from './api';

// Service dédié aux vulnérabilités pour le dashboard (dashboard_api.py)
export const vulnerabilitiesService = {
  // Liste des vulnérabilités avec filtres
  getVulnerabilities: async ({ limit = 100, severity, status, search } = {}) => {
    const response = await api.get('/api/vulnerabilities', {
      params: {
        limit,
        severity: severity || undefined,
        status: status || undefined,
        search: search || undefined,
      },
    });
    return response.data;
  },

  // Export CSV global ou pour un scan
  exportCsv: async ({ scanId, severity } = {}) => {
    const response = await api.get('/api/vulnerabilities/export/csv', {
      params: {
        scan_id: scanId || undefined,
        severity: severity || undefined,
      },
      responseType: 'blob',
    });

    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'vulnerabilites.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },
};

export default vulnerabilitiesService;

