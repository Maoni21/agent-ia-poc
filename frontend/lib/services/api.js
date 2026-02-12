import axios from 'axios';

const API_URL =
  process.env.NEXT_PUBLIC_API_URL ||
  process.env.REACT_APP_API_URL ||
  'http://localhost:8000';

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercepteur requête : ajoute automatiquement le JWT si présent
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Intercepteur pour gérer les erreurs
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);

    if (error.response) {
      const { status, data } = error.response;

      if (status === 401 && typeof window !== 'undefined') {
        // Token invalide ou expiré → on nettoie et on renvoie vers /login
        localStorage.removeItem('access_token');
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      }

      return Promise.reject({
        message: data?.detail || data?.message || 'Une erreur est survenue',
        status,
        data,
      });
    } else if (error.request) {
      return Promise.reject({
        message: 'Impossible de contacter le serveur',
        status: 0,
      });
    } else {
      return Promise.reject({
        message: error.message || 'Erreur inconnue',
        status: 0,
      });
    }
  }
);

export default api;
