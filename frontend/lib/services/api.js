import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercepteur pour gérer les erreurs
api.interceptors.response.use(
  response => response,
  error => {
    console.error('API Error:', error);
    
    // Gérer les erreurs spécifiques
    if (error.response) {
      // Erreur avec réponse du serveur
      const { status, data } = error.response;
      
      if (status === 401) {
        // Non autorisé - rediriger vers login si nécessaire
        console.error('Non autorisé');
      } else if (status === 404) {
        console.error('Ressource non trouvée');
      } else if (status >= 500) {
        console.error('Erreur serveur');
      }
      
      return Promise.reject({
        message: data?.detail || data?.message || 'Une erreur est survenue',
        status,
        data,
      });
    } else if (error.request) {
      // Requête envoyée mais pas de réponse
      console.error('Pas de réponse du serveur');
      return Promise.reject({
        message: 'Impossible de contacter le serveur',
        status: 0,
      });
    } else {
      // Erreur lors de la configuration de la requête
      return Promise.reject({
        message: error.message || 'Erreur inconnue',
        status: 0,
      });
    }
  }
);

export default api;
