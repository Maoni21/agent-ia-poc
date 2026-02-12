import api from './api';

export const authService = {
  login: async (email, password) => {
    // L'endpoint backend attend un formulaire OAuth2PasswordRequestForm
    const params = new URLSearchParams();
    params.append('username', email);
    params.append('password', password);

    const response = await api.post('/auth/login', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token } = response.data;
    if (typeof window !== 'undefined' && access_token) {
      localStorage.setItem('access_token', access_token);
    }
    return response.data;
  },

  register: async ({ email, password, full_name, organization_name }) => {
    const response = await api.post('/auth/register', {
      email,
      password,
      full_name,
      organization_name,
    });
    return response.data;
  },

  logout: () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
  },

  getMe: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },

  isAuthenticated: () => {
    if (typeof window === 'undefined') return false;
    return !!localStorage.getItem('access_token');
  },
};

export default authService;

