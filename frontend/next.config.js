/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  env: {
    REACT_APP_API_URL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
    REACT_APP_WS_URL: process.env.REACT_APP_WS_URL || 'ws://localhost:8000',
  },
  async rewrites() {
    const apiBase = process.env.REACT_APP_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
      {
        source: '/api/v2/:path*',
        destination: `${apiBase}/api/v2/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
