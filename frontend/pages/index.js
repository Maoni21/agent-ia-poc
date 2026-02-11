import Head from 'next/head';
import { Container } from '@mui/material';
import Layout from '../components/Layout';
import Dashboard from '../components/Dashboard';

export default function HomePage() {
  return (
    <>
      <Head>
        <title>CyberSec AI - Dashboard</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          <Dashboard />
        </Container>
      </Layout>
    </>
  );
}
