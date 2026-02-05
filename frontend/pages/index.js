import Head from 'next/head';

export default function HomePage() {
  return (
    <>
      <Head>
        <title>CyberSec AI - Dashboard</title>
      </Head>
      {/* On réutilise le dashboard HTML d'origine dans une iframe plein écran */}
      <div style={{ width: '100vw', height: '100vh', border: 'none', margin: 0, padding: 0 }}>
        <iframe
          src="/dashboard.html"
          style={{ width: '100%', height: '100%', border: 'none' }}
          title="CyberSec AI Dashboard"
        />
      </div>
    </>
  );
}
