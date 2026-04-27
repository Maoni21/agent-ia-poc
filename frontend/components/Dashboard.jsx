import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Play, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';

import { SecurityScoreWidget } from './dashboard/SecurityScoreWidget';
import { TopRiskyAssets } from './dashboard/TopRiskyAssets';
import { VulnerabilityTrendChart } from './dashboard/VulnerabilityTrendChart';
import { SeverityDistributionChart } from './dashboard/SeverityDistributionChart';
import { TopVulnerabilitiesChart } from './dashboard/TopVulnerabilitiesChart';

import dashboardService from '../lib/services/dashboardService';

const Dashboard = () => {
  const [scoreData,    setScoreData]    = useState(null);
  const [topAssets,    setTopAssets]    = useState([]);
  const [trendsData,   setTrendsData]   = useState([]);
  const [severityData, setSeverityData] = useState([]);
  const [topVulnsData, setTopVulnsData] = useState([]);

  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error,      setError]      = useState(null);

  const fetchDashboardData = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const [score, assets, trends, severity, topVulns] = await Promise.all([
        dashboardService.getSecurityScore(),
        dashboardService.getTopRiskyAssets(10),
        dashboardService.getVulnerabilityTrends(30),
        dashboardService.getSeverityDistribution(),
        dashboardService.getTopVulnerabilitiesByAssets(10),
      ]);

      setScoreData(score);
      setTopAssets(assets);
      setTrendsData(trends);
      setSeverityData(severity);
      setTopVulnsData(topVulns);

    } catch (err) {
      setError(err.message || 'Erreur lors du chargement du tableau de bord');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => fetchDashboardData(true), 30000);
    return () => clearInterval(interval);
  }, []);

  if (error && !scoreData) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Tableau de bord</h1>
          <p className="text-muted-foreground">Vue d&apos;ensemble de votre posture de sécurité</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => fetchDashboardData(true)}
            disabled={refreshing}
            title="Rafraîchir"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          </Button>
          <Link href="/scans/new" passHref legacyBehavior>
            <Button asChild>
              <a>
                <Play className="mr-2 h-4 w-4" />
                Nouveau scan
              </a>
            </Button>
          </Link>
        </div>
      </div>

      {/* Security Score Widget — prominent */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SecurityScoreWidget data={scoreData} loading={loading} />
      </div>

      {/* Top Risky Assets */}
      <TopRiskyAssets assets={topAssets} loading={loading} />

      {/* Charts : trends + severity */}
      <div className="grid gap-4 md:grid-cols-2">
        <VulnerabilityTrendChart data={trendsData} loading={loading} />
        <SeverityDistributionChart data={severityData} loading={loading} />
      </div>

      {/* Top CVEs */}
      <TopVulnerabilitiesChart data={topVulnsData} loading={loading} />
    </div>
  );
};

export default Dashboard;
