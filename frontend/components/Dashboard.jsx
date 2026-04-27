import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Play, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';

import { SecurityScoreWidget }      from './dashboard/SecurityScoreWidget';
import { TopRiskyAssets }           from './dashboard/TopRiskyAssets';
import { VulnerabilityTrendChart }  from './dashboard/VulnerabilityTrendChart';
import { SeverityDistributionChart }from './dashboard/SeverityDistributionChart';
import { TopVulnerabilitiesChart }  from './dashboard/TopVulnerabilitiesChart';
import { RemediationProjects }      from './dashboard/RemediationProjects';
import { ComplianceStatus }         from './dashboard/ComplianceStatus';
import { MTTRWidget }               from './dashboard/MTTRWidget';

import dashboardService from '../lib/services/dashboardService';

const Dashboard = () => {
  const [scoreData,      setScoreData]      = useState(null);
  const [topAssets,      setTopAssets]      = useState([]);
  const [trendsData,     setTrendsData]     = useState([]);
  const [severityData,   setSeverityData]   = useState([]);
  const [topVulnsData,   setTopVulnsData]   = useState([]);
  const [complianceData, setComplianceData] = useState([]);
  const [mttrData,       setMttrData]       = useState(null);
  const [projects,       setProjects]       = useState([]);

  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error,      setError]      = useState(null);

  const fetchDashboardData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const [
        score, assets, trends, severity, topVulns,
        compliance, mttr, projectsList,
      ] = await Promise.all([
        dashboardService.getSecurityScore(),
        dashboardService.getTopRiskyAssets(10),
        dashboardService.getVulnerabilityTrends(30),
        dashboardService.getSeverityDistribution(),
        dashboardService.getTopVulnerabilitiesByAssets(10),
        dashboardService.getComplianceStatus(),
        dashboardService.getMTTR(),
        dashboardService.getRemediationProjects(),
      ]);

      setScoreData(score);
      setTopAssets(assets);
      setTrendsData(trends);
      setSeverityData(severity);
      setTopVulnsData(topVulns);
      setComplianceData(compliance);
      setMttrData(mttr);
      setProjects(projectsList);

    } catch (err) {
      setError(err.message || 'Erreur lors du chargement du tableau de bord');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => fetchDashboardData(true), 30000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  const handleRefresh = () => fetchDashboardData(true);

  const handleProjectCreated = async () => {
    const name = window.prompt('Nom du projet de remédiation :');
    if (!name) return;
    try {
      await dashboardService.createRemediationProject({ name, priority: 'medium' });
      const updated = await dashboardService.getRemediationProjects();
      setProjects(updated);
    } catch (e) {
      console.error('Erreur création projet:', e);
    }
  };

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
            onClick={handleRefresh}
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

      {/* ── Ligne 1 : Security Score (prominent) ── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SecurityScoreWidget data={scoreData} loading={loading} />
      </div>

      {/* ── Ligne 2 : Top Risky Assets ── */}
      <TopRiskyAssets assets={topAssets} loading={loading} />

      {/* ── Ligne 3 : Trends + Severity ── */}
      <div className="grid gap-4 md:grid-cols-2">
        <VulnerabilityTrendChart data={trendsData} loading={loading} />
        <SeverityDistributionChart data={severityData} loading={loading} />
      </div>

      {/* ── Ligne 4 : Top CVEs ── */}
      <TopVulnerabilitiesChart data={topVulnsData} loading={loading} />

      {/* ── Ligne 5 : Compliance + MTTR ── */}
      <div className="grid gap-4 md:grid-cols-2">
        <ComplianceStatus data={complianceData} loading={loading} />
        <MTTRWidget data={mttrData} loading={loading} />
      </div>

      {/* ── Ligne 6 : Remediation Projects ── */}
      <RemediationProjects
        projects={projects}
        loading={loading}
        onCreateProject={handleProjectCreated}
      />
    </div>
  );
};

export default Dashboard;
