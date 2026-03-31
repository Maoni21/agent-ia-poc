import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Shield, Bug, CheckCircle, Activity, TrendingUp,
  AlertTriangle, Code2, Play, Loader2, RefreshCw,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from '@/components/ui/table';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from 'recharts';
import scanService from '../lib/services/scanService';
import dashboardService from '../lib/services/dashboardService';

function StatCard({ title, value, icon: Icon, iconClassName, trend }) {
  return (
    <Card className="hover:shadow-lg transition-shadow">
      <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className={`h-5 w-5 ${iconClassName || 'text-muted-foreground'}`} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value ?? '—'}</div>
        {trend && (
          <p className="text-xs text-muted-foreground flex items-center mt-1">
            <TrendingUp className="h-3 w-3 text-green-500 mr-1" />
            {trend}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function StatCardSkeleton() {
  return (
    <Card>
      <CardHeader className="pb-2">
        <Skeleton className="h-4 w-24" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="h-3 w-32 mt-2" />
      </CardContent>
    </Card>
  );
}

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [severityDistribution, setSeverityDistribution] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [topVulnerabilities, setTopVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const fetchDashboardData = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const [overview, severity, timeline, top, scansData] = await Promise.all([
        dashboardService.getOverview(),
        dashboardService.getSeverityDistribution(),
        dashboardService.getTimeline(),
        dashboardService.getTopVulnerabilities(10),
        scanService.getScans(100),
      ]);

      const scans = scansData.scans || [];
      const activeScans = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
      const completedScans = scans.filter(s => s.status === 'completed').length;

      setStats({
        totalScans: overview.total_scans || 0,
        recentScans: overview.recent_scans || 0,
        activeScans,
        completedScans,
        totalVulnerabilities: overview.total_vulnerabilities || 0,
        criticalVulnerabilities: overview.critical_vulnerabilities || 0,
        totalScripts: overview.total_scripts || 0,
        averageCvss: overview.average_cvss || 0,
      });

      setSeverityDistribution(severity);
      setTimelineData(timeline);
      setTopVulnerabilities(top?.vulnerabilities || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement du tableau de bord');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => fetchDashboardData(true), 15000);
    return () => clearInterval(interval);
  }, []);

  const severityChartData = severityDistribution?.labels?.map((label, i) => ({
    name: label,
    value: severityDistribution.values[i],
    color: severityDistribution.colors[i],
  })) || [];

  const timelineChartData = timelineData?.labels?.map((label, i) => ({
    date: label,
    count: timelineData.datasets[0]?.data[i] || 0,
  })) || [];

  if (error && !stats) {
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

      {/* Stats Grid */}
      {loading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => <StatCardSkeleton key={i} />)}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard title="Scans totaux" value={stats?.totalScans} icon={Shield} iconClassName="text-blue-500" />
          <StatCard title="Scans récents (30j)" value={stats?.recentScans} icon={Activity} iconClassName="text-cyan-500" />
          <StatCard
            title="Scans actifs"
            value={stats?.activeScans}
            icon={stats?.activeScans > 0 ? Loader2 : Activity}
            iconClassName={stats?.activeScans > 0 ? 'text-blue-500 animate-spin' : 'text-muted-foreground'}
          />
          <StatCard title="Scans terminés" value={stats?.completedScans} icon={CheckCircle} iconClassName="text-green-500" />
          <StatCard title="Vulnérabilités" value={stats?.totalVulnerabilities} icon={Bug} iconClassName="text-red-500" />
          <StatCard title="Critiques" value={stats?.criticalVulnerabilities} icon={AlertTriangle} iconClassName="text-red-600" />
          <StatCard title="Scripts générés" value={stats?.totalScripts} icon={Code2} iconClassName="text-purple-500" />
          <StatCard
            title="CVSS moyen"
            value={stats?.averageCvss?.toFixed ? stats.averageCvss.toFixed(1) : stats?.averageCvss}
            icon={Shield}
            iconClassName="text-amber-500"
          />
        </div>
      )}

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Distribution par sévérité</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-56 w-full" />
            ) : severityChartData.length === 0 ? (
              <div className="flex items-center justify-center h-56 text-sm text-muted-foreground">
                Aucune donnée disponible
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={severityChartData} dataKey="value" nameKey="name" outerRadius={80} label>
                    {severityChartData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', border: '1px solid hsl(var(--border))' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Détections (30 derniers jours)</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-56 w-full" />
            ) : timelineChartData.length === 0 ? (
              <div className="flex items-center justify-center h-56 text-sm text-muted-foreground">
                Aucune donnée disponible
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={timelineChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', border: '1px solid hsl(var(--border))' }} />
                  <Line type="monotone" dataKey="count" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Vulnerabilities */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top 10 vulnérabilités critiques</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 space-y-2">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
            </div>
          ) : topVulnerabilities.length === 0 ? (
            <div className="p-6 flex flex-col items-center gap-2 text-muted-foreground">
              <CheckCircle className="h-10 w-10 text-green-500" />
              <p className="text-sm">Aucune vulnérabilité critique trouvée.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Nom</TableHead>
                  <TableHead>Sévérité</TableHead>
                  <TableHead>CVSS</TableHead>
                  <TableHead>Service</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topVulnerabilities.map((vuln) => (
                  <TableRow key={vuln.vulnerability_id}>
                    <TableCell className="font-mono text-xs">
                      <Badge variant="outline">{vuln.vulnerability_id}</Badge>
                    </TableCell>
                    <TableCell className="font-medium max-w-[200px] truncate">{vuln.name}</TableCell>
                    <TableCell><SeverityBadge severity={vuln.severity} /></TableCell>
                    <TableCell className="font-mono text-sm">{vuln.cvss_score ?? '—'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{vuln.affected_service || '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard;
