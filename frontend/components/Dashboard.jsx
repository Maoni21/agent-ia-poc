import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CircularProgress,
  Alert,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
} from '@mui/material';
import {
  Security,
  BugReport,
  CheckCircle,
  Error as ErrorIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import scanService from '../lib/services/scanService';
import dashboardService from '../lib/services/dashboardService';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    recentScans: 0,
    activeScans: 0,
    completedScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    totalScripts: 0,
    averageCvss: 0,
  });
  const [severityDistribution, setSeverityDistribution] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [topVulnerabilities, setTopVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true);
      setError(null);

      try {
        // On récupère les stats agrégées depuis l’API du dashboard
        const [
          overview,
          severity,
          timeline,
          top,
          scansData,
        ] = await Promise.all([
          dashboardService.getOverview(),
          dashboardService.getSeverityDistribution(),
          dashboardService.getTimeline(),
          dashboardService.getTopVulnerabilities(10),
          scanService.getScans(100),
        ]);

        const scans = scansData.scans || [];

        const activeScans = scans.filter(
          (s) => s.status === 'running' || s.status === 'pending',
        ).length;
        const completedScans = scans.filter(
          (s) => s.status === 'completed',
        ).length;

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
        console.error('Erreur chargement dashboard:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();

    // Rafraîchissement périodique comme dans le dashboard HTML
    const interval = setInterval(fetchDashboardData, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" p={3}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  const statCards = [
    {
      title: 'Scans totaux',
      value: stats.totalScans,
      icon: <Security />,
      color: '#1976d2',
    },
    {
      title: 'Scans récents (30 jours)',
      value: stats.recentScans,
      icon: <TimelineIcon />,
      color: '#0288d1',
    },
    {
      title: 'Scans actifs',
      value: stats.activeScans,
      icon: <CircularProgress size={24} />,
      color: '#0288d1',
    },
    {
      title: 'Scans terminés',
      value: stats.completedScans,
      icon: <CheckCircle />,
      color: '#2e7d32',
    },
    {
      title: 'Vulnérabilités détectées',
      value: stats.totalVulnerabilities,
      icon: <BugReport />,
      color: '#d32f2f',
    },
    {
      title: 'Vulnérabilités critiques',
      value: stats.criticalVulnerabilities,
      icon: <ErrorIcon />,
      color: '#c62828',
    },
    {
      title: 'Scripts générés',
      value: stats.totalScripts,
      icon: <BugReport />,
      color: '#7b1fa2',
    },
    {
      title: 'CVSS moyen',
      value: stats.averageCvss.toFixed ? stats.averageCvss.toFixed(1) : stats.averageCvss,
      icon: <Security />,
      color: '#f9a825',
    },
  ];

  const severityChartData =
    severityDistribution?.labels?.map((label, index) => ({
      name: label,
      value: severityDistribution.values[index],
      color: severityDistribution.colors[index],
    })) || [];

  const timelineChartData =
    timelineData?.labels?.map((label, index) => ({
      date: label,
      count: timelineData.datasets[0]?.data[index] || 0,
    })) || [];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Tableau de bord
      </Typography>

      <Grid container spacing={3} sx={{ mt: 1, mb: 3 }}>
        {statCards.map((stat, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="body2">
                      {stat.title}
                    </Typography>
                    <Typography variant="h5" component="div">
                      {stat.value}
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      color: stat.color,
                      display: 'flex',
                      alignItems: 'center',
                    }}
                  >
                    {stat.icon}
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 320 }}>
            <Typography variant="h6" gutterBottom>
              Distribution par sévérité
            </Typography>
            {severityChartData.length === 0 ? (
              <Box display="flex" justifyContent="center" alignItems="center" height={240}>
                <Typography variant="body2" color="text.secondary">
                  Aucune donnée disponible
                </Typography>
              </Box>
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={90}
                    label
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={index} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: 320 }}>
            <Typography variant="h6" gutterBottom>
              Détections (30 derniers jours)
            </Typography>
            {timelineChartData.length === 0 ? (
              <Box display="flex" justifyContent="center" alignItems="center" height={240}>
                <Typography variant="body2" color="text.secondary">
                  Aucune donnée disponible
                </Typography>
              </Box>
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <LineChart data={timelineChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Line type="monotone" dataKey="count" stroke="#3B82F6" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </Paper>
        </Grid>
      </Grid>

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Top 10 vulnérabilités critiques
        </Typography>
        {topVulnerabilities.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            Aucune vulnérabilité critique trouvée.
          </Typography>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>CVE</TableCell>
                <TableCell>Nom</TableCell>
                <TableCell>Gravité</TableCell>
                <TableCell>CVSS</TableCell>
                <TableCell>Service</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {topVulnerabilities.map((vuln) => (
                <TableRow key={vuln.vulnerability_id}>
                  <TableCell>{vuln.vulnerability_id}</TableCell>
                  <TableCell>{vuln.name}</TableCell>
                  <TableCell>{vuln.severity}</TableCell>
                  <TableCell>{vuln.cvss_score ?? '-'}</TableCell>
                  <TableCell>{vuln.affected_service || '-'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Paper>
    </Box>
  );
};

export default Dashboard;
