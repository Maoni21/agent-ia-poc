import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft, Shield, AlertTriangle,
  Network, Bug, Sparkles, Wrench, Users, Brain, Loader2, CheckCircle,
  Server, Globe, Lock, Terminal, Clock, Cpu,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Legend, Tooltip, ResponsiveContainer,
} from 'recharts';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import { StatusBadge } from '@/components/ui/status-badge';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import scansService from '../../lib/services/scansService';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import groupsService from '../../lib/services/groupsService';
import remediationService from '../../lib/services/remediationService';

const WS_BASE =
  typeof window !== 'undefined'
    ? (process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000')
    : '';

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

const formatDuration = (seconds) => {
  if (!seconds) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
};

// ── Icône de service ──────────────────────────────────────────────────────────
function ServiceIcon({ service }) {
  const s = (service || '').toLowerCase();
  if (s.includes('http') || s.includes('web')) return <Globe className="h-3.5 w-3.5 text-blue-500" />;
  if (s.includes('ssh') || s.includes('sftp')) return <Terminal className="h-3.5 w-3.5 text-green-500" />;
  if (s.includes('ssl') || s.includes('tls') || s.includes('https')) return <Lock className="h-3.5 w-3.5 text-emerald-500" />;
  if (s.includes('smb') || s.includes('microsoft-ds')) return <Cpu className="h-3.5 w-3.5 text-purple-500" />;
  return <Server className="h-3.5 w-3.5 text-muted-foreground" />;
}

// ── Badge état du port ────────────────────────────────────────────────────────
function PortStateBadge({ state }) {
  if (state === 'open') return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 text-xs font-mono">open</Badge>;
  if (state === 'filtered') return <Badge variant="outline" className="text-xs font-mono text-amber-600">filtered</Badge>;
  return <Badge variant="outline" className="text-xs font-mono text-muted-foreground">{state}</Badge>;
}

export default function ScanDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(null);
  const [selectedVulnIds, setSelectedVulnIds] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);

  // Analyse IA batch
  const [analyzeDialogOpen, setAnalyzeDialogOpen] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await scansService.getScan(id);
        setScan(data);
        setSelectedVulnIds([]);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement du scan');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  useEffect(() => {
    if (!id) return;
    let ws;
    try {
      ws = new WebSocket(`${WS_BASE}/ws/scans/${id}`);
    } catch (e) { return; }

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const data = payload.data || payload;
        setProgress({
          progress: data.progress ?? 0,
          status: data.status || '',
          currentStep: data.current_step || '',
          message: data.message || '',
        });
        if (['completed', 'failed', 'cancelled'].includes((data.status || '').toLowerCase())) {
          scansService.getScan(id).then(setScan).catch(() => {});
        }
      } catch {}
    };
    return () => { if (ws) ws.close(1000, 'Page fermée'); };
  }, [id]);

  const severityChartData = useMemo(() => {
    if (!scan) return [];
    return [
      { label: 'CRITICAL', value: scan.critical_count || 0, color: '#DC2626' },
      { label: 'HIGH', value: scan.high_count || 0, color: '#F97316' },
      { label: 'MEDIUM', value: scan.medium_count || 0, color: '#FACC15' },
      { label: 'LOW', value: scan.low_count || 0, color: '#22C55E' },
      { label: 'INFO', value: scan.info_count || 0, color: '#9CA3AF' },
    ].filter((e) => e.value > 0);
  }, [scan]);

  // Services triés par port
  const services = useMemo(() => {
    if (!scan?.services) return [];
    return [...scan.services].sort((a, b) => (a.port || 0) - (b.port || 0));
  }, [scan]);

  const toggleVulnSelection = (vulnId, checked) => {
    setSelectedVulnIds((prev) =>
      checked ? [...prev.filter((x) => x !== vulnId), vulnId] : prev.filter((x) => x !== vulnId)
    );
  };

  const handleAnalyzeSelected = async () => {
    if (!selectedVulnIds.length) return;
    setActionLoading(true);
    try {
      await Promise.all(selectedVulnIds.map((vid) => vulnerabilitiesService.analyzeVulnerability(vid)));
      const refreshed = await scansService.getScan(id);
      setScan(refreshed);
      alert(`Analyse IA terminée pour ${selectedVulnIds.length} vulnérabilité(s).`);
    } catch (err) {
      alert("Erreur lors de l'analyse IA: " + (err.message || 'inconnue'));
    } finally {
      setActionLoading(false);
    }
  };

  const handleCorrectSelected = async () => {
    if (!selectedVulnIds.length) return;
    setActionLoading(true);
    try {
      const results = await Promise.all(
        selectedVulnIds.map((vid) =>
          vulnerabilitiesService.generateScript(vid, { target_system: 'ubuntu-22.04', script_type: 'bash' })
        )
      );
      alert(`Scripts générés pour ${results.length} vulnérabilité(s).`);
    } catch (err) {
      alert('Erreur génération scripts: ' + (err.message || 'inconnue'));
    } finally {
      setActionLoading(false);
    }
  };

  const handleAnalyzeBatch = async () => {
    if (!id) return;
    setAnalyzing(true);
    setAnalyzeError(null);
    try {
      const result = await remediationService.startBatchAnalysis(id);
      setAnalyzeDialogOpen(false);
      router.push(`/remediation/plan/${id}?analysis_id=${result.analysis_id}`);
    } catch (err) {
      setAnalyzeError(err?.message || "Erreur lors du lancement de l'analyse");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleCreateGroup = async () => {
    if (!selectedVulnIds.length) return;
    const name = window.prompt('Nom du groupe :', `Scan ${id} - ${selectedVulnIds.length} vulnérabilités`);
    if (!name) return;
    const description = window.prompt('Description (optionnel) :', '') || '';
    setActionLoading(true);
    try {
      await groupsService.createGroup({ name, description, vulnerabilityIds: selectedVulnIds });
      alert('Groupe créé avec succès.');
    } catch (err) {
      alert('Erreur: ' + (err.message || 'inconnue'));
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <Head>
        <title>Détails du scan - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* ── Header ── */}
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.push('/scans')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex-1">
            <h1 className="text-2xl font-bold">
              Scan{id ? ` #${id.slice(0, 8)}` : ''}
            </h1>
            {scan && (
              <p className="text-sm text-muted-foreground">
                Type : {scan.scan_type}
                {(scan.asset_hostname || scan.asset_ip) && (
                  <> · Asset : <span className="font-medium">{scan.asset_hostname || scan.asset_ip}</span></>
                )}
                {scan.duration_seconds && (
                  <> · Durée : <span className="font-medium">{formatDuration(scan.duration_seconds)}</span></>
                )}
                {' '}· Commencé le {formatDate(scan.started_at || scan.created_at)}
              </p>
            )}
          </div>
          {scan && <StatusBadge status={scan.status} />}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : !scan ? (
          <Alert><AlertDescription>Scan introuvable.</AlertDescription></Alert>
        ) : (
          <>
            {/* Alerte scan échoué */}
            {scan.status === 'failed' && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <span className="font-semibold">Scan échoué.</span>{' '}
                  Causes possibles : hôte inaccessible, timeout réseau, ou nmap non disponible.
                  Vérifiez que l&apos;adresse IP <code className="font-mono text-xs">{scan.asset_ip || ''}</code> est joignable depuis ce serveur,
                  puis relancez le scan.
                </AlertDescription>
              </Alert>
            )}

            {/* Barre de progression WebSocket */}
            {progress && scan.status === 'running' && (
              <Card>
                <CardContent className="pt-6 space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground font-medium">
                      {progress.currentStep || 'Progression du scan'}
                    </span>
                    <span className="font-bold">{progress.progress ?? 0}%</span>
                  </div>
                  <Progress value={progress.progress ?? 0} className="h-2" />
                  <p className="text-sm text-muted-foreground">
                    {progress.message || 'Traitement en cours...'}
                  </p>
                </CardContent>
              </Card>
            )}

            {/* ── Stats strip ── */}
            <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
              {[
                { label: 'Vulnérabilités', value: scan.vulnerabilities_found ?? 0, icon: Bug, cls: 'text-red-500' },
                { label: 'Critiques', value: scan.critical_count ?? 0, icon: AlertTriangle, cls: 'text-red-600' },
                { label: 'Ports ouverts', value: scan.ports_scanned ?? '—', icon: Network, cls: 'text-blue-500' },
                { label: 'Services', value: scan.services_found ?? '—', icon: Shield, cls: 'text-purple-500' },
              ].map((s) => {
                const Icon = s.icon;
                return (
                  <Card key={s.label}>
                    <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                      <CardTitle className="text-sm font-medium text-muted-foreground">{s.label}</CardTitle>
                      <Icon className={`h-4 w-4 ${s.cls}`} />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{s.value}</div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* ── CTA Analyse IA ── */}
            {scan.status === 'completed' && (scan.vulnerabilities_found ?? 0) > 0 && (
              <Card className="border-2 border-primary/30 bg-primary/5">
                <CardContent className="pt-6">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2 rounded-lg bg-primary/10">
                        <Brain className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-semibold">Analyse IA & Remédiation automatique</h3>
                        <p className="text-sm text-muted-foreground mt-0.5">
                          Notre IA va analyser les {scan.vulnerabilities_found} vulnérabilités et générer un plan
                          de remédiation exécutable automatiquement via SSH.
                        </p>
                      </div>
                    </div>
                    <Button
                      size="lg"
                      className="shrink-0"
                      onClick={() => setAnalyzeDialogOpen(true)}
                    >
                      <Sparkles className="mr-2 h-4 w-4" />
                      Analyser avec l&apos;IA
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* ══════════════════════════════════════════════════════ TABS ══ */}
            <Tabs defaultValue="overview">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="overview">Vue d&apos;ensemble</TabsTrigger>
                <TabsTrigger value="services">
                  Services &amp; Ports
                  {services.length > 0 && (
                    <Badge variant="secondary" className="ml-2 text-xs">{services.length}</Badge>
                  )}
                </TabsTrigger>
                <TabsTrigger value="vulns">
                  Vulnérabilités
                  {(scan.vulnerabilities?.length ?? 0) > 0 && (
                    <Badge variant="destructive" className="ml-2 text-xs">{scan.vulnerabilities.length}</Badge>
                  )}
                </TabsTrigger>
              </TabsList>

              {/* ─── Onglet Vue d'ensemble ─── */}
              <TabsContent value="overview" className="space-y-4 mt-4">
                <div className="grid gap-4 md:grid-cols-2">
                  {/* Chart sévérité */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Distribution par sévérité</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {severityChartData.length === 0 ? (
                        <p className="text-sm text-muted-foreground py-8 text-center">Aucune vulnérabilité détectée</p>
                      ) : (
                        <ResponsiveContainer width="100%" height={220}>
                          <PieChart>
                            <Pie data={severityChartData} dataKey="value" nameKey="label" outerRadius={80} label>
                              {severityChartData.map((e, i) => <Cell key={i} fill={e.color} />)}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', border: '1px solid hsl(var(--border))' }} />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      )}
                    </CardContent>
                  </Card>

                  {/* Informations générales */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Informations générales</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-sm">
                      {[
                        ['ID scan', <span key="id" className="font-mono text-xs truncate max-w-[180px]">{scan.id}</span>],
                        ['Asset', <span key="a" className="font-medium">{scan.asset_hostname || scan.asset_ip || '—'}</span>],
                        ['IP cible', <span key="ip" className="font-mono text-xs">{scan.asset_ip || '—'}</span>],
                        ['Type de scan', scan.scan_type],
                        ['Statut', <StatusBadge key="s" status={scan.status} />],
                        ['Début', formatDate(scan.started_at || scan.created_at)],
                        ['Fin', formatDate(scan.completed_at)],
                        ['Durée', formatDuration(scan.duration_seconds)],
                        ['Ports ouverts', scan.ports_scanned ?? 0],
                        ['Services détectés', scan.services_found ?? 0],
                        ['Vulnérabilités', scan.vulnerabilities_found ?? 0],
                      ].map(([label, val]) => (
                        <div key={label} className="flex justify-between items-center gap-2">
                          <span className="text-muted-foreground shrink-0">{label}</span>
                          <span className="font-medium text-right">{val}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </div>

                {/* Résumé sévérités */}
                {(scan.vulnerabilities_found ?? 0) > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Répartition des risques</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {[
                          { label: 'Critical', count: scan.critical_count ?? 0, color: 'bg-red-600', text: 'text-red-600' },
                          { label: 'High', count: scan.high_count ?? 0, color: 'bg-orange-500', text: 'text-orange-500' },
                          { label: 'Medium', count: scan.medium_count ?? 0, color: 'bg-amber-400', text: 'text-amber-600' },
                          { label: 'Low', count: scan.low_count ?? 0, color: 'bg-gray-400', text: 'text-gray-500' },
                          { label: 'Info', count: scan.info_count ?? 0, color: 'bg-blue-400', text: 'text-blue-500' },
                        ].filter(s => s.count > 0).map((s) => (
                          <div key={s.label} className="flex items-center gap-3">
                            <span className={`text-xs font-semibold w-14 ${s.text}`}>{s.label}</span>
                            <div className="flex-1 bg-muted rounded-full h-2 overflow-hidden">
                              <div
                                className={`h-2 rounded-full ${s.color}`}
                                style={{ width: `${Math.round((s.count / (scan.vulnerabilities_found || 1)) * 100)}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono w-6 text-right text-muted-foreground">{s.count}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* ─── Onglet Services & Ports ─── */}
              <TabsContent value="services" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Network className="h-4 w-4" />
                      Carte réseau — {services.length} service{services.length !== 1 ? 's' : ''} détecté{services.length !== 1 ? 's' : ''}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {services.length === 0 ? (
                      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
                        <Server className="h-10 w-10" />
                        <p className="font-medium">Aucun service découvert</p>
                        <p className="text-sm text-center max-w-xs">
                          Les données de services sont disponibles après un scan complété. Relancez un scan si nécessaire.
                        </p>
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b text-muted-foreground">
                              <th className="text-left py-2 pr-4 font-medium w-20">Port</th>
                              <th className="text-left py-2 pr-4 font-medium w-16">Proto</th>
                              <th className="text-left py-2 pr-4 font-medium w-24">État</th>
                              <th className="text-left py-2 pr-4 font-medium w-32">Service</th>
                              <th className="text-left py-2 pr-4 font-medium">Version / Bannière</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {services.map((svc, i) => {
                              const versionStr = [svc.banner, svc.version, svc.extra_info]
                                .filter(Boolean)
                                .join(' ')
                                .trim();
                              // Vulnérabilités détectées sur ce port
                              const portVulns = (scan.vulnerabilities || []).filter(v => v.port === svc.port);
                              return (
                                <tr key={i} className="hover:bg-accent/30 transition-colors">
                                  <td className="py-2.5 pr-4">
                                    <span className="font-mono font-semibold text-primary">
                                      {svc.port}
                                    </span>
                                  </td>
                                  <td className="py-2.5 pr-4">
                                    <span className="font-mono text-xs text-muted-foreground uppercase">
                                      {svc.protocol || 'tcp'}
                                    </span>
                                  </td>
                                  <td className="py-2.5 pr-4">
                                    <PortStateBadge state={svc.state} />
                                  </td>
                                  <td className="py-2.5 pr-4">
                                    <div className="flex items-center gap-1.5">
                                      <ServiceIcon service={svc.service_name} />
                                      <span className="font-medium">{svc.service_name || '—'}</span>
                                    </div>
                                  </td>
                                  <td className="py-2.5 pr-4">
                                    <div className="space-y-0.5">
                                      {versionStr ? (
                                        <span className="text-xs text-muted-foreground font-mono">{versionStr}</span>
                                      ) : (
                                        <span className="text-xs text-muted-foreground italic">—</span>
                                      )}
                                      {portVulns.length > 0 && (
                                        <div className="flex gap-1 flex-wrap mt-1">
                                          {portVulns.slice(0, 3).map((v) => (
                                            <button
                                              key={v.id}
                                              onClick={() => router.push(`/vulnerabilities/${v.id}`)}
                                              className="inline-flex items-center gap-1"
                                            >
                                              <SeverityBadge severity={v.severity} className="text-xs cursor-pointer hover:opacity-80" />
                                            </button>
                                          ))}
                                          {portVulns.length > 3 && (
                                            <span className="text-xs text-muted-foreground">+{portVulns.length - 3}</span>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {/* Ports ouverts résumé */}
                    {scan.open_ports?.length > 0 && (
                      <div className="mt-4 pt-4 border-t">
                        <p className="text-xs text-muted-foreground mb-2 font-medium">Ports ouverts</p>
                        <div className="flex flex-wrap gap-1.5">
                          {scan.open_ports.map((port) => (
                            <Badge key={port} variant="outline" className="font-mono text-xs">{port}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* ─── Onglet Vulnérabilités ─── */}
              <TabsContent value="vulns" className="mt-4">
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <CardTitle className="text-base">
                        Vulnérabilités ({scan.vulnerabilities?.length ?? 0})
                      </CardTitle>
                      {scan.vulnerabilities?.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          <Button variant="ghost" size="sm" onClick={() => setSelectedVulnIds(scan.vulnerabilities.map((v) => v.id))}>
                            Tout sélectionner
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => setSelectedVulnIds([])} disabled={!selectedVulnIds.length}>
                            Vider
                          </Button>
                          <Separator orientation="vertical" className="h-6" />
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={handleAnalyzeSelected}
                            disabled={actionLoading || !selectedVulnIds.length}
                          >
                            <Sparkles className="mr-2 h-4 w-4" />
                            Analyser IA ({selectedVulnIds.length})
                          </Button>
                          <Button
                            size="sm"
                            onClick={handleCorrectSelected}
                            disabled={actionLoading || !selectedVulnIds.length}
                          >
                            <Wrench className="mr-2 h-4 w-4" />
                            Scripts fix
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={handleCreateGroup}
                            disabled={actionLoading || !selectedVulnIds.length}
                          >
                            <Users className="mr-2 h-4 w-4" />
                            Créer groupe
                          </Button>
                        </div>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2 max-h-[600px] overflow-y-auto">
                    {!scan.vulnerabilities?.length ? (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        Aucune vulnérabilité associée à ce scan.
                      </p>
                    ) : (
                      scan.vulnerabilities.map((vuln) => (
                        <div
                          key={vuln.id}
                          className="flex items-start gap-3 p-3 rounded-lg border hover:bg-accent/50 transition-colors cursor-pointer"
                          onClick={() => router.push(`/vulnerabilities/${vuln.id}`)}
                        >
                          <Checkbox
                            checked={selectedVulnIds.includes(vuln.id)}
                            onCheckedChange={(checked) => toggleVulnSelection(vuln.id, checked)}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <div className="flex-1 space-y-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <SeverityBadge severity={vuln.severity} />
                              {vuln.cve_id && (
                                <Badge variant="outline" className="font-mono text-xs">{vuln.cve_id}</Badge>
                              )}
                              {vuln.exploit_available && (
                                <Badge className="bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300 text-xs">Exploit</Badge>
                              )}
                              {vuln.ai_priority_score != null && (
                                <Badge variant="secondary" className="text-xs">IA: {vuln.ai_priority_score}/10</Badge>
                              )}
                            </div>
                            <p className="font-semibold text-sm truncate">{vuln.title || vuln.cve_id}</p>
                            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                              {vuln.cvss_score != null && <span>CVSS: <span className="font-medium">{vuln.cvss_score}</span></span>}
                              {vuln.port && (
                                <span className="flex items-center gap-1">
                                  <span className="font-mono font-medium">{vuln.port}/{vuln.protocol || 'tcp'}</span>
                                  {vuln.service && <span className="text-muted-foreground">({vuln.service})</span>}
                                </span>
                              )}
                              {vuln.affected_version && (
                                <span>Version: <span className="font-mono font-medium">{vuln.affected_version}</span></span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>

      {/* ── Dialog: Confirmer l'analyse IA batch ── */}
      <Dialog open={analyzeDialogOpen} onOpenChange={setAnalyzeDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-primary" />
              Analyse IA — {scan?.vulnerabilities_found ?? 0} vulnérabilités
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2 text-sm text-muted-foreground">
            <p>Notre IA va analyser toutes les vulnérabilités et générer un plan de remédiation.</p>
            <div className="space-y-1.5">
              {[
                "Évaluation du contexte et de l'impact",
                'Priorisation des risques métier',
                'Dépendances & prérequis',
                'Génération des étapes de remédiation',
                'Procédures de rollback',
              ].map((item) => (
                <div key={item} className="flex items-center gap-2">
                  <CheckCircle className="h-3.5 w-3.5 text-primary shrink-0" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
            <p className="font-medium text-foreground">Durée estimée : ~2 minutes</p>
            {analyzeError && (
              <p className="text-red-600 bg-red-50 dark:bg-red-950/30 p-2 rounded text-xs">{analyzeError}</p>
            )}
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setAnalyzeDialogOpen(false)}>Annuler</Button>
            <Button onClick={handleAnalyzeBatch} disabled={analyzing}>
              {analyzing
                ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Lancement...</>
                : <><Sparkles className="mr-2 h-4 w-4" />Lancer l&apos;analyse</>
              }
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
