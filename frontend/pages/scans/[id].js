import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft, RefreshCw, Shield, AlertTriangle,
  Network, Bug, Sparkles, Wrench, Users,
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
import scansService from '../../lib/services/scansService';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import groupsService from '../../lib/services/groupsService';

const WS_BASE =
  typeof window !== 'undefined'
    ? (process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000')
    : '';

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

export default function ScanDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(null);
  const [selectedVulnIds, setSelectedVulnIds] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);

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
        {/* Header */}
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
                Type : {scan.scan_type} · Commencé le {formatDate(scan.started_at || scan.created_at)}
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
            {/* Progress bar (WebSocket) */}
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

            {/* Stats */}
            <div className="grid gap-4 md:grid-cols-4">
              {[
                { label: 'Vulnérabilités', value: scan.vulnerabilities_found ?? 0, icon: Bug, cls: 'text-red-500' },
                { label: 'Critiques', value: scan.critical_count ?? 0, icon: AlertTriangle, cls: 'text-red-600' },
                { label: 'Ports scannés', value: scan.ports_scanned ?? '—', icon: Network, cls: 'text-blue-500' },
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

            {/* Charts + Info */}
            <div className="grid gap-4 md:grid-cols-2">
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

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Informations générales</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  {[
                    ['ID', <span key="id" className="font-mono text-xs">{scan.id}</span>],
                    ['Type', scan.scan_type],
                    ['Statut', <StatusBadge key="s" status={scan.status} />],
                    ['Début', formatDate(scan.started_at || scan.created_at)],
                    ['Fin', formatDate(scan.completed_at)],
                    ['Vulnérabilités', scan.vulnerabilities_found ?? 0],
                  ].map(([label, val]) => (
                    <div key={label} className="flex justify-between items-center">
                      <span className="text-muted-foreground">{label}</span>
                      <span className="font-medium">{val}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            {/* Vulnerabilities list */}
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
              <CardContent className="space-y-3 max-h-[500px] overflow-y-auto">
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
                          {vuln.ai_priority_score != null && (
                            <Badge variant="secondary" className="text-xs">
                              IA: {vuln.ai_priority_score}/10
                            </Badge>
                          )}
                        </div>
                        <p className="font-semibold text-sm truncate">
                          {vuln.title || vuln.cve_id}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          CVSS: {vuln.cvss_score ?? '—'}
                          {vuln.port && ` · Port: ${vuln.port}`}
                          {vuln.ai_analyzed && !vuln.ai_priority_score && ' · Analysée par IA'}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </>
  );
}
