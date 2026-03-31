import Head from 'next/head';
import { useRouter } from 'next/router';
import { useState, useEffect } from 'react';
import {
  Search, Download, AlertTriangle, Bug, Sparkles, Wrench, Filter,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { SeverityBadge } from '@/components/ui/severity-badge';
import {
  Select, SelectContent, SelectItem,
  SelectTrigger, SelectValue,
} from '@/components/ui/select';
import vulnerabilitiesService from '../lib/services/vulnerabilitiesService';

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'bg-red-600', light: 'bg-red-50 dark:bg-red-950', border: 'border-red-200 dark:border-red-800' },
  HIGH: { bg: 'bg-orange-500', light: 'bg-orange-50 dark:bg-orange-950', border: 'border-orange-200 dark:border-orange-800' },
  MEDIUM: { bg: 'bg-amber-400', light: 'bg-amber-50 dark:bg-amber-950', border: 'border-amber-200 dark:border-amber-800' },
  LOW: { bg: 'bg-gray-400', light: 'bg-gray-50 dark:bg-gray-900', border: 'border-gray-200 dark:border-gray-700' },
  INFO: { bg: 'bg-blue-400', light: 'bg-blue-50 dark:bg-blue-950', border: 'border-blue-200 dark:border-blue-800' },
};

export default function VulnerabilitiesPage() {
  const router = useRouter();
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [filteredVulnerabilities, setFilteredVulnerabilities] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [falsePositiveFilter, setFalsePositiveFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadVulnerabilities = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await vulnerabilitiesService.getVulnerabilities({
        limit: 200,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
      });
      const vulns = data.vulnerabilities || [];
      setVulnerabilities(vulns);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des vulnérabilités');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadVulnerabilities(); }, [severityFilter]);

  useEffect(() => {
    let base = [...vulnerabilities];
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      base = base.filter(
        (v) =>
          v.name?.toLowerCase().includes(term) ||
          v.vulnerability_id?.toLowerCase().includes(term) ||
          v.description?.toLowerCase().includes(term),
      );
    }
    if (falsePositiveFilter === 'false_positive') base = base.filter((v) => v.is_false_positive);
    if (falsePositiveFilter === 'true_positive') base = base.filter((v) => v.is_false_positive === false);
    setFilteredVulnerabilities(base);
  }, [searchTerm, falsePositiveFilter, vulnerabilities]);

  // Severity counts for filter cards
  const severityCounts = vulnerabilities.reduce((acc, v) => {
    const sev = (v.severity || 'INFO').toUpperCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const handleAnalyzeAll = async () => {
    if (!filteredVulnerabilities.length) return;
    try {
      const ids = filteredVulnerabilities.map((v) => v.id || v.vulnerability_id).filter(Boolean);
      await Promise.all(ids.map((id) => vulnerabilitiesService.analyzeVulnerability(id)));
      alert(`Analyse IA terminée pour ${ids.length} vulnérabilité(s).`);
    } catch (err) {
      alert('Erreur: ' + (err.message || 'inconnue'));
    }
  };

  const handleCorrectAll = async () => {
    if (!filteredVulnerabilities.length) return;
    try {
      const ids = filteredVulnerabilities.map((v) => v.id || v.vulnerability_id).filter(Boolean);
      const results = await Promise.all(
        ids.map((id) => vulnerabilitiesService.generateScript(id, { target_system: 'ubuntu-22.04', script_type: 'bash' }))
      );
      alert(`Scripts générés pour ${results.length} vulnérabilité(s).`);
    } catch (err) {
      alert('Erreur: ' + (err.message || 'inconnue'));
    }
  };

  const handleExportCsv = async () => {
    try {
      await vulnerabilitiesService.exportCsv({ severity: severityFilter !== 'all' ? severityFilter : undefined });
    } catch (err) {
      alert('Erreur export: ' + (err.message || 'inconnue'));
    }
  };

  return (
    <>
      <Head>
        <title>Vulnérabilités - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Vulnérabilités</h1>
            <p className="text-muted-foreground">
              {loading ? '...' : `${filteredVulnerabilities.length} vulnérabilité(s) trouvée(s)`}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleExportCsv}>
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
            <Button variant="outline" onClick={handleAnalyzeAll} disabled={!filteredVulnerabilities.length}>
              <Sparkles className="mr-2 h-4 w-4" />
              Analyser IA
            </Button>
            <Button onClick={handleCorrectAll} disabled={!filteredVulnerabilities.length}>
              <Wrench className="mr-2 h-4 w-4" />
              Générer scripts
            </Button>
          </div>
        </div>

        {/* Severity quick-filter cards */}
        {!loading && (
          <div className="grid gap-3 grid-cols-2 md:grid-cols-4">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
              const colors = SEVERITY_COLORS[sev];
              const count = severityCounts[sev] || 0;
              const isActive = severityFilter === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(isActive ? 'all' : sev)}
                  className={`rounded-lg border p-4 text-left transition-all hover:shadow-md ${
                    isActive
                      ? `${colors.light} ${colors.border} ring-2 ring-offset-1`
                      : 'bg-card border-border hover:bg-accent'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <AlertTriangle className={`h-4 w-4 ${isActive ? '' : 'text-muted-foreground'}`} />
                    <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{sev}</span>
                  </div>
                  <p className="text-2xl font-bold">{count}</p>
                </button>
              );
            })}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Rechercher une vulnérabilité..."
              className="pl-9"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Sévérité" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Toutes</SelectItem>
              <SelectItem value="CRITICAL">Critique</SelectItem>
              <SelectItem value="HIGH">Élevée</SelectItem>
              <SelectItem value="MEDIUM">Moyenne</SelectItem>
              <SelectItem value="LOW">Faible</SelectItem>
            </SelectContent>
          </Select>
          <Select value={falsePositiveFilter} onValueChange={setFalsePositiveFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Faux positifs" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous</SelectItem>
              <SelectItem value="true_positive">Vrais positifs</SelectItem>
              <SelectItem value="false_positive">Faux positifs</SelectItem>
            </SelectContent>
          </Select>
          {(searchTerm || severityFilter !== 'all' || falsePositiveFilter !== 'all') && (
            <Button
              variant="ghost"
              onClick={() => { setSearchTerm(''); setSeverityFilter('all'); setFalsePositiveFilter('all'); }}
            >
              Réinitialiser
            </Button>
          )}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* List */}
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-24 w-full" />
            ))}
          </div>
        ) : filteredVulnerabilities.length === 0 ? (
          <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
            <Bug className="h-12 w-12" />
            <p className="font-medium text-lg">Aucune vulnérabilité trouvée</p>
            <p className="text-sm">Lancez un scan pour détecter des vulnérabilités</p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredVulnerabilities.map((vuln, index) => {
              const vulnId = vuln.id || vuln.vulnerability_id;
              const sev = (vuln.severity || 'INFO').toUpperCase();
              const colors = SEVERITY_COLORS[sev] || SEVERITY_COLORS.INFO;
              return (
                <Card
                  key={vulnId || index}
                  className={`cursor-pointer hover:shadow-md transition-shadow ${colors.border} border-l-4`}
                  style={{ borderLeftColor: sev === 'CRITICAL' ? '#DC2626' : sev === 'HIGH' ? '#F97316' : sev === 'MEDIUM' ? '#FACC15' : sev === 'LOW' ? '#9CA3AF' : '#60A5FA' }}
                  onClick={() => vulnId && router.push(`/vulnerabilities/${vulnId}`)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 space-y-1.5 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <SeverityBadge severity={vuln.severity} />
                          {vuln.vulnerability_id && (
                            <Badge variant="outline" className="font-mono text-xs">
                              {vuln.vulnerability_id}
                            </Badge>
                          )}
                          {vuln.ai_analyzed && (
                            <Badge variant="secondary" className="text-xs">
                              <Sparkles className="mr-1 h-3 w-3" />
                              Analysée IA
                            </Badge>
                          )}
                          {vuln.is_false_positive && (
                            <Badge variant="outline" className="text-xs text-muted-foreground">
                              Faux positif
                            </Badge>
                          )}
                        </div>
                        <h3 className="font-semibold text-sm truncate">
                          {vuln.name || vuln.title || vuln.vulnerability_id}
                        </h3>
                        {vuln.description && (
                          <p className="text-xs text-muted-foreground line-clamp-2">
                            {vuln.description}
                          </p>
                        )}
                        <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                          {vuln.cvss_score != null && (
                            <span>CVSS: <span className="font-medium">{vuln.cvss_score}</span></span>
                          )}
                          {vuln.affected_service && (
                            <span>Service: <span className="font-medium">{vuln.affected_service}</span></span>
                          )}
                          {vuln.port && (
                            <span>Port: <span className="font-mono font-medium">{vuln.port}</span></span>
                          )}
                        </div>
                      </div>
                      <div className="flex gap-2 shrink-0">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (vulnId) vulnerabilitiesService.analyzeVulnerability(vulnId).catch(() => {});
                          }}
                        >
                          <Sparkles className="mr-1 h-3 w-3" />
                          Analyser
                        </Button>
                        <Button
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (vulnId) router.push(`/vulnerabilities/${vulnId}`);
                          }}
                        >
                          <Wrench className="mr-1 h-3 w-3" />
                          Fix
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
