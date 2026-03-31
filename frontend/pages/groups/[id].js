import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState, useMemo } from 'react';
import {
  Users, Sparkles, FileCode, Loader2, AlertCircle,
  ChevronLeft, CheckSquare, Square
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
import { SeverityBadge } from '@/components/ui/severity-badge';
import groupsService from '../../lib/services/groupsService';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

const severityBorderClass = {
  CRITICAL: 'border-l-red-600',
  HIGH: 'border-l-orange-500',
  MEDIUM: 'border-l-amber-400',
  LOW: 'border-l-green-500',
  INFO: 'border-l-gray-400',
};

export default function GroupDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [group, setGroup] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedVulnIds, setSelectedVulnIds] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  const loadGroup = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await groupsService.getGroup(id);
      setGroup(data);
      setSelectedVulnIds([]);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement du groupe');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadGroup(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  const severitySummary = useMemo(() => {
    if (!group?.vulnerabilities) return null;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    group.vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'INFO').toUpperCase();
      if (counts[sev] != null) counts[sev] += 1;
      else counts.INFO += 1;
    });
    return counts;
  }, [group]);

  const toggleVulnSelection = (vulnId, checked) => {
    setSelectedVulnIds((prev) =>
      checked ? (prev.includes(vulnId) ? prev : [...prev, vulnId]) : prev.filter((x) => x !== vulnId)
    );
  };

  const handleSelectAll = () => {
    if (!group?.vulnerabilities) return;
    setSelectedVulnIds(group.vulnerabilities.map((v) => v.id));
  };

  const handleClearSelection = () => setSelectedVulnIds([]);

  const handleAnalyzeGroup = async () => {
    if (!id) return;
    setActionLoading(true);
    try {
      const result = await groupsService.analyzeGroup(id);
      setAnalysisResult(result);
      await loadGroup();
    } catch (err) {
      alert(err.message || "Erreur lors de l'analyse du groupe");
    } finally {
      setActionLoading(false);
    }
  };

  const handleAnalyzeSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.analyzeVulnerability(vulnId)
      );
      const results = await Promise.all(promises);
      const analyzedItems = results.map((r) => r.analysis || r).filter(Boolean);
      setAnalysisResult({
        vulnerability_count: analyzedItems.length,
        analysis_summary: null,
        remediation_plan: null,
        vulnerabilities: analyzedItems,
      });
      await loadGroup();
      alert(`Analyse IA terminée pour ${selectedVulnIds.length} vulnérabilité(s) du groupe.`);
    } catch (err) {
      alert("Erreur lors de l'analyse IA: " + (err.message || 'inconnue'));
    } finally {
      setActionLoading(false);
    }
  };

  const handleCorrectSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.generateScript(vulnId, {
          target_system: 'ubuntu-22.04',
          script_type: 'bash',
        })
      );
      const results = await Promise.all(promises);
      alert(`Scripts de remédiation générés pour ${results.length} vulnérabilité(s) du groupe.`);
    } catch (err) {
      alert('Erreur lors de la génération de scripts: ' + (err.message || 'inconnue'));
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <Head>
        <title>Groupe - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Back button */}
        <Button variant="ghost" size="sm" onClick={() => router.push('/groups')}>
          <ChevronLeft className="mr-1 h-4 w-4" />
          Retour aux groupes
        </Button>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-10 w-64" />
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-96 w-full" />
          </div>
        ) : !group ? (
          <Alert>
            <AlertDescription>Groupe introuvable.</AlertDescription>
          </Alert>
        ) : (
          <>
            {/* Group Header */}
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Users className="h-6 w-6 text-muted-foreground" />
                  <h1 className="text-3xl font-bold tracking-tight">{group.name}</h1>
                </div>
                {group.description && (
                  <p className="text-muted-foreground">{group.description}</p>
                )}
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <span>{group.vulnerability_count ?? 0} vulnérabilité(s)</span>
                  <span>•</span>
                  <span>Créé le {formatDate(group.created_at)}</span>
                </div>
                {severitySummary && (
                  <div className="flex items-center gap-2 mt-2">
                    {severitySummary.CRITICAL > 0 && <SeverityBadge severity="CRITICAL">{severitySummary.CRITICAL} CRIT</SeverityBadge>}
                    {severitySummary.HIGH > 0 && <SeverityBadge severity="HIGH">{severitySummary.HIGH} HIGH</SeverityBadge>}
                    {severitySummary.MEDIUM > 0 && <SeverityBadge severity="MEDIUM">{severitySummary.MEDIUM} MED</SeverityBadge>}
                    {severitySummary.LOW > 0 && <SeverityBadge severity="LOW">{severitySummary.LOW} LOW</SeverityBadge>}
                  </div>
                )}
              </div>
              <Button onClick={handleAnalyzeGroup} disabled={actionLoading}>
                {actionLoading ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Analyse...</>
                ) : (
                  <><Sparkles className="mr-2 h-4 w-4" />Analyser le groupe (IA)</>
                )}
              </Button>
            </div>

            {/* Vulnerabilities Card */}
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <CardTitle>Vulnérabilités du groupe</CardTitle>
                  {group.vulnerabilities && group.vulnerabilities.length > 0 && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm text-muted-foreground">
                        {selectedVulnIds.length} / {group.vulnerabilities.length} sélectionnée(s)
                      </span>
                      <Button size="sm" variant="ghost" onClick={handleSelectAll} disabled={actionLoading}>
                        <CheckSquare className="mr-1 h-3.5 w-3.5" />
                        Tout
                      </Button>
                      <Button size="sm" variant="ghost" onClick={handleClearSelection} disabled={actionLoading || selectedVulnIds.length === 0}>
                        <Square className="mr-1 h-3.5 w-3.5" />
                        Vider
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleAnalyzeSelected}
                        disabled={actionLoading || selectedVulnIds.length === 0}
                      >
                        <Sparkles className="mr-1 h-3.5 w-3.5" />
                        Analyser IA
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleCorrectSelected}
                        disabled={actionLoading || selectedVulnIds.length === 0}
                        className="text-green-600 hover:text-green-700"
                      >
                        <FileCode className="mr-1 h-3.5 w-3.5" />
                        Scripts
                      </Button>
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent>
                {!group.vulnerabilities || group.vulnerabilities.length === 0 ? (
                  <p className="text-muted-foreground text-sm py-4 text-center">
                    Aucune vulnérabilité dans ce groupe.
                  </p>
                ) : (
                  <div className="space-y-2 max-h-[420px] overflow-y-auto pr-1">
                    {group.vulnerabilities.map((vuln) => {
                      const sev = (vuln.severity || 'INFO').toUpperCase();
                      const borderClass = severityBorderClass[sev] || 'border-l-gray-400';
                      return (
                        <div key={vuln.id} className="flex items-start gap-3">
                          <Checkbox
                            checked={selectedVulnIds.includes(vuln.id)}
                            onCheckedChange={(checked) => toggleVulnSelection(vuln.id, checked)}
                            className="mt-2"
                          />
                          <div className={`flex-1 rounded-md border-l-4 bg-muted/40 px-3 py-2 ${borderClass}`}>
                            <div className="flex items-center justify-between gap-2">
                              <p className="font-medium text-sm">{vuln.title || vuln.cve_id}</p>
                              {vuln.ai_priority_score != null && (
                                <Badge variant="secondary" className="text-xs whitespace-nowrap">
                                  IA: {vuln.ai_priority_score}/10
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mt-0.5">
                              {vuln.severity} — CVSS: {vuln.cvss_score ?? '—'}
                              {vuln.ai_analyzed && vuln.ai_priority_score == null && ' • Analysée par IA'}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Analysis Result */}
            {analysisResult && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Sparkles className="h-5 w-5" />
                    Résultats de l&apos;analyse IA
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Summary Badges */}
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">
                      {analysisResult.vulnerability_count ?? 'N/A'} vulnérabilité(s) analysée(s)
                    </Badge>
                    {analysisResult.analysis_summary?.overall_risk_score != null && (
                      <Badge variant="warning">
                        Score de risque global: {analysisResult.analysis_summary.overall_risk_score}
                      </Badge>
                    )}
                    {analysisResult.analysis_summary?.average_cvss != null && (
                      <Badge variant="outline">
                        CVSS moyen: {analysisResult.analysis_summary.average_cvss}
                      </Badge>
                    )}
                  </div>

                  {/* Summary text */}
                  {analysisResult.analysis_summary && (
                    <div className="text-sm space-y-1 text-muted-foreground">
                      <p>
                        Ce groupe contient{' '}
                        <strong className="text-foreground">{analysisResult.analysis_summary.total_vulnerabilities}</strong> vulnérabilités,
                        dont <strong className="text-red-600">{analysisResult.analysis_summary.critical_count} critiques</strong>,{' '}
                        <strong className="text-orange-500">{analysisResult.analysis_summary.high_count} élevées</strong>,{' '}
                        <strong className="text-amber-500">{analysisResult.analysis_summary.medium_count} moyennes</strong> et{' '}
                        <strong className="text-green-600">{analysisResult.analysis_summary.low_count} faibles</strong>.
                      </p>
                    </div>
                  )}

                  {/* Remediation plan */}
                  {analysisResult.remediation_plan && (
                    <>
                      <Separator />
                      <div className="space-y-4">
                        {analysisResult.remediation_plan.immediate_actions?.length > 0 && (
                          <div>
                            <p className="font-semibold text-sm mb-2 text-red-600">
                              Actions immédiates (CRITICAL / HIGH)
                            </p>
                            <ul className="space-y-1 pl-4">
                              {analysisResult.remediation_plan.immediate_actions.map((action, idx) => (
                                <li key={idx} className="text-sm list-disc">
                                  <strong>{action.vulnerability_name}</strong> – {action.action}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                        {analysisResult.remediation_plan.short_term_actions?.length > 0 && (
                          <div>
                            <p className="font-semibold text-sm mb-2 text-amber-500">
                              Actions court terme (MEDIUM)
                            </p>
                            <ul className="space-y-1 pl-4">
                              {analysisResult.remediation_plan.short_term_actions.map((action, idx) => (
                                <li key={idx} className="text-sm list-disc">
                                  <strong>{action.vulnerability_name}</strong> – {action.action}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </>
                  )}

                  {/* Per-vulnerability details */}
                  {analysisResult.vulnerabilities?.length > 0 && (
                    <>
                      <Separator />
                      <div>
                        <p className="font-semibold text-sm mb-3">Analyse détaillée par vulnérabilité</p>
                        <div className="space-y-4">
                          {analysisResult.vulnerabilities.map((v, idx) => (
                            <div key={v.vulnerability_id || idx} className="space-y-1 border-l-2 border-muted pl-3">
                              <p className="font-medium text-sm">
                                {v.name || 'Vulnérabilité'}{' '}
                                <span className="text-muted-foreground font-normal">({v.vulnerability_id})</span>
                              </p>
                              {v.ai_explanation && (
                                <p className="text-sm text-muted-foreground">
                                  <span className="font-medium text-foreground">Explication :</span> {v.ai_explanation}
                                </p>
                              )}
                              {v.impact_analysis && (
                                <p className="text-sm text-muted-foreground">
                                  <span className="font-medium text-foreground">Impact technique :</span> {v.impact_analysis}
                                </p>
                              )}
                              {v.business_impact && (
                                <p className="text-sm text-muted-foreground">
                                  <span className="font-medium text-foreground">Impact métier :</span> {v.business_impact}
                                </p>
                              )}
                              {v.recommended_actions?.length > 0 && (
                                <div>
                                  <p className="text-sm font-medium">Actions recommandées :</p>
                                  <ul className="pl-4 space-y-0.5">
                                    {v.recommended_actions.map((action, aidx) => (
                                      <li key={aidx} className="text-sm text-muted-foreground list-disc">
                                        {action}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>
    </>
  );
}
