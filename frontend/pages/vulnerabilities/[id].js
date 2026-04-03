import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import {
  ArrowLeft, Sparkles, Wrench, Play, Copy, CheckCircle, Loader2,
  AlertTriangle, TrendingUp, ShieldAlert, Target, Link2, CheckSquare,
  XCircle, Info, ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { CVSSMeter } from '@/components/ui/cvss-meter';
import { StatusBadge } from '@/components/ui/status-badge';
import { Separator } from '@/components/ui/separator';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import scriptsService from '../../lib/services/scriptsService';
import { api } from '../../lib/services/api';

export default function VulnerabilityDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [vuln, setVuln] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [scriptGenerating, setScriptGenerating] = useState(false);
  const [scriptLoading, setScriptLoading] = useState(false);
  const [scriptError, setScriptError] = useState(null);
  const [script, setScript] = useState(null);
  const [copied, setCopied] = useState(false);

  const [sshHost, setSshHost] = useState('');
  const [sshUser, setSshUser] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [executing, setExecuting] = useState(false);

  const loadVuln = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get(`/api/v1/vulnerabilities/${id}`);
      setVuln(data.data || data);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement de la vulnérabilité');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadVuln(); }, [id]);

  const handleAnalyze = async () => {
    if (!id) return;
    setAnalyzing(true);
    try {
      await vulnerabilitiesService.analyzeVulnerability(id);
      await loadVuln();
      alert('Analyse IA terminée.');
    } catch (err) {
      alert("Erreur analyse IA: " + (err.message || 'inconnue'));
    } finally {
      setAnalyzing(false);
    }
  };

  const handleGenerateScript = async () => {
    if (!id) return;
    setScriptGenerating(true);
    setScriptError(null);
    try {
      const result = await vulnerabilitiesService.generateScript(id, {
        target_system: 'ubuntu-22.04',
        script_type: 'bash',
      });
      if (result.script_id) {
        const scriptDetails = await scriptsService.getScript(result.script_id);
        setScript(scriptDetails);
      }
    } catch (err) {
      setScriptError(err.message || 'Erreur lors de la génération du script');
    } finally {
      setScriptGenerating(false);
    }
  };

  const handleApproveScript = async () => {
    if (!script?.id) return;
    setScriptLoading(true);
    try {
      await api.put(`/api/v1/remediation-scripts/${script.id}/approve`);
      const refreshed = await scriptsService.getScript(script.id);
      setScript(refreshed);
    } catch (err) {
      setScriptError(err.message || "Erreur approbation");
    } finally {
      setScriptLoading(false);
    }
  };

  const handleExecuteScript = async () => {
    if (!script?.id) return;
    if (!sshHost || !sshUser || !sshPassword) {
      alert('Veuillez renseigner host, username et password SSH.');
      return;
    }
    setExecuting(true);
    try {
      await api.post(`/api/v1/remediation-scripts/${script.id}/execute`, {
        host: sshHost, username: sshUser, password: sshPassword,
      });
      alert('Exécution du script lancée.');
    } catch (err) {
      setScriptError(err.message || 'Erreur exécution');
    } finally {
      setExecuting(false);
    }
  };

  const handleCopyScript = () => {
    if (script?.script_content) {
      navigator.clipboard.writeText(script.script_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const formatScore = (val) => {
    if (val == null) return '—';
    const n = typeof val === 'number' ? val : parseFloat(val);
    return Number.isNaN(n) ? String(val) : n.toFixed(1);
  };

  return (
    <>
      <Head>
        <title>Détails vulnérabilité - CyberSec AI</title>
      </Head>

      <div className="space-y-6 max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-start gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.push('/vulnerabilities')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex-1 min-w-0">
            {loading ? (
              <Skeleton className="h-8 w-64" />
            ) : vuln ? (
              <>
                <h1 className="text-2xl font-bold truncate">
                  {vuln.title || vuln.name || vuln.cve_id}
                </h1>
                <div className="flex flex-wrap gap-2 mt-2">
                  <SeverityBadge severity={vuln.severity} />
                  {vuln.cve_id && (
                    <Badge variant="outline" className="font-mono">{vuln.cve_id}</Badge>
                  )}
                  <StatusBadge status={vuln.status || 'open'} />
                  {vuln.ai_analyzed && (
                    <Badge variant="secondary">
                      <Sparkles className="mr-1 h-3 w-3" />
                      Analysée IA
                    </Badge>
                  )}
                </div>
              </>
            ) : null}
          </div>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : !vuln ? (
          <Alert><AlertDescription>Vulnérabilité introuvable.</AlertDescription></Alert>
        ) : (
          <>
            {/* CVSS meter */}
            {vuln.cvss_score != null && (
              <Card>
                <CardContent className="pt-6">
                  <CVSSMeter score={vuln.cvss_score} />
                </CardContent>
              </Card>
            )}

            <Tabs defaultValue="overview">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="overview">Vue d&apos;ensemble</TabsTrigger>
                <TabsTrigger value="ai">Analyse IA</TabsTrigger>
                <TabsTrigger value="remediation">Remédiation</TabsTrigger>
              </TabsList>

              {/* Tab Overview */}
              <TabsContent value="overview" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Description</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm leading-relaxed text-muted-foreground">
                      {vuln.description || 'Aucune description disponible.'}
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Détails techniques</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    {[
                      ['ID', <span key="i" className="font-mono text-xs">{vuln.id}</span>],
                      vuln.cve_id && ['CVE', <Badge key="c" variant="outline" className="font-mono">{vuln.cve_id}</Badge>],
                      ['Sévérité', <SeverityBadge key="s" severity={vuln.severity} />],
                      vuln.cvss_score != null && ['CVSS', `${formatScore(vuln.cvss_score)}/10`],
                      vuln.service && ['Service', `${vuln.service}${vuln.port ? ` (port ${vuln.port}/${vuln.protocol || 'tcp'})` : ''}`],
                      vuln.affected_package && ['Package', `${vuln.affected_package}${vuln.affected_version ? ` (${vuln.affected_version})` : ''}`],
                    ].filter(Boolean).map(([label, val]) => (
                      <div key={label} className="flex justify-between items-center">
                        <span className="text-muted-foreground">{label}</span>
                        <span className="font-medium">{val}</span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab AI Analysis */}
              <TabsContent value="ai" className="space-y-4">
                {/* Header card with action button */}
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between pb-3">
                    <div>
                      <CardTitle className="text-base">Analyse IA</CardTitle>
                      <CardDescription>
                        {vuln.ai_analyzed
                          ? 'Analyse effectuée par Intelligence Artificielle'
                          : 'Aucune analyse IA disponible pour cette vulnérabilité'}
                      </CardDescription>
                    </div>
                    <Button onClick={handleAnalyze} disabled={analyzing}>
                      {analyzing ? (
                        <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Analyse...</>
                      ) : (
                        <><Sparkles className="mr-2 h-4 w-4" />{vuln.ai_analyzed ? 'Relancer' : 'Analyser'}</>
                      )}
                    </Button>
                  </CardHeader>
                </Card>

                {vuln.ai_analysis ? (() => {
                  const ai = typeof vuln.ai_analysis === 'string'
                    ? (() => { try { return JSON.parse(vuln.ai_analysis); } catch { return null; } })()
                    : vuln.ai_analysis;

                  if (!ai) return (
                    <Card><CardContent className="pt-6">
                      <pre className="text-xs bg-muted rounded-lg p-4 overflow-x-auto whitespace-pre-wrap">
                        {String(vuln.ai_analysis)}
                      </pre>
                    </CardContent></Card>
                  );

                  return (
                    <div className="space-y-4">
                      {/* Scores row */}
                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                        {(ai.priority_score ?? vuln.ai_priority_score) != null && (
                          <Card className="border-primary/30 bg-primary/5">
                            <CardContent className="pt-4 pb-4 text-center">
                              <p className="text-xs text-muted-foreground mb-1">Score de priorité IA</p>
                              <p className="text-3xl font-bold text-primary">
                                {ai.priority_score ?? vuln.ai_priority_score}
                                <span className="text-sm font-normal text-muted-foreground">/10</span>
                              </p>
                            </CardContent>
                          </Card>
                        )}
                        {ai.exploitability && (
                          <Card className={ai.exploitability === 'HIGH' ? 'border-red-500/30 bg-red-500/5' : 'border-amber-500/30 bg-amber-500/5'}>
                            <CardContent className="pt-4 pb-4 text-center">
                              <p className="text-xs text-muted-foreground mb-1">Exploitabilité</p>
                              <Badge variant={ai.exploitability === 'HIGH' ? 'destructive' : 'warning'} className="text-sm px-3">
                                {ai.exploitability}
                              </Badge>
                            </CardContent>
                          </Card>
                        )}
                        {ai.is_false_positive != null && (
                          <Card className={ai.is_false_positive ? 'border-green-500/30 bg-green-500/5' : 'border-orange-500/30 bg-orange-500/5'}>
                            <CardContent className="pt-4 pb-4 text-center">
                              <p className="text-xs text-muted-foreground mb-1">Faux positif</p>
                              <div className="flex items-center justify-center gap-1.5">
                                {ai.is_false_positive
                                  ? <XCircle className="h-5 w-5 text-green-600" />
                                  : <CheckSquare className="h-5 w-5 text-orange-500" />}
                                <span className="font-semibold text-sm">
                                  {ai.is_false_positive ? 'Probable' : 'Non'}
                                </span>
                              </div>
                              {ai.false_positive_confidence != null && (
                                <p className="text-xs text-muted-foreground mt-1">
                                  confiance : {Math.round(ai.false_positive_confidence * 100)}%
                                </p>
                              )}
                            </CardContent>
                          </Card>
                        )}
                      </div>

                      {/* AI Explanation */}
                      {ai.ai_explanation && (
                        <Card>
                          <CardHeader className="pb-3">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Info className="h-4 w-4 text-blue-500" />
                              Explication de l&apos;IA
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-sm leading-relaxed text-foreground">{ai.ai_explanation}</p>
                          </CardContent>
                        </Card>
                      )}

                      {/* Impact cards row */}
                      {(ai.impact_analysis || ai.business_impact) && (
                        <div className="grid gap-4 md:grid-cols-2">
                          {ai.impact_analysis && (
                            <Card className="border-orange-500/20">
                              <CardHeader className="pb-2">
                                <CardTitle className="text-sm flex items-center gap-2">
                                  <ShieldAlert className="h-4 w-4 text-orange-500" />
                                  Impact technique
                                </CardTitle>
                              </CardHeader>
                              <CardContent>
                                <p className="text-sm text-muted-foreground leading-relaxed">{ai.impact_analysis}</p>
                              </CardContent>
                            </Card>
                          )}
                          {ai.business_impact && (
                            <Card className="border-red-500/20">
                              <CardHeader className="pb-2">
                                <CardTitle className="text-sm flex items-center gap-2">
                                  <TrendingUp className="h-4 w-4 text-red-500" />
                                  Impact métier
                                </CardTitle>
                              </CardHeader>
                              <CardContent>
                                <p className="text-sm text-muted-foreground leading-relaxed">{ai.business_impact}</p>
                              </CardContent>
                            </Card>
                          )}
                        </div>
                      )}

                      {/* Recommended actions */}
                      {ai.recommended_actions?.length > 0 && (
                        <Card className="border-green-500/20">
                          <CardHeader className="pb-3">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Target className="h-4 w-4 text-green-600" />
                              Actions recommandées
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ul className="space-y-2">
                              {ai.recommended_actions.map((action, i) => (
                                <li key={i} className="flex items-start gap-2 text-sm">
                                  <ChevronRight className="h-4 w-4 text-green-600 mt-0.5 shrink-0" />
                                  <span>{action}</span>
                                </li>
                              ))}
                            </ul>
                          </CardContent>
                        </Card>
                      )}

                      {/* False positive reasoning */}
                      {ai.false_positive_reasoning && (
                        <Card className="border-muted bg-muted/30">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2 text-muted-foreground">
                              <AlertTriangle className="h-4 w-4" />
                              Raisonnement faux positif
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-sm text-muted-foreground leading-relaxed italic">{ai.false_positive_reasoning}</p>
                          </CardContent>
                        </Card>
                      )}

                      {/* Solution links */}
                      {ai.solution_links?.length > 0 && (
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Link2 className="h-4 w-4" />
                              Ressources
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ul className="space-y-1">
                              {ai.solution_links.map((link, i) => (
                                <li key={i}>
                                  <a href={link} target="_blank" rel="noopener noreferrer"
                                    className="text-sm text-blue-600 hover:underline break-all">
                                    {link}
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </CardContent>
                        </Card>
                      )}
                    </div>
                  );
                })() : (
                  <Card>
                    <CardContent className="py-12 text-center">
                      <Sparkles className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
                      <p className="text-sm text-muted-foreground">
                        Cliquez sur &quot;Analyser&quot; pour lancer l&apos;analyse IA
                      </p>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* Tab Remediation */}
              <TabsContent value="remediation" className="space-y-4">
                {scriptError && (
                  <Alert variant="destructive">
                    <AlertDescription>{scriptError}</AlertDescription>
                  </Alert>
                )}

                {!script ? (
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Script de remédiation</CardTitle>
                      <CardDescription>Générez un script de correction pour cette vulnérabilité</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Button onClick={handleGenerateScript} disabled={scriptGenerating}>
                        {scriptGenerating ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Génération...
                          </>
                        ) : (
                          <>
                            <Wrench className="mr-2 h-4 w-4" />
                            Générer le script
                          </>
                        )}
                      </Button>
                    </CardContent>
                  </Card>
                ) : (
                  <>
                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between">
                        <div>
                          <CardTitle className="text-base">Script de correction</CardTitle>
                          <CardDescription>
                            {script.script_type} · OS cible : {script.target_os}
                          </CardDescription>
                        </div>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm" onClick={handleCopyScript}>
                            {copied ? (
                              <><CheckCircle className="mr-2 h-4 w-4 text-green-500" />Copié</>
                            ) : (
                              <><Copy className="mr-2 h-4 w-4" />Copier</>
                            )}
                          </Button>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <pre className="bg-gray-950 text-gray-100 rounded-lg p-4 text-xs overflow-x-auto max-h-64">
                          {script.script_content || '# (vide)'}
                        </pre>
                      </CardContent>
                    </Card>

                    {script.rollback_script && (
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-base text-amber-600">Script de rollback</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <pre className="bg-gray-950 text-gray-100 rounded-lg p-4 text-xs overflow-x-auto max-h-40">
                            {script.rollback_script}
                          </pre>
                        </CardContent>
                      </Card>
                    )}

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Exécution SSH</CardTitle>
                        <CardDescription>Exécutez le script directement sur la cible via SSH</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <Alert variant="warning">
                          <AlertDescription>
                            ⚠️ Cette action modifie le système cible. Vérifiez le script avant d&apos;exécuter.
                          </AlertDescription>
                        </Alert>
                        <div className="grid gap-3 md:grid-cols-3">
                          <div className="space-y-1">
                            <Label>SSH Host</Label>
                            <Input placeholder="192.168.1.100" value={sshHost} onChange={(e) => setSshHost(e.target.value)} />
                          </div>
                          <div className="space-y-1">
                            <Label>Username</Label>
                            <Input placeholder="root" value={sshUser} onChange={(e) => setSshUser(e.target.value)} />
                          </div>
                          <div className="space-y-1">
                            <Label>Password</Label>
                            <Input type="password" placeholder="••••••" value={sshPassword} onChange={(e) => setSshPassword(e.target.value)} />
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            onClick={handleApproveScript}
                            disabled={scriptLoading || script.execution_status === 'approved'}
                          >
                            Approuver le script
                          </Button>
                          <Button
                            variant="destructive"
                            onClick={handleExecuteScript}
                            disabled={executing}
                          >
                            {executing ? (
                              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Exécution...</>
                            ) : (
                              <><Play className="mr-2 h-4 w-4" />Exécuter (SSH)</>
                            )}
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </>
  );
}
