/**
 * Page Plan de Remédiation
 * Affiche le plan généré par l'IA avec les phases et les étapes,
 * et permet de lancer l'exécution automatique via SSH.
 */

import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft, Sparkles, Shield, AlertTriangle, Clock,
  ChevronDown, ChevronUp, Loader2, CheckCircle, Play,
  FileText, RotateCcw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import remediationService from '../../../lib/services/remediationService';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-950/30 dark:text-red-400',
  HIGH: 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950/30 dark:text-orange-400',
  MEDIUM: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-950/30 dark:text-yellow-400',
  LOW: 'bg-green-100 text-green-700 border-green-200 dark:bg-green-950/30 dark:text-green-400',
};

export default function RemediationPlanPage() {
  const router = useRouter();
  const { scanId, analysis_id } = router.query;

  const [plan, setPlan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeProgress, setAnalyzeProgress] = useState(null);
  const [expandedPhases, setExpandedPhases] = useState({});

  // Dialog approbation
  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [approveChecks, setApproveChecks] = useState({
    reviewed: false, backup: false, downtime: false, approved: false,
  });
  const [approving, setApproving] = useState(false);
  const [approveError, setApproveError] = useState(null);

  const loadPlan = async (sid) => {
    setLoading(true);
    setError(null);
    try {
      const data = await remediationService.getRemediationPlan(sid);
      setPlan(data);
      // Expand first phase by default
      if (data.phases?.length > 0) {
        setExpandedPhases({ 0: true });
      }
    } catch (err) {
      if (err?.status === 404) {
        setError('Plan de remédiation non disponible. L\'analyse est peut-être encore en cours.');
      } else {
        setError(err?.message || 'Erreur lors du chargement du plan');
      }
    } finally {
      setLoading(false);
    }
  };

  // Polling si analyse en cours
  useEffect(() => {
    if (!scanId) return;

    const poll = async () => {
      if (analysis_id) {
        setAnalyzing(true);
        const interval = setInterval(async () => {
          try {
            const status = await remediationService.getAnalysisStatus(analysis_id);
            setAnalyzeProgress(status);
            if (status.status !== 'analyzing') {
              clearInterval(interval);
              setAnalyzing(false);
              await loadPlan(scanId);
            }
          } catch {
            clearInterval(interval);
            setAnalyzing(false);
            await loadPlan(scanId);
          }
        }, 3000);
        return () => clearInterval(interval);
      } else {
        await loadPlan(scanId);
      }
    };

    poll();
  }, [scanId, analysis_id]);

  const togglePhase = (idx) => {
    setExpandedPhases((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const canApprove = Object.values(approveChecks).every(Boolean);

  const handleApprove = async () => {
    if (!plan) return;
    setApproving(true);
    setApproveError(null);
    try {
      await remediationService.approveRemediationPlan(plan.plan_id, { confirmed: true });
      setApproveDialogOpen(false);
      router.push(`/remediation/execution/${plan.plan_id}`);
    } catch (err) {
      setApproveError(err?.message || "Erreur lors de l'approbation");
    } finally {
      setApproving(false);
    }
  };

  const priority = plan?.executive_summary?.priority || 'UNKNOWN';
  const priorityColor = {
    CRITICAL: 'text-red-600',
    HIGH: 'text-orange-600',
    MEDIUM: 'text-yellow-600',
    LOW: 'text-green-600',
  }[priority] || 'text-muted-foreground';

  return (
    <>
      <Head>
        <title>Plan de remédiation - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Sparkles className="h-6 w-6 text-primary" />
              Plan de remédiation IA
            </h1>
            <p className="text-sm text-muted-foreground">Scan #{String(scanId || '').slice(0, 8)}</p>
          </div>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription className="flex items-center justify-between">
              {error}
              {scanId && (
                <Button variant="outline" size="sm" onClick={() => loadPlan(scanId)}>
                  <RotateCcw className="mr-2 h-3 w-3" /> Réessayer
                </Button>
              )}
            </AlertDescription>
          </Alert>
        )}

        {/* Analyse en cours */}
        {analyzing && (
          <Card>
            <CardContent className="pt-6 space-y-4">
              <div className="flex items-center gap-3">
                <Loader2 className="h-5 w-5 text-primary animate-spin" />
                <div>
                  <p className="font-medium">Analyse IA en cours...</p>
                  {analyzeProgress && (
                    <p className="text-sm text-muted-foreground">
                      {analyzeProgress.progress}/{analyzeProgress.total} vulnérabilités analysées
                      {analyzeProgress.current_vulnerability && ` · ${analyzeProgress.current_vulnerability}`}
                    </p>
                  )}
                </div>
              </div>
              {analyzeProgress && analyzeProgress.total > 0 && (
                <Progress
                  value={(analyzeProgress.progress / analyzeProgress.total) * 100}
                  className="h-2"
                />
              )}
            </CardContent>
          </Card>
        )}

        {loading && !analyzing && (
          <div className="space-y-4">
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        )}

        {plan && !loading && (
          <>
            {/* Executive Summary */}
            <Card className={`border-2 ${priority === 'CRITICAL' ? 'border-red-200' : 'border-orange-200'}`}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Résumé exécutif
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className={`text-xl font-bold ${priorityColor}`}>
                  Priorité : {priority}
                </div>
                <p className="text-sm text-muted-foreground">
                  {plan.executive_summary?.description ||
                    `${plan.executive_summary?.total_fixes || 0} correctifs à appliquer.`}
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {[
                    { label: 'Correctifs', value: plan.executive_summary?.total_fixes || 0, icon: CheckCircle },
                    { label: 'Durée estimée', value: `~${plan.executive_summary?.estimated_duration || 0} min`, icon: Clock },
                    { label: 'Temps d\'arrêt', value: `~${plan.executive_summary?.estimated_downtime || 0} min`, icon: AlertTriangle },
                    { label: 'Phases', value: plan.phases?.length || 0, icon: Play },
                  ].map(({ label, value, icon: Icon }) => (
                    <div key={label} className="text-center p-3 bg-muted/40 rounded-lg">
                      <Icon className="h-4 w-4 mx-auto mb-1 text-muted-foreground" />
                      <div className="font-bold text-lg">{value}</div>
                      <div className="text-xs text-muted-foreground">{label}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Phases */}
            {(plan.phases || []).map((phase, phaseIdx) => (
              <Card key={phaseIdx}>
                <CardHeader
                  className="cursor-pointer hover:bg-muted/30 transition-colors"
                  onClick={() => togglePhase(phaseIdx)}
                >
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Badge variant="outline">Phase {phase.phase_number}</Badge>
                      {phase.name}
                      <Badge variant="secondary" className="ml-1 text-xs">
                        {(phase.steps || []).length} étape{(phase.steps || []).length > 1 ? 's' : ''}
                      </Badge>
                    </CardTitle>
                    {expandedPhases[phaseIdx]
                      ? <ChevronUp className="h-4 w-4 text-muted-foreground" />
                      : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                  </div>
                </CardHeader>

                {expandedPhases[phaseIdx] && (
                  <CardContent className="space-y-3 pt-0">
                    {(phase.steps || []).map((step) => (
                      <div key={step.step_number} className="p-4 border rounded-lg space-y-2">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-muted-foreground w-6">{step.step_number}.</span>
                            <div>
                              <p className="font-medium text-sm">{step.title || step.action}</p>
                              {step.cve_id && (
                                <Badge variant="outline" className="font-mono text-xs mt-1">{step.cve_id}</Badge>
                              )}
                            </div>
                          </div>
                          {step.severity && (
                            <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[step.severity] || ''}`}>
                              {step.severity}
                            </span>
                          )}
                        </div>
                        {step.command && !step.command.startsWith('#') && (
                          <div className="bg-muted/60 rounded p-2">
                            <p className="text-xs font-mono text-muted-foreground">{step.command}</p>
                          </div>
                        )}
                        <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                          {step.risk && <span>⚠️ {step.risk}</span>}
                          {step.duration && <span>⏱ ~{step.duration} min</span>}
                          {step.rollback && !step.rollback.startsWith('#') && (
                            <span>↩️ Rollback disponible</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </CardContent>
                )}
              </Card>
            ))}

            {/* Avertissements avant exécution */}
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="ml-2">
                <strong>Avant de procéder :</strong> Assurez-vous d&apos;avoir une sauvegarde de vos données
                critiques, une fenêtre de maintenance planifiée, et que le plan de rollback est compris.
              </AlertDescription>
            </Alert>

            {/* Actions */}
            <div className="flex flex-wrap justify-between items-center gap-3 p-4 border rounded-lg bg-muted/20">
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => router.back()}>
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Retour au scan
                </Button>
              </div>
              <Button
                size="lg"
                onClick={() => setApproveDialogOpen(true)}
                disabled={plan.status === 'executing' || plan.status === 'completed'}
              >
                <Play className="mr-2 h-4 w-4" />
                Procéder à l&apos;exécution →
              </Button>
            </div>
          </>
        )}
      </div>

      {/* Dialog: Confirmation d'exécution */}
      <Dialog open={approveDialogOpen} onOpenChange={setApproveDialogOpen}>
        <DialogContent className="sm:max-w-md max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Confirmer l&apos;exécution automatisée
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2 text-sm">
            <div className="p-3 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 rounded-lg">
              <p className="font-medium">Serveur cible</p>
              <p className="text-muted-foreground">Scan #{String(scanId || '').slice(0, 8)}</p>
            </div>
            <div className="space-y-2">
              <p className="font-medium">Ce qui sera exécuté :</p>
              <ul className="text-muted-foreground space-y-1 ml-2">
                <li>• {plan?.executive_summary?.total_fixes || 0} correctifs de vulnérabilités</li>
                <li>• Mises à jour des paquets système</li>
                <li>• Redémarrages de services nécessaires</li>
              </ul>
            </div>
            <div className="space-y-2">
              <p className="font-medium">Impact estimé :</p>
              <ul className="text-muted-foreground space-y-1 ml-2">
                <li>• Durée totale : ~{plan?.executive_summary?.estimated_duration || 0} minutes</li>
                <li>• Temps d&apos;arrêt : ~{plan?.executive_summary?.estimated_downtime || 0} minutes</li>
              </ul>
            </div>
            <div className="space-y-2 border-t pt-3">
              <p className="font-medium">Je confirme que :</p>
              {[
                { key: 'reviewed', label: "J'ai examiné le plan de remédiation" },
                { key: 'backup', label: "J'ai une sauvegarde des données critiques" },
                { key: 'downtime', label: "Je comprends les temps d'arrêt possibles" },
                { key: 'approved', label: "J'approuve l'exécution automatisée" },
              ].map(({ key, label }) => (
                <div key={key} className="flex items-center gap-2">
                  <Checkbox
                    id={key}
                    checked={approveChecks[key]}
                    onCheckedChange={(v) => setApproveChecks((p) => ({ ...p, [key]: !!v }))}
                  />
                  <Label htmlFor={key} className="cursor-pointer font-normal">{label}</Label>
                </div>
              ))}
            </div>
            {approveError && (
              <p className="text-red-600 text-xs bg-red-50 dark:bg-red-950/30 p-2 rounded">
                {approveError}
              </p>
            )}
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setApproveDialogOpen(false)}>Annuler</Button>
            <Button
              onClick={handleApprove}
              disabled={!canApprove || approving}
              className="bg-red-600 hover:bg-red-700"
            >
              {approving
                ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Lancement...</>
                : <><Play className="mr-2 h-4 w-4" />Exécuter le plan</>
              }
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
