/**
 * Page d'exécution en temps réel de la remédiation.
 * Affiche la progression live via WebSocket + polling.
 */

import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useRef, useState } from 'react';
import {
  ArrowLeft, CheckCircle, XCircle, Clock, Loader2,
  AlertTriangle, Terminal, StopCircle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import remediationService from '../../../lib/services/remediationService';

const WS_BASE =
  typeof window !== 'undefined'
    ? (process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000')
    : '';

const STATUS_ICONS = {
  completed: <CheckCircle className="h-4 w-4 text-green-500" />,
  failed: <XCircle className="h-4 w-4 text-red-500" />,
  running: <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />,
  rolled_back: <AlertTriangle className="h-4 w-4 text-amber-500" />,
  pending: <Clock className="h-4 w-4 text-muted-foreground" />,
  skipped: <CheckCircle className="h-4 w-4 text-muted-foreground" />,
};

export default function RemediationExecutionPage() {
  const router = useRouter();
  const { planId } = router.query;

  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  // Charger le statut initial
  const loadStatus = async () => {
    if (!planId) return;
    try {
      const data = await remediationService.getExecutionStatus(planId);
      setStatus(data);

      // Construire les logs à partir des étapes
      const newLogs = [];
      for (const step of data.all_steps || []) {
        if (step.status === 'completed') {
          newLogs.push(`[✅] ${step.name} (${step.duration || 0}s)`);
        } else if (step.status === 'failed') {
          newLogs.push(`[❌] ${step.name} — ÉCHEC`);
          if (step.stderr) newLogs.push(`     ${step.stderr.slice(0, 200)}`);
        } else if (step.status === 'running') {
          newLogs.push(`[🔄] ${step.name} — En cours...`);
        }
      }
      if (newLogs.length > 0) setLogs(newLogs);
    } catch (err) {
      console.error('Erreur chargement statut:', err);
    } finally {
      setLoading(false);
    }
  };

  // WebSocket pour mises à jour temps réel
  useEffect(() => {
    if (!planId) return;
    loadStatus();

    let ws;
    try {
      ws = new WebSocket(`${WS_BASE}/ws/remediation/${planId}`);
    } catch { return; }

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const data = payload.data || payload;

        setStatus((prev) => ({
          ...(prev || {}),
          ...data,
          plan_id: planId,
        }));

        if (data.log_entry) {
          setLogs((prev) => [...prev, data.log_entry]);
        }

        // Rediriger vers validation si terminé
        if (data.status === 'completed') {
          setTimeout(() => {
            router.push(`/remediation/validation/${planId}`);
          }, 2000);
        }
      } catch {}
    };

    // Polling de secours
    const pollInterval = setInterval(() => {
      loadStatus();
    }, 5000);

    return () => {
      if (ws) ws.close(1000, 'Page fermée');
      clearInterval(pollInterval);
    };
  }, [planId]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const isFinished = status?.status === 'completed' || status?.status === 'failed';
  const progress = status?.overall_progress ?? 0;

  return (
    <>
      <Head>
        <title>Exécution remédiation - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex-1">
            <h1 className="text-2xl font-bold">Exécution automatisée en cours</h1>
            <p className="text-sm text-muted-foreground">
              Plan #{String(planId || '').slice(0, 8)}
            </p>
          </div>
          {status?.status && (
            <Badge variant={
              status.status === 'completed' ? 'default' :
              status.status === 'failed' ? 'destructive' : 'secondary'
            }>
              {status.status === 'executing' ? 'En cours' :
               status.status === 'completed' ? 'Terminé ✅' :
               status.status === 'failed' ? 'Échec ❌' : status.status}
            </Badge>
          )}
        </div>

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : (
          <>
            {/* Progression globale */}
            <Card>
              <CardContent className="pt-6 space-y-4">
                <div className="flex justify-between text-sm font-medium">
                  <span>
                    {status?.status === 'executing'
                      ? `Étape ${status?.current_step || '?'}/${status?.total_steps || '?'} : ${status?.step_name || '...'}`
                      : status?.status === 'completed' ? '✅ Toutes les étapes terminées'
                      : status?.status === 'failed' ? '❌ Échec lors de l\'exécution'
                      : 'En attente...'}
                  </span>
                  <span>{progress}%</span>
                </div>
                <Progress value={progress} className="h-3" />
                {status?.estimated_time_remaining > 0 && status?.status === 'executing' && (
                  <p className="text-xs text-muted-foreground">
                    ⏱ Temps restant estimé : ~{Math.ceil(status.estimated_time_remaining / 60)} min
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Étapes */}
            {(status?.all_steps || []).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Étapes d&apos;exécution</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {(status.all_steps || []).map((step) => (
                    <div
                      key={step.step}
                      className={`flex items-center gap-3 p-2.5 rounded-lg
                        ${step.status === 'running' ? 'bg-blue-50 dark:bg-blue-950/30 border border-blue-200' : ''}
                        ${step.status === 'completed' ? 'opacity-70' : ''}
                      `}
                    >
                      {STATUS_ICONS[step.status] || STATUS_ICONS.pending}
                      <span className="flex-1 text-sm">{step.name}</span>
                      {step.duration && step.status === 'completed' && (
                        <span className="text-xs text-muted-foreground">{step.duration}s</span>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Log en temps réel */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Log d&apos;exécution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-black/90 rounded-lg p-4 max-h-72 overflow-y-auto font-mono text-xs text-green-400 space-y-0.5">
                  {logs.length === 0 ? (
                    <span className="text-muted-foreground">En attente des logs...</span>
                  ) : (
                    logs.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))
                  )}
                  {status?.status === 'executing' && (
                    <div className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      <span>...</span>
                    </div>
                  )}
                  <div ref={logsEndRef} />
                </div>
              </CardContent>
            </Card>

            {/* Terminé → redirection auto */}
            {status?.status === 'completed' && (
              <Alert className="border-green-200 bg-green-50 dark:bg-green-950/30">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <AlertDescription className="ml-2 flex items-center justify-between">
                  <span>Remédiation terminée avec succès ! Lancement du scan de validation...</span>
                  <Button size="sm" onClick={() => router.push(`/remediation/validation/${planId}`)}>
                    Voir les résultats →
                  </Button>
                </AlertDescription>
              </Alert>
            )}

            {status?.status === 'failed' && (
              <Alert variant="destructive">
                <XCircle className="h-4 w-4" />
                <AlertDescription className="ml-2 flex items-center justify-between">
                  <span>L&apos;exécution a échoué. Consultez les logs pour plus de détails.</span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => router.push(`/remediation/plan/${status?.plan_id?.slice(0, 8) || planId}`)}
                  >
                    Retour au plan
                  </Button>
                </AlertDescription>
              </Alert>
            )}

            {/* Bouton arrêt d'urgence */}
            {status?.status === 'executing' && (
              <div className="flex justify-end">
                <Button variant="destructive" size="sm" disabled>
                  <StopCircle className="mr-2 h-4 w-4" />
                  Arrêt d&apos;urgence
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
