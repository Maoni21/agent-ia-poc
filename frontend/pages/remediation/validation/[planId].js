/**
 * Page Résultats de Validation Post-Remédiation.
 * Affiche la comparaison avant/après et les vulnérabilités corrigées.
 */

import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft, TrendingUp, CheckCircle, AlertTriangle,
  Shield, Calendar, RefreshCw, Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from '@/components/ui/table';
import remediationService from '../../../lib/services/remediationService';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-100 text-red-700 border-red-200',
  HIGH: 'bg-orange-100 text-orange-700 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  LOW: 'bg-green-100 text-green-700 border-green-200',
};

function ScoreCard({ label, score, className }) {
  const color = score >= 80 ? 'text-green-600' : score >= 60 ? 'text-yellow-600' : 'text-red-600';
  const bg = score >= 80 ? 'bg-green-50 dark:bg-green-950/30' : score >= 60 ? 'bg-yellow-50 dark:bg-yellow-950/30' : 'bg-red-50 dark:bg-red-950/30';
  const grade = score >= 80 ? 'BON' : score >= 60 ? 'MOYEN' : 'CRITIQUE';
  return (
    <div className={`${bg} ${className || ''} p-6 rounded-xl text-center border`}>
      <p className="text-sm text-muted-foreground font-medium mb-1">{label}</p>
      <div className={`text-5xl font-black ${color}`}>{score ?? '—'}</div>
      <div className="text-sm text-muted-foreground mt-1">/100</div>
      <Badge className="mt-2" variant="outline">{grade}</Badge>
    </div>
  );
}

export default function ValidationResultsPage() {
  const router = useRouter();
  const { planId } = router.query;

  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);

  const loadResults = async () => {
    if (!planId) return;
    setError(null);
    try {
      const data = await remediationService.getValidationResults(planId);
      setResults(data);
      if (data.status === 'scanning' || data.status === 'pending') {
        setPolling(true);
      } else {
        setPolling(false);
      }
    } catch (err) {
      setError(err?.message || 'Erreur lors du chargement des résultats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!planId) return;
    loadResults();
  }, [planId]);

  // Polling si scan de validation en cours
  useEffect(() => {
    if (!polling || !planId) return;
    const interval = setInterval(async () => {
      try {
        const data = await remediationService.getValidationResults(planId);
        setResults(data);
        if (data.status !== 'scanning' && data.status !== 'pending') {
          setPolling(false);
          clearInterval(interval);
        }
      } catch { clearInterval(interval); }
    }, 4000);
    return () => clearInterval(interval);
  }, [polling, planId]);

  const improvement = results?.improvement ?? 0;
  const beforeScore = results?.before_score ?? 0;
  const afterScore = results?.after_score ?? 0;
  const fixed = results?.fixed_vulnerabilities || [];
  const remaining = results?.remaining_vulnerabilities || [];

  return (
    <>
      <Head>
        <title>Résultats de validation - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="flex-1">
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <TrendingUp className="h-6 w-6 text-green-500" />
              Résultats de validation
            </h1>
            <p className="text-sm text-muted-foreground">Scan de vérification post-remédiation</p>
          </div>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription className="flex items-center justify-between">
              {error}
              <Button variant="outline" size="sm" onClick={loadResults}>
                <RefreshCw className="mr-2 h-3 w-3" /> Réessayer
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-64 w-full" />
          </div>
        ) : results?.status === 'pending' || results?.status === 'scanning' ? (
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3 text-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
                <div>
                  <p className="font-semibold">Scan de validation en cours...</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Vérification que toutes les vulnérabilités ont été corrigées.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : results?.status === 'completed' ? (
          <>
            {/* Amélioration du score */}
            <Card className={improvement > 0 ? 'border-green-200 bg-green-50/30 dark:bg-green-950/10' : 'border-muted'}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  Amélioration du score de sécurité
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col sm:flex-row items-center gap-6 justify-center py-4">
                  <ScoreCard label="AVANT" score={beforeScore} />
                  <div className="text-center">
                    <TrendingUp className={`h-10 w-10 mx-auto ${improvement > 0 ? 'text-green-500' : 'text-muted-foreground'}`} />
                    <div className={`text-3xl font-black mt-2 ${improvement > 0 ? 'text-green-600' : 'text-muted-foreground'}`}>
                      {improvement > 0 ? `+${improvement}` : improvement}
                    </div>
                    <div className="text-xs text-muted-foreground">points</div>
                  </div>
                  <ScoreCard label="APRÈS" score={afterScore} />
                </div>
                {improvement > 0 && (
                  <div className="mt-4 space-y-2">
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Avant : {beforeScore}/100</span>
                      <span>Après : {afterScore}/100</span>
                    </div>
                    <Progress value={afterScore} className="h-3" />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Comparaison avant/après */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Comparaison avant / après</CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Sévérité</TableHead>
                      <TableHead className="text-center">Avant</TableHead>
                      <TableHead className="text-center">Après</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
                      const beforeCount = (results?.summary?.fixed_by_severity?.[sev] || 0)
                        + (results?.summary?.remaining_by_severity?.[sev] || 0);
                      const afterCount = results?.summary?.remaining_by_severity?.[sev] || 0;
                      return (
                        <TableRow key={sev}>
                          <TableCell>
                            <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[sev] || ''}`}>
                              {sev}
                            </span>
                          </TableCell>
                          <TableCell className="text-center font-medium">{beforeCount}</TableCell>
                          <TableCell className="text-center">
                            <span className={afterCount === 0 ? 'text-green-600 font-bold' : 'font-medium'}>
                              {afterCount === 0 ? '0 ✅' : afterCount}
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {/* Vulnérabilités corrigées */}
            {fixed.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    Vulnérabilités corrigées ({fixed.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 max-h-64 overflow-y-auto">
                  {fixed.map((v, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-green-50 dark:bg-green-950/20">
                      <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          {v.cve_id && <Badge variant="outline" className="font-mono text-xs">{v.cve_id}</Badge>}
                          <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_COLORS[v.severity] || ''}`}>
                            {v.severity}
                          </span>
                        </div>
                        <p className="text-sm font-medium truncate mt-0.5">{v.title}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Vulnérabilités restantes */}
            {remaining.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    Vulnérabilités restantes ({remaining.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 max-h-64 overflow-y-auto">
                  {remaining.map((v, i) => (
                    <div key={i} className="flex items-start gap-2 p-2 rounded-lg border">
                      <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          {v.cve_id && <Badge variant="outline" className="font-mono text-xs">{v.cve_id}</Badge>}
                          <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_COLORS[v.severity] || ''}`}>
                            {v.severity}
                          </span>
                        </div>
                        <p className="text-sm font-medium truncate mt-0.5">{v.title}</p>
                        {v.reason && <p className="text-xs text-muted-foreground mt-0.5">ℹ️ {v.reason}</p>}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Actions recommandées */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Prochaines étapes recommandées</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm text-muted-foreground">
                {remaining.length > 0 && (
                  <div className="flex items-start gap-2">
                    <span className="font-bold text-foreground">1.</span>
                    <span>Examiner les {remaining.length} vulnérabilités restantes nécessitant une intervention manuelle</span>
                  </div>
                )}
                <div className="flex items-start gap-2">
                  <span className="font-bold text-foreground">{remaining.length > 0 ? '2.' : '1.'}</span>
                  <span>Planifier le prochain scan de sécurité (dans 7 jours)</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-foreground">{remaining.length > 0 ? '3.' : '2.'}</span>
                  <span>Mettre à jour les politiques de sécurité si nécessaire</span>
                </div>
              </CardContent>
            </Card>

            {/* Boutons */}
            <div className="flex flex-wrap justify-between gap-3">
              <Link href="/scans">
                <Button variant="outline">
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Retour aux scans
                </Button>
              </Link>
              <Link href="/scans/new">
                <Button>
                  <Calendar className="mr-2 h-4 w-4" />
                  Planifier un nouveau scan
                </Button>
              </Link>
            </div>
          </>
        ) : (
          <Alert>
            <AlertDescription>
              Le scan de validation n&apos;a pas encore démarré.
              <Button variant="link" className="ml-2 p-0 h-auto" onClick={loadResults}>Actualiser</Button>
            </AlertDescription>
          </Alert>
        )}
      </div>
    </>
  );
}
