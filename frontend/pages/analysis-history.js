import Head from 'next/head';
import { useEffect, useState } from 'react';
import { BrainCircuit, Loader2, AlertCircle, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import analysisHistoryService from '../lib/services/analysisHistoryService';

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

const formatScore = (score) => {
  if (score === null || score === undefined) return '—';
  const n = parseFloat(score);
  if (isNaN(n)) return score;
  return `${(n * 100).toFixed(0)}%`;
};

export default function AnalysisHistoryPage() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [details, setDetails] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const loadAnalyses = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await analysisHistoryService.listAnalyses(50);
      setAnalyses(data.analyses || []);
    } catch (err) {
      setError(err.message || "Erreur lors du chargement de l'historique IA");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAnalyses(); }, []);

  const openDetails = async (analysis) => {
    setSelected(analysis);
    setDetails(null);
    setLoadingDetails(true);
    try {
      const data = await analysisHistoryService.getAnalysisDetails(analysis.analysis_id);
      setDetails(data);
    } catch (err) {
      alert(err.message || "Erreur lors du chargement des détails de l'analyse");
    } finally {
      setLoadingDetails(false);
    }
  };

  const closeDetails = () => {
    setSelected(null);
    setDetails(null);
  };

  return (
    <>
      <Head>
        <title>Historique IA - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Historique des analyses IA</h1>
          <p className="text-muted-foreground">
            {loading ? '...' : `${analyses.length} analyse(s) enregistrée(s)`}
          </p>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-3 p-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : analyses.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
                <BrainCircuit className="h-12 w-12" />
                <p className="font-medium text-lg">Aucune analyse IA enregistrée</p>
                <p className="text-sm text-center max-w-sm">
                  Les analyses IA apparaissent ici après avoir lancé une analyse sur une vulnérabilité ou un groupe.
                </p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Analysis ID</TableHead>
                    <TableHead>Cible</TableHead>
                    <TableHead>Vulnérabilités</TableHead>
                    <TableHead>Modèle IA</TableHead>
                    <TableHead>Score de confiance</TableHead>
                    <TableHead>Date</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {analyses.map((analysis) => (
                    <TableRow
                      key={analysis.analysis_id}
                      className="cursor-pointer hover:bg-accent/50"
                      onClick={() => openDetails(analysis)}
                    >
                      <TableCell>
                        <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">
                          {analysis.analysis_id}
                        </code>
                      </TableCell>
                      <TableCell className="text-sm">{analysis.target_system || '—'}</TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {analysis.vulnerability_count ?? 0}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {analysis.ai_model_used || '—'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {analysis.confidence_score !== null && analysis.confidence_score !== undefined ? (
                          <span className="font-medium text-sm">
                            {formatScore(analysis.confidence_score)}
                          </span>
                        ) : '—'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(analysis.analyzed_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Analysis Detail Dialog */}
        <Dialog open={Boolean(selected)} onOpenChange={(open) => { if (!open) closeDetails(); }}>
          <DialogContent className="sm:max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <BrainCircuit className="h-5 w-5" />
                Détails de l&apos;analyse IA
              </DialogTitle>
              {selected && (
                <DialogDescription>
                  <code className="text-xs font-mono">{selected.analysis_id}</code>
                </DialogDescription>
              )}
            </DialogHeader>

            {loadingDetails ? (
              <div className="flex flex-col items-center gap-3 py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">Chargement des détails...</p>
              </div>
            ) : details ? (
              <div className="space-y-4">
                {/* Meta info */}
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Cible</p>
                    <p className="font-medium">{details.target_system || '—'}</p>
                  </div>
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Score de confiance</p>
                    <p className="font-medium">{formatScore(details.confidence_score)}</p>
                  </div>
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Vulnérabilités analysées</p>
                    <p className="font-medium">{details.vulnerability_ids?.length ?? 0}</p>
                  </div>
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Modèle IA</p>
                    <Badge variant="outline" className="font-mono text-xs w-fit">
                      {details.ai_model_used || '—'}
                    </Badge>
                  </div>
                </div>

                {details.analysis_summary && (
                  <>
                    <Separator />
                    <div className="space-y-2">
                      <p className="text-sm font-semibold">Résumé de l&apos;analyse</p>
                      <pre className="bg-muted p-3 rounded-md text-xs overflow-auto max-h-48 whitespace-pre-wrap">
                        {JSON.stringify(details.analysis_summary, null, 2)}
                      </pre>
                    </div>
                  </>
                )}

                {details.remediation_plan && (
                  <>
                    <Separator />
                    <div className="space-y-2">
                      <p className="text-sm font-semibold">Plan de remédiation</p>
                      <pre className="bg-muted p-3 rounded-md text-xs overflow-auto max-h-48 whitespace-pre-wrap">
                        {JSON.stringify(details.remediation_plan, null, 2)}
                      </pre>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-4 text-center">
                Aucun détail disponible.
              </p>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={closeDetails}>
                Fermer
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}
