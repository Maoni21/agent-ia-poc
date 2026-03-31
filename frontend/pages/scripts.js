import Head from 'next/head';
import { useEffect, useState } from 'react';
import { FileCode, Loader2, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import scriptsService from '../lib/services/scriptsService';

const statusVariant = {
  approved: 'success',
  rejected: 'destructive',
  reject: 'destructive',
};

const riskColor = {
  low: 'text-green-500',
  medium: 'text-amber-500',
  high: 'text-orange-500',
  critical: 'text-red-600',
};

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

export default function ScriptsPage() {
  const [scripts, setScripts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadScripts = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await scriptsService.getScripts({ limit: 100 });
        setScripts(data.scripts || []);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement des scripts');
      } finally {
        setLoading(false);
      }
    };
    loadScripts();
  }, []);

  return (
    <>
      <Head>
        <title>Scripts - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scripts de remédiation</h1>
          <p className="text-muted-foreground">
            {loading ? '...' : `${scripts.length} script(s) généré(s)`}
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
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : scripts.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
                <FileCode className="h-12 w-12" />
                <p className="font-medium text-lg">Aucun script généré</p>
                <p className="text-sm text-center max-w-sm">
                  Les scripts de remédiation sont générés automatiquement lors de l&apos;analyse des vulnérabilités.
                </p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Script ID</TableHead>
                    <TableHead>Vulnérabilité</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Système cible</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead>Risque</TableHead>
                    <TableHead>Généré le</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scripts.map((script) => {
                    const status = script.validation_status || 'pending';
                    const risk = (script.risk_level || 'medium').toLowerCase();
                    return (
                      <TableRow key={script.script_id}>
                        <TableCell>
                          <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">
                            {script.script_id}
                          </code>
                        </TableCell>
                        <TableCell className="text-sm">{script.vulnerability_id || '—'}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{script.script_type || '—'}</Badge>
                        </TableCell>
                        <TableCell className="text-sm">{script.target_system || '—'}</TableCell>
                        <TableCell>
                          <Badge variant={statusVariant[status] || 'warning'}>
                            {status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className={`text-sm font-medium capitalize ${riskColor[risk] || 'text-muted-foreground'}`}>
                            {script.risk_level || 'medium'}
                          </span>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {formatDate(script.generated_at)}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
