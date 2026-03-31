import Head from 'next/head';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import Link from 'next/link';
import {
  Plus, RefreshCw, Eye, Play, CheckCircle, XCircle,
  Loader2, Activity, Scan,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { StatusBadge } from '@/components/ui/status-badge';
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from '@/components/ui/table';
import scansService from '../../lib/services/scansService';
import assetsService from '../../lib/services/assetsService';

const formatDate = (value) => {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString('fr-FR');
  } catch {
    return value;
  }
};

export default function ScansListPage() {
  const router = useRouter();
  const [scans, setScans] = useState([]);
  const [assetsById, setAssetsById] = useState({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const loadData = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const [assetsData, scansData] = await Promise.all([
        assetsService.getAssets().catch(() => []),
        scansService.getScans({ limit: 100 }),
      ]);
      const map = {};
      (assetsData || []).forEach((a) => { map[a.id] = a; });
      setAssetsById(map);
      setScans(scansData || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des scans');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 10000);
    return () => clearInterval(interval);
  }, []);

  // Stats
  const totalScans = scans.length;
  const runningScans = scans.filter((s) => s.status === 'running').length;
  const completedScans = scans.filter((s) => s.status === 'completed').length;
  const failedScans = scans.filter((s) => s.status === 'failed').length;

  return (
    <>
      <Head>
        <title>Scans - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Security Scans</h1>
            <p className="text-muted-foreground">Historique et état de vos scans de sécurité</p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => loadData(true)}
              disabled={refreshing}
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            </Button>
            <Link href="/scans/new" passHref legacyBehavior>
              <Button asChild>
                <a>
                  <Plus className="mr-2 h-4 w-4" />
                  Nouveau scan
                </a>
              </Button>
            </Link>
          </div>
        </div>

        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total</CardTitle>
              <Scan className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{loading ? '—' : totalScans}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium text-muted-foreground">En cours</CardTitle>
              <Loader2 className={`h-4 w-4 text-blue-500 ${runningScans > 0 ? 'animate-spin' : ''}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">{loading ? '—' : runningScans}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium text-muted-foreground">Terminés</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{loading ? '—' : completedScans}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium text-muted-foreground">Échoués</CardTitle>
              <XCircle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{loading ? '—' : failedScans}</div>
            </CardContent>
          </Card>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Progression</TableHead>
                <TableHead>Début</TableHead>
                <TableHead>Vulnérabilités</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 7 }).map((__, j) => (
                      <TableCell key={j}><Skeleton className="h-4 w-full" /></TableCell>
                    ))}
                  </TableRow>
                ))
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <div className="flex flex-col items-center gap-3 text-muted-foreground">
                      <Activity className="h-10 w-10" />
                      <div>
                        <p className="font-medium">Aucun scan trouvé</p>
                        <p className="text-sm">Lancez votre premier scan de sécurité</p>
                      </div>
                      <Link href="/scans/new" passHref legacyBehavior>
                        <Button asChild size="sm">
                          <a>
                            <Play className="mr-2 h-4 w-4" />
                            Lancer un scan
                          </a>
                        </Button>
                      </Link>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => {
                  const asset = assetsById[scan.asset_id];
                  return (
                    <TableRow
                      key={scan.id}
                      className="hover:bg-muted/50 cursor-pointer"
                      onClick={() => router.push(`/scans/${scan.id}`)}
                    >
                      <TableCell className="font-medium">
                        {asset
                          ? `${asset.hostname || asset.ip_address}`
                          : scan.asset_id?.slice(0, 8) + '...'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{scan.scan_type || 'standard'}</Badge>
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={scan.status} />
                      </TableCell>
                      <TableCell className="w-[120px]">
                        {scan.status === 'running' && scan.progress != null ? (
                          <div className="space-y-1">
                            <Progress value={scan.progress} className="h-1.5" />
                            <p className="text-xs text-muted-foreground">{scan.progress}%</p>
                          </div>
                        ) : '—'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(scan.started_at || scan.created_at)}
                      </TableCell>
                      <TableCell>
                        {scan.vulnerabilities_found != null ? (
                          <Badge variant={scan.vulnerabilities_found > 0 ? 'destructive' : 'success'}>
                            {scan.vulnerabilities_found}
                          </Badge>
                        ) : '—'}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push(`/scans/${scan.id}`);
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </Card>
      </div>
    </>
  );
}
