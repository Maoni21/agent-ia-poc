import Link from 'next/link';
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import {
  Table, TableHeader, TableRow, TableHead,
  TableBody, TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

function getRiskBarColor(score) {
  if (score > 500) return 'bg-red-500';
  if (score > 300) return 'bg-orange-500';
  if (score > 100) return 'bg-yellow-500';
  return 'bg-green-500';
}

export function TopRiskyAssets({ assets, loading }) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assets les plus vulnérables</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (!assets || assets.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Assets les plus vulnérables</CardTitle>
        </CardHeader>
        <CardContent className="p-6 text-center text-sm text-muted-foreground">
          Aucun asset trouvé
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Assets les plus vulnérables (Top {assets.length})</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Asset</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>Risk Score</TableHead>
              <TableHead className="text-center">Critical</TableHead>
              <TableHead className="text-center">High</TableHead>
              <TableHead className="text-center">Total</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <div className={`w-1 h-8 rounded ${getRiskBarColor(asset.risk_score)}`} />
                    <span className="font-medium">{asset.hostname}</span>
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground font-mono text-sm">
                  {asset.ip_address}
                </TableCell>
                <TableCell>
                  <span className="font-bold text-lg">{asset.risk_score}</span>
                </TableCell>
                <TableCell className="text-center">
                  <Badge variant="destructive">{asset.critical_vulns}</Badge>
                </TableCell>
                <TableCell className="text-center">
                  <Badge variant="outline">{asset.high_vulns}</Badge>
                </TableCell>
                <TableCell className="text-center text-muted-foreground">
                  {asset.total_vulns}
                </TableCell>
                <TableCell>
                  <Link href={`/assets/${asset.id}`} className="text-blue-500 hover:underline text-sm">
                    Voir →
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
