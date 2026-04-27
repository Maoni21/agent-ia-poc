import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

const STATUS_CONFIG = {
  COMPLIANT: {
    label: 'Conforme',
    icon: <CheckCircle className="h-4 w-4 text-green-500" />,
    badgeClass: 'bg-green-100 text-green-700 border-green-200',
    barClass: 'bg-green-500',
  },
  PARTIAL: {
    label: 'Partiel',
    icon: <AlertTriangle className="h-4 w-4 text-yellow-500" />,
    badgeClass: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    barClass: 'bg-yellow-500',
  },
  NON_COMPLIANT: {
    label: 'Non conforme',
    icon: <XCircle className="h-4 w-4 text-red-500" />,
    badgeClass: 'bg-red-100 text-red-700 border-red-200',
    barClass: 'bg-red-500',
  },
};

function FrameworkCard({ framework }) {
  const config = STATUS_CONFIG[framework.status] || STATUS_CONFIG.NON_COMPLIANT;

  return (
    <div className="p-4 border rounded-lg space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {config.icon}
          <span className="font-semibold text-sm">{framework.framework}</span>
        </div>
        <Badge variant="outline" className={`text-xs ${config.badgeClass}`}>
          {config.label}
        </Badge>
      </div>

      {/* Score progress */}
      <div className="space-y-1">
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{framework.controls_passed}/{framework.controls_total} contrôles</span>
          <span className="font-medium">{framework.score}%</span>
        </div>
        <div className="relative h-2 bg-muted rounded-full overflow-hidden">
          <div
            className={`absolute top-0 left-0 h-full rounded-full transition-all ${config.barClass}`}
            style={{ width: `${framework.score}%` }}
          />
        </div>
      </div>

      {/* Issues */}
      {framework.issues && framework.issues.length > 0 && (
        <ul className="space-y-1">
          {framework.issues.map((issue, i) => (
            <li key={i} className="text-xs text-red-600 flex items-start gap-1">
              <XCircle className="h-3 w-3 mt-0.5 shrink-0" />
              {issue}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function ComplianceStatus({ data, loading }) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Conformité réglementaire</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Conformité réglementaire</CardTitle>
        </CardHeader>
        <CardContent className="p-6 text-center text-sm text-muted-foreground">
          Aucune donnée disponible
        </CardContent>
      </Card>
    );
  }

  const compliantCount = data.filter((f) => f.status === 'COMPLIANT').length;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Conformité réglementaire</CardTitle>
          <span className="text-xs text-muted-foreground">
            {compliantCount}/{data.length} conformes
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {data.map((framework) => (
            <FrameworkCard key={framework.framework} framework={framework} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
