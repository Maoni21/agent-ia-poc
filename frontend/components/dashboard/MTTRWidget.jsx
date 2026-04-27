import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { TrendingUp, TrendingDown, Minus, Clock } from 'lucide-react';

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'bg-red-500',    text: 'text-red-600',    light: 'bg-red-50'    },
  HIGH:     { bg: 'bg-orange-500', text: 'text-orange-600', light: 'bg-orange-50' },
  MEDIUM:   { bg: 'bg-yellow-500', text: 'text-yellow-600', light: 'bg-yellow-50' },
  LOW:      { bg: 'bg-green-500',  text: 'text-green-600',  light: 'bg-green-50'  },
};

const STATUS_CONFIG = {
  WITHIN_BENCHMARK: {
    label: 'Dans les normes',
    icon: <TrendingDown className="h-4 w-4 text-green-500" />,
    color: 'text-green-600',
  },
  SLIGHTLY_ABOVE: {
    label: 'Légèrement au-dessus',
    icon: <Minus className="h-4 w-4 text-yellow-500" />,
    color: 'text-yellow-600',
  },
  ABOVE_BENCHMARK: {
    label: 'Au-dessus des normes',
    icon: <TrendingUp className="h-4 w-4 text-red-500" />,
    color: 'text-red-600',
  },
  NO_DATA: {
    label: 'Pas de données',
    icon: <Minus className="h-4 w-4 text-gray-400" />,
    color: 'text-gray-400',
  },
};

function SeverityRow({ item }) {
  const colors = SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.LOW;
  const statusCfg = STATUS_CONFIG[item.status] || STATUS_CONFIG.NO_DATA;

  const barWidth = item.mttr_days && item.benchmark_days
    ? Math.min((item.benchmark_days / Math.max(item.mttr_days, item.benchmark_days)) * 100, 100)
    : 0;

  const actualWidth = item.mttr_days && item.benchmark_days
    ? Math.min((item.mttr_days / Math.max(item.mttr_days, item.benchmark_days)) * 100, 100)
    : 0;

  return (
    <div className={`p-3 rounded-lg ${colors.light} space-y-2`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${colors.bg}`} />
          <span className="text-sm font-medium">{item.severity}</span>
        </div>
        <div className="flex items-center gap-1 text-xs">
          {statusCfg.icon}
          <span className={statusCfg.color}>{statusCfg.label}</span>
        </div>
      </div>

      {/* Valeurs */}
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>
          Votre MTTR :{' '}
          <strong className={colors.text}>
            {item.mttr_days !== null ? `${item.mttr_days}j` : 'N/A'}
          </strong>
        </span>
        <span>Benchmark : <strong>{item.benchmark_days}j</strong></span>
        <span>{item.resolved_count} résolues</span>
      </div>

      {/* Barre comparative */}
      {item.mttr_days !== null && (
        <div className="space-y-1">
          {/* Benchmark (vert) */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <div className="w-16 text-right">Benchmark</div>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div className="h-full bg-green-400 rounded-full" style={{ width: `${barWidth}%` }} />
            </div>
          </div>
          {/* MTTR réel */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <div className="w-16 text-right">Votre MTTR</div>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  item.status === 'WITHIN_BENCHMARK' ? 'bg-green-500' :
                  item.status === 'SLIGHTLY_ABOVE'  ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${actualWidth}%` }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function MTTRWidget({ data, loading }) {
  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">MTTR — Mean Time to Remediate</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">MTTR — Mean Time to Remediate</CardTitle>
        </CardHeader>
        <CardContent className="p-6 text-center text-sm text-muted-foreground">
          Aucune donnée disponible
        </CardContent>
      </Card>
    );
  }

  const overallStatus = STATUS_CONFIG[data.benchmark_comparison] || STATUS_CONFIG.NO_DATA;

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">MTTR — Mean Time to Remediate</CardTitle>
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            {data.overall_mttr_days !== null ? (
              <span className="text-sm font-bold">
                {data.overall_mttr_days}j moy.
              </span>
            ) : (
              <span className="text-sm text-muted-foreground">N/A</span>
            )}
          </div>
        </div>
        {/* Statut global */}
        <div className={`flex items-center gap-1 text-xs mt-1 ${overallStatus.color}`}>
          {overallStatus.icon}
          <span>{overallStatus.label} vs industrie</span>
          <span className="text-muted-foreground ml-2">
            ({data.total_resolved} vulns résolues)
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {(data.by_severity || []).map((item) => (
            <SeverityRow key={item.severity} item={item} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
