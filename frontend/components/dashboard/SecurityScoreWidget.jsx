import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { ArrowUp, ArrowDown, Minus } from 'lucide-react';

const RISK_COLORS = {
  LOW:      { text: 'text-green-500',  bar: 'bg-green-500'  },
  MEDIUM:   { text: 'text-yellow-500', bar: 'bg-yellow-500' },
  HIGH:     { text: 'text-orange-500', bar: 'bg-orange-500' },
  CRITICAL: { text: 'text-red-500',    bar: 'bg-red-500'    },
};

export function SecurityScoreWidget({ data, loading }) {
  if (loading || !data) {
    return (
      <Card className="col-span-2">
        <CardHeader>
          <p className="text-sm font-medium text-muted-foreground">Security Posture Score</p>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-4">
            <div className="h-20 bg-muted rounded" />
            <div className="h-3 bg-muted rounded" />
          </div>
        </CardContent>
      </Card>
    );
  }

  const riskColors = RISK_COLORS[data.risk_level] || { text: 'text-gray-500', bar: 'bg-gray-500' };

  const TrendIcon =
    data.direction === 'up'   ? ArrowUp   :
    data.direction === 'down' ? ArrowDown : Minus;

  const trendColor =
    data.direction === 'up'   ? 'text-green-500' :
    data.direction === 'down' ? 'text-red-500'   : 'text-gray-500';

  return (
    <Card className="col-span-2 hover:shadow-lg transition-shadow">
      <CardHeader>
        <p className="text-sm font-medium text-muted-foreground">Security Posture Score</p>
      </CardHeader>
      <CardContent>
        <div className="text-center space-y-4">
          {/* Score principal */}
          <div>
            <h1 className="text-7xl font-bold tracking-tight">{data.current}/100</h1>
            <p className={`text-lg font-semibold mt-2 ${riskColors.text}`}>
              {data.risk_level} RISK
            </p>
          </div>

          {/* Progress bar */}
          <div className="relative h-3">
            <Progress value={data.current} className="h-3" />
            <div
              className={`absolute top-0 left-0 h-3 rounded-full transition-all ${riskColors.bar}`}
              style={{ width: `${data.current}%` }}
            />
          </div>

          {/* Trend */}
          <div className="flex items-center justify-center gap-2">
            <TrendIcon className={`h-5 w-5 ${trendColor}`} />
            <span className={`text-sm font-medium ${trendColor}`}>
              {Math.abs(data.trend)} pts vs last week
            </span>
          </div>

          <p className="text-xs text-muted-foreground">
            Semaine précédente : {data.last_week}/100
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
