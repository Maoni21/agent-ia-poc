import { Badge } from '@/components/ui/badge';
import { Shield, Flame, TrendingUp } from 'lucide-react';

export function ThreatBadges({ vulnerability }) {
  if (!vulnerability) return null;

  const hasBadge =
    vulnerability.cisa_kev ||
    vulnerability.exploit_available ||
    (vulnerability.epss_score && vulnerability.epss_score > 0.5);

  if (!hasBadge) return null;

  return (
    <div className="flex gap-2 flex-wrap">
      {vulnerability.cisa_kev && (
        <Badge variant="destructive" className="gap-1">
          <Shield className="h-3 w-3" />
          CISA KEV
        </Badge>
      )}

      {vulnerability.exploit_available && (
        <Badge variant="destructive" className="gap-1">
          <Flame className="h-3 w-3" />
          Exploit Available
        </Badge>
      )}

      {vulnerability.epss_score && vulnerability.epss_score > 0.5 && (
        <Badge variant="outline" className="gap-1">
          <TrendingUp className="h-3 w-3" />
          EPSS : {(vulnerability.epss_score * 100).toFixed(1)}%
        </Badge>
      )}
    </div>
  );
}
