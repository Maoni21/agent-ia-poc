import Head from 'next/head';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  FileCode, Loader2, AlertCircle, CheckCircle2, XCircle,
  Clock, Terminal, ChevronDown, ChevronUp, RotateCcw, Shield,
  RefreshCw, AlertTriangle,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import scriptsService from '../lib/services/scriptsService';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  executed:    { label: 'Exécuté',    variant: 'success',     icon: CheckCircle2,   color: 'text-green-500'  },
  approved:    { label: 'Approuvé',   variant: 'secondary',   icon: CheckCircle2,   color: 'text-blue-500'   },
  failed:      { label: 'Échoué',     variant: 'destructive', icon: XCircle,        color: 'text-red-500'    },
  running:     { label: 'En cours',   variant: 'warning',     icon: Loader2,        color: 'text-amber-500'  },
  pending:     { label: 'En attente', variant: 'secondary',   icon: Clock,          color: 'text-slate-400'  },
  rolled_back: { label: 'Annulé',     variant: 'outline',     icon: RotateCcw,      color: 'text-purple-500' },
};

const RISK_CONFIG = {
  CRITICAL: { color: 'text-red-600',    bg: 'bg-red-50 dark:bg-red-950'    },
  HIGH:     { color: 'text-orange-500', bg: 'bg-orange-50 dark:bg-orange-950' },
  MEDIUM:   { color: 'text-amber-500',  bg: 'bg-amber-50 dark:bg-amber-950'  },
  LOW:      { color: 'text-green-500',  bg: 'bg-green-50 dark:bg-green-950'  },
};

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

// ─── Composant ligne de script ─────────────────────────────────────────────────

function ScriptRow({ script }) {
  const [expanded, setExpanded] = useState(false);

  const statusKey = script.execution_status || 'pending';
  const cfg = STATUS_CONFIG[statusKey] || STATUS_CONFIG.pending;
  const Icon = cfg.icon;

  const riskKey = (script.risk_level || 'MEDIUM').toUpperCase();
  const riskCfg = RISK_CONFIG[riskKey] || RISK_CONFIG.MEDIUM;

  const hasContent  = script.script_content && script.script_content.trim().length > 0;
  const hasRollback = script.rollback_script && script.rollback_script.trim().length > 0;
  const hasOutput   = script.execution_output;
  const canExpand   = hasContent || hasRollback || hasOutput;

  return (
    <div className="border rounded-lg overflow-hidden bg-card">
      {/* En-tête */}
      <div
        className={`flex items-center gap-3 px-4 py-3 ${canExpand ? 'cursor-pointer hover:bg-muted/50' : ''} transition-colors`}
        onClick={() => canExpand && setExpanded(!expanded)}
      >
        {/* Icône risque */}
        <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${riskCfg.bg}`}>
          <Shield className={`h-4 w-4 ${riskCfg.color}`} />
        </div>

        {/* Infos principales */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="font-medium text-sm truncate">
              Script {script.script_type?.toUpperCase() || 'BASH'}
            </p>
            <span className={`text-xs font-semibold ${riskCfg.color}`}>
              {riskKey}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            {script.target_os || 'Système cible inconnu'}
            {script.vulnerability_id && (
              <>
                {' · Vulnérabilité '}
                <Link
                  href={`/vulnerabilities/${script.vulnerability_id}`}
                  className="text-primary hover:underline font-mono"
                  onClick={(e) => e.stopPropagation()}
                >
                  {script.vulnerability_id.slice(0, 8)}…
                </Link>
              </>
            )}
            {script.requires_reboot && (
              <span className="ml-2 text-amber-500">⚠ Reboot requis</span>
            )}
          </p>
        </div>

        {/* Statut */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <Icon className={`h-4 w-4 ${cfg.color} ${statusKey === 'running' ? 'animate-spin' : ''}`} />
          <Badge variant={cfg.variant} className="text-xs">{cfg.label}</Badge>
        </div>

        {/* Exit code */}
        {script.exit_code !== null && script.exit_code !== undefined && (
          <div className={`text-xs font-mono flex-shrink-0 ${script.exit_code === 0 ? 'text-green-500' : 'text-red-500'}`}>
            exit {script.exit_code}
          </div>
        )}

        {/* Date */}
        <div className="text-xs text-muted-foreground flex-shrink-0 hidden md:block w-36 text-right">
          {formatDate(script.executed_at || script.created_at)}
        </div>

        {/* Chevron */}
        {canExpand && (
          <div className="flex-shrink-0 text-muted-foreground">
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </div>
        )}
      </div>

      {/* Contenu expandable */}
      {expanded && canExpand && (
        <div className="border-t bg-muted/10 divide-y">
          {/* Script */}
          {hasContent && (
            <div className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <Terminal className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Script {script.script_type}
                  {script.requires_sudo && <span className="ml-2 text-amber-500">sudo requis</span>}
                </span>
              </div>
              <pre className="bg-zinc-950 text-green-400 text-xs font-mono p-4 rounded-md overflow-x-auto whitespace-pre-wrap max-h-72 overflow-y-auto leading-relaxed">
                {script.script_content}
              </pre>
            </div>
          )}

          {/* Rollback */}
          {hasRollback && (
            <div className="p-4">
              <div className="flex items-center gap-2 mb-2">
                <RotateCcw className="h-3.5 w-3.5 text-purple-500" />
                <span className="text-xs font-semibold text-purple-500 uppercase tracking-wider">Script de rollback</span>
              </div>
              <pre className="bg-zinc-950 text-purple-300 text-xs font-mono p-4 rounded-md overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed">
                {script.rollback_script}
              </pre>
            </div>
          )}

          {/* Sortie d'exécution */}
          {hasOutput && (
            <div className="p-4">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Sortie d&apos;exécution</span>
              <pre className="mt-2 bg-zinc-950 text-slate-300 text-xs font-mono p-4 rounded-md overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed">
                {script.execution_output}
              </pre>
            </div>
          )}

          {/* Lien vers la vulnérabilité */}
          {script.vulnerability_id && (
            <div className="px-4 py-2 flex justify-end">
              <Link href={`/vulnerabilities/${script.vulnerability_id}`}>
                <Button variant="ghost" size="sm" className="text-xs gap-1.5">
                  Voir la vulnérabilité associée
                </Button>
              </Link>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Filtres ───────────────────────────────────────────────────────────────────

const FILTERS = [
  { label: 'Tous',        value: null        },
  { label: 'Exécutés',   value: 'executed'  },
  { label: 'Approuvés',  value: 'approved'  },
  { label: 'En attente', value: 'pending'   },
  { label: 'Échoués',    value: 'failed'    },
];

// ─── Page principale ───────────────────────────────────────────────────────────

export default function ScriptsPage() {
  const [scripts, setScripts]           = useState([]);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [filterStatus, setFilterStatus] = useState(null);

  const loadScripts = async (status) => {
    setLoading(true);
    setError(null);
    try {
      const data = await scriptsService.getScripts({ status: status || undefined });
      setScripts(data.scripts || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des scripts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadScripts(filterStatus); }, [filterStatus]);

  const stats = {
    total:    scripts.length,
    executed: scripts.filter(s => s.execution_status === 'executed').length,
    failed:   scripts.filter(s => s.execution_status === 'failed').length,
    pending:  scripts.filter(s => s.execution_status === 'pending').length,
  };

  return (
    <>
      <Head>
        <title>Scripts - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Scripts de remédiation</h1>
            <p className="text-muted-foreground">
              Scripts générés par l&apos;IA pour corriger vos vulnérabilités
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => loadScripts(filterStatus)} className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Actualiser
          </Button>
        </div>

        {/* Stats */}
        {!loading && scripts.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Total',      value: stats.total,    color: 'text-foreground'  },
              { label: 'Exécutés',   value: stats.executed, color: 'text-green-500'   },
              { label: 'Échoués',    value: stats.failed,   color: 'text-red-500'     },
              { label: 'En attente', value: stats.pending,  color: 'text-slate-400'   },
            ].map(({ label, value, color }) => (
              <Card key={label}>
                <CardContent className="pt-4 pb-3">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Filtres */}
        {!loading && scripts.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            {FILTERS.map(f => (
              <Button
                key={f.label}
                variant={filterStatus === f.value ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterStatus(f.value)}
              >
                {f.label}
              </Button>
            ))}
          </div>
        )}

        {/* Erreur */}
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Skeleton */}
        {loading && (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full rounded-lg" />
            ))}
          </div>
        )}

        {/* Vide */}
        {!loading && !error && scripts.length === 0 && (
          <Card>
            <CardContent className="flex flex-col items-center gap-3 py-20 text-muted-foreground">
              <FileCode className="h-14 w-14" />
              <p className="font-semibold text-lg">Aucun script généré</p>
              <p className="text-sm text-center max-w-sm">
                Les scripts apparaissent ici après avoir cliqué sur &quot;Générer un script de remédiation&quot;
                depuis une page de vulnérabilité.
              </p>
              <Link href="/vulnerabilities">
                <Button variant="outline" size="sm" className="mt-2 gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  Voir mes vulnérabilités
                </Button>
              </Link>
            </CardContent>
          </Card>
        )}

        {/* Liste */}
        {!loading && scripts.length > 0 && (
          <div className="space-y-2">
            {scripts.map(script => (
              <ScriptRow key={script.id} script={script} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}
