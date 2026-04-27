import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import {
  ArrowLeft, Sparkles, Wrench, Play, Copy, CheckCircle, Loader2,
  AlertTriangle, TrendingUp, ShieldAlert, Target, Link2, CheckSquare,
  XCircle, Info, ChevronRight, Shield, Clock, Globe, Database,
  FileText, Activity, AlertCircle, ExternalLink, Server, Zap,
  Lock, Eye, RefreshCw, BookOpen, Code, Terminal, Bug,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { SeverityBadge } from '@/components/ui/severity-badge';
import { CVSSMeter } from '@/components/ui/cvss-meter';
import { StatusBadge } from '@/components/ui/status-badge';
import { Separator } from '@/components/ui/separator';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';
import scriptsService from '../../lib/services/scriptsService';
import { api } from '../../lib/services/api';

// ─────────────────────────────────────────────
// Helper utilities
// ─────────────────────────────────────────────
const formatScore = (val) => {
  if (val == null) return '—';
  const n = typeof val === 'number' ? val : parseFloat(val);
  return Number.isNaN(n) ? String(val) : n.toFixed(1);
};

const daysBetween = (dateStr) => {
  if (!dateStr) return null;
  const diff = Date.now() - new Date(dateStr).getTime();
  return Math.floor(diff / 86400000);
};

const formatDate = (dateStr) => {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
};

// ─────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────

/** Threat-intelligence badges row */
function ThreatBadges({ vuln }) {
  const enriched = vuln?.enriched_data || {};
  const badges = [];

  if (enriched.cisa_kev || vuln?.cisa_kev)
    badges.push({ label: 'CISA KEV', color: 'bg-red-600 text-white', icon: <AlertCircle className="h-3 w-3 mr-1" /> });
  if (enriched.exploit_available || vuln?.exploit_available)
    badges.push({ label: 'Exploit Disponible', color: 'bg-orange-600 text-white', icon: <Bug className="h-3 w-3 mr-1" /> });
  if (enriched.in_the_wild || vuln?.in_the_wild)
    badges.push({ label: 'In-the-Wild', color: 'bg-purple-700 text-white', icon: <Globe className="h-3 w-3 mr-1" /> });
  if (enriched.ransomware_use || vuln?.ransomware_use)
    badges.push({ label: 'Ransomware', color: 'bg-pink-700 text-white', icon: <Lock className="h-3 w-3 mr-1" /> });

  if (badges.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5 mt-2">
      {badges.map((b) => (
        <span key={b.label} className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${b.color}`}>
          {b.icon}{b.label}
        </span>
      ))}
    </div>
  );
}

/** CVSS metrics row with label + value + explanation */
function CVSSRow({ label, value, explanation, highlight }) {
  return (
    <div className={`flex flex-col gap-0.5 py-2 border-b last:border-0 ${highlight ? 'bg-red-50 dark:bg-red-950/20 -mx-4 px-4' : ''}`}>
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium text-muted-foreground">{label}</span>
        <Badge variant="outline" className="font-mono text-xs">{value || '—'}</Badge>
      </div>
      {explanation && <p className="text-xs text-muted-foreground">{explanation}</p>}
    </div>
  );
}

/** Visual progress bar */
function ScoreBar({ value, max = 10, colorClass = 'bg-red-500' }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="w-full bg-muted rounded-full h-2">
      <div className={`h-2 rounded-full transition-all ${colorClass}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

/** Compliance status card */
function ComplianceCard({ framework, requirement, status, detail }) {
  const isNonCompliant = status === 'Non-Compliant' || status === 'At Risk';
  return (
    <div className={`rounded-lg border p-3 ${isNonCompliant ? 'border-orange-400/40 bg-orange-50 dark:bg-orange-950/20' : 'border-green-400/40 bg-green-50 dark:bg-green-950/20'}`}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-semibold text-sm">{framework}</p>
          {requirement && <p className="text-xs text-muted-foreground">{requirement}</p>}
        </div>
        <Badge variant={isNonCompliant ? 'destructive' : 'success'} className="shrink-0 text-xs">
          {status}
        </Badge>
      </div>
      {detail && <p className="text-xs text-muted-foreground mt-1.5">{detail}</p>}
    </div>
  );
}

/** Timeline item */
function TimelineItem({ date, label, icon, variant = 'default', isCurrent }) {
  const colors = {
    default: 'bg-muted text-muted-foreground',
    success: 'bg-green-100 text-green-700 dark:bg-green-900/40',
    danger: 'bg-red-100 text-red-700 dark:bg-red-900/40',
    warning: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40',
    info: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40',
  };
  return (
    <div className={`flex gap-3 items-start py-2 ${isCurrent ? 'font-semibold' : ''}`}>
      <div className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs ${colors[variant]}`}>
        {icon}
      </div>
      <div className="flex-1">
        <p className="text-sm">{label}</p>
        {date && <p className="text-xs text-muted-foreground">{formatDate(date)}</p>}
      </div>
      {isCurrent && <Badge variant="outline" className="text-xs">Actuel</Badge>}
    </div>
  );
}

/** Code block with copy button */
function CodeBlock({ code, language = 'bash' }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="relative rounded-lg overflow-hidden border border-gray-700">
      <div className="flex items-center justify-between bg-gray-900 px-3 py-1.5">
        <span className="text-xs text-gray-400 font-mono">{language}</span>
        <Button variant="ghost" size="sm" className="h-6 text-gray-300 hover:text-white" onClick={copy}>
          {copied ? <CheckCircle className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
          <span className="ml-1 text-xs">{copied ? 'Copié' : 'Copier'}</span>
        </Button>
      </div>
      <pre className="bg-gray-950 text-gray-100 p-4 text-xs overflow-x-auto whitespace-pre-wrap">
        {code}
      </pre>
    </div>
  );
}

// ─────────────────────────────────────────────
// TABS CONTENT
// ─────────────────────────────────────────────

/** Tab: Overview */
function OverviewTab({ vuln }) {
  const enriched = vuln?.enriched_data || {};
  const openDays = daysBetween(vuln?.detected_at || vuln?.created_at);
  const cvePubDays = daysBetween(vuln?.cve_published_date);

  const refs = vuln?.references || enriched?.references || {};
  const nvdUrl = refs.nvd_url || (vuln?.cve_id ? `https://nvd.nist.gov/vuln/detail/${vuln.cve_id}` : null);
  const mitreUrl = refs.mitre_url || (vuln?.cve_id ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}` : null);
  const exploitdbUrl = refs.exploitdb_url || enriched?.exploitdb_url;
  const vendorAdvisory = refs.vendor_advisory || enriched?.vendor_advisory;

  const compliance = vuln?.compliance || enriched?.compliance || {};

  const epssScore = vuln?.epss_score ?? enriched?.epss_score;
  const exploitMaturity = vuln?.exploit_maturity || enriched?.exploit_maturity;
  const metasploitModule = vuln?.metasploit_module || enriched?.metasploit_module;
  const exploitdbId = vuln?.exploitdb_id || enriched?.exploitdb_id;
  const cisakev = vuln?.cisa_kev || enriched?.cisa_kev;
  const inTheWild = vuln?.in_the_wild || enriched?.in_the_wild;
  const exploitAvailable = vuln?.exploit_available || enriched?.exploit_available;

  const affectedAssets = vuln?.affected_assets || enriched?.affected_assets || [];
  const exposedServices = vuln?.exposed_services || enriched?.exposed_services || [];
  const dataAtRisk = vuln?.data_at_risk || enriched?.data_at_risk || [];
  const financialRisk = vuln?.financial_risk || enriched?.financial_risk;
  const reputationalRisk = vuln?.reputational_risk || enriched?.reputational_risk;
  const businessCriticality = vuln?.business_criticality || enriched?.business_criticality;

  const history = vuln?.history || enriched?.history || [];

  return (
    <div className="space-y-5">
      {/* Description */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <FileText className="h-4 w-4 text-blue-500" />
            Description
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {vuln?.description || 'Aucune description disponible.'}
          </p>
          {(vuln?.vulnerability_type || enriched?.vulnerability_types?.length) && (
            <div className="flex flex-wrap gap-1.5 mt-3">
              {(enriched?.vulnerability_types || [vuln?.vulnerability_type]).filter(Boolean).map((t) => (
                <Badge key={t} variant="secondary" className="font-mono text-xs">{t}</Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threat Intelligence */}
      {(exploitAvailable || cisakev || epssScore != null || inTheWild) && (
        <Card className="border-red-400/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-500" />
              Threat Intelligence
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {inTheWild && (
              <Alert variant="destructive" className="py-2">
                <AlertDescription className="text-xs font-semibold">
                  ⚠️ EXPLOITATION ACTIVE DÉTECTÉE DANS LA NATURE (In-the-Wild)
                </AlertDescription>
              </Alert>
            )}
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
              {cisakev != null && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CISA KEV Listed</span>
                  <span className={`font-semibold ${cisakev ? 'text-red-600' : 'text-green-600'}`}>
                    {cisakev ? 'Oui ⚠️' : 'Non'}
                  </span>
                </div>
              )}
              {exploitAvailable != null && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Exploit Disponible</span>
                  <span className={`font-semibold ${exploitAvailable ? 'text-red-600' : 'text-green-600'}`}>
                    {exploitAvailable ? 'Oui ⚠️' : 'Non'}
                  </span>
                </div>
              )}
              {exploitMaturity && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Maturité Exploit</span>
                  <span className="font-semibold">{exploitMaturity}</span>
                </div>
              )}
              {epssScore != null && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">EPSS Score</span>
                  <span className="font-semibold text-orange-600">
                    {(epssScore * 100).toFixed(1)}%
                  </span>
                </div>
              )}
              {metasploitModule && (
                <div className="flex justify-between col-span-2">
                  <span className="text-muted-foreground">Metasploit Module</span>
                  <code className="text-xs font-mono text-orange-600">{metasploitModule}</code>
                </div>
              )}
              {exploitdbId && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ExploitDB ID</span>
                  <a
                    href={`https://www.exploit-db.com/exploits/${exploitdbId}`}
                    target="_blank" rel="noopener noreferrer"
                    className="text-blue-600 hover:underline text-xs font-mono"
                  >
                    #{exploitdbId}
                  </a>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Impact Métier */}
      {(affectedAssets.length > 0 || exposedServices.length > 0 || financialRisk || businessCriticality) && (
        <Card className="border-orange-400/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-orange-500" />
              Impact Métier
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {businessCriticality && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Criticité Business</span>
                <Badge variant={businessCriticality === 'Critical' ? 'destructive' : 'warning'}>{businessCriticality}</Badge>
              </div>
            )}
            {affectedAssets.length > 0 && (
              <div>
                <p className="text-muted-foreground mb-1.5">Assets Affectés ({affectedAssets.length})</p>
                <div className="space-y-1">
                  {affectedAssets.map((a, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs bg-muted rounded px-2 py-1">
                      <Server className="h-3 w-3 text-muted-foreground shrink-0" />
                      <span className="font-mono">{a.hostname || a.asset_id}</span>
                      {a.criticality && <Badge variant="outline" className="ml-auto text-xs">{a.criticality}</Badge>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {exposedServices.length > 0 && (
              <div>
                <p className="text-muted-foreground mb-1">Services Exposés</p>
                <div className="flex flex-wrap gap-1">
                  {exposedServices.map((s, i) => (
                    <code key={i} className="text-xs bg-muted px-2 py-0.5 rounded">{s}</code>
                  ))}
                </div>
              </div>
            )}
            {dataAtRisk.length > 0 && (
              <div>
                <p className="text-muted-foreground mb-1">Données à Risque</p>
                <div className="flex flex-wrap gap-1">
                  {dataAtRisk.map((d, i) => (
                    <Badge key={i} variant="destructive" className="text-xs">{d}</Badge>
                  ))}
                </div>
              </div>
            )}
            {financialRisk && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Risque Financier Estimé</span>
                <span className="font-semibold text-red-600">{financialRisk}</span>
              </div>
            )}
            {reputationalRisk && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Risque Réputationnel</span>
                <span className="font-semibold">{reputationalRisk}</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Clock className="h-4 w-4 text-blue-500" />
            Timeline
          </CardTitle>
        </CardHeader>
        <CardContent className="divide-y">
          {vuln?.cve_published_date && (
            <TimelineItem date={vuln.cve_published_date} label="CVE Publiée" icon="📅" variant="info" />
          )}
          {vuln?.patch_available_date && (
            <TimelineItem date={vuln.patch_available_date} label={`Patch Disponible (v${vuln?.fixed_version || '?'})`} icon="✅" variant="success" />
          )}
          {enriched?.exploit_published_date && (
            <TimelineItem date={enriched.exploit_published_date} label="Exploit Publié" icon="🔴" variant="danger" />
          )}
          {(vuln?.detected_at || vuln?.created_at) && (
            <TimelineItem date={vuln?.detected_at || vuln?.created_at} label={`Première Détection${vuln?.scan_id ? ` (Scan #${vuln.scan_id})` : ''}`} icon="🔍" variant="warning" />
          )}
          {history.map((h, i) => (
            <TimelineItem key={i} date={h.date} label={h.event} icon="•" variant="default" />
          ))}
          <div className="pt-2 flex gap-4 text-xs text-muted-foreground">
            {cvePubDays != null && <span>🕐 CVE: il y a {cvePubDays > 365 ? `${Math.floor(cvePubDays / 365)} an(s)` : `${cvePubDays} j`}</span>}
            {openDays != null && <span className={openDays > 7 ? 'text-red-600 font-semibold' : ''}>⏱ Ouvert: {openDays} jour(s)</span>}
          </div>
        </CardContent>
      </Card>

      {/* Compliance */}
      {Object.keys(compliance).length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-500" />
              Compliance Impact
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 sm:grid-cols-2">
            {compliance.pci_dss && (
              <ComplianceCard framework="PCI DSS 4.0" requirement={`Req. ${compliance.pci_dss.requirement}`} status={compliance.pci_dss.status} detail={compliance.pci_dss.reason} />
            )}
            {compliance.gdpr && (
              <ComplianceCard framework="GDPR" requirement={`Article ${compliance.gdpr.article}`} status="At Risk" detail={compliance.gdpr.risk} />
            )}
            {compliance.iso_27001 && (
              <ComplianceCard framework="ISO 27001" requirement={compliance.iso_27001.control} status="At Risk" detail={compliance.iso_27001.gap} />
            )}
            {compliance.soc2 && (
              <ComplianceCard framework="SOC 2" requirement={compliance.soc2.criteria} status="At Risk" detail={compliance.soc2.finding} />
            )}
            {compliance.nist_csf && (
              <ComplianceCard framework="NIST CSF" requirement={compliance.nist_csf.control} status="At Risk" detail={compliance.nist_csf.detail} />
            )}
          </CardContent>
        </Card>
      )}

      {/* References */}
      {(nvdUrl || mitreUrl || exploitdbUrl || vendorAdvisory) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-muted-foreground" />
              Références
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {nvdUrl && (
              <a href={nvdUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-blue-600 hover:underline">
                <ExternalLink className="h-3 w-3 shrink-0" /> NVD — {vuln?.cve_id}
              </a>
            )}
            {mitreUrl && (
              <a href={mitreUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-blue-600 hover:underline">
                <ExternalLink className="h-3 w-3 shrink-0" /> MITRE CVE
              </a>
            )}
            {vendorAdvisory && (
              <a href={vendorAdvisory} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-blue-600 hover:underline">
                <ExternalLink className="h-3 w-3 shrink-0" /> Vendor Advisory
              </a>
            )}
            {exploitdbUrl && (
              <a href={exploitdbUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-orange-600 hover:underline">
                <Bug className="h-3 w-3 shrink-0" /> ExploitDB
              </a>
            )}
            {(refs.github_pocs || enriched?.github_pocs || []).map((url, i) => (
              <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm text-orange-600 hover:underline">
                <Code className="h-3 w-3 shrink-0" /> GitHub PoC #{i + 1}
              </a>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Tab: CVSS Details */
function CVSSDetailsTab({ vuln }) {
  const score = vuln?.cvss_score;
  const enriched = vuln?.enriched_data || {};
  const [copiedVector, setCopiedVector] = useState(false);

  const vector = vuln?.cvss_vector || enriched?.cvss_vector || '';
  const av = vuln?.attack_vector || enriched?.attack_vector;
  const ac = vuln?.attack_complexity || enriched?.attack_complexity;
  const pr = vuln?.privileges_required || enriched?.privileges_required;
  const ui = vuln?.user_interaction || enriched?.user_interaction;
  const scope = vuln?.scope || enriched?.scope;
  const ci = vuln?.confidentiality_impact || enriched?.confidentiality_impact;
  const ii = vuln?.integrity_impact || enriched?.integrity_impact;
  const ai_impact = vuln?.availability_impact || enriched?.availability_impact;
  const exploitabilityScore = vuln?.exploitability_score ?? enriched?.exploitability_score;
  const impactScore = vuln?.impact_score ?? enriched?.impact_score;

  const cvssExplanations = {
    attack_vector: {
      Network: 'Exploitable à distance via le réseau. Aucun accès physique requis.',
      Adjacent: 'Exploitable via le réseau local (LAN/WiFi) uniquement.',
      Local: 'Exploitation nécessite un accès local à la machine.',
      Physical: 'Nécessite un accès physique à la cible.',
    },
    attack_complexity: {
      Low: 'Aucune condition spéciale requise. Facile à exploiter.',
      High: 'Conditions préalables complexes nécessaires.',
    },
    privileges_required: {
      None: 'Aucune authentification requise. Exploitation anonyme possible.',
      Low: 'Un compte utilisateur basique suffit.',
      High: 'Nécessite des droits administrateur/root.',
    },
    user_interaction: {
      None: "Entièrement automatisable. Aucune action de l'utilisateur cible.",
      Required: "Nécessite qu'un utilisateur effectue une action (clic, ouverture fichier...).",
    },
    scope: {
      Unchanged: 'Impact limité au composant vulnérable.',
      Changed: "L'exploit peut impacter d'autres composants.",
    },
    impact: {
      High: 'Compromission totale.',
      Low: 'Impact limité, informations partielles exposées.',
      None: 'Aucun impact sur ce vecteur.',
    },
  };

  return (
    <div className="space-y-5">
      {/* Score principal */}
      <Card>
        <CardContent className="pt-6">
          <CVSSMeter score={score} />
          {(exploitabilityScore != null || impactScore != null) && (
            <div className="grid grid-cols-2 gap-4 mt-4">
              {exploitabilityScore != null && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Score Exploitabilité</p>
                  <div className="flex items-center gap-2">
                    <ScoreBar value={exploitabilityScore} max={4} colorClass="bg-orange-500" />
                    <span className="text-sm font-bold w-8 shrink-0">{exploitabilityScore}</span>
                  </div>
                </div>
              )}
              {impactScore != null && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Score Impact</p>
                  <div className="flex items-center gap-2">
                    <ScoreBar value={impactScore} max={6} colorClass="bg-red-600" />
                    <span className="text-sm font-bold w-8 shrink-0">{impactScore}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Vector string */}
      {vector && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Vector String CVSS v3.1</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-muted rounded px-3 py-2 text-xs font-mono break-all">{vector}</code>
              <Button
                variant="outline" size="sm"
                onClick={() => { navigator.clipboard.writeText(vector); setCopiedVector(true); setTimeout(() => setCopiedVector(false), 2000); }}
              >
                {copiedVector ? <CheckCircle className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Breakdown */}
      {(av || ac || pr || ui || ci || ii || ai_impact) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Décomposition des Métriques
            </CardTitle>
          </CardHeader>
          <CardContent>
            {av && <CVSSRow label="Attack Vector (AV)" value={av} explanation={cvssExplanations.attack_vector[av]} highlight={av === 'Network'} />}
            {ac && <CVSSRow label="Attack Complexity (AC)" value={ac} explanation={cvssExplanations.attack_complexity[ac]} highlight={ac === 'Low'} />}
            {pr && <CVSSRow label="Privileges Required (PR)" value={pr} explanation={cvssExplanations.privileges_required[pr]} highlight={pr === 'None'} />}
            {ui && <CVSSRow label="User Interaction (UI)" value={ui} explanation={cvssExplanations.user_interaction[ui]} highlight={ui === 'None'} />}
            {scope && <CVSSRow label="Scope (S)" value={scope} explanation={cvssExplanations.scope[scope]} />}
            {ci && <CVSSRow label="Confidentiality Impact (C)" value={ci} explanation={cvssExplanations.impact[ci]} highlight={ci === 'High'} />}
            {ii && <CVSSRow label="Integrity Impact (I)" value={ii} explanation={cvssExplanations.impact[ii]} highlight={ii === 'High'} />}
            {ai_impact && <CVSSRow label="Availability Impact (A)" value={ai_impact} explanation={cvssExplanations.impact[ai_impact]} highlight={ai_impact === 'High'} />}
          </CardContent>
        </Card>
      )}

      {/* Why critical explanation */}
      {score >= 9 && (
        <Card className="border-red-400/40 bg-red-50/30 dark:bg-red-950/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-red-700 dark:text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Pourquoi ce score est Critique ?
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5 text-sm text-muted-foreground">
              {av === 'Network' && <li className="flex gap-2"><ChevronRight className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />Exploitable à distance via internet</li>}
              {pr === 'None' && <li className="flex gap-2"><ChevronRight className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />Aucune authentification requise</li>}
              {ac === 'Low' && <li className="flex gap-2"><ChevronRight className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />Faible complexité — facile à reproduire</li>}
              {ui === 'None' && <li className="flex gap-2"><ChevronRight className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />Entièrement automatisable, aucune interaction utilisateur</li>}
              {ci === 'High' && ii === 'High' && ai_impact === 'High' && <li className="flex gap-2"><ChevronRight className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />Compromission totale (confidentialité, intégrité, disponibilité)</li>}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Tab: Technical Details */
function TechnicalTab({ vuln }) {
  const enriched = vuln?.enriched_data || {};
  const pkgInfo = vuln?.package_info || enriched?.package_info || {};
  const components = vuln?.affected_components || enriched?.affected_components || [];
  const vulnTypes = vuln?.vulnerability_types || enriched?.vulnerability_types || [];
  const attackScenario = vuln?.attack_scenario || enriched?.attack_scenario;
  const cweIds = vuln?.cwe_ids || enriched?.cwe_ids || [];

  return (
    <div className="space-y-5">
      {/* Package info */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Database className="h-4 w-4" />
            Package Information
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-y-2 text-sm">
          {[
            ['Package', vuln?.affected_package || pkgInfo?.name],
            ['Version actuelle', vuln?.affected_version || pkgInfo?.current_version],
            ['Version corrigée', vuln?.fixed_version || pkgInfo?.fixed_version],
            ['Distribution', pkgInfo?.distribution],
            ['Architecture', pkgInfo?.architecture],
            ['Service', vuln?.service ? `${vuln.service}${vuln.port ? ` (port ${vuln.port}/${vuln.protocol || 'tcp'})` : ''}` : null],
          ].filter(([, v]) => v).map(([k, v]) => (
            <div key={k} className="flex justify-between items-center border-b pb-1.5 last:border-0">
              <span className="text-muted-foreground">{k}</span>
              <code className="text-xs font-mono">{v}</code>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* CWE & Components */}
      {(cweIds.length > 0 || vulnTypes.length > 0 || components.length > 0) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Bug className="h-4 w-4" />
              Détails de la Vulnérabilité
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {(cweIds.length > 0 || vulnTypes.length > 0) && (
              <div>
                <p className="text-muted-foreground mb-1.5">Types / CWE</p>
                <div className="flex flex-wrap gap-1.5">
                  {[...cweIds, ...vulnTypes].map((t) => (
                    <Badge key={t} variant="outline" className="font-mono text-xs">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
            {components.length > 0 && (
              <div>
                <p className="text-muted-foreground mb-1.5">Composants Affectés</p>
                <div className="flex flex-wrap gap-1.5">
                  {components.map((c) => (
                    <code key={c} className="text-xs bg-muted px-2 py-0.5 rounded">{c}</code>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Attack scenario */}
      {attackScenario && (
        <Card className="border-orange-400/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-orange-500" />
              Scénario d&apos;Attaque
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed text-muted-foreground">{attackScenario}</p>
          </CardContent>
        </Card>
      )}

      {/* Technical metadata */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Info className="h-4 w-4 text-muted-foreground" />
            Identifiants
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex justify-between items-center border-b pb-1.5">
            <span className="text-muted-foreground">ID Interne</span>
            <code className="text-xs font-mono text-muted-foreground">{vuln?.id}</code>
          </div>
          {vuln?.cve_id && (
            <div className="flex justify-between items-center border-b pb-1.5">
              <span className="text-muted-foreground">CVE ID</span>
              <Badge variant="outline" className="font-mono">{vuln.cve_id}</Badge>
            </div>
          )}
          {(vuln?.hostname || vuln?.asset_hostname) && (
            <div className="flex justify-between items-center border-b pb-1.5">
              <span className="text-muted-foreground">Hostname</span>
              <code className="text-xs font-mono">{vuln.hostname || vuln.asset_hostname}</code>
            </div>
          )}
          {(vuln?.ip_address || vuln?.asset_ip) && (
            <div className="flex justify-between items-center">
              <span className="text-muted-foreground">Adresse IP</span>
              <code className="text-xs font-mono">{vuln.ip_address || vuln.asset_ip}</code>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/** Tab: AI Analysis */
function AIAnalysisTab({ vuln, onAnalyze, analyzing }) {
  const aiRaw = vuln?.ai_analysis;
  const ai = (() => {
    if (!aiRaw) return null;
    if (typeof aiRaw === 'object') return aiRaw;
    try { return JSON.parse(aiRaw); } catch { return null; }
  })();

  return (
    <div className="space-y-4">
      {/* Header card with action */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="text-base">Analyse IA</CardTitle>
            <CardDescription>
              {vuln?.ai_analyzed ? 'Analyse effectuée par Intelligence Artificielle' : 'Aucune analyse IA disponible'}
            </CardDescription>
          </div>
          <Button onClick={onAnalyze} disabled={analyzing}>
            {analyzing
              ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Analyse...</>
              : <><Sparkles className="mr-2 h-4 w-4" />{vuln?.ai_analyzed ? 'Relancer' : 'Analyser'}</>}
          </Button>
        </CardHeader>
      </Card>

      {!ai ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Sparkles className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">Cliquez sur &quot;Analyser&quot; pour lancer l&apos;analyse IA</p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Scores row */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {(ai.priority_score ?? vuln?.ai_priority_score) != null && (
              <Card className="border-primary/30 bg-primary/5">
                <CardContent className="pt-4 pb-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Score Priorité IA</p>
                  <p className="text-3xl font-bold text-primary">
                    {ai.priority_score ?? vuln?.ai_priority_score}
                    <span className="text-sm font-normal text-muted-foreground">/10</span>
                  </p>
                </CardContent>
              </Card>
            )}
            {ai.exploitability && (
              <Card className={ai.exploitability === 'HIGH' ? 'border-red-500/30 bg-red-500/5' : 'border-amber-500/30 bg-amber-500/5'}>
                <CardContent className="pt-4 pb-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Exploitabilité</p>
                  <Badge variant={ai.exploitability === 'HIGH' ? 'destructive' : 'warning'} className="text-sm px-3">
                    {ai.exploitability}
                  </Badge>
                </CardContent>
              </Card>
            )}
            {ai.is_false_positive != null && (
              <Card className={ai.is_false_positive ? 'border-green-500/30 bg-green-500/5' : 'border-orange-500/30 bg-orange-500/5'}>
                <CardContent className="pt-4 pb-4 text-center">
                  <p className="text-xs text-muted-foreground mb-1">Faux Positif</p>
                  <div className="flex items-center justify-center gap-1.5">
                    {ai.is_false_positive
                      ? <XCircle className="h-5 w-5 text-green-600" />
                      : <CheckSquare className="h-5 w-5 text-orange-500" />}
                    <span className="font-semibold text-sm">{ai.is_false_positive ? 'Probable' : 'Non'}</span>
                  </div>
                  {ai.false_positive_confidence != null && (
                    <p className="text-xs text-muted-foreground mt-1">confiance : {Math.round(ai.false_positive_confidence * 100)}%</p>
                  )}
                </CardContent>
              </Card>
            )}
          </div>

          {ai.ai_explanation && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Info className="h-4 w-4 text-blue-500" />Explication IA
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm leading-relaxed">{ai.ai_explanation}</p>
              </CardContent>
            </Card>
          )}

          {(ai.impact_analysis || ai.business_impact) && (
            <div className="grid gap-4 md:grid-cols-2">
              {ai.impact_analysis && (
                <Card className="border-orange-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-orange-500" />Impact technique
                    </CardTitle>
                  </CardHeader>
                  <CardContent><p className="text-sm text-muted-foreground leading-relaxed">{ai.impact_analysis}</p></CardContent>
                </Card>
              )}
              {ai.business_impact && (
                <Card className="border-red-500/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <TrendingUp className="h-4 w-4 text-red-500" />Impact métier
                    </CardTitle>
                  </CardHeader>
                  <CardContent><p className="text-sm text-muted-foreground leading-relaxed">{ai.business_impact}</p></CardContent>
                </Card>
              )}
            </div>
          )}

          {ai.recommended_actions?.length > 0 && (
            <Card className="border-green-500/20">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Target className="h-4 w-4 text-green-600" />Actions recommandées
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {ai.recommended_actions.map((action, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <ChevronRight className="h-4 w-4 text-green-600 mt-0.5 shrink-0" />
                      <span>{action}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          {ai.false_positive_reasoning && (
            <Card className="border-muted bg-muted/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-muted-foreground">
                  <AlertTriangle className="h-4 w-4" />Raisonnement faux positif
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground leading-relaxed italic">{ai.false_positive_reasoning}</p>
              </CardContent>
            </Card>
          )}

          {ai.solution_links?.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Link2 className="h-4 w-4" />Ressources
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1">
                  {ai.solution_links.map((link, i) => (
                    <li key={i}>
                      <a href={link} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-600 hover:underline break-all">{link}</a>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

/** Tab: Remediation */
function RemediationTab({
  vuln, script, scriptGenerating, scriptLoading, scriptError,
  onGenerate, onApprove, onExecute, onCopy, copied,
  sshHost, setSshHost, sshUser, setSshUser, sshPassword, setSshPassword, executing,
}) {
  const enriched = vuln?.enriched_data || {};
  const remInfo = vuln?.remediation || enriched?.remediation || {};
  const manualSteps = remInfo.manual_steps || enriched?.manual_steps || [];
  const workarounds = remInfo.workarounds || enriched?.workarounds || [];
  const dependencies = remInfo.dependencies || enriched?.dependencies || [];
  const estimatedMin = remInfo.estimated_time_minutes ?? enriched?.estimated_time_minutes;
  const successRate = remInfo.success_rate ?? enriched?.success_rate;
  const patchInfo = remInfo.patch_info || enriched?.patch_info || {};
  const currentVersion = patchInfo?.current_version || vuln?.affected_version;
  const fixedVersion = patchInfo?.fixed_version || vuln?.fixed_version;

  return (
    <div className="space-y-5">
      {scriptError && (
        <Alert variant="destructive">
          <AlertDescription>{scriptError}</AlertDescription>
        </Alert>
      )}

      {/* Quick patch info */}
      {(fixedVersion || estimatedMin || successRate) && (
        <Card className="border-green-400/30 bg-green-50/30 dark:bg-green-950/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-green-700 dark:text-green-400">
              <CheckCircle className="h-4 w-4" />
              Solution Recommandée
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-4">
            {fixedVersion && (
              <div>
                <p className="text-xs text-muted-foreground">Version corrigée</p>
                <code className="font-semibold font-mono text-green-700">{fixedVersion}</code>
              </div>
            )}
            {currentVersion && (
              <div>
                <p className="text-xs text-muted-foreground">Version actuelle</p>
                <code className="font-semibold font-mono text-red-600">{currentVersion}</code>
              </div>
            )}
            {estimatedMin != null && (
              <div>
                <p className="text-xs text-muted-foreground">Temps estimé</p>
                <span className="font-semibold">{estimatedMin} min</span>
              </div>
            )}
            {successRate != null && (
              <div>
                <p className="text-xs text-muted-foreground">Taux de succès</p>
                <span className="font-semibold">{(successRate * 100).toFixed(0)}%</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Script Generation */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="text-base">Script de Remédiation</CardTitle>
            <CardDescription>Générez et exécutez un script de correction automatique</CardDescription>
          </div>
          {!script && (
            <Button onClick={onGenerate} disabled={scriptGenerating}>
              {scriptGenerating
                ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Génération...</>
                : <><Wrench className="mr-2 h-4 w-4" />Générer le script</>}
            </Button>
          )}
        </CardHeader>
        {script && (
          <CardContent className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{script.script_type}</Badge>
                  <Badge variant="outline">{script.target_os}</Badge>
                  {script.execution_status && (
                    <Badge variant={script.execution_status === 'approved' ? 'success' : 'secondary'}>
                      {script.execution_status}
                    </Badge>
                  )}
                </div>
                <Button variant="outline" size="sm" onClick={onCopy}>
                  {copied ? <><CheckCircle className="mr-2 h-4 w-4 text-green-500" />Copié</> : <><Copy className="mr-2 h-4 w-4" />Copier</>}
                </Button>
              </div>
              <pre className="bg-gray-950 text-gray-100 rounded-lg p-4 text-xs overflow-x-auto max-h-72">
                {script.script_content || '# (vide)'}
              </pre>
            </div>

            {script.rollback_script && (
              <div>
                <p className="text-sm font-medium text-amber-600 mb-2 flex items-center gap-2">
                  <RefreshCw className="h-3.5 w-3.5" />Script de rollback
                </p>
                <pre className="bg-gray-950 text-gray-100 rounded-lg p-4 text-xs overflow-x-auto max-h-40">
                  {script.rollback_script}
                </pre>
              </div>
            )}

            <Separator />
            {/* SSH Execution */}
            <div className="space-y-3">
              <p className="text-sm font-medium flex items-center gap-2">
                <Terminal className="h-4 w-4" />Exécution SSH
              </p>
              <Alert variant="warning">
                <AlertDescription>
                  ⚠️ Cette action modifie le système cible. Vérifiez le script avant d&apos;exécuter.
                </AlertDescription>
              </Alert>
              <div className="grid gap-3 md:grid-cols-3">
                <div className="space-y-1">
                  <Label>SSH Host</Label>
                  <Input placeholder="192.168.1.100" value={sshHost} onChange={(e) => setSshHost(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label>Username</Label>
                  <Input placeholder="root" value={sshUser} onChange={(e) => setSshUser(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label>Password</Label>
                  <Input type="password" placeholder="••••••" value={sshPassword} onChange={(e) => setSshPassword(e.target.value)} />
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" onClick={onApprove} disabled={scriptLoading || script.execution_status === 'approved'}>
                  Approuver
                </Button>
                <Button variant="destructive" onClick={onExecute} disabled={executing}>
                  {executing ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Exécution...</> : <><Play className="mr-2 h-4 w-4" />Exécuter (SSH)</>}
                </Button>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Manual Steps */}
      {manualSteps.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Code className="h-4 w-4" />Étapes Manuelles
            </CardTitle>
          </CardHeader>
          <CardContent>
            <CodeBlock code={manualSteps.join('\n')} language="bash" />
          </CardContent>
        </Card>
      )}

      {/* Workarounds */}
      {workarounds.length > 0 && (
        <Card className="border-amber-400/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <Shield className="h-4 w-4" />Workarounds Temporaires
            </CardTitle>
            <CardDescription>Ces mesures NE remplacent PAS le patch</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {workarounds.map((w, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <span className="text-amber-600 font-bold shrink-0">{i + 1}.</span>
                  <span>{w}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* Dependencies */}
      {dependencies.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" />Dépendances à Vérifier
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1.5">
              {dependencies.map((d) => (
                <Badge key={d} variant="outline" className="text-xs">{d}</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Tab: Evidence */
function EvidenceTab({ vuln }) {
  const enriched = vuln?.enriched_data || {};
  const evidence = vuln?.evidence || enriched?.evidence || {};
  const scanner = evidence.scanner || vuln?.scanner;
  const detectionMethod = evidence.detection_method || vuln?.detection_method;
  const confidence = evidence.confidence ?? vuln?.confidence;
  const rawOutput = evidence.raw_output || vuln?.raw_output;

  if (!scanner && !rawOutput && !detectionMethod) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <Eye className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">Aucune donnée de détection disponible</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Eye className="h-4 w-4" />Détails de Détection
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {scanner && (
            <div className="flex justify-between border-b pb-1.5">
              <span className="text-muted-foreground">Scanner</span>
              <span className="font-medium">{scanner}</span>
            </div>
          )}
          {detectionMethod && (
            <div className="flex justify-between border-b pb-1.5">
              <span className="text-muted-foreground">Méthode</span>
              <span className="font-medium">{detectionMethod}</span>
            </div>
          )}
          {confidence != null && (
            <div className="flex items-center justify-between border-b pb-1.5">
              <span className="text-muted-foreground">Confiance</span>
              <div className="flex items-center gap-2">
                <div className="w-24">
                  <ScoreBar value={confidence * 100} max={100} colorClass="bg-green-500" />
                </div>
                <span className="font-semibold text-sm w-10 text-right">{(confidence * 100).toFixed(0)}%</span>
              </div>
            </div>
          )}
          {vuln?.port && (
            <div className="flex justify-between">
              <span className="text-muted-foreground">Port</span>
              <code className="font-mono">{vuln.port}/{vuln.protocol || 'tcp'}</code>
            </div>
          )}
        </CardContent>
      </Card>

      {rawOutput && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Terminal className="h-4 w-4" />Raw Output
            </CardTitle>
          </CardHeader>
          <CardContent>
            <CodeBlock code={rawOutput} language="text" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────
// MAIN PAGE
// ─────────────────────────────────────────────
export default function VulnerabilityDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [vuln, setVuln] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [scriptGenerating, setScriptGenerating] = useState(false);
  const [scriptLoading, setScriptLoading] = useState(false);
  const [scriptError, setScriptError] = useState(null);
  const [script, setScript] = useState(null);
  const [copied, setCopied] = useState(false);

  const [sshHost, setSshHost] = useState('');
  const [sshUser, setSshUser] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [executing, setExecuting] = useState(false);

  const loadVuln = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get(`/api/v1/vulnerabilities/${id}`);
      setVuln(data.data || data);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement de la vulnérabilité');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadVuln(); }, [id]);

  const handleAnalyze = async () => {
    if (!id) return;
    setAnalyzing(true);
    try {
      await vulnerabilitiesService.analyzeVulnerability(id);
      await loadVuln();
    } catch (err) {
      alert('Erreur analyse IA: ' + (err.message || 'inconnue'));
    } finally {
      setAnalyzing(false);
    }
  };

  const handleGenerateScript = async () => {
    if (!id) return;
    setScriptGenerating(true);
    setScriptError(null);
    try {
      const result = await vulnerabilitiesService.generateScript(id, {
        target_system: 'ubuntu-22.04',
        script_type: 'bash',
      });
      if (result.script_id) {
        const scriptDetails = await scriptsService.getScript(result.script_id);
        setScript(scriptDetails);
      }
    } catch (err) {
      setScriptError(err.message || 'Erreur lors de la génération du script');
    } finally {
      setScriptGenerating(false);
    }
  };

  const handleApproveScript = async () => {
    if (!script?.id) return;
    setScriptLoading(true);
    try {
      await api.put(`/api/v1/remediation-scripts/${script.id}/approve`);
      const refreshed = await scriptsService.getScript(script.id);
      setScript(refreshed);
    } catch (err) {
      setScriptError(err.message || 'Erreur approbation');
    } finally {
      setScriptLoading(false);
    }
  };

  const handleExecuteScript = async () => {
    if (!script?.id) return;
    if (!sshHost || !sshUser || !sshPassword) {
      alert('Veuillez renseigner host, username et password SSH.');
      return;
    }
    setExecuting(true);
    try {
      await api.post(`/api/v1/remediation-scripts/${script.id}/execute`, {
        host: sshHost, username: sshUser, password: sshPassword,
      });
      alert('Exécution du script lancée.');
    } catch (err) {
      setScriptError(err.message || 'Erreur exécution');
    } finally {
      setExecuting(false);
    }
  };

  const handleCopyScript = () => {
    if (script?.script_content) {
      navigator.clipboard.writeText(script.script_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Header derived values
  const openDays = daysBetween(vuln?.detected_at || vuln?.created_at);
  const epssScore = vuln?.epss_score ?? vuln?.enriched_data?.epss_score;
  const slaDaysLeft = vuln?.sla_deadline
    ? Math.ceil((new Date(vuln.sla_deadline) - Date.now()) / 86400000)
    : null;

  return (
    <>
      <Head>
        <title>{vuln?.cve_id || 'Vulnérabilité'} — CyberSec AI</title>
      </Head>

      <div className="space-y-5 max-w-4xl mx-auto pb-10">
        {/* ── HEADER ── */}
        <div className="flex items-start gap-3">
          <Button variant="ghost" size="icon" className="shrink-0 mt-0.5" onClick={() => router.push('/vulnerabilities')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>

          {loading ? (
            <div className="flex-1 space-y-2">
              <Skeleton className="h-8 w-64" />
              <Skeleton className="h-5 w-96" />
            </div>
          ) : vuln ? (
            <div className="flex-1 min-w-0">
              <h1 className="text-2xl font-bold leading-tight">
                {vuln.title || vuln.name || vuln.cve_id}
              </h1>

              {/* Badges */}
              <div className="flex flex-wrap gap-2 mt-2">
                <SeverityBadge severity={vuln.severity} />
                {vuln.cve_id && <Badge variant="outline" className="font-mono">{vuln.cve_id}</Badge>}
                <StatusBadge status={vuln.status || 'open'} />
                {vuln.ai_analyzed && (
                  <Badge variant="secondary">
                    <Sparkles className="mr-1 h-3 w-3" />IA Analysée
                  </Badge>
                )}
              </div>

              {/* Threat badges */}
              <ThreatBadges vuln={vuln} />

              {/* Stats strip */}
              <div className="flex flex-wrap gap-x-5 gap-y-1 mt-3 text-xs text-muted-foreground">
                {vuln.cvss_score != null && (
                  <span>CVSS <span className="font-bold text-foreground">{formatScore(vuln.cvss_score)}/10</span></span>
                )}
                {epssScore != null && (
                  <span>EPSS <span className="font-bold text-orange-600">{(epssScore * 100).toFixed(1)}%</span></span>
                )}
                {openDays != null && (
                  <span className={openDays > 7 ? 'text-red-600 font-semibold' : ''}>
                    Ouvert: {openDays}j
                  </span>
                )}
                {slaDaysLeft != null && (
                  <span className={slaDaysLeft <= 1 ? 'text-red-600 font-semibold' : slaDaysLeft <= 3 ? 'text-orange-600' : ''}>
                    SLA: {slaDaysLeft > 0 ? `${slaDaysLeft}j restants` : `Dépassé (${Math.abs(slaDaysLeft)}j)`}
                  </span>
                )}
              </div>
            </div>
          ) : null}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading ? (
          <div className="space-y-4">
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-48 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : !vuln ? (
          <Alert><AlertDescription>Vulnérabilité introuvable.</AlertDescription></Alert>
        ) : (
          <Tabs defaultValue="overview">
            <TabsList className="grid w-full grid-cols-3 sm:grid-cols-6 h-auto gap-0.5">
              <TabsTrigger value="overview" className="text-xs py-1.5">Vue d&apos;ensemble</TabsTrigger>
              <TabsTrigger value="cvss" className="text-xs py-1.5">CVSS</TabsTrigger>
              <TabsTrigger value="technical" className="text-xs py-1.5">Technique</TabsTrigger>
              <TabsTrigger value="ai" className="text-xs py-1.5">Analyse IA</TabsTrigger>
              <TabsTrigger value="remediation" className="text-xs py-1.5">Remédiation</TabsTrigger>
              <TabsTrigger value="evidence" className="text-xs py-1.5">Evidence</TabsTrigger>
            </TabsList>

            <TabsContent value="overview">
              <OverviewTab vuln={vuln} />
            </TabsContent>

            <TabsContent value="cvss">
              <CVSSDetailsTab vuln={vuln} />
            </TabsContent>

            <TabsContent value="technical">
              <TechnicalTab vuln={vuln} />
            </TabsContent>

            <TabsContent value="ai">
              <AIAnalysisTab vuln={vuln} onAnalyze={handleAnalyze} analyzing={analyzing} />
            </TabsContent>

            <TabsContent value="remediation">
              <RemediationTab
                vuln={vuln}
                script={script}
                scriptGenerating={scriptGenerating}
                scriptLoading={scriptLoading}
                scriptError={scriptError}
                onGenerate={handleGenerateScript}
                onApprove={handleApproveScript}
                onExecute={handleExecuteScript}
                onCopy={handleCopyScript}
                copied={copied}
                sshHost={sshHost} setSshHost={setSshHost}
                sshUser={sshUser} setSshUser={setSshUser}
                sshPassword={sshPassword} setSshPassword={setSshPassword}
                executing={executing}
              />
            </TabsContent>

            <TabsContent value="evidence">
              <EvidenceTab vuln={vuln} />
            </TabsContent>
          </Tabs>
        )}
      </div>
    </>
  );
}
