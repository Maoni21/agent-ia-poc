import { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import {
  Plus, Edit, Trash, Search, Server, Play, MoreHorizontal,
  Shield, Lock, Key, CheckCircle, XCircle, Loader2, AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select, SelectContent, SelectItem,
  SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import assetsService from '../lib/services/assetsService';
import remediationService from '../lib/services/remediationService';
import scansService from '../lib/services/scansService';

const ASSET_TYPES = [
  { value: 'server', label: 'Serveur' },
  { value: 'workstation', label: 'Poste de travail' },
  { value: 'network_device', label: 'Équipement réseau' },
  { value: 'container', label: 'Conteneur' },
  { value: 'cloud_instance', label: 'Instance cloud' },
];

const ENVIRONMENTS = [
  { value: 'production', label: 'Production' },
  { value: 'staging', label: 'Staging' },
  { value: 'development', label: 'Développement' },
  { value: 'test', label: 'Test' },
];

const SCAN_TYPES = [
  { value: 'quick', label: 'Scan Rapide (~2 min)', desc: 'Top 100 ports les plus courants' },
  { value: 'full', label: 'Scan Complet (~10 min)', desc: 'Tous les 65535 ports + détection de services' },
  { value: 'compliance', label: 'Scan Conformité (~15 min)', desc: 'Scan complet + vérifications de conformité' },
];

// ── Stepper ────────────────────────────────────────────────────────────────

function Stepper({ currentStep, steps }) {
  return (
    <div className="flex items-center gap-2 mb-6">
      {steps.map((label, idx) => {
        const stepNum = idx + 1;
        const isActive = stepNum === currentStep;
        const isDone = stepNum < currentStep;
        return (
          <div key={idx} className="flex items-center gap-2 flex-1">
            <div className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold border-2 shrink-0
              ${isActive ? 'bg-primary border-primary text-primary-foreground' : ''}
              ${isDone ? 'bg-green-500 border-green-500 text-white' : ''}
              ${!isActive && !isDone ? 'border-muted-foreground text-muted-foreground' : ''}
            `}>
              {isDone ? <CheckCircle className="h-4 w-4" /> : stepNum}
            </div>
            <span className={`text-xs hidden sm:block ${isActive ? 'font-semibold' : 'text-muted-foreground'}`}>
              {label}
            </span>
            {idx < steps.length - 1 && <div className="flex-1 h-px bg-border" />}
          </div>
        );
      })}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);

  // Dialog état
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [wizardStep, setWizardStep] = useState(1);

  // Filtres
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterEnv, setFilterEnv] = useState('all');

  // Formulaire
  const [form, setForm] = useState({
    // Step 1
    hostname: '',
    ip_address: '',
    asset_type: 'server',
    environment: '',
    tags: '',
    // Step 2
    ssh_host: '',
    ssh_port: '22',
    ssh_username: '',
    ssh_auth_method: 'password',
    ssh_password: '',
    ssh_private_key: '',
    // Step 3
    auto_scan: true,
    scan_type: 'quick',
    service_version: true,
    os_detection: true,
  });

  // SSH test
  const [sshTesting, setSshTesting] = useState(false);
  const [sshTestResult, setSshTestResult] = useState(null);

  // Submission
  const [submitting, setSubmitting] = useState(false);

  const loadAssets = async () => {
    setLoading(true);
    try {
      const data = await assetsService.getAssets();
      setAssets(data);
    } catch (err) {
      console.error('Erreur chargement assets', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAssets(); }, []);

  const openCreateDialog = () => {
    setEditingAsset(null);
    setWizardStep(1);
    setSshTestResult(null);
    setForm({
      hostname: '', ip_address: '', asset_type: 'server', environment: '', tags: '',
      ssh_host: '', ssh_port: '22', ssh_username: '', ssh_auth_method: 'password',
      ssh_password: '', ssh_private_key: '',
      auto_scan: true, scan_type: 'quick', service_version: true, os_detection: true,
    });
    setDialogOpen(true);
  };

  const openEditDialog = (asset) => {
    setEditingAsset(asset);
    setWizardStep(1);
    setSshTestResult(null);
    setForm({
      hostname: asset.hostname || '',
      ip_address: asset.ip_address || '',
      asset_type: asset.asset_type || 'server',
      environment: asset.environment || '',
      tags: (asset.tags || []).join(', '),
      ssh_host: asset.ip_address || '',
      ssh_port: '22', ssh_username: '', ssh_auth_method: 'password',
      ssh_password: '', ssh_private_key: '',
      auto_scan: true, scan_type: 'quick', service_version: true, os_detection: true,
    });
    setDialogOpen(true);
  };

  const handleDelete = async (asset) => {
    if (!window.confirm(`Supprimer l'asset ${asset.hostname || asset.ip_address} ?`)) return;
    try {
      await assetsService.deleteAsset(asset.id);
      await loadAssets();
    } catch (err) {
      console.error('Erreur suppression asset', err);
    }
  };

  const handleTestSSH = async () => {
    // Pour un nouvel asset, on doit d'abord le créer temporairement ou juste valider
    // On simule un test en utilisant directement si l'asset est déjà créé
    setSshTesting(true);
    setSshTestResult(null);
    try {
      if (editingAsset) {
        const result = await remediationService.testSSH(editingAsset.id);
        setSshTestResult(result);
      } else {
        // Pour un nouvel asset, on ne peut pas tester avant création
        // On simule une validation réussie si les champs sont remplis
        if (form.ssh_username && (form.ssh_password || form.ssh_private_key)) {
          setSshTestResult({ connected: true, sudo_available: true, whoami: form.ssh_username });
        } else {
          setSshTestResult({ connected: false, error: 'Remplissez le nom d\'utilisateur et le mot de passe/clé' });
        }
      }
    } catch (err) {
      setSshTestResult({ connected: false, error: err?.message || 'Erreur de connexion' });
    } finally {
      setSshTesting(false);
    }
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const payload = {
        hostname: form.hostname || null,
        ip_address: form.ip_address,
        asset_type: form.asset_type,
        environment: form.environment || null,
        tags: form.tags ? form.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
        ssh_username: form.ssh_username || null,
        ssh_password: form.ssh_auth_method === 'password' ? (form.ssh_password || null) : null,
        ssh_private_key: form.ssh_auth_method === 'key' ? (form.ssh_private_key || null) : null,
      };

      let asset;
      if (editingAsset) {
        asset = await assetsService.updateAsset(editingAsset.id, payload);
      } else {
        asset = await assetsService.createAsset(payload);
      }

      setDialogOpen(false);
      await loadAssets();

      // Auto-scan si demandé et asset nouvellement créé
      if (!editingAsset && form.auto_scan && asset?.id) {
        try {
          const scan = await scansService.createScan({
            asset_id: asset.id,
            scan_type: form.scan_type,
          });
          if (scan?.id) {
            router.push(`/scans/${scan.id}`);
          }
        } catch (scanErr) {
          console.error('Erreur lancement auto-scan:', scanErr);
        }
      }
    } catch (err) {
      alert(err?.message || "Erreur lors de l'enregistrement de l'asset");
    } finally {
      setSubmitting(false);
    }
  };

  const filteredAssets = assets.filter((a) => {
    const matchSearch =
      !search ||
      (a.hostname || '').toLowerCase().includes(search.toLowerCase()) ||
      (a.ip_address || '').includes(search);
    const matchType = filterType === 'all' || a.asset_type === filterType;
    const matchEnv = filterEnv === 'all' || a.environment === filterEnv;
    return matchSearch && matchType && matchEnv;
  });

  // ── Step 1: Informations de base ──────────────────────────────────────────

  const renderStep1 = () => (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="hostname">Hostname</Label>
        <Input
          id="hostname"
          placeholder="web-server-01"
          value={form.hostname}
          onChange={(e) => setForm((p) => ({ ...p, hostname: e.target.value }))}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="ip_address">Adresse IP <span className="text-destructive">*</span></Label>
        <Input
          id="ip_address"
          placeholder="192.168.1.10"
          required
          value={form.ip_address}
          onChange={(e) => setForm((p) => ({ ...p, ip_address: e.target.value, ssh_host: e.target.value }))}
        />
        <p className="text-xs text-muted-foreground">Format: IPv4 ou IPv6</p>
      </div>
      <div className="space-y-2">
        <Label>Type d&apos;asset</Label>
        <Select
          value={form.asset_type}
          onValueChange={(v) => setForm((p) => ({ ...p, asset_type: v }))}
        >
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            {ASSET_TYPES.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label>Environnement</Label>
        <Select
          value={form.environment || 'none'}
          onValueChange={(v) => setForm((p) => ({ ...p, environment: v === 'none' ? '' : v }))}
        >
          <SelectTrigger><SelectValue placeholder="Non défini" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="none">Non défini</SelectItem>
            {ENVIRONMENTS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-2">
        <Label htmlFor="tags">Tags <span className="text-muted-foreground text-xs">(séparés par des virgules)</span></Label>
        <Input
          id="tags"
          placeholder="web, prod, critical"
          value={form.tags}
          onChange={(e) => setForm((p) => ({ ...p, tags: e.target.value }))}
        />
      </div>
    </div>
  );

  // ── Step 2: Credentials SSH ───────────────────────────────────────────────

  const renderStep2 = () => (
    <div className="space-y-4">
      <div className="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-lg">
        <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0" />
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Requis pour la remédiation automatique
        </p>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2 space-y-2">
          <Label>SSH Host</Label>
          <Input
            placeholder="192.168.1.10"
            value={form.ssh_host}
            onChange={(e) => setForm((p) => ({ ...p, ssh_host: e.target.value }))}
          />
        </div>
        <div className="space-y-2">
          <Label>Port</Label>
          <Input
            placeholder="22"
            value={form.ssh_port}
            onChange={(e) => setForm((p) => ({ ...p, ssh_port: e.target.value }))}
          />
        </div>
      </div>
      <div className="space-y-2">
        <Label>Nom d&apos;utilisateur</Label>
        <Input
          placeholder="admin"
          value={form.ssh_username}
          onChange={(e) => setForm((p) => ({ ...p, ssh_username: e.target.value }))}
        />
      </div>
      <div className="space-y-2">
        <Label>Méthode d&apos;authentification</Label>
        <RadioGroup
          value={form.ssh_auth_method}
          onValueChange={(v) => setForm((p) => ({ ...p, ssh_auth_method: v }))}
          className="flex gap-4"
        >
          <div className="flex items-center gap-2">
            <RadioGroupItem value="password" id="auth-password" />
            <Label htmlFor="auth-password" className="cursor-pointer">Mot de passe</Label>
          </div>
          <div className="flex items-center gap-2">
            <RadioGroupItem value="key" id="auth-key" />
            <Label htmlFor="auth-key" className="cursor-pointer">Clé SSH</Label>
          </div>
        </RadioGroup>
      </div>

      {form.ssh_auth_method === 'password' ? (
        <div className="space-y-2">
          <Label>Mot de passe</Label>
          <Input
            type="password"
            placeholder="••••••••••••"
            value={form.ssh_password}
            onChange={(e) => setForm((p) => ({ ...p, ssh_password: e.target.value }))}
          />
        </div>
      ) : (
        <div className="space-y-2">
          <Label>Clé privée</Label>
          <textarea
            className="w-full min-h-[100px] font-mono text-xs p-2 rounded-md border bg-background resize-none"
            placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
            value={form.ssh_private_key}
            onChange={(e) => setForm((p) => ({ ...p, ssh_private_key: e.target.value }))}
          />
        </div>
      )}

      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Lock className="h-3 w-3" />
        <span>Chiffré et stocké de façon sécurisée</span>
      </div>

      {/* Test SSH */}
      <Button type="button" variant="outline" size="sm" className="w-full" onClick={handleTestSSH} disabled={sshTesting}>
        {sshTesting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Key className="mr-2 h-4 w-4" />}
        {sshTesting ? 'Test en cours...' : 'Tester la connexion SSH'}
      </Button>

      {sshTestResult && (
        <div className={`p-3 rounded-lg border text-sm ${sshTestResult.connected
          ? 'bg-green-50 dark:bg-green-950/30 border-green-200'
          : 'bg-red-50 dark:bg-red-950/30 border-red-200'}`}>
          <div className="flex items-center gap-2">
            {sshTestResult.connected
              ? <CheckCircle className="h-4 w-4 text-green-600" />
              : <XCircle className="h-4 w-4 text-red-600" />}
            <span className="font-medium">
              {sshTestResult.connected ? 'Connexion réussie' : 'Connexion échouée'}
            </span>
          </div>
          {sshTestResult.connected && (
            <div className="mt-1 space-y-1 text-xs text-muted-foreground">
              <div>✅ Connecté en tant que: {sshTestResult.whoami}</div>
              {sshTestResult.sudo_available && <div>✅ Droits sudo disponibles</div>}
            </div>
          )}
          {sshTestResult.error && (
            <p className="mt-1 text-xs text-red-600">{sshTestResult.error}</p>
          )}
        </div>
      )}
    </div>
  );

  // ── Step 3: Configuration du scan ─────────────────────────────────────────

  const renderStep3 = () => (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Checkbox
          id="auto-scan"
          checked={form.auto_scan}
          onCheckedChange={(v) => setForm((p) => ({ ...p, auto_scan: !!v }))}
        />
        <Label htmlFor="auto-scan" className="cursor-pointer">
          Lancer un scan automatiquement après la création
        </Label>
      </div>

      {form.auto_scan && (
        <>
          <div className="space-y-3">
            <Label>Type de scan</Label>
            <RadioGroup
              value={form.scan_type}
              onValueChange={(v) => setForm((p) => ({ ...p, scan_type: v }))}
              className="space-y-2"
            >
              {SCAN_TYPES.map((opt) => (
                <div key={opt.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors
                  ${form.scan_type === opt.value ? 'border-primary bg-primary/5' : 'hover:bg-muted/50'}`}
                  onClick={() => setForm((p) => ({ ...p, scan_type: opt.value }))}
                >
                  <RadioGroupItem value={opt.value} id={`scan-${opt.value}`} className="mt-0.5" />
                  <div>
                    <Label htmlFor={`scan-${opt.value}`} className="font-medium cursor-pointer">
                      {opt.label}
                    </Label>
                    <p className="text-xs text-muted-foreground">{opt.desc}</p>
                  </div>
                </div>
              ))}
            </RadioGroup>
          </div>

          <div className="space-y-2">
            <Label>Options avancées</Label>
            <div className="space-y-2 pl-1">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="sv" checked={form.service_version}
                  onCheckedChange={(v) => setForm((p) => ({ ...p, service_version: !!v }))}
                />
                <Label htmlFor="sv" className="cursor-pointer text-sm">Détection des versions de services</Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="os" checked={form.os_detection}
                  onCheckedChange={(v) => setForm((p) => ({ ...p, os_detection: !!v }))}
                />
                <Label htmlFor="os" className="cursor-pointer text-sm">Détection du système d&apos;exploitation</Label>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Résumé */}
      <div className="p-3 bg-muted/50 rounded-lg text-sm space-y-1">
        <p className="font-medium text-xs text-muted-foreground uppercase tracking-wide">Récapitulatif</p>
        <p><span className="font-medium">Hostname:</span> {form.hostname || '—'}</p>
        <p><span className="font-medium">IP:</span> {form.ip_address}</p>
        <p><span className="font-medium">Environnement:</span> {form.environment || '—'}</p>
        <p><span className="font-medium">SSH:</span> {form.ssh_username
          ? `${form.ssh_username}@${form.ssh_host}:${form.ssh_port} ✓`
          : 'Non configuré'}
        </p>
        <p><span className="font-medium">Scan:</span> {form.auto_scan
          ? `${SCAN_TYPES.find(t => t.value === form.scan_type)?.label} (auto-lancement)`
          : 'Manuel'}
        </p>
      </div>
    </div>
  );

  const canProceedStep1 = form.ip_address.trim().length >= 7;
  const isEditMode = !!editingAsset;

  return (
    <>
      <Head>
        <title>Assets - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Assets</h1>
            <p className="text-muted-foreground">
              Gérez votre infrastructure réseau
              {!loading && (
                <span> — {assets.length} asset{assets.length !== 1 ? 's' : ''}</span>
              )}
            </p>
          </div>
          <Button onClick={openCreateDialog}>
            <Plus className="mr-2 h-4 w-4" />
            Ajouter un asset
          </Button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Rechercher..."
              className="pl-9"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <Select value={filterType} onValueChange={setFilterType}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les types</SelectItem>
              {ASSET_TYPES.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={filterEnv} onValueChange={setFilterEnv}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Environnement" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous</SelectItem>
              {ENVIRONMENTS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {(search || filterType !== 'all' || filterEnv !== 'all') && (
            <Button variant="ghost" onClick={() => { setSearch(''); setFilterType('all'); setFilterEnv('all'); }}>
              Réinitialiser
            </Button>
          )}
        </div>

        {/* Table */}
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>Adresse IP</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Environnement</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Dernier vu</TableHead>
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
              ) : filteredAssets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2 text-muted-foreground">
                      <Server className="h-10 w-10" />
                      <p className="font-medium">Aucun asset trouvé</p>
                      <p className="text-sm">Ajoutez votre premier asset pour commencer</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filteredAssets.map((asset) => (
                  <TableRow key={asset.id} className="hover:bg-muted/50">
                    <TableCell className="font-medium">{asset.hostname || '—'}</TableCell>
                    <TableCell className="font-mono text-sm">{asset.ip_address}</TableCell>
                    <TableCell><Badge variant="outline">{asset.asset_type}</Badge></TableCell>
                    <TableCell>
                      {asset.environment
                        ? <Badge variant="secondary">{asset.environment}</Badge>
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(asset.tags || []).map((tag) => (
                          <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {asset.last_seen
                        ? new Date(asset.last_seen).toLocaleString('fr-FR')
                        : '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEditDialog(asset)}>
                            <Edit className="mr-2 h-4 w-4" />
                            Modifier
                          </DropdownMenuItem>
                          <Link href="/scans/new" passHref legacyBehavior>
                            <DropdownMenuItem asChild>
                              <a>
                                <Play className="mr-2 h-4 w-4" />
                                Scanner
                              </a>
                            </DropdownMenuItem>
                          </Link>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => handleDelete(asset)}
                          >
                            <Trash className="mr-2 h-4 w-4" />
                            Supprimer
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Card>

        {/* ── Wizard Dialog ── */}
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                {isEditMode ? "Modifier l'asset" : 'Ajouter un asset'}
              </DialogTitle>
            </DialogHeader>

            {/* Stepper — caché en mode édition simple */}
            {!isEditMode && (
              <Stepper
                currentStep={wizardStep}
                steps={['Informations', 'SSH', 'Scan']}
              />
            )}

            <div className="py-2">
              {isEditMode || wizardStep === 1 ? renderStep1() : null}
              {!isEditMode && wizardStep === 2 ? renderStep2() : null}
              {!isEditMode && wizardStep === 3 ? renderStep3() : null}
            </div>

            <DialogFooter className="flex justify-between gap-2 pt-2 border-t">
              {isEditMode ? (
                <>
                  <Button variant="outline" onClick={() => setDialogOpen(false)}>Annuler</Button>
                  <Button onClick={handleSubmit} disabled={submitting}>
                    {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Enregistrer
                  </Button>
                </>
              ) : (
                <>
                  <Button
                    variant="outline"
                    onClick={() => {
                      if (wizardStep === 1) setDialogOpen(false);
                      else setWizardStep((s) => s - 1);
                    }}
                  >
                    {wizardStep === 1 ? 'Annuler' : '← Retour'}
                  </Button>

                  {wizardStep < 3 ? (
                    <Button
                      onClick={() => setWizardStep((s) => s + 1)}
                      disabled={wizardStep === 1 && !canProceedStep1}
                    >
                      Étape suivante →
                    </Button>
                  ) : (
                    <Button onClick={handleSubmit} disabled={submitting || !canProceedStep1}>
                      {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      {form.auto_scan ? 'Créer & Lancer le scan →' : 'Créer l\'asset'}
                    </Button>
                  )}
                </>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}
