import { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import {
  Plus, Edit, Trash, Search, Server, Play, MoreHorizontal,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
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
import assetsService from '../lib/services/assetsService';

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

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterEnv, setFilterEnv] = useState('all');
  const [form, setForm] = useState({
    hostname: '',
    ip_address: '',
    asset_type: 'server',
    environment: '',
    tags: '',
  });

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
    setForm({ hostname: '', ip_address: '', asset_type: 'server', environment: '', tags: '' });
    setDialogOpen(true);
  };

  const openEditDialog = (asset) => {
    setEditingAsset(asset);
    setForm({
      hostname: asset.hostname || '',
      ip_address: asset.ip_address || '',
      asset_type: asset.asset_type || 'server',
      environment: asset.environment || '',
      tags: (asset.tags || []).join(', '),
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

  const handleFormChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const payload = {
      hostname: form.hostname || null,
      ip_address: form.ip_address,
      asset_type: form.asset_type,
      environment: form.environment || null,
      tags: form.tags ? form.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
    };
    try {
      if (editingAsset) {
        await assetsService.updateAsset(editingAsset.id, payload);
      } else {
        await assetsService.createAsset(payload);
      }
      setDialogOpen(false);
      await loadAssets();
    } catch (err) {
      alert(err?.message || "Erreur lors de l'enregistrement de l'asset");
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
            <Button
              variant="ghost"
              onClick={() => { setSearch(''); setFilterType('all'); setFilterEnv('all'); }}
            >
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
                    <TableCell>
                      <Badge variant="outline">{asset.asset_type}</Badge>
                    </TableCell>
                    <TableCell>
                      {asset.environment ? (
                        <Badge variant="secondary">{asset.environment}</Badge>
                      ) : '—'}
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

        {/* Add/Edit Dialog */}
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingAsset ? "Modifier l'asset" : 'Ajouter un asset'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="hostname">Hostname</Label>
                <Input
                  id="hostname"
                  name="hostname"
                  placeholder="server01.company.com"
                  value={form.hostname}
                  onChange={handleFormChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ip_address">
                  Adresse IP <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="ip_address"
                  name="ip_address"
                  placeholder="192.168.1.100"
                  required
                  value={form.ip_address}
                  onChange={handleFormChange}
                />
              </div>
              <div className="space-y-2">
                <Label>Type d&apos;asset</Label>
                <Select
                  value={form.asset_type}
                  onValueChange={(v) => setForm((p) => ({ ...p, asset_type: v }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
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
                  <SelectTrigger>
                    <SelectValue placeholder="Non défini" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Non défini</SelectItem>
                    {ENVIRONMENTS.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="tags">
                  Tags{' '}
                  <span className="text-muted-foreground text-xs">(séparés par des virgules)</span>
                </Label>
                <Input
                  id="tags"
                  name="tags"
                  placeholder="web, prod, critical"
                  value={form.tags}
                  onChange={handleFormChange}
                />
              </div>
              <DialogFooter className="gap-2">
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingAsset ? 'Enregistrer' : 'Ajouter'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}
