import Head from 'next/head';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { Users, Plus, Sparkles, Trash2, Loader2, FolderOpen } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import groupsService from '../lib/services/groupsService';

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

export default function GroupsPage() {
  const router = useRouter();
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [vulnIdsText, setVulnIdsText] = useState('');
  const [saving, setSaving] = useState(false);
  const [analyzingId, setAnalyzingId] = useState(null);

  const loadGroups = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await groupsService.listGroups();
      setGroups(data.groups || []);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement des groupes');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadGroups(); }, []);

  const handleOpenDialog = () => {
    setName('');
    setDescription('');
    setVulnIdsText('');
    setDialogOpen(true);
  };

  const handleCreateGroup = async () => {
    setSaving(true);
    try {
      const vulnerabilityIds = vulnIdsText
        .split(/[,\s]+/)
        .map((id) => id.trim())
        .filter(Boolean);
      await groupsService.createGroup({ name, description, vulnerabilityIds });
      setDialogOpen(false);
      await loadGroups();
    } catch (err) {
      alert(err.message || 'Erreur lors de la création du groupe');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteGroup = async (e, groupId) => {
    e.stopPropagation();
    if (!window.confirm('Supprimer ce groupe ?')) return;
    try {
      await groupsService.deleteGroup(groupId);
      await loadGroups();
    } catch (err) {
      alert(err.message || 'Erreur lors de la suppression du groupe');
    }
  };

  const handleAnalyzeGroup = async (e, groupId) => {
    e.stopPropagation();
    setAnalyzingId(groupId);
    try {
      const result = await groupsService.analyzeGroup(groupId);
      alert(
        `Analyse lancée / terminée.\nAnalysis ID: ${result.analysis_id || 'n/a'}\n${result.message || ''}`
      );
    } catch (err) {
      alert(err.message || "Erreur lors de l'analyse du groupe");
    } finally {
      setAnalyzingId(null);
    }
  };

  return (
    <>
      <Head>
        <title>Groupes - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Groupes de vulnérabilités</h1>
            <p className="text-muted-foreground">
              {loading ? '...' : `${groups.length} groupe(s) configuré(s)`}
            </p>
          </div>
          <Button onClick={handleOpenDialog}>
            <Plus className="mr-2 h-4 w-4" />
            Nouveau groupe
          </Button>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="space-y-3 p-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : groups.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
                <FolderOpen className="h-12 w-12" />
                <p className="font-medium text-lg">Aucun groupe créé</p>
                <p className="text-sm">Créez un groupe pour regrouper des vulnérabilités liées</p>
                <Button variant="outline" onClick={handleOpenDialog}>
                  <Plus className="mr-2 h-4 w-4" />
                  Créer un groupe
                </Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Nom</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Vulnérabilités</TableHead>
                    <TableHead>Créé le</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {groups.map((group) => (
                    <TableRow
                      key={group.group_id}
                      className="cursor-pointer hover:bg-accent/50"
                      onClick={() => router.push(`/groups/${group.group_id}`)}
                    >
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <Users className="h-4 w-4 text-muted-foreground" />
                          {group.name}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground max-w-xs truncate">
                        {group.description || '—'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {group.vulnerability_count ?? 0} vulnérabilité(s)
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {formatDate(group.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={(e) => handleAnalyzeGroup(e, group.group_id)}
                            disabled={analyzingId === group.group_id}
                          >
                            {analyzingId === group.group_id ? (
                              <><Loader2 className="mr-1 h-3 w-3 animate-spin" />Analyse...</>
                            ) : (
                              <><Sparkles className="mr-1 h-3 w-3" />Analyser IA</>
                            )}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                            onClick={(e) => handleDeleteGroup(e, group.group_id)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Create Group Dialog */}
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Nouveau groupe de vulnérabilités</DialogTitle>
              <DialogDescription>
                Regroupez des vulnérabilités liées pour une analyse et remédiation groupée.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="group-name">
                  Nom du groupe <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="group-name"
                  placeholder="Ex: Serveurs web critiques"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="group-description">Description</Label>
                <textarea
                  id="group-description"
                  rows={2}
                  placeholder="Description optionnelle du groupe..."
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 resize-none"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="vuln-ids">IDs de vulnérabilités</Label>
                <textarea
                  id="vuln-ids"
                  rows={3}
                  placeholder="CVE-2023-1234, CVE-2024-5678&#10;Séparés par des virgules ou espaces"
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 resize-none font-mono"
                  value={vulnIdsText}
                  onChange={(e) => setVulnIdsText(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Séparés par des virgules ou espaces (ex: CVE-2023-1234, CVE-2024-5678)
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Annuler
              </Button>
              <Button
                onClick={handleCreateGroup}
                disabled={saving || !name.trim()}
              >
                {saving ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Création...</>
                ) : (
                  <>Créer le groupe</>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}
