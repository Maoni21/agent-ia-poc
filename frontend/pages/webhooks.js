import { useEffect, useState } from 'react';
import Head from 'next/head';
import { Plus, Trash2, Webhook, CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Separator } from '@/components/ui/separator';
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
import webhooksService from '../lib/services/webhooksService';

const AVAILABLE_EVENTS = [
  { id: 'scan_completed', label: 'Scan terminé', description: 'Déclenché lorsqu\'un scan se termine' },
  { id: 'critical_vulnerability', label: 'Vulnérabilité critique', description: 'Déclenché lors de la détection d\'une vulnérabilité critique' },
  { id: 'remediation_completed', label: 'Remédiation terminée', description: 'Déclenché lorsqu\'une remédiation est appliquée avec succès' },
];

const formatDate = (value) => {
  if (!value) return '—';
  try { return new Date(value).toLocaleString('fr-FR'); }
  catch { return value; }
};

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [selectedEvents, setSelectedEvents] = useState(['scan_completed']);
  const [saving, setSaving] = useState(false);

  const loadWebhooks = async () => {
    setLoading(true);
    try {
      const data = await webhooksService.getWebhooks();
      setWebhooks(data || []);
    } catch (err) {
      console.error('Erreur chargement webhooks', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadWebhooks(); }, []);

  const handleToggleEvent = (eventId) => {
    setSelectedEvents((prev) =>
      prev.includes(eventId)
        ? prev.filter((e) => e !== eventId)
        : [...prev, eventId]
    );
  };

  const handleOpenDialog = () => {
    setUrl('');
    setSelectedEvents(['scan_completed']);
    setDialogOpen(true);
  };

  const handleCreate = async () => {
    if (!url.trim()) return;
    setSaving(true);
    try {
      await webhooksService.createWebhook({ url, events: selectedEvents });
      setDialogOpen(false);
      await loadWebhooks();
    } catch (err) {
      alert(err?.message || 'Erreur création webhook');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Supprimer ce webhook ?')) return;
    try {
      await webhooksService.deleteWebhook(id);
      await loadWebhooks();
    } catch (err) {
      alert(err?.message || 'Erreur suppression webhook');
    }
  };

  return (
    <>
      <Head>
        <title>Webhooks - CyberSec AI</title>
      </Head>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Webhooks</h1>
            <p className="text-muted-foreground">
              Notifications automatiques vers vos systèmes externes
            </p>
          </div>
          <Button onClick={handleOpenDialog}>
            <Plus className="mr-2 h-4 w-4" />
            Ajouter un webhook
          </Button>
        </div>

        <Card>
          <CardContent className="p-0">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : webhooks.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-muted-foreground">
                <Webhook className="h-12 w-12" />
                <p className="font-medium text-lg">Aucun webhook configuré</p>
                <p className="text-sm text-center max-w-sm">
                  Configurez des webhooks pour recevoir des notifications en temps réel dans vos outils (Slack, Teams, etc.)
                </p>
                <Button variant="outline" onClick={handleOpenDialog}>
                  <Plus className="mr-2 h-4 w-4" />
                  Ajouter un webhook
                </Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>Événements</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead>Dernière livraison</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.map((wh) => (
                    <TableRow key={wh.id}>
                      <TableCell className="max-w-xs">
                        <code className="text-xs font-mono truncate block">
                          {wh.url}
                        </code>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(wh.events || []).map((ev) => (
                            <Badge key={ev} variant="secondary" className="text-xs">
                              {ev}
                            </Badge>
                          ))}
                          {(!wh.events || wh.events.length === 0) && (
                            <span className="text-muted-foreground text-sm">—</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {wh.is_active ? (
                          <span className="flex items-center gap-1.5 text-green-600 text-sm font-medium">
                            <CheckCircle2 className="h-4 w-4" />
                            Actif
                          </span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-muted-foreground text-sm">
                            <XCircle className="h-4 w-4" />
                            Inactif
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(wh.last_delivery_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                          onClick={() => handleDelete(wh.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Create Webhook Dialog */}
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Ajouter un webhook</DialogTitle>
              <DialogDescription>
                Configurez une URL pour recevoir des notifications d&apos;événements.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="webhook-url">
                  URL du webhook <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="webhook-url"
                  type="url"
                  placeholder="https://hooks.example.com/..."
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <Separator />
              <div className="space-y-3">
                <Label>Événements déclencheurs</Label>
                {AVAILABLE_EVENTS.map((ev) => (
                  <div key={ev.id} className="flex items-start gap-3">
                    <Checkbox
                      id={`event-${ev.id}`}
                      checked={selectedEvents.includes(ev.id)}
                      onCheckedChange={() => handleToggleEvent(ev.id)}
                      className="mt-0.5"
                    />
                    <div className="space-y-0.5">
                      <label
                        htmlFor={`event-${ev.id}`}
                        className="text-sm font-medium cursor-pointer"
                      >
                        {ev.label}
                      </label>
                      <p className="text-xs text-muted-foreground">{ev.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Annuler
              </Button>
              <Button
                onClick={handleCreate}
                disabled={saving || !url.trim() || selectedEvents.length === 0}
              >
                {saving ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Enregistrement...</>
                ) : (
                  <>Enregistrer</>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </>
  );
}
