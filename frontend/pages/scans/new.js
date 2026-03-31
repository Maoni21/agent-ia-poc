import Head from 'next/head';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { ArrowLeft, Play, Target, Zap, Search, UserX, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select, SelectContent, SelectItem,
  SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';
import assetsService from '../../lib/services/assetsService';
import scansService from '../../lib/services/scansService';

const SCAN_TYPES = [
  {
    value: 'quick',
    label: 'Rapide',
    description: '~2 minutes — Scan des ports principaux et vulnérabilités courantes',
    icon: Zap,
    iconClass: 'text-yellow-500',
  },
  {
    value: 'full',
    label: 'Complet',
    description: '~10 minutes — Scan exhaustif de tous les ports et services',
    icon: Search,
    iconClass: 'text-blue-500',
  },
  {
    value: 'stealth',
    label: 'Furtif',
    description: '~15 minutes — Scan discret pour éviter la détection',
    icon: UserX,
    iconClass: 'text-purple-500',
  },
  {
    value: 'compliance',
    label: 'Conformité',
    description: '~8 minutes — Vérification des standards de sécurité',
    icon: Target,
    iconClass: 'text-green-500',
  },
];

export default function NewScanPage() {
  const router = useRouter();
  const [assets, setAssets] = useState([]);
  const [assetId, setAssetId] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loadingAssets, setLoadingAssets] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadAssets = async () => {
      setLoadingAssets(true);
      try {
        const data = await assetsService.getAssets();
        setAssets(data || []);
      } catch (err) {
        setError(err.message || 'Erreur lors du chargement des assets');
      } finally {
        setLoadingAssets(false);
      }
    };
    loadAssets();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!assetId) return;
    setSubmitting(true);
    setError(null);
    try {
      const result = await scansService.createScan({ asset_id: assetId, scan_type: scanType });
      const newId = result.id || result.scan_id;
      if (newId) {
        router.push(`/scans/${newId}`);
      } else {
        throw new Error("L'API n'a pas renvoyé d'identifiant de scan");
      }
    } catch (err) {
      setError(err.message || 'Erreur lors de la création du scan');
    } finally {
      setSubmitting(false);
    }
  };

  const selectedAsset = assets.find((a) => a.id === assetId);
  const selectedType = SCAN_TYPES.find((t) => t.value === scanType);

  return (
    <>
      <Head>
        <title>Nouveau scan - CyberSec AI</title>
      </Head>

      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => router.push('/scans')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Nouveau scan</h1>
            <p className="text-muted-foreground">Configurez et lancez un scan de sécurité</p>
          </div>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Step 1: Asset */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">1. Sélectionner la cible</CardTitle>
              <CardDescription>Choisissez l&apos;asset à scanner</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Label htmlFor="asset">Asset <span className="text-destructive">*</span></Label>
                <Select
                  value={assetId}
                  onValueChange={setAssetId}
                  disabled={loadingAssets || submitting}
                >
                  <SelectTrigger>
                    <SelectValue placeholder={loadingAssets ? 'Chargement...' : 'Sélectionner un asset'} />
                  </SelectTrigger>
                  <SelectContent>
                    {assets.length === 0 && !loadingAssets ? (
                      <SelectItem value="none" disabled>Aucun asset disponible</SelectItem>
                    ) : (
                      assets.map((asset) => (
                        <SelectItem key={asset.id} value={asset.id}>
                          {asset.hostname || asset.ip_address}
                          {asset.hostname && ` (${asset.ip_address})`}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Step 2: Scan type */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">2. Type de scan</CardTitle>
              <CardDescription>Choisissez la profondeur du scan</CardDescription>
            </CardHeader>
            <CardContent>
              <RadioGroup
                value={scanType}
                onValueChange={setScanType}
                className="space-y-3"
              >
                {SCAN_TYPES.map((type) => {
                  const Icon = type.icon;
                  return (
                    <div
                      key={type.value}
                      className={cn(
                        'flex items-start gap-3 rounded-lg border p-4 cursor-pointer transition-colors',
                        scanType === type.value
                          ? 'border-primary bg-primary/5'
                          : 'hover:bg-accent'
                      )}
                      onClick={() => setScanType(type.value)}
                    >
                      <RadioGroupItem value={type.value} id={type.value} className="mt-0.5" />
                      <Icon className={cn('h-5 w-5 mt-0.5 shrink-0', type.iconClass)} />
                      <div>
                        <Label htmlFor={type.value} className="font-semibold cursor-pointer">
                          {type.label}
                        </Label>
                        <p className="text-sm text-muted-foreground">{type.description}</p>
                      </div>
                    </div>
                  );
                })}
              </RadioGroup>
            </CardContent>
          </Card>

          {/* Preview */}
          {selectedAsset && (
            <Card className="border-primary/30 bg-primary/5">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Récapitulatif</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Cible</span>
                  <span className="font-medium">{selectedAsset.hostname || selectedAsset.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Adresse IP</span>
                  <span className="font-mono">{selectedAsset.ip_address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type de scan</span>
                  <span className="font-medium">{selectedType?.label}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Durée estimée</span>
                  <span className="text-muted-foreground">{selectedType?.description.split('—')[0].trim()}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Actions */}
          <div className="flex gap-3 justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => router.push('/scans')}
              disabled={submitting}
            >
              Annuler
            </Button>
            <Button
              type="submit"
              disabled={!assetId || submitting}
            >
              {submitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Lancement...
                </>
              ) : (
                <>
                  <Play className="mr-2 h-4 w-4" />
                  Lancer le scan
                </>
              )}
            </Button>
          </div>
        </form>
      </div>
    </>
  );
}
