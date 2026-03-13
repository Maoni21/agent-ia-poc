import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  Stepper,
  Step,
  StepLabel,
  Box,
} from '@mui/material';
import {
  Storage as Server,
  Dns as Database,
  Cloud,
} from '@mui/icons-material';

export default function WelcomeWizard({ open, onClose, onComplete }) {
  const [step, setStep] = useState(0);

  const handleNext = () => {
    if (step === 2) {
      localStorage.setItem('welcome_wizard_completed', 'true');
      if (onComplete) {
        onComplete();
      } else if (onClose) {
        onClose();
      }
    } else {
      setStep((s) => s + 1);
    }
  };

  const handleSkip = () => {
    localStorage.setItem('welcome_wizard_completed', 'true');
    if (onClose) onClose();
  };

  return (
    <Dialog
      open={open}
      maxWidth="md"
      fullWidth
      disableEscapeKeyDown
    >
      <DialogTitle>👋 Bienvenue sur Vulnerability Agent !</DialogTitle>

      <DialogContent>
        <Stepper activeStep={step} sx={{ mb: 3 }}>
          <Step>
            <StepLabel>Comprendre les assets</StepLabel>
          </Step>
          <Step>
            <StepLabel>Ajouter un serveur</StepLabel>
          </Step>
          <Step>
            <StepLabel>Lancer un scan</StepLabel>
          </Step>
        </Stepper>

        {step === 0 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Qu&apos;est-ce qu&apos;un asset ?
            </Typography>
            <Typography color="text.secondary" paragraph>
              Un &quot;asset&quot; est un serveur ou une machine que vous voulez sécuriser.
              Voici quelques exemples :
            </Typography>

            <List>
              <ListItem>
                <ListItemIcon>
                  <Server color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary="Serveur web"
                  secondary="Apache, Nginx, IIS — ex: 192.168.1.10"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Database color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary="Base de données"
                  secondary="PostgreSQL, MySQL — ex: 192.168.1.20"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Cloud color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary="Serveur cloud"
                  secondary="AWS, Azure, GCP — ex: 34.123.45.67"
                />
              </ListItem>
            </List>

            <Alert severity="info" sx={{ mt: 2 }}>
              <strong>Conseil :</strong> commencez par un serveur de test, pas un serveur
              de production.
            </Alert>
          </Box>
        )}

        {step === 1 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Comment ajouter un serveur ?
            </Typography>
            <Typography color="text.secondary" paragraph>
              Vous aurez besoin de :
            </Typography>
            <List>
              <ListItem>
                <ListItemText
                  primary="1. Adresse IP du serveur"
                  secondary="Ex: 192.168.1.10 (LAN) ou 34.123.45.67 (Internet)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="2. Un nom facile à retenir"
                  secondary="Ex: &quot;Serveur Web Production&quot; ou &quot;Base MySQL Dev&quot;"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="3. Type de serveur (optionnel)"
                  secondary="Serveur, base de données, équipement réseau..."
                />
              </ListItem>
            </List>
            <Alert severity="success">
              ✅ Après ajout, vous pourrez lancer un scan de sécurité immédiatement.
            </Alert>
          </Box>
        )}

        {step === 2 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Prêt à commencer ?
            </Typography>
            <Typography color="text.secondary" paragraph>
              Vous allez maintenant :
            </Typography>
            <List>
              <ListItem>
                <ListItemText
                  primary="1️⃣ Ajouter votre premier serveur"
                  secondary="Formulaire simple (IP + nom)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="2️⃣ Lancer un scan de sécurité"
                  secondary="L&apos;agent IA analysera les vulnérabilités (2–5 min)"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="3️⃣ Voir les résultats"
                  secondary="Liste de vulnérabilités + correctifs automatiques"
                />
              </ListItem>
            </List>
            <Alert severity="info">
              📺 Astuce : vous pourrez relancer ce tutoriel plus tard depuis les paramètres.
            </Alert>
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={handleSkip} color="inherit">
          Passer le tutoriel
        </Button>
        <Box sx={{ flex: 1 }} />
        {step > 0 && (
          <Button onClick={() => setStep((s) => s - 1)}>Retour</Button>
        )}
        <Button variant="contained" onClick={handleNext}>
          {step === 2 ? "C'est parti →" : 'Suivant →'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

