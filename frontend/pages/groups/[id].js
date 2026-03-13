import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useState, useMemo } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  CircularProgress,
  Alert,
  Checkbox,
  Button,
} from '@mui/material';
import Layout from '../../components/Layout';
import groupsService from '../../lib/services/groupsService';
import vulnerabilitiesService from '../../lib/services/vulnerabilitiesService';

const getVulnSeverityColors = (severity) => {
  const sev = (severity || '').toUpperCase();
  switch (sev) {
    case 'CRITICAL':
      return { border: '#DC2626', bg: '#FEF2F2' };
    case 'HIGH':
      return { border: '#EA580C', bg: '#FFF7ED' };
    case 'MEDIUM':
      return { border: '#D97706', bg: '#FFFBEB' };
    case 'LOW':
      return { border: '#16A34A', bg: '#ECFDF3' };
    case 'INFO':
    default:
      return { border: '#6B7280', bg: '#F3F4F6' };
  }
};

export default function GroupDetailsPage() {
  const router = useRouter();
  const { id } = router.query;

  const [group, setGroup] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedVulnIds, setSelectedVulnIds] = useState([]);
  const [actionLoading, setActionLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  const loadGroup = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await groupsService.getGroup(id);
      setGroup(data);
      setSelectedVulnIds([]);
    } catch (err) {
      setError(err.message || 'Erreur lors du chargement du groupe');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGroup();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const severitySummary = useMemo(() => {
    if (!group?.vulnerabilities) return null;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    group.vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'INFO').toUpperCase();
      if (counts[sev] == null) {
        counts.INFO += 1;
      } else {
        counts[sev] += 1;
      }
    });
    return counts;
  }, [group]);

  const toggleVulnSelection = (vulnId, checked) => {
    setSelectedVulnIds((prev) => {
      if (checked) {
        if (prev.includes(vulnId)) return prev;
        return [...prev, vulnId];
      }
      return prev.filter((x) => x !== vulnId);
    });
  };

  const handleSelectAll = () => {
    if (!group?.vulnerabilities || group.vulnerabilities.length === 0) return;
    setSelectedVulnIds(group.vulnerabilities.map((v) => v.id));
  };

  const handleClearSelection = () => {
    setSelectedVulnIds([]);
  };

  const handleAnalyzeGroup = async () => {
    if (!id) return;
    setActionLoading(true);
    try {
      const result = await groupsService.analyzeGroup(id);
      setAnalysisResult(result);
      await loadGroup();
      alert(result.message || 'Analyse IA du groupe terminée.');
    } catch (err) {
      alert(err.message || "Erreur lors de l'analyse du groupe");
    } finally {
      setActionLoading(false);
    }
  };

  const handleAnalyzeSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      // Analyse IA vulnérabilité par vulnérabilité, mais on affiche aussi le détail texte en dessous
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.analyzeVulnerability(vulnId),
      );
      const results = await Promise.all(promises);
      const analyzedItems =
        results
          .map((r) => r.analysis || r)
          .filter(Boolean) || [];

      setAnalysisResult({
        vulnerability_count: analyzedItems.length,
        analysis_summary: null,
        remediation_plan: null,
        vulnerabilities: analyzedItems,
      });

      await loadGroup();
      alert(
        `Analyse IA terminée pour ${selectedVulnIds.length} vulnérabilité(s) du groupe.`,
      );
    } catch (err) {
      alert(
        "Erreur lors de l'analyse IA: " + (err.message || 'inconnue'),
      );
    } finally {
      setActionLoading(false);
    }
  };

  const handleCorrectSelected = async () => {
    if (selectedVulnIds.length === 0) return;
    setActionLoading(true);
    try {
      const promises = selectedVulnIds.map((vulnId) =>
        vulnerabilitiesService.generateScript(vulnId, {
          target_system: 'ubuntu-22.04',
          script_type: 'bash',
        }),
      );
      const results = await Promise.all(promises);
      alert(
        `Scripts de remédiation générés pour ${results.length} vulnérabilité(s) du groupe.`,
      );
      // eslint-disable-next-line no-console
      console.log('Scripts générés pour le groupe:', results);
    } catch (err) {
      alert(
        'Erreur lors de la génération de scripts: ' +
          (err.message || 'inconnue'),
      );
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <Head>
        <title>Détails du groupe - CyberSec AI</title>
      </Head>
      <Layout>
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {loading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : !group ? (
            <Alert severity="info">Groupe introuvable.</Alert>
          ) : (
            <>
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  mb: 2,
                }}
              >
                <Box>
                  <Typography variant="h4" gutterBottom>
                    {group.name}
                  </Typography>
                  {group.description && (
                    <Typography variant="body2" color="text.secondary">
                      {group.description}
                    </Typography>
                  )}
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    {group.vulnerability_count} vulnérabilité(s) • Créé le{' '}
                    {group.created_at}
                  </Typography>
                </Box>

                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <Button
                    variant="contained"
                    onClick={handleAnalyzeGroup}
                    disabled={actionLoading}
                  >
                    Analyser tout le groupe (IA)
                  </Button>
                  {severitySummary && (
                    <Box sx={{ textAlign: 'right' }}>
                      <Typography variant="caption" color="text.secondary">
                        CRIT: {severitySummary.CRITICAL} • HIGH: {severitySummary.HIGH}{' '}
                        • MED: {severitySummary.MEDIUM} • LOW: {severitySummary.LOW}
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Box>

              <Paper sx={{ p: 2, mb: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Vulnérabilités du groupe
                </Typography>
                {!group.vulnerabilities || group.vulnerabilities.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    Aucune vulnérabilité dans ce groupe.
                  </Typography>
                ) : (
                  <>
                    <Box
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        mb: 1.5,
                        flexWrap: 'wrap',
                        gap: 1,
                      }}
                    >
                      <Typography variant="body2" color="text.secondary">
                        Sélection : {selectedVulnIds.length} /{' '}
                        {group.vulnerabilities.length}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Button
                          size="small"
                          variant="text"
                          onClick={handleSelectAll}
                          disabled={actionLoading}
                        >
                          Tout sélectionner
                        </Button>
                        <Button
                          size="small"
                          variant="text"
                          onClick={handleClearSelection}
                          disabled={actionLoading || selectedVulnIds.length === 0}
                        >
                          Vider
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          onClick={handleAnalyzeSelected}
                          disabled={actionLoading || selectedVulnIds.length === 0}
                        >
                          Analyser IA (sélection)
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          color="success"
                          onClick={handleCorrectSelected}
                          disabled={actionLoading || selectedVulnIds.length === 0}
                        >
                          Scripts de remédiation
                        </Button>
                      </Box>
                    </Box>

                    <Box sx={{ maxHeight: 420, overflowY: 'auto' }}>
                      {group.vulnerabilities.map((vuln) => {
                        const colors = getVulnSeverityColors(vuln.severity);
                        return (
                          <Box
                            key={vuln.id}
                            sx={{
                              mb: 1.5,
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: 1,
                            }}
                          >
                            <Checkbox
                              size="small"
                              checked={selectedVulnIds.includes(vuln.id)}
                              onChange={(e) =>
                                toggleVulnSelection(vuln.id, e.target.checked)
                              }
                            />
                            <Box
                              sx={{
                                flex: 1,
                                borderRadius: 1,
                                borderLeft: '4px solid',
                                borderLeftColor: colors.border,
                                backgroundColor: colors.bg,
                                px: 1.5,
                                py: 0.75,
                              }}
                            >
                              <Box
                                sx={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  alignItems: 'center',
                                  mb: 0.25,
                                }}
                              >
                                <Typography variant="subtitle2">
                                  {vuln.title || vuln.cve_id}
                                </Typography>
                                {vuln.ai_priority_score != null && (
                                  <Typography
                                    variant="caption"
                                    sx={{ fontWeight: 600 }}
                                  >
                                    IA&nbsp;score: {vuln.ai_priority_score}/10
                                  </Typography>
                                )}
                              </Box>
                              <Typography variant="caption" color="text.secondary">
                                {vuln.severity} — CVSS:{' '}
                                {vuln.cvss_score != null ? vuln.cvss_score : '-'}
                                {vuln.ai_analyzed && vuln.ai_priority_score == null && (
                                  <> • Analysée par IA</>
                                )}
                              </Typography>
                            </Box>
                          </Box>
                        );
                      })}
                    </Box>
                  </>
                )}
              </Paper>

              {analysisResult && (
                <Paper sx={{ p: 2, mt: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Analyse IA du groupe
                  </Typography>

                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 1.5 }}>
                    <Chip
                      label={`Vulnérabilités analysées : ${
                        analysisResult.vulnerability_count ?? 'N/A'
                      }`}
                      size="small"
                    />
                    {analysisResult.analysis_summary?.overall_risk_score != null && (
                      <Chip
                        label={`Score de risque global : ${analysisResult.analysis_summary.overall_risk_score}`}
                        size="small"
                        color="warning"
                      />
                    )}
                    {analysisResult.analysis_summary?.average_cvss != null && (
                      <Chip
                        label={`CVSS moyen : ${analysisResult.analysis_summary.average_cvss}`}
                        size="small"
                        color="info"
                      />
                    )}
                  </Box>

                  {analysisResult.analysis_summary && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" paragraph>
                        Ce groupe contient{' '}
                        <strong>
                          {analysisResult.analysis_summary.total_vulnerabilities}
                        </strong>{' '}
                        vulnérabilités, dont{' '}
                        <strong>
                          {analysisResult.analysis_summary.critical_count} critiques
                        </strong>
                        ,{' '}
                        <strong>{analysisResult.analysis_summary.high_count} élevées</strong>,{' '}
                        <strong>
                          {analysisResult.analysis_summary.medium_count} moyennes
                        </strong>{' '}
                        et{' '}
                        <strong>{analysisResult.analysis_summary.low_count} faibles</strong>.
                      </Typography>
                      <Typography variant="body2" paragraph>
                        Le <strong>score de risque global</strong> estimé par l&apos;IA est de{' '}
                        <strong>
                          {analysisResult.analysis_summary.overall_risk_score}
                        </strong>
                        , avec un <strong>CVSS moyen</strong> de{' '}
                        <strong>{analysisResult.analysis_summary.average_cvss}</strong>.
                      </Typography>
                    </Box>
                  )}

                  {analysisResult.remediation_plan && (
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 2 }}>
                      <Box>
                        <Typography variant="subtitle1" gutterBottom>
                          Actions immédiates (CRITICAL / HIGH)
                        </Typography>
                        {analysisResult.remediation_plan.immediate_actions &&
                        analysisResult.remediation_plan.immediate_actions.length > 0 ? (
                          <Box component="ul" sx={{ pl: 3, m: 0 }}>
                            {analysisResult.remediation_plan.immediate_actions.map(
                              (action, idx) => (
                                <li key={idx}>
                                  <Typography variant="body2">
                                    <strong>{action.vulnerability_name}</strong> –{' '}
                                    {action.action}
                                  </Typography>
                                </li>
                              ),
                            )}
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            Aucune action immédiate recommandée.
                          </Typography>
                        )}
                      </Box>

                      <Box>
                        <Typography variant="subtitle1" gutterBottom>
                          Actions court terme (MEDIUM)
                        </Typography>
                        {analysisResult.remediation_plan.short_term_actions &&
                        analysisResult.remediation_plan.short_term_actions.length > 0 ? (
                          <Box component="ul" sx={{ pl: 3, m: 0 }}>
                            {analysisResult.remediation_plan.short_term_actions.map(
                              (action, idx) => (
                                <li key={idx}>
                                  <Typography variant="body2">
                                    <strong>{action.vulnerability_name}</strong> –{' '}
                                    {action.action}
                                  </Typography>
                                </li>
                              ),
                            )}
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            Aucune action court terme spécifique recommandée.
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  )}

                  {analysisResult.vulnerabilities &&
                    analysisResult.vulnerabilities.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle1" gutterBottom>
                          Analyse détaillée par vulnérabilité
                        </Typography>
                        {analysisResult.vulnerabilities.map((v, idx) => (
                          <Box key={v.vulnerability_id || idx} sx={{ mb: 2 }}>
                            <Typography variant="body2" fontWeight={600}>
                              {v.name || 'Vulnérabilité'} ({v.vulnerability_id})
                            </Typography>
                            {v.ai_explanation && (
                              <Typography variant="body2" paragraph sx={{ mt: 0.5 }}>
                                <strong>Explication IA :</strong> {v.ai_explanation}
                              </Typography>
                            )}
                            {v.impact_analysis && (
                              <Typography variant="body2" paragraph>
                                <strong>Impact technique :</strong> {v.impact_analysis}
                              </Typography>
                            )}
                            {v.business_impact && (
                              <Typography variant="body2" paragraph>
                                <strong>Impact métier :</strong> {v.business_impact}
                              </Typography>
                            )}
                            {v.recommended_actions && v.recommended_actions.length > 0 && (
                              <Box sx={{ pl: 2 }}>
                                <Typography variant="body2" color="text.secondary">
                                  <strong>Actions recommandées :</strong>
                                </Typography>
                                <ul style={{ marginTop: 4, paddingLeft: 18 }}>
                                  {v.recommended_actions.map((action, aidx) => (
                                    <li key={aidx}>
                                      <Typography variant="body2">{action}</Typography>
                                    </li>
                                  ))}
                                </ul>
                              </Box>
                            )}
                          </Box>
                        ))}
                      </Box>
                    )}
                </Paper>
              )}
            </>
          )}
        </Container>
      </Layout>
    </>
  );
}

