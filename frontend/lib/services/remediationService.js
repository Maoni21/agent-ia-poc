/**
 * Service pour la gestion du workflow de remédiation complet :
 * Analyse IA batch → Plan → Approbation → Exécution SSH → Validation
 */

import api from './api';

const remediationService = {
  // ─── Analyse batch ────────────────────────────────────────────────────────

  /**
   * Lance l'analyse IA de toutes les vulnérabilités d'un scan.
   * @param {string} scanId
   * @returns {{ analysis_id, total_vulnerabilities, status, estimated_duration }}
   */
  async startBatchAnalysis(scanId) {
    const { data } = await api.post(`/api/v1/scans/${scanId}/analyze-batch`);
    return data;
  },

  /**
   * Récupère le statut de l'analyse en cours.
   * @param {string} analysisId
   * @returns {{ status, progress, total, current_vulnerability, estimated_time_remaining }}
   */
  async getAnalysisStatus(analysisId) {
    const { data } = await api.get(`/api/v1/analysis/${analysisId}/status`);
    return data;
  },

  // ─── Plan de remédiation ──────────────────────────────────────────────────

  /**
   * Récupère le plan de remédiation pour un scan.
   * @param {string} scanId
   * @returns {{ plan_id, scan_id, status, executive_summary, phases }}
   */
  async getRemediationPlan(scanId) {
    const { data } = await api.get(`/api/v1/remediation-plan/${scanId}`);
    return data;
  },

  /**
   * Récupère un plan de remédiation par son ID.
   * @param {string} planId
   */
  async getRemediationPlanById(planId) {
    const { data } = await api.get(`/api/v1/remediation-plan/by-id/${planId}`);
    return data;
  },

  /**
   * Approuve un plan de remédiation et lance l'exécution.
   * @param {string} planId
   * @param {{ confirmed: boolean, security_code?: string }} payload
   * @returns {{ plan_id, status, message }}
   */
  async approveRemediationPlan(planId, payload) {
    const { data } = await api.post(`/api/v1/remediation-plan/${planId}/approve`, payload);
    return data;
  },

  // ─── Exécution ────────────────────────────────────────────────────────────

  /**
   * Récupère le statut détaillé de l'exécution.
   * @param {string} planId
   * @returns {{ status, overall_progress, current_step, total_steps, completed_steps }}
   */
  async getExecutionStatus(planId) {
    const { data } = await api.get(`/api/v1/remediation-execution/${planId}/status`);
    return data;
  },

  // ─── Validation ───────────────────────────────────────────────────────────

  /**
   * Récupère les résultats du scan de validation.
   * @param {string} planId
   * @returns {{ before_score, after_score, improvement, fixed_vulnerabilities, remaining_vulnerabilities }}
   */
  async getValidationResults(planId) {
    const { data } = await api.get(`/api/v1/validation/${planId}`);
    return data;
  },

  // ─── SSH ──────────────────────────────────────────────────────────────────

  /**
   * Teste la connexion SSH d'un asset.
   * @param {string} assetId
   * @returns {{ connected, sudo_available, whoami, error }}
   */
  async testSSH(assetId) {
    const { data } = await api.post(`/api/v1/assets/${assetId}/test-ssh`);
    return data;
  },
};

export default remediationService;
