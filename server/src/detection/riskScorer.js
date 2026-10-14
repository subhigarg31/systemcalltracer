/**
 * Prototype Risk Scoring Model
 * 
 * NOTE: This is a deterministic heuristic risk scoring model designed for
 * educational security operations demonstrations, not a certified malware probability metric.
 * 
 * Model Specification:
 * - Dynamic range: [0, 100]
 * - Severity weights for active alerts:
 *     * Critical: +35 points
 *     * High:     +20 points
 *     * Medium:   +10 points
 *     * Low:      +5 points
 * - Threat Diversity Multiplier:
 *     * If alerts span 2+ unique categories (e.g., Credential Access AND C2 Exfiltration),
 *       an extra correlation boost (+15 points) is added.
 * - Score Decay Policy:
 *     * If no new alerts have been triggered within decayIntervalMs (default 3000ms),
 *       the accumulated score decays toward baseline by decayStep (default 5 points)
 *       every tick, until it settles back into the Low band (0-24).
 * - Display Bands:
 *     * 0  - 24 : Low      (Normal operational baseline)
 *     * 25 - 49 : Guarded  (Isolated non-critical anomalies detected)
 *     * 50 - 74 : High     (Multiple significant suspicious behaviors)
 *     * 75 - 100: Critical (High-confidence active compromise / ransomware / exfiltration)
 */

class RiskScorer {
  constructor(riskConfig = {}) {
    this.decayIntervalMs = riskConfig.decayIntervalMs || 3000;
    this.decayStep = riskConfig.decayStep || 5;
    this.severityWeights = riskConfig.severityWeights || {
      Critical: 35,
      High: 20,
      Medium: 10,
      Low: 5
    };
    
    this.currentScore = 0;
    this.lastAlertTime = 0;
    this.lastDecayCheck = Date.now();
  }

  getBand(score) {
    if (score >= 75) return 'Critical';
    if (score >= 50) return 'High';
    if (score >= 25) return 'Guarded';
    return 'Low';
  }

  /**
   * Recalculates risk score based on active alerts and recent events
   * @param {Array} activeAlerts
   * @param {boolean} newAlertTriggered
   * @returns {{ score: number, band: string, breakdown: object }}
   */
  calculate(activeAlerts = [], newAlertTriggered = false) {
    const now = Date.now();

    if (newAlertTriggered) {
      this.lastAlertTime = now;
    }

    if (activeAlerts.length === 0) {
      // Natural decay towards 0
      this._applyDecay(now);
      return {
        score: Math.round(this.currentScore),
        band: this.getBand(this.currentScore),
        breakdown: { activeAlertCount: 0, severityPoints: 0, correlationBonus: 0 }
      };
    }

    // Calculate base points from active alerts
    let severityPoints = 0;
    const categories = new Set();

    for (const alert of activeAlerts) {
      const weight = this.severityWeights[alert.severity] || 5;
      severityPoints += weight;
      if (alert.category) {
        categories.add(alert.category);
      }
    }

    // Threat Correlation Bonus
    let correlationBonus = 0;
    if (categories.size >= 2) {
      correlationBonus = 15;
    }
    if (categories.size >= 3) {
      correlationBonus = 25;
    }

    const targetScore = Math.min(100, Math.max(0, severityPoints + correlationBonus));

    // If new alerts triggered, score immediately elevates to targetScore
    if (newAlertTriggered || targetScore > this.currentScore) {
      this.currentScore = targetScore;
    } else {
      // If no new alerts recently, apply decay towards target or baseline
      if (now - this.lastAlertTime > this.decayIntervalMs) {
        this._applyDecay(now, targetScore);
      }
    }

    this.currentScore = Math.min(100, Math.max(0, this.currentScore));

    return {
      score: Math.round(this.currentScore),
      band: this.getBand(this.currentScore),
      breakdown: {
        activeAlertCount: activeAlerts.length,
        severityPoints,
        correlationBonus,
        categoriesCount: categories.size
      }
    };
  }

  _applyDecay(now, floor = 0) {
    const elapsed = now - this.lastDecayCheck;
    if (elapsed >= this.decayIntervalMs) {
      const steps = Math.floor(elapsed / this.decayIntervalMs);
      this.currentScore = Math.max(floor, this.currentScore - (steps * this.decayStep));
      this.lastDecayCheck = now;
    }
  }

  forceDecayStep() {
    this.currentScore = Math.max(0, this.currentScore - this.decayStep);
    return {
      score: Math.round(this.currentScore),
      band: this.getBand(this.currentScore)
    };
  }

  recalculateScore(activeAlerts = []) {
    if (activeAlerts.length === 0) {
      this.currentScore = 0;
      return {
        score: 0,
        band: 'Low',
        breakdown: { activeAlertCount: 0, severityPoints: 0, correlationBonus: 0 }
      };
    }

    let severityPoints = 0;
    const categories = new Set();
    for (const alert of activeAlerts) {
      const weight = this.severityWeights[alert.severity] || 5;
      severityPoints += weight;
      if (alert.category) categories.add(alert.category);
    }

    let correlationBonus = 0;
    if (categories.size >= 2) correlationBonus = 15;
    if (categories.size >= 3) correlationBonus = 25;

    const targetScore = Math.min(100, Math.max(0, severityPoints + correlationBonus));
    this.currentScore = targetScore;

    return {
      score: Math.round(this.currentScore),
      band: this.getBand(this.currentScore),
      breakdown: {
        activeAlertCount: activeAlerts.length,
        severityPoints,
        correlationBonus,
        categoriesCount: categories.size
      }
    };
  }

  reset() {
    this.currentScore = 0;
    this.lastAlertTime = 0;
    this.lastDecayCheck = Date.now();
  }
}

module.exports = RiskScorer;
