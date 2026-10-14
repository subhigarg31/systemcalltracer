const { evaluateRuleA, evaluateRuleB, evaluateRuleC, evaluateRuleD } = require('./rules');
const RiskScorer = require('./riskScorer');
const config = require('../config');

class DetectionEngine {
  constructor(engineConfig = config) {
    this.config = engineConfig;
    this.riskScorer = new RiskScorer(this.config.risk);
    this.state = {
      dedupMap: new Map(),
      fileWriteHistory: [],
      processSpawnHistory: [],
      sensitiveFileAccessHistory: new Map()
    };
  }

  reset() {
    this.state = {
      dedupMap: new Map(),
      fileWriteHistory: [],
      processSpawnHistory: [],
      sensitiveFileAccessHistory: new Map()
    };
    this.riskScorer.reset();
  }

  /**
   * Validates event schema
   */
  validateEvent(event) {
    if (!event || typeof event !== 'object') {
      return { valid: false, error: 'Event must be an object' };
    }
    if (!event.timestamp || typeof event.timestamp !== 'string') {
      return { valid: false, error: 'Missing or invalid timestamp' };
    }
    if (typeof event.pid !== 'number' || isNaN(event.pid)) {
      return { valid: false, error: 'Missing or invalid pid' };
    }
    if (!event.syscall || typeof event.syscall !== 'string') {
      return { valid: false, error: 'Missing or invalid syscall' };
    }
    if (!event.category || typeof event.category !== 'string') {
      return { valid: false, error: 'Missing or invalid category' };
    }
    return { valid: true };
  }

  /**
   * Evaluates rules against an event and returns detection result
   */
  processEvent(rawEvent, activeAlertsList = []) {
    const val = this.validateEvent(rawEvent);
    if (!val.valid) {
      throw new Error(`Invalid event schema: ${val.error}`);
    }

    const event = { ...rawEvent };
    const triggeredAlerts = [];

    // Evaluate Rule A: Sensitive file access
    const alertA = evaluateRuleA(event, this.config.rules.ruleA, this.state);
    if (alertA) triggeredAlerts.push(alertA);

    // Evaluate Rule B: Ransomware-like multi-file writes
    const alertB = evaluateRuleB(event, this.config.rules.ruleB, this.state);
    if (alertB) triggeredAlerts.push(alertB);

    // Evaluate Rule C: Suspicious network connection
    const alertC = evaluateRuleC(event, this.config.rules.ruleC, this.state);
    if (alertC) triggeredAlerts.push(alertC);

    // Evaluate Rule D: Process spawn burst
    const alertD = evaluateRuleD(event, this.config.rules.ruleD, this.state);
    if (alertD) triggeredAlerts.push(alertD);

    // Update risk score
    const combinedActive = [...activeAlertsList, ...triggeredAlerts];
    const risk = this.riskScorer.calculate(combinedActive, triggeredAlerts.length > 0);

    // Attach current risk score and band to each newly triggered alert
    for (const a of triggeredAlerts) {
      a.riskScore = risk.score;
      a.riskBand = risk.band;
    }

    // Attach detection metadata to event
    event.detection = {
      flagged: triggeredAlerts.length > 0,
      alertCount: triggeredAlerts.length,
      alertIds: triggeredAlerts.map(a => a.alertId),
      highestSeverity: triggeredAlerts.length > 0 ? triggeredAlerts[0].severity : 'None'
    };

    event.risk = {
      score: risk.score,
      band: risk.band
    };

    return {
      event,
      newAlerts: triggeredAlerts,
      risk
    };
  }

  /**
   * Periodic decay tick
   */
  decayTick(activeAlertsList = []) {
    return this.riskScorer.calculate(activeAlertsList, false);
  }

  /**
   * Explicit recalculation upon alert status changes
   */
  recalculateScore(activeAlertsList = []) {
    return this.riskScorer.recalculateScore(activeAlertsList);
  }
}

module.exports = DetectionEngine;
