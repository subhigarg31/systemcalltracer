const test = require('node:test');
const assert = require('node:assert');
const RiskScorer = require('../src/detection/riskScorer');

test('Risk Scoring Model & Decay Policy', async (t) => {
  let scorer;

  t.beforeEach(() => {
    scorer = new RiskScorer({
      decayIntervalMs: 50, // Short interval for rapid test execution
      decayStep: 10
    });
  });

  await t.test('Initial score starts at 0 (Low band)', () => {
    const res = scorer.calculate([]);
    assert.strictEqual(res.score, 0);
    assert.strictEqual(res.band, 'Low');
  });

  await t.test('Score bands correctly mapped', () => {
    assert.strictEqual(scorer.getBand(0), 'Low');
    assert.strictEqual(scorer.getBand(24), 'Low');
    assert.strictEqual(scorer.getBand(25), 'Guarded');
    assert.strictEqual(scorer.getBand(49), 'Guarded');
    assert.strictEqual(scorer.getBand(50), 'High');
    assert.strictEqual(scorer.getBand(74), 'High');
    assert.strictEqual(scorer.getBand(75), 'Critical');
    assert.strictEqual(scorer.getBand(100), 'Critical');
  });

  await t.test('Accumulates score based on alert severities', () => {
    const alerts = [
      { severity: 'Critical', category: 'Credential Access' }, // +35
      { severity: 'High', category: 'Credential Access' }       // +20
    ];
    const res = scorer.calculate(alerts, true);
    assert.strictEqual(res.score, 55);
    assert.strictEqual(res.band, 'High');
  });

  await t.test('Applies correlation bonus for multi-category threats reaching Critical', () => {
    const alerts = [
      { severity: 'Critical', category: 'Credential Access' },
      { severity: 'Critical', category: 'Ransomware / Data Destruction' }
    ];
    // 35 + 35 = 70 + 15 correlation bonus = 85 -> Critical!
    const res = scorer.calculate(alerts, true);
    assert.strictEqual(res.score, 85);
    assert.strictEqual(res.band, 'Critical');
  });

  await t.test('Caps score at 100', () => {
    const alerts = [
      { severity: 'Critical', category: 'A' },
      { severity: 'Critical', category: 'B' },
      { severity: 'Critical', category: 'C' }
    ];
    const res = scorer.calculate(alerts, true);
    assert.strictEqual(res.score, 100);
    assert.strictEqual(res.band, 'Critical');
  });

  await t.test('Decays score when no active alerts present', async () => {
    // Elevate score first
    const alerts = [{ severity: 'Critical', category: 'Credential Access' }];
    scorer.calculate(alerts, true);
    assert.strictEqual(scorer.currentScore, 35);

    // Sleep past decay interval
    await new Promise(resolve => setTimeout(resolve, 80));

    // Calculate with 0 active alerts -> score should decay
    const decayed = scorer.calculate([], false);
    assert.ok(decayed.score < 35, `Expected score < 35, got ${decayed.score}`);
  });

  await t.test('Force decay step decrements score gracefully', () => {
    scorer.currentScore = 40;
    const res = scorer.forceDecayStep();
    assert.strictEqual(res.score, 30);
    assert.strictEqual(res.band, 'Guarded');
  });
});
