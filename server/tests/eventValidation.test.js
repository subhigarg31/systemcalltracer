const test = require('node:test');
const assert = require('node:assert');
const DetectionEngine = require('../src/detection/engine');

test('Event Schema Validation', async (t) => {
  const engine = new DetectionEngine();

  await t.test('accepts valid event', () => {
    const validEvent = {
      timestamp: '2026-10-13T10:00:00.000Z',
      pid: 1234,
      process_name: 'test_proc',
      syscall: 'openat',
      category: 'file',
      scenario: 'normal',
      ret: 3,
      args: { path: '/tmp/test' }
    };
    const res = engine.validateEvent(validEvent);
    assert.strictEqual(res.valid, true);
  });

  await t.test('rejects non-object or null', () => {
    assert.strictEqual(engine.validateEvent(null).valid, false);
    assert.strictEqual(engine.validateEvent('string').valid, false);
  });

  await t.test('rejects missing timestamp', () => {
    const res = engine.validateEvent({ pid: 1234, syscall: 'openat', category: 'file' });
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /timestamp/i);
  });

  await t.test('rejects missing or non-numeric pid', () => {
    const res = engine.validateEvent({ timestamp: '2026-10-13T10:00:00.000Z', pid: '1234', syscall: 'openat', category: 'file' });
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /pid/i);
  });

  await t.test('rejects missing syscall', () => {
    const res = engine.validateEvent({ timestamp: '2026-10-13T10:00:00.000Z', pid: 1234, category: 'file' });
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /syscall/i);
  });

  await t.test('rejects missing category', () => {
    const res = engine.validateEvent({ timestamp: '2026-10-13T10:00:00.000Z', pid: 1234, syscall: 'openat' });
    assert.strictEqual(res.valid, false);
    assert.match(res.error, /category/i);
  });
});
