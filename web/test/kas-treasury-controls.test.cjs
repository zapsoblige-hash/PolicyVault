'use strict';

// Independent synthetic contract tests. No network, signing, storage, or shared writes.
// Portable destination: web/test/kas-treasury-controls.test.cjs. Optional repository override:
// PV_RC41_REPO=/path/to/worktree node web/test/kas-treasury-controls.test.cjs
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const repo = process.env.PV_RC41_REPO || path.resolve(__dirname, '../..');
const core = require(path.join(repo, 'web/core-bundle.js'));
const setup = require(path.join(repo, 'web/setup-ui.js')).createModule({ core });
const key = ch => ch.repeat(64);
const resolveCalls = [];
const api = { resolveXOnly: async address => {
  resolveCalls.push(address);
  if (address === 'kaspa:synthetic-recipient-a' || address === 'kaspa:synthetic-recipient-a-alias') return key('2');
  if (address === 'kaspa:synthetic-recipient-b') return key('3');
  throw new Error('synthetic recipient rejected');
} };
const kas = require(path.join(repo, 'web/kas-vault-ui.js')).createModule({ core, setup, api });
const budget = setup.BUDGET_SETTING;
const exactOptions = { allowExactDaa: true };
const max = '2900000000000000000';
const clone = value => JSON.parse(JSON.stringify(value));
const exactSelection = value => ({ preset: 'custom', customValue: value, customUnit: 'daa' });
const existing = (daa = '1005', agentPk = key('1')) => ({
  agentPk, maxPerSpend: '100000000', periodBudget: '200000000', periodLengthDaa: daa,
  periodStartDaa: '400', periodSpent: '3', approvalThreshold: '100000000',
  agentMaxFeePerTx: '5000000', recipients: [key('2')]
});
const row = (daa = '1005', agentPk = key('1')) => kas.agentRowFrom(existing(daa, agentPk), '999999');
const vault = { vaultId: 'synthetic-controls-vault', contractVersion: 'policyvault-0.7-kas' };
const validate = rows => kas.validateVaultOpDraft({ op: 'ownerSetAgentRoot', draft: { agents: rows }, vault });
function expectedPolicy(input) {
  return { ...input, agentRecipientRoot: core.recipientMerkle.buildRecipientTree(input.recipients).root };
}
function expectedRoot(inputs) {
  return core.agentMerkle.buildAgentTreeV4(inputs.map(expectedPolicy)).root;
}
function leafHex(policy) {
  return Buffer.from(core.agentMerkle.agentLeafPreimage(policy)).toString('hex');
}
function assertRefused(result) {
  assert.equal(result.ok, false);
  assert.equal(result.vaultOperation, null);
}
function agentError(result, index) {
  const errors = result.errors.get('agentRows');
  assert.ok(errors && errors[index], `missing delegate-local error for index ${index}`);
  return errors[index];
}
function recipientError(result, agentIndex, recipientIndex) {
  const errors = agentError(result, agentIndex);
  assert.ok(errors.recipientRows && errors.recipientRows[recipientIndex], `missing recipient-local error for delegate ${agentIndex}, recipient ${recipientIndex}`);
  return errors.recipientRows[recipientIndex];
}

test('shared budget presets and canonical conversion remain unchanged', () => {
  assert.equal(core.durationDaa.DAA_PER_SECOND, 10n);
  assert.equal(budget.defaultPreset, '1d');
  assert.deepEqual(budget.presets.map(p => [p.key, p.daa]), [
    ['1h', '36000'], ['6h', '216000'], ['1d', '864000'], ['1w', '6048000']
  ]);
  for (const preset of budget.presets) {
    const raw = { preset: preset.key };
    assert.deepEqual(setup.readDurationSelection(budget, raw, exactOptions), setup.readDurationSelection(budget, raw));
  }
  assert.throws(() => core.durationDaa.durationSettingFor('budgetPeriod', 'policyvault-0.7-kas'), e => e.code === 'DURATION_SETTING_UNKNOWN');
});

test('exact DAA entry is opt-in and cannot broaden normal shared duration controls', () => {
  assert.throws(() => setup.readDurationSelection(budget, exactSelection('1005')));
  assert.throws(() => setup.readDurationSelection(budget, exactSelection('1005'), { allowExactDaa: false }));
  const normal = setup.renderDurationControl({ name: 'ordinary-period', setting: budget, selection: { preset: '1d' } });
  assert.doesNotMatch(normal, /<option value="daa"/);
});

for (const daa of ['1', '10', '1005', '35999', '864000', '320544001', max]) {
  test(`opt-in exact DAA entry preserves ${daa} and labels its source accurately`, () => {
    const selected = setup.readDurationSelection(budget, exactSelection(daa), exactOptions);
    const canonical = core.durationDaa.normalizeDurationSelection(budget, { mode: 'existing', daa });
    assert.deepEqual(selected, { ...canonical, source: 'custom-exact' });
    assert.equal(selected.daa, daa);
    assert.match(setup.durationExactText(budget, exactSelection(daa), exactOptions), new RegExp(`Exactly ${daa} DAA`));
    assert.doesNotMatch(setup.durationExactText(budget, exactSelection(daa), exactOptions), /current value kept unchanged/);
    assert.doesNotMatch(setup.durationEffectText(budget, exactSelection(daa), exactOptions), /unsupported|unknown|invalid|current value kept unchanged/i);
  });
  test(`unchanged existing ${daa} retains policy bytes, root, start, and spending`, async () => {
    const input = existing(daa);
    const draft = kas.agentRowFrom(input, '999999');
    assert.deepEqual(draft.period, { preset: 'existing', existingDaa: daa, customValue: '', customUnit: 'daa' });
    assert.deepEqual(draft.recipients, [{ address: key('2') }]);
    const before = clone(draft);
    const result = await validate([draft]);
    assert.equal(result.ok, true, JSON.stringify([...result.errors]));
    assert.deepEqual(result.vaultOperation.params.agents[0], expectedPolicy(input));
    assert.equal(leafHex(result.vaultOperation.params.agents[0]), leafHex(expectedPolicy(input)));
    assert.equal(result.agentRoot, expectedRoot([input]));
    assert.deepEqual(draft, before, 'validation must not mutate form state');
  });
}

test('exact DAA selection rejects zero, malformed, unsafe, overflow, and unsigned-64 values', () => {
  for (const value of ['', '0', '-1', '1.5', '1e3', 'NaN', '2900000000000000001', '18446744073709551615', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => setup.readDurationSelection(budget, exactSelection(value), exactOptions), undefined, String(value));
  }
});

test('human custom selections retain whole-unit conversion, product bounds, and no rounding', () => {
  const valid = { preset: 'custom', customValue: '36', customUnit: 'hour' };
  assert.equal(setup.readDurationSelection(budget, valid, exactOptions).daa, '1296000');
  assert.deepEqual(setup.readDurationSelection(budget, valid, exactOptions), setup.readDurationSelection(budget, valid));
  assert.throws(() => setup.readDurationSelection(budget, { preset: 'custom', customValue: '1.5', customUnit: 'day' }, exactOptions), e => e.code === 'DURATION_PRECISION' && /36 hours/.test(e.message));
  assert.throws(() => setup.readDurationSelection(budget, { preset: 'custom', customValue: '54', customUnit: 'week' }, exactOptions));
  assert.equal(setup.readDurationSelection(budget, { preset: 'custom', customValue: '53', customUnit: 'week' }, exactOptions).daa, '320544000');
});

test('opt-in control displays the selected exact unit and approximate duration', () => {
  const html = setup.renderDurationControl({ name: 'kas-period', setting: budget, selection: exactSelection('1005'), allowExactDaa: true });
  assert.match(html, /<option value="daa" selected/);
  assert.match(html, /Exactly 1005 DAA/);
  assert.match(html, /10 DAA per second/);
  assert.doesNotMatch(html, /current value kept unchanged/);
});

test('new delegate defaults share one-day budget policy without resetting imported state', () => {
  const fresh = kas.agentRowFrom(null, '12345');
  assert.equal(fresh.period.preset, budget.defaultPreset);
  assert.equal(setup.readDurationSelection(budget, fresh.period, exactOptions).daa, '864000');
  assert.equal(fresh.periodStartDaa, '12345');
  assert.equal(fresh.periodSpent, '0');
  assert.ok(Array.isArray(fresh.recipients));
  assert.equal(kas.agentPeriodSelection({ periodLengthDaa: '1005' }).existingDaa, '1005');
  assert.equal(kas.agentPeriodSelection({ period: exactSelection('1005'), periodLengthDaa: '864000' }).customValue, '1005');
});

test('deliberate preset and exact changes affect only the requested period field', async () => {
  for (const [selection, daa] of [[{ preset: '1d' }, '864000'], [exactSelection('1'), '1'], [exactSelection(max), max]]) {
    const draft = row();
    draft.period = selection;
    const result = await validate([draft]);
    assert.equal(result.ok, true, JSON.stringify([...result.errors]));
    assert.deepEqual(result.vaultOperation.params.agents[0], expectedPolicy(existing(daa)));
    assert.equal(result.agentRoot, expectedRoot([existing(daa)]));
  }
});

test('invalid explicit selection cannot fall back to a valid legacy raw period', async () => {
  for (const selection of [exactSelection('0'), exactSelection('18446744073709551615'), { preset: 'not-a-preset' }, { preset: 'existing', existingDaa: '' }]) {
    const draft = row();
    draft.periodLengthDaa = '864000';
    draft.period = selection;
    const result = await validate([draft]);
    assertRefused(result);
    assert.ok(agentError(result, 0).periodLengthDaa || agentError(result, 0).period);
  }
});

test('legacy raw period and delimited recipient drafts preserve their canonical output', async () => {
  const draft = row();
  delete draft.period;
  draft.periodLengthDaa = '1005';
  draft.recipients = `${key('2')},\n${key('3')}`;
  const input = { ...existing(), recipients: [key('2'), key('3')] };
  const result = await validate([draft]);
  assert.equal(result.ok, true, JSON.stringify([...result.errors]));
  assert.deepEqual(result.vaultOperation.params.agents[0], expectedPolicy(input));
  assert.equal(result.agentRoot, expectedRoot([input]));
});

test('new recipient rows resolve addresses and raw keys through the existing identity boundary', async () => {
  const draft = row();
  draft.recipients = [{ address: 'kaspa:synthetic-recipient-a' }, { address: key('3') }];
  const callsBefore = resolveCalls.length;
  const result = await validate([draft]);
  assert.equal(result.ok, true, JSON.stringify([...result.errors]));
  assert.deepEqual(result.vaultOperation.params.agents[0].recipients, [key('2'), key('3')]);
  assert.deepEqual(resolveCalls.slice(callsBefore), ['kaspa:synthetic-recipient-a']);
  assert.equal(result.agentRoot, expectedRoot([{ ...existing(), recipients: [key('2'), key('3')] }]));
});

test('recipient row conversion preserves text and returns independent editable row objects', () => {
  assert.deepEqual(kas.recipientRowsFrom(`${key('2')},\nkaspa:synthetic-recipient-b`), [{ address: key('2') }, { address: 'kaspa:synthetic-recipient-b' }]);
  const input = { recipients: [{ address: key('2') }, { address: 'bad<recipient>' }] };
  const rows = kas.recipientRowsFrom(input.recipients);
  assert.deepEqual(rows, input.recipients);
  rows[0].address = key('3');
  assert.equal(input.recipients[0].address, key('2'));
  const a = row(), b = row('1005', key('4'));
  a.recipients.push({ address: key('3') });
  assert.deepEqual(b.recipients, [{ address: key('2') }]);
});

for (const bad of [
  { name: 'malformed address', rows: [{ address: key('2') }, { address: 'not-an-address' }] },
  { name: 'empty explicit row', rows: [{ address: key('2') }, { address: '' }] },
  { name: 'duplicate raw key', rows: [{ address: key('2') }, { address: key('2') }] },
  { name: 'raw-key and address alias', rows: [{ address: key('2') }, { address: 'kaspa:synthetic-recipient-a' }] },
  { name: 'two addresses for same key', rows: [{ address: 'kaspa:synthetic-recipient-a' }, { address: 'kaspa:synthetic-recipient-a-alias' }] }
]) {
  test(`${bad.name} rejects at the responsible recipient row without a transaction payload`, async () => {
    const draft = row();
    draft.recipients = clone(bad.rows);
    const result = await validate([draft]);
    assertRefused(result);
    recipientError(result, 0, 1);
    assert.deepEqual(draft.recipients, bad.rows, 'invalid user input must survive validation for correction');
  });
}

test('each delegate needs a recipient, but the same recipient may belong to two delegates', async () => {
  const blank = row();
  blank.recipients = [];
  assertRefused(await validate([blank]));
  const result = await validate([row(), row('1005', key('4'))]);
  assert.equal(result.ok, true, JSON.stringify([...result.errors]));
  assert.equal(result.agentRoot, expectedRoot([existing(), existing('1005', key('4'))]));
});

test('recipient validation errors remain on their delegate and do not overwrite another list', async () => {
  const a = row(), b = row('1005', key('4'));
  b.recipients = [{ address: key('3') }, { address: 'not-an-address' }];
  const beforeA = clone(a), beforeB = clone(b);
  const result = await validate([a, b]);
  assertRefused(result);
  assert.equal(result.errors.get('agentRows')[0], undefined);
  recipientError(result, 1, 1);
  assert.deepEqual(a, beforeA);
  assert.deepEqual(b, beforeB);
});

test('an untouched blank creation delegate stays optional after recipients become an array', async () => {
  const draft = kas.kasDraftDefaults('kaspa:synthetic-funder', '12345');
  const result = await kas.validateKasDraft(draft, { step: 'delegates' });
  assert.equal(result.ok, true, JSON.stringify([...result.errors]));
  const partial = kas.kasDraftDefaults('kaspa:synthetic-funder', '12345');
  partial.agents[0].recipients = [{ address: key('2') }];
  const partialResult = await kas.validateKasDraft(partial, { step: 'delegates' });
  assert.equal(partialResult.ok, false, 'a partly filled delegate must not silently disappear');
});

test('shared single-input recipient rendering retains values, escapes input, and exposes local errors', () => {
  const html = setup.renderAddressRows({ kind: 'kas-recipient-0', rows: [{ address: key('2') }, { address: '<bad&recipient>' }], allowKey: false, rowLabel: 'Recipient', addressLabel: 'wallet address or 64-hex public key', placeholder: 'Wallet address or 64-hex key', errors: { 1: '<invalid>' } });
  assert.match(html, new RegExp(`value="${key('2')}"`));
  assert.match(html, /value="&lt;bad&amp;recipient&gt;"/);
  assert.match(html, /&lt;invalid&gt;/);
  assert.doesNotMatch(html, /data-keytoggle|class="mono addr-key"|<textarea/);
  assert.match(html, /aria-label="Recipient 1 [^"]*"/);
  const other = setup.renderAddressRows({ kind: 'kas-recipient-1', rows: [{ address: key('3') }], allowKey: false });
  assert.match(html, /id="v4-add-kas-recipient-0"/);
  assert.match(other, /id="v4-add-kas-recipient-1"/);
});

test('owner delegate form uses shared duration and address rows with independent identifiers', () => {
  const html = kas.renderVaultOpFormHtml({ op: 'ownerSetAgentRoot', vault, draft: { agents: [row(), row('864000', key('4'))], currentDaa: '999999' } });
  assert.match(html, /data-duration="[^"]+"/);
  assert.match(html, /Exactly 1005 DAA/);
  assert.match(html, /Exactly 864000 DAA/);
  assert.doesNotMatch(html, /About 1 DAA per second|864000.{0,15}10 days|<textarea/);
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
  assert.equal(new Set(ids).size, ids.length, 'rendered form must not have duplicate IDs');
});


for (const invalid of ['0', '2900000000000000001', '18446744073709551615']) {
  test(`invalid imported exact period ${invalid} stays a refusal and never defaults to a day`, async () => {
    const selection = kas.agentPeriodSelection({ periodLengthDaa: invalid });
    assert.equal(selection.preset, 'existing');
    assert.equal(selection.existingDaa, invalid);
    const draft = row();
    draft.period = selection;
    const selected = await validate([draft]);
    assertRefused(selected);
    const legacy = row();
    delete legacy.period;
    legacy.periodLengthDaa = invalid;
    legacy.recipients = key('2');
    assertRefused(await validate([legacy]));
  });
}

test('creation delegate-local errors use original displayed indices when a blank delegate is skipped', async () => {
  const d = kas.kasDraftDefaults('kaspa:synthetic-funder', '12345');
  const invalid = row();
  invalid.recipients = [{ address: key('2') }, { address: 'not-an-address' }];
  d.agents.push(invalid);
  const result = await kas.validateKasDraft(d, { step: 'delegates' });
  assert.equal(result.ok, false);
  assert.equal(result.errors.get('agentRows')[0], undefined, 'blank optional delegate must not receive a later delegate error');
  recipientError(result, 1, 1);
});

test('a newly entered recipient field never splits pasted comma or newline lists', async () => {
  for (const address of [`${key('2')},${key('3')}`, `${key('2')}\n${key('3')}`]) {
    const draft = row();
    draft.recipients = [{ address }];
    const result = await validate([draft]);
    assertRefused(result);
    recipientError(result, 0, 0);
    assert.equal(draft.recipients[0].address, address);
  }
});

test('address resolver results still pass the canonical key boundary before output', async () => {
  const invalidKas = require(path.join(repo, 'web/kas-vault-ui.js')).createModule({ core, setup, api: { resolveXOnly: async () => 'not-a-key' } });
  const draft = row();
  draft.recipients = [{ address: 'kaspa:synthetic-invalid-resolution' }];
  const result = await invalidKas.validateVaultOpDraft({ op: 'ownerSetAgentRoot', draft: { agents: [draft] }, vault });
  assertRefused(result);
});
