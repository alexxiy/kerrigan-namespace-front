// Runs the REAL payment-address block lifted verbatim out of js/app.js (by marker, so the
// test breaks if the source moves) against stubbed fetch/DOM. The address rules block is lifted
// with it: fetchPaymentAddress() holds the served address to them, and the block also carries the
// registrar clock offset and the command nonce (commandNonce) that this test checks too, and
// the offset measured again when the device clock moved (deviceClockMoved).
//
//   node scripts/payaddr.test.js
const fs = require('fs'), vm = require('vm'), path = require('path');

const SRC = path.join(__dirname, '..', 'js', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');

const rulesFrom = src.indexOf('// Accepted Kerrigan Sapling address shape per network.');
const rulesEnd = src.indexOf('\n}', src.indexOf('function isValidKerriganAddress')) + 2;
const from = src.indexOf('// The protocol payment address, served by the registrar');
// stop BEFORE the source's own invocation - the harness drives it explicitly
const to = src.indexOf('// Invoked here rather than beside initLocalization()');
if (rulesFrom < 0 || rulesEnd < rulesFrom || from < rulesEnd || to < from) {
  throw new Error('markers not found - did app.js change?');
}
const block = src.slice(rulesFrom, rulesEnd) + '\n' + src.slice(from, to);

// Real addresses, from the corpus the circuit and the indexer are checked against.
const MAINNET = 'ks1zakp8l6gscp7kamwzyqxe67sk35xmmfvdvfj5e8erjc57n6ge9d8alzh0x2ut4vuh3fhvdrrnwf';
const MAINNET2 = 'ks14ge6h7x58v3le8zyrvxejha5gkvqvwy9emt23sudwxe5up44flxww0vuzv0rwgrqcd5m2mjtg44';
const TESTNET = 'ktestsapling1xfxjd5wc803pt47xq3tsqt5k3qp9jkdmjrqv9u8l9jqhgftkzhs8ekjnpzcysz2gcz9qvx5kj0y';
const UPPER = 'KS1J63XFG4Z8WQK6K49MXGNQHYWLLL0DML6KAKRWM7H6T35U5PY08GT0Q3FFYMEDWRZ6HFQW5Y7NFF';
// One character of the checksum changed.
const BAD_CHECKSUM = MAINNET.slice(0, -1) + (MAINNET.endsWith('a') ? 'q' : 'a');

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + name); cond ? pass++ : fail++; };

// A clock the test sets: Date.now() inside the lifted code reads it.
let fakeNowMs = 1780000000000;
const FakeDate = { now: () => fakeNowMs };
// performance.now() inside the lifted code: it does not follow the device clock.
let fakePerfMs = 5000;
const FakePerformance = { now: () => fakePerfMs };

const PRODUCTION_REGISTRAR = 'https://registrar.kerrigan-name.space';
// The same registrar as the onion mirror reaches it, as app.js names it: held to the published
// address the same way.
const ONION_REGISTRAR = (src.match(/^const ONION_REGISTRAR = "([^"]+)";$/m) || [])[1];
if (!ONION_REGISTRAR) throw new Error('ONION_REGISTRAR not found in app.js - did it move?');
// The published payment address (docs intro), which the production registrar must serve.
const PUBLISHED = 'ks14uyfh9m64njntdtxsnt662utf2yxtvtnyzyh2v8d0nna7cngzd6eeht3x80689d973v0yvc2fkz';

function run({ fetchImpl, hasField = true, bech32m, apiBase = 'https://registrar.example' }) {
  const field = { value: 'PRESET', placeholder: '' };
  const ctx = {
    API_BASE_URL: apiBase,
    PRODUCTION_REGISTRAR,
    ONION_REGISTRAR,
    fetch: fetchImpl,
    localizationReady: Promise.resolve(),
    t: (k) => 'TRANSLATED:' + k,
    console: { error: () => {}, warn: () => {} },
    document: { getElementById: (id) => (hasField && id === 'payAddress' ? field : null) },
    bech32m,
    Date: FakeDate,
    performance: FakePerformance,
    applyProtocolZones: (zones) => { ctx.__zones = zones; },
  };
  vm.createContext(ctx);
  vm.runInContext(block + `
;globalThis.__ready = initPaymentAddress(localizationReady);
globalThis.__state = () => ({ network: kerriganNetwork, offset: serverClockOffsetSec, now: nowSeconds(),
  payConfs: typeof PAYMENT_CONFIRMATIONS === 'undefined' ? undefined : PAYMENT_CONFIRMATIONS });
globalThis.__lastSigned = lastSignedNonce;`, ctx);
  return { field, ctx };
}

const answer = (response) => async () => ({ ok: true, json: async () => ({ response }) });
const okResp = (addr) => answer({ address: addr });

(async () => {
  const { bech32m } = await import(path.join(__dirname, '..', 'js', 'vendor', 'bech32.js'));
  const go = (opts) => run({ bech32m, ...opts });
  const fieldAfter = async (response) => {
    const r = go({ fetchImpl: answer(response) });
    await r.ctx.__ready;
    return r;
  };

  let r = go({ fetchImpl: okResp(MAINNET) });
  await r.ctx.__ready;
  check('populates the field from the API', r.field.value === MAINNET);
  check('no network served: mainnet rules stay', r.ctx.__state().network === 'mainnet');

  r = go({ fetchImpl: async () => ({ ok: false, json: async () => ({}) }) });
  await r.ctx.__ready;
  check('HTTP error clears the field', r.field.value === '');
  check('HTTP error shows a translated placeholder', r.field.placeholder === 'TRANSLATED:errors.request_failed');

  r = go({ fetchImpl: async () => { throw new Error('offline'); } });
  await r.ctx.__ready;
  check('network failure is caught, not thrown', r.field.value === '');

  r = await fieldAfter({});
  check('missing address in payload is rejected', r.field.value === '');

  r = await fieldAfter({ address: '' });
  check('empty address string is rejected', r.field.value === '');

  // The address is held to the rules of an address a user types.
  r = await fieldAfter({ address: UPPER });
  check('uppercase address is refused', r.field.value === '');
  r = await fieldAfter({ address: ' ' + MAINNET });
  check('address with a space before it is refused', r.field.value === '');
  r = await fieldAfter({ address: MAINNET + '\n' });
  check('address with a newline after it is refused', r.field.value === '');
  r = await fieldAfter({ address: BAD_CHECKSUM });
  check('address with a bad checksum is refused', r.field.value === '');
  r = await fieldAfter({ address: TESTNET });
  check('testnet address on mainnet rules is refused', r.field.value === '');
  r = await fieldAfter({ address: TESTNET, network: 'testnet' });
  check('testnet answer switches the rules: ktestsapling address taken', r.field.value === TESTNET && r.ctx.__state().network === 'testnet');
  r = await fieldAfter({ address: MAINNET, network: 'testnet' });
  check('testnet answer with a mainnet address is refused', r.field.value === '');
  check('a refused answer leaves the network as it was', r.ctx.__state().network === 'mainnet');
  r = await fieldAfter({ address: MAINNET, network: 'regtest' });
  check('unknown network is ignored (mainnet rules kept)', r.field.value === MAINNET && r.ctx.__state().network === 'mainnet');
  // The production registrar must serve the published address; others serve their own.
  r = go({ fetchImpl: okResp(PUBLISHED), apiBase: PRODUCTION_REGISTRAR });
  await r.ctx.__ready;
  check('production registrar serving the published address: taken', r.field.value === PUBLISHED);
  r = go({ fetchImpl: okResp(MAINNET), apiBase: PRODUCTION_REGISTRAR });
  await r.ctx.__ready;
  check('production registrar serving another valid address: refused', r.field.value === '');
  r = go({ fetchImpl: answer({ address: TESTNET, network: 'testnet' }), apiBase: PRODUCTION_REGISTRAR });
  await r.ctx.__ready;
  check('production registrar claiming testnet: refused', r.field.value === '');
  check('production registrar claiming testnet: mainnet rules kept', r.ctx.__state().network === 'mainnet');
  r = go({ fetchImpl: okResp(PUBLISHED), apiBase: ONION_REGISTRAR });
  await r.ctx.__ready;
  check('onion registrar serving the published address: taken', r.field.value === PUBLISHED);
  r = go({ fetchImpl: okResp(MAINNET), apiBase: ONION_REGISTRAR });
  await r.ctx.__ready;
  check('onion registrar serving another valid address: refused', r.field.value === '');
  r = await fieldAfter({ address: PUBLISHED });
  check('the published address is valid by the address rules', r.field.value === PUBLISHED);

  r = await fieldAfter({ address: MAINNET, payment_confirmations: 7, zones: ['krgn', 'x'] });
  check('confirmations and zones are adopted', r.ctx.__state().payConfs === 7 && Array.isArray(r.ctx.__zones));

  // The registrar's clock.
  fakeNowMs = 1780000000000;
  r = await fieldAfter({ address: MAINNET, server_time: 1780000000 - 3600 });
  check('device an hour ahead: offset adopted, nonces on the registrar clock', r.ctx.__state().now === 1780000000 - 3600);
  r = await fieldAfter({ address: MAINNET, server_time: 1780000000 + 120 });
  check('device two minutes behind: offset adopted', r.ctx.__state().now === 1780000000 + 120);
  r = await fieldAfter({ address: MAINNET, server_time: 1780000000 - 1 });
  check('a second apart is noise: device clock kept', r.ctx.__state().offset === 0 && r.ctx.__state().now === 1780000000);
  r = await fieldAfter({ address: MAINNET, server_time: '1780003600' });
  check('a server_time that is not an integer is ignored', r.ctx.__state().offset === 0);
  r = await fieldAfter({ address: MAINNET });
  check('no server_time: offset stays 0', r.ctx.__state().offset === 0);

  let calls = 0;
  r = go({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ response: { address: MAINNET } }) }; } });
  await r.ctx.__ready;
  await r.ctx.fetchPaymentAddress();
  await r.ctx.fetchPaymentAddress();
  check('result is cached, not refetched (1 request for 3 calls)', calls === 1);

  // concurrent callers must share one request, not race two
  calls = 0;
  r = go({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ response: { address: MAINNET2 } }) }; } });
  const both = await Promise.all([r.ctx.fetchPaymentAddress(), r.ctx.fetchPaymentAddress(), r.ctx.__ready]);
  check('concurrent callers share a single request', calls === 1);
  check('concurrent callers get the same address', both[0] === MAINNET2 && both[1] === MAINNET2);

  // a failed attempt must not poison the cache
  let attempt = 0;
  r = go({ fetchImpl: async () => {
    if (++attempt === 1) throw new Error('offline');
    return { ok: true, json: async () => ({ response: { address: MAINNET } }) };
  } });
  await r.ctx.__ready;
  check('field left empty after the failed attempt', r.field.value === '');
  check('a later retry succeeds (failure not cached)', (await r.ctx.fetchPaymentAddress()) === MAINNET);

  r = go({ fetchImpl: okResp(MAINNET), hasField: false });
  await r.ctx.__ready;
  check('missing #payAddress element does not throw', true);

  // A step that leads to a payment panel awaits fillPaymentAddress(): the field filled from its
  // answer, where a request at startup that failed had left it empty while the payment went ahead.
  attempt = 0;
  r = go({ fetchImpl: async () => {
    if (++attempt === 1) throw new Error('offline');
    return { ok: true, json: async () => ({ response: { address: MAINNET } }) };
  } });
  await r.ctx.__ready;
  check('startup failed: the field empty', r.field.value === '');
  check('fillPaymentAddress(): the address answered', (await r.ctx.fillPaymentAddress()) === MAINNET);
  check('fillPaymentAddress(): the field filled with it', r.field.value === MAINNET);
  r = go({ fetchImpl: async () => { throw new Error('offline'); } });
  await r.ctx.__ready;
  let fillError = null;
  try { await r.ctx.fillPaymentAddress(); } catch (e) { fillError = e.message; }
  check('fillPaymentAddress() failing throws, as the fetch does (nothing signed)', fillError === 'offline' && r.field.value === '');
  r = go({ fetchImpl: okResp(MAINNET), hasField: false });
  await r.ctx.__ready;
  check('fillPaymentAddress() without #payAddress: the address, no throw', (await r.ctx.fillPaymentAddress()) === MAINNET);

  // In app.js: each step that shows the payment panel fills the field before it does, and no other
  // step shows that panel. (The history awaits the fetch alone: it needs the network and the
  // clock, and shows no address.)
  for (const step of ['const proceedToPayment = async () => {', 'const proceedRemoval = async () => {']) {
    const at = src.indexOf(step);
    const panel = src.indexOf('setActiveSlide(slidePayment', at);
    check(step.split(' ')[1] + ' fills the field before the payment panel',
      at >= 0 && panel > at && src.slice(at, panel).includes('await fillPaymentAddress();'));
  }
  check('no other step shows the payment panel', (src.match(/setActiveSlide\(slidePayment\b/g) || []).length === 2);

  // The device clock moved since the registrar's was read - set by its user, or a sleep where
  // performance.now() stood still: the next fetchPaymentAddress(), which every signing awaits
  // first, measures the offset again.
  let serverSec = 1780000000 + 600;   // the device ten minutes behind
  let clockFails = false;
  fakeNowMs = 1780000000000;
  fakePerfMs = 5000;
  calls = 0;
  r = go({ fetchImpl: async () => {
    calls++;
    if (clockFails) throw new Error('offline');
    return { ok: true, json: async () => ({ response: { address: MAINNET, server_time: serverSec } }) };
  } });
  await r.ctx.__ready;
  check('device ten minutes behind: offset adopted', calls === 1 && r.ctx.__state().now === 1780000600);
  fakeNowMs += 60000; fakePerfMs += 60000; serverSec += 60;
  await r.ctx.fetchPaymentAddress();
  check('a minute on both clocks: not measured again', calls === 1 && r.ctx.__state().now === 1780000660);
  fakeNowMs += 1500;
  await r.ctx.fetchPaymentAddress();
  check('the device clock 1.5 s off performance.now(): not measured again', calls === 1);
  fakeNowMs -= 1500;
  // The device clock is corrected: ten minutes ahead at once, performance.now() as it was.
  fakeNowMs += 600000;
  check('clock corrected: nowSeconds() alone still runs ahead by the old offset', r.ctx.__state().now === 1780001260);
  await r.ctx.fetchPaymentAddress();
  check('clock corrected: measured again at the next signing', calls === 2);
  check('clock corrected: back on the registrar clock', r.ctx.__state().offset === 0 && r.ctx.__state().now === 1780000660);
  // An hour asleep, where performance.now() stood still.
  fakeNowMs += 3600000; serverSec += 3600;
  await r.ctx.fetchPaymentAddress();
  check('a sleep where performance.now() stood still: measured again', calls === 3 && r.ctx.__state().now === 1780004260);
  // The device clock set ten minutes ahead.
  fakeNowMs += 600000;
  await r.ctx.fetchPaymentAddress();
  check('clock set ahead: measured again', calls === 4 && r.ctx.__state().offset === -600 && r.ctx.__state().now === 1780004260);
  // Set right again, and the registrar unreachable when it is measured.
  fakeNowMs -= 600000;
  clockFails = true;
  let measureError = null;
  try { await r.ctx.fetchPaymentAddress(); } catch (e) { measureError = e.message; }
  check('measured again, the registrar unreachable: the signing fails', measureError === 'offline' && calls === 5);
  check('measured again, the registrar unreachable: the old offset is dropped', r.ctx.__state().offset === 0);
  clockFails = false;
  await r.ctx.fetchPaymentAddress();
  check('the next attempt measures it', calls === 6 && r.ctx.__state().offset === 0 && r.ctx.__state().now === 1780004260);
  // A registrar that sends no time: nothing was measured, so nothing is measured again.
  calls = 0;
  r = go({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ response: { address: MAINNET } }) }; } });
  await r.ctx.__ready;
  fakeNowMs += 3600000;
  await r.ctx.fetchPaymentAddress();
  check('no server_time: not fetched again when the device clock moves', calls === 1);
  fakeNowMs = 1780000000000;
  fakePerfMs = 5000;

  // commandNonce(): the clock, but greater than the name's stored nonce and the last one signed.
  fakeNowMs = 1780000000000;
  let checkAnswer = { exists: true, nonce: 0 };
  let checkUrl = '';
  r = go({ fetchImpl: async (url) => {
    if (url.includes('/v1.0/check/')) {
      checkUrl = url;
      return { ok: true, json: async () => ({ response: checkAnswer }) };
    }
    return { ok: true, json: async () => ({ response: { address: MAINNET, server_time: 1780000000 } }) };
  } });
  await r.ctx.__ready;
  const nonceFor = (d) => r.ctx.commandNonce(d);
  const rejection = async (d) => { try { await nonceFor(d); return null; } catch (e) { return e.message; } };

  checkAnswer = { exists: false, price: 1 };
  check('free name: the time', await nonceFor('free.krgn') === 1780000000 && checkUrl.endsWith('/v1.0/check/free.krgn'));
  checkAnswer = { exists: true, nonce: 1779990000 };
  check('stored nonce in the past: the time', await nonceFor('a.krgn') === 1780000000);
  checkAnswer = { exists: true, nonce: 1780000100 };
  check('stored nonce ahead (clock behind, listing ahead): stored + 1', await nonceFor('a.krgn') === 1780000101);
  checkAnswer = { exists: true, nonce: 1780000000 };
  check('stored nonce == the time: stored + 1', await nonceFor('a.krgn') === 1780000001);
  checkAnswer = { exists: true, nonce: 1780000300 };
  check('stored + 1 one second past the tolerance: refused (wait)', await rejection('a.krgn') === 'Nonce wait');
  checkAnswer = { exists: true, nonce: 1780000299 };
  check('stored + 1 at the tolerance: taken', await nonceFor('a.krgn') === 1780000300);
  checkAnswer = { exists: true };
  check('registrar without `nonce`: the time', await nonceFor('a.krgn') === 1780000000);
  checkAnswer = { exists: true, nonce: '1780000500' };
  check('a nonce that is not an integer is ignored', await nonceFor('a.krgn') === 1780000000);
  r.ctx.__lastSigned.set('b.krgn', 1780000000);
  checkAnswer = { exists: true, nonce: 1779990000 };
  check('second command on a name in the same second: last signed + 1', await nonceFor('b.krgn') === 1780000001);
  check('other names are not affected by it', await nonceFor('c.krgn') === 1780000000);
  fakeNowMs = 1780000000000 + 3600 * 1000;
  check('nonce follows the device clock from there on', await nonceFor('c.krgn') === 1780003600);
  fakeNowMs = 1780000000000;

  const failing = go({ fetchImpl: async (url) => (url.includes('/check/')
    ? { ok: true, json: async () => ({ error: { error_message: 'x' } }) }
    : { ok: true, json: async () => ({ response: { address: MAINNET } }) }) });
  await failing.ctx.__ready;
  let msg = null;
  try { await failing.ctx.commandNonce('a.krgn'); } catch (e) { msg = e.message; }
  check('an error answer from check throws (no command signed)', msg !== null && msg !== 'Nonce wait');
  const offline = go({ fetchImpl: async (url) => { if (url.includes('/check/')) throw new Error('offline'); return { ok: true, json: async () => ({ response: { address: MAINNET } }) }; } });
  await offline.ctx.__ready;
  msg = null;
  try { await offline.ctx.commandNonce('a.krgn'); } catch (e) { msg = e.message; }
  check('a failed check request throws', msg === 'offline');

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail === 0 ? 0 : 1);
})();
