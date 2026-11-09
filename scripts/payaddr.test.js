// Runs the REAL payment-address block lifted verbatim out of js/app.js (by marker, so the
// test breaks if the source moves) against stubbed fetch/DOM.
const fs = require('fs'), vm = require('vm');

const SRC = require('path').join(__dirname, '..', 'js', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');
const from = src.indexOf('// The protocol payment address, served by the registrar');
// stop BEFORE the source's own invocation - the harness drives it explicitly
const to = src.indexOf('// Invoked here rather than beside initLocalization()');
if (from < 0 || to < from) throw new Error('markers not found - did app.js change?');
const block = src.slice(from, to);

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + name); cond ? pass++ : fail++; };

function run({ fetchImpl, hasField = true }) {
  const field = { value: 'PRESET', placeholder: '' };
  const ctx = {
    API_BASE_URL: 'https://registrar.example',
    fetch: fetchImpl,
    localizationReady: Promise.resolve(),
    t: (k) => 'TRANSLATED:' + k,
    console: { error: () => {}, warn: () => {} },
    document: { getElementById: (id) => (hasField && id === 'payAddress' ? field : null) },
  };
  vm.createContext(ctx);
  vm.runInContext(block + '\n;globalThis.__ready = initPaymentAddress(localizationReady);', ctx);
  return { field, ctx };
}

const okResp = (addr) => async () => ({ ok: true, json: async () => ({ response: { address: addr } }) });

(async () => {
  let r = run({ fetchImpl: okResp('u1abcdef') });
  await r.ctx.__ready;
  check('populates the field from the API', r.field.value === 'u1abcdef');

  r = run({ fetchImpl: async () => ({ ok: false, json: async () => ({}) }) });
  await r.ctx.__ready;
  check('HTTP error clears the field', r.field.value === '');
  check('HTTP error shows a translated placeholder', r.field.placeholder === 'TRANSLATED:errors.request_failed');

  r = run({ fetchImpl: async () => { throw new Error('offline'); } });
  await r.ctx.__ready;
  check('network failure is caught, not thrown', r.field.value === '');

  r = run({ fetchImpl: async () => ({ ok: true, json: async () => ({ response: {} }) }) });
  await r.ctx.__ready;
  check('missing address in payload is rejected', r.field.value === '');

  r = run({ fetchImpl: async () => ({ ok: true, json: async () => ({ response: { address: '' } }) }) });
  await r.ctx.__ready;
  check('empty address string is rejected', r.field.value === '');

  let calls = 0;
  r = run({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ response: { address: 'u1cached' } }) }; } });
  await r.ctx.__ready;
  await r.ctx.fetchPaymentAddress();
  await r.ctx.fetchPaymentAddress();
  check('result is cached, not refetched (1 request for 3 calls)', calls === 1);

  // concurrent callers must share one request, not race two
  calls = 0;
  r = run({ fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ response: { address: 'u1conc' } }) }; } });
  const both = await Promise.all([r.ctx.fetchPaymentAddress(), r.ctx.fetchPaymentAddress(), r.ctx.__ready]);
  check('concurrent callers share a single request', calls === 1);
  check('concurrent callers get the same address', both[0] === 'u1conc' && both[1] === 'u1conc');

  // a failed attempt must not poison the cache
  let attempt = 0;
  r = run({ fetchImpl: async () => {
    if (++attempt === 1) throw new Error('offline');
    return { ok: true, json: async () => ({ response: { address: 'u1recovered' } }) };
  } });
  await r.ctx.__ready;
  check('field left empty after the failed attempt', r.field.value === '');
  check('a later retry succeeds (failure not cached)', (await r.ctx.fetchPaymentAddress()) === 'u1recovered');

  r = run({ fetchImpl: okResp('u1x'), hasField: false });
  await r.ctx.__ready;
  check('missing #payAddress element does not throw', true);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail === 0 ? 0 : 1);
})();
