// Runs the REAL payment status block lifted verbatim out of js/app.js (by marker, so the test
// breaks if the source moves: from the iPaidBtn lookup to the end of its click handler) against
// stubbed DOM and fetch, with the fetch answers released one by one. It checks that a check still
// in flight from an earlier payment ("I paid" clicked again, or the flow reset) can neither take
// its transaction for the new payment nor hold off the new payment's first check.
//
//   node scripts/poll.test.js
const fs = require('fs'), vm = require('vm'), path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'js', 'app.js'), 'utf8');
const from = src.indexOf("const iPaidBtn = document.getElementById('iPaidBtn');");
const to = src.indexOf('// Name Availability Search Logic');
if (from < 0 || to < from) throw new Error('markers not found - did app.js change?');
const block = src.slice(from, to);

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + name); cond ? pass++ : fail++; };

function el(id) {
  return {
    id, textContent: '', innerHTML: '', value: id === 'payMemo' ? 'MEMO' : '',
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener(ev, fn) { this['on' + ev] = fn; },
  };
}
const els = {};
const calls = []; // each request: { body, resolve }
const steps = [];
const ctx = {
  document: { getElementById: (id) => (els[id] ??= el(id)) },
  t: (k) => k,
  tSafe: (k) => k,
  setActiveSlide() {},
  setStep: (s) => steps.push(s),
  slideStatus: {},
  API_BASE_URL: 'https://registrar.example',
  currentRegistrationDomain: 'abc.krgn',
  currentTransactionType: 'REG',
  PAYMENT_CONFIRMATIONS: 40,
  REFUND_CONFIRMATIONS: 120,
  btoa: (s) => Buffer.from(s).toString('base64'),
  // The timers are driven by hand below.
  setInterval: () => 1,
  clearInterval() {},
  console: { error() {}, log() {} },
  fetch: (url, init) => new Promise((resolve) => calls.push({ body: JSON.parse(init.body), resolve })),
};
vm.createContext(ctx);
vm.runInContext(block + `
;globalThis.__state = () => ({ currentTxId, isPolling });
globalThis.__poll = pollTransactionStatus;`, ctx);

const answer = (call, response) => call.resolve({ json: async () => ({ response }) });
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };

(async () => {
  const iPaid = () => els.iPaidBtn.onclick();

  iPaid(); // payment 1: its first check in flight
  await settle();
  check('payment 1: one check sent, by memo', calls.length === 1 && calls[0].body.reg_id !== undefined);

  iPaid(); // payment 2, while payment 1's check is still in flight
  await settle();
  check('payment 2: its first check is sent at once, not held off by the earlier one', calls.length === 2);

  answer(calls[0], { tx_id: 'OLD' }); // payment 1's answer arrives late
  await settle();
  check('the late answer of payment 1 is dropped: no transaction taken', ctx.__state().currentTxId === null);
  check('nor a check made for it', calls.length === 2);
  check('payment 2 keeps the in-flight flag', ctx.__state().isPolling === true);

  ctx.__poll(); // the 30-second timer firing meanwhile
  await settle();
  check('a timer check while payment 2 is in flight is skipped', calls.length === 2);

  answer(calls[1], { tx_id: 'NEW' }); // payment 2's own answer
  await settle();
  check('payment 2 takes its own transaction', ctx.__state().currentTxId === 'NEW');
  check('and checks it at once, by tx_id', calls.length === 3 && calls[2].body.tx_id === 'NEW');

  answer(calls[2], { status: 5 });
  await settle();
  check('its status is shown (the success step)', steps.includes('yours'));
  check('the in-flight flag is cleared at the end', ctx.__state().isPolling === false);

  // A reset of the flow moves pollGeneration on as well: an answer then in flight is dropped.
  ctx.__poll();
  await settle();
  vm.runInContext('pollGeneration++;', ctx);
  answer(calls[calls.length - 1], { status: 6 });
  await settle();
  check('after a reset, the answer in flight changes nothing', els.statusHeading.textContent !== 'status.failed_title');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
