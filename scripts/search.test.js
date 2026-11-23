// Runs the REAL name search block lifted verbatim out of js/app.js (by marker, so the test breaks
// if the source moves: from the search form's submit handler to the end of the name box's input
// handler) against stubbed DOM, fetch and timers, with the fetch answers released one by one. It
// checks that an answer which comes back after the name was edited is dropped rather than shown
// for a name no longer in the box, and that the fade of an edit no longer blanks an answer shown
// within it.
//
//   node scripts/search.test.js
const fs = require('fs'), vm = require('vm'), path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'js', 'app.js'), 'utf8');
const from = src.indexOf('// Name Availability Search Logic');
const to = src.indexOf("btnBackToSearchFromAddress.addEventListener('click'");
const genDecl = 'let searchGeneration = 0;';
if (from < 0 || to < from || !src.includes('\n' + genDecl + '\n')) {
  throw new Error('markers not found - did app.js change?');
}
const block = src.slice(from, to);

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? '  PASS  ' : '  FAIL  ') + name); cond ? pass++ : fail++; };

function el(id) {
  return {
    id, textContent: '', innerHTML: '', value: '', disabled: false, style: { opacity: '0' },
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener(ev, fn) { this['on' + ev] = fn; },
    dispatchEvent() {},
  };
}
const els = {};
const calls = []; // each request: { url, resolve, reject }
let timers = [];  // setTimeout callbacks, run by hand
const ctx = {
  document: { getElementById: (id) => (els[id] ??= el(id)) },
  form: el('registrationForm'),
  input: el('kerriganName'),
  domainZoneSelect: Object.assign(el('domainZone'), { value: '.krgn' }),
  btn: el('checkBtn'),
  btnText: el('btnText'),
  resultMessage: el('resultMessage'),
  slide1: {},
  slideAddress: {},
  targetAddressInput: el('targetAddress'),
  localStorage: { getItem: () => null },
  API_BASE_URL: 'https://registrar.example',
  t: (k) => k,
  tSafe: (k) => k,
  escapeHtml: (s) => String(s),
  formatSats: (v) => String(v),
  apiErrorText: (e, d) => d,
  showErrorAlert() {},
  getCachedPublicKey: () => null,
  setStep() {},
  setActiveSlide() {},
  setupSlide2Inputs() {},
  handleBuyDomain() {},
  handleRemoveFromSale() {},
  Event: class { constructor(type) { this.type = type; } },
  setTimeout: (fn) => { timers.push(fn); return timers.length; },
  console: { error() {}, log() {} },
  fetch: (url) => new Promise((resolve, reject) => calls.push({ url, resolve, reject })),
};
vm.createContext(ctx);
vm.runInContext(genDecl + '\n' + block, ctx);

const answer = (call, response) => call.resolve({ json: async () => ({ response }) });
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r)); };
const runTimers = () => { const due = timers; timers = []; due.forEach((fn) => fn()); };
const search = async (name) => { ctx.input.value = name; ctx.form.onsubmit({ preventDefault() {} }); await settle(); };
const type = (name) => { ctx.input.value = name; ctx.input.oninput(); };
const shown = () => ctx.resultMessage.style.opacity === '1' ? ctx.resultMessage.innerHTML : '';
const FREE = { exists: false, price: 100 };

(async () => {
  await search('alpha');
  check('a search asks for its name', calls.length === 1 && calls[0].url.endsWith('/v1.0/check/alpha.krgn'));
  answer(calls[0], FREE);
  await settle();
  check('its answer is shown', shown().includes('alpha.krgn') && ctx.btn.disabled === false);

  // Edited while the answer is on its way.
  type('alph');
  runTimers();
  await search('beta');
  type('gamma');
  answer(calls[1], FREE);
  await settle();
  check('an answer for a name no longer in the box is dropped', !ctx.resultMessage.innerHTML.includes('beta.krgn') && shown() === '');
  check('the search button is given back', ctx.btn.disabled === false);

  // Its search failing after the edit: no error for it either.
  await search('delta');
  type('delt');
  calls[2].reject(new Error('offline'));
  await settle();
  check('a failure for a name no longer in the box is not shown', !ctx.resultMessage.innerHTML.includes('search.conn_error'));

  // The same failure, the name unchanged: shown.
  await search('delta');
  calls[3].reject(new Error('offline'));
  await settle();
  check('a failure for the name in the box is shown', shown().includes('search.conn_error'));

  // Hidden content from before the search goes with a dropped answer: its buttons take clicks.
  ctx.resultMessage.innerHTML = 'OLD';
  await search('eps');
  type('epsi');
  answer(calls[4], FREE);
  await settle();
  check('a dropped answer empties what was hidden in the area', ctx.resultMessage.innerHTML === '');

  // An answer shown within the fade of an edit is not blanked by it.
  await search('zeta');
  answer(calls[5], FREE);
  await settle();
  type('zet');                      // fades the answer for zeta out, emptied in 300 ms
  check('an edit fades the answer out', ctx.resultMessage.style.opacity === '0' && timers.length === 1);
  await search('zet');              // sent within the fade
  answer(calls[6], FREE);
  await settle();
  runTimers();
  check('an answer shown within the fade of an edit stays', shown().includes('zet.krgn'));

  // With nothing shown meanwhile, the fade empties the area.
  type('ze');
  type('z');                        // a second edit within the fade
  runTimers();
  check('a faded answer is emptied', ctx.resultMessage.innerHTML === '');

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail === 0 ? 0 : 1);
})();
