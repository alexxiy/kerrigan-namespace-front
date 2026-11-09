/* Kerrigan NameSpace — landing page.
 *
 * Four pieces, all vanilla and all offline:
 *   0. localisation,
 *   1. the address/name transformer in the hero,
 *   2. the spot-the-difference game,
 *   3. the pricing table, rendered from the protocol's own constants.
 *
 * Deliberately no availability lookup anywhere. The page can compute a price exactly,
 * because prices are protocol constants derived from length alone - but whether a name is
 * free is a question only the live registry can answer, and guessing at it on a marketing
 * page would be a promise we cannot keep. Every "is it free?" path sends you to the app.
 */
(function () {
  'use strict';

  /* ═══════════════════════════ 0. localisation ═══════════════════════════
   *
   * Mirrors js/app.js on purpose, including the `kerrigan_lang` storage key: a visitor who
   * picks a language here lands in the app already in that language, and vice versa. The
   * catalogue is separate (lang/landing/) because the two pages share no strings.
   *
   * Absolute paths, not './': the app is served at /app with no trailing slash, and a
   * relative fetch would resolve differently the moment that changes. */
  var SUPPORTED = ['en', 'de', 'es', 'pt', 'tr', 'az', 'ru', 'be', 'uk', 'vi', 'zh', 'ko', 'ja'];
  var VERSION = '0';
  var strings = {};
  var fallback = {};
  var redrawHooks = [];

  function onRedraw(fn) { redrawHooks.push(fn); }

  function lookup(tree, key) {
    return key.split('.').reduce(function (o, k) { return o ? o[k] : undefined; }, tree);
  }

  /* Falls back to English per-key rather than per-file, so a partially translated
   * catalogue degrades to English only where it is actually missing. */
  function t(key, vars) {
    var s = lookup(strings, key);
    if (s === undefined) { s = lookup(fallback, key); }
    if (s === undefined) { return key; }
    if (vars) {
      Object.keys(vars).forEach(function (k) {
        s = s.split('{' + k + '}').join(vars[k]);
      });
    }
    return s;
  }

  function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      if (el.tagName === 'TITLE') { document.title = t(key); return; }
      el.textContent = t(key);
    });
    /* An explicit attribute rather than a hardcoded list of "keys that contain markup".
     * The app keeps such a list in applyTranslations() and it has to be edited every time
     * a string gains a tag - the kind of parallel list that silently goes stale. */
    document.querySelectorAll('[data-i18n-html]').forEach(function (el) {
      el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-meta]').forEach(function (el) {
      el.setAttribute('content', t(el.getAttribute('data-i18n-meta')));
    });
    redrawHooks.forEach(function (fn) { fn(); });
  }

  /* security.html runs this script too. It names its own catalogue in <html data-catalogue>,
   * which is merged over the landing one, so the nav and footer strings live in one place. */
  var PAGE_CATALOGUE = document.documentElement.getAttribute('data-catalogue');

  function fetchJson(path) {
    return fetch(path + '?v=' + VERSION)
      .then(function (r) { if (!r.ok) { throw new Error(path); } return r.json(); })
      .catch(function () { return {}; });
  }

  function fetchCatalogue(lang) {
    var landing = fetchJson('/lang/landing/' + lang + '.json');
    if (!PAGE_CATALOGUE) { return landing; }
    return Promise.all([landing, fetchJson('/lang/' + PAGE_CATALOGUE + '/' + lang + '.json')])
      .then(function (both) { return Object.assign({}, both[0], both[1]); });
  }

  function setLanguage(lang) {
    localStorage.setItem('kerrigan_lang', lang);
    document.documentElement.setAttribute('lang', lang);
    return fetchCatalogue(lang).then(function (data) {
      strings = data;
      applyTranslations();
      var sel = document.getElementById('langSelect');
      if (sel) { sel.value = lang; }
    });
  }

  function detectLanguage() {
    var stored = localStorage.getItem('kerrigan_lang');
    if (stored && SUPPORTED.indexOf(stored) !== -1) { return stored; }
    // navigator.languages is the ordered preference list; navigator.language is only the
    // top one. Walking the list means a browser set to [ja, en] still gets Japanese even
    // if some future build drops a locale.
    var prefs = (navigator.languages && navigator.languages.length)
      ? navigator.languages : [navigator.language || ''];
    for (var i = 0; i < prefs.length; i++) {
      var prefix = String(prefs[i]).toLowerCase().split('-')[0];
      if (SUPPORTED.indexOf(prefix) !== -1) { return prefix; }
    }
    return 'en';
  }

  function initLocalization() {
    return fetch('/version.json?t=' + Date.now(), { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && d.version) { VERSION = d.version; } })
      .catch(function () { /* keep the default; a missing version only affects cache-busting */ })
      .then(function () { return fetchCatalogue('en'); })
      .then(function (en) {
        fallback = en;
        return setLanguage(detectLanguage());
      })
      .then(function () {
        var sel = document.getElementById('langSelect');
        if (sel) {
          sel.addEventListener('change', function (e) { setLanguage(e.target.value); });
        }
      });
  }

  /* ═════════════════════════════ shared data ═════════════════════════════ */

  /* A Kerrigan Sapling payment address: `ks1` plus the bech32m data part, 78 characters on
   * mainnet (88 on testnet, prefixed `ktestsapling1`). Unlike a Unified Address it carries exactly
   * one receiver, so the length is fixed - there is no composition for the visitor to vary
   * and no growth to demonstrate. That is why this page has no receiver chips and no
   * length ladder: both would be inventing a variable the protocol does not have.
   *
   * It is a sample, not an address anyone should pay. */
  var ADDR_LEN = 78;
  var ADDR_PREFIX = 'ks1';

  // The bech32m character set (bech32's): no 1, b, i or o - excluded precisely because they are easy to
  // confuse, which is what makes any of these strings so unrewarding to proof-read.
  var ALPHABET = 'acdefghjklmnpqrstuvwxyz023456789';

  function makeSample(len) {
    var out = ADDR_PREFIX;
    while (out.length < len) { out += ALPHABET.charAt(Math.floor(Math.random() * ALPHABET.length)); }
    return out.slice(0, len);
  }

  var EXAMPLE_NAME = 'bob.krgn';

  /* Protocol constants: Protocol::PRICES_REG / PRICES_UPD, in satoshi, keyed by the length
   * of the label before the dot. Index 7 is the floor - every name of 7 characters or more
   * pays the same. Kept in satoshi and divided for display so the numbers on the page are
   * the numbers in the protocol, not a re-typed approximation. */
  var SAT = 1e8;
  // Mirrors Protocol::PRICES_REG in the indexer. Satoshi, not KRGN.
  var PRICES_REG = { 1: 2000000000000, 2: 1500000000000, 3: 480000000000, 4: 140000000000, 5: 70000000000, 6: 35000000000, 7: 18000000000 };
  // Mirrors Protocol::PRICES_UPD.
  var PRICES_UPD = { 1: 3000000000, 2: 2400000000, 3: 2000000000, 4: 1800000000, 5: 1600000000, 6: 1400000000, 7: 1200000000 };

  function priceFor(table, len) { return table[Math.min(Math.max(len, 1), 7)]; }
  function coin(satoshi) {
    // Trim trailing zeros but never render scientific notation for the small update prices.
    return parseFloat((satoshi / SAT).toFixed(8)).toString();
  }

  function $(id) { return document.getElementById(id); }

  /* ═══════════════════════════ 1. transformer ═══════════════════════════ */
  (function transformer() {
    var addrEl  = $('addrText');
    var nameEl  = $('nameText');
    var counter = $('counter');
    var input   = $('nameInput');
    var zone    = $('zoneSelect');
    var price   = $('priceLine');
    var tabs    = document.querySelectorAll('.switch button');
    if (!addrEl) { return; }

    var mode = 'address';
    var sample = makeSample(ADDR_LEN);

    addrEl.textContent = sample;

    function currentName() {
      var label = (input.value || '').trim().toLowerCase();
      return label ? label + '.' + zone.value : t('panel.placeholder') + '.' + zone.value;
    }

    /* Mirrors Protocol::isDomainNameValid for the label part: a–z, 0–9 and hyphen, no
     * leading or trailing hyphen, no doubled hyphen. Shown as guidance only - the registry
     * re-validates every command, so this can never be the thing that decides. */
    function labelProblem(label) {
      if (!label) { return null; }
      if (!/^[a-z0-9-]+$/.test(label)) { return t('panel.err_charset'); }
      if (label.charAt(0) === '-' || label.charAt(label.length - 1) === '-') { return t('panel.err_hyphen_edge'); }
      if (label.indexOf('--') !== -1) { return t('panel.err_hyphen_dbl'); }
      return null;
    }

    function render() {
      var name = currentName();
      nameEl.textContent = name;

      var shown = mode === 'address' ? sample.length : name.length;
      counter.innerHTML = t('panel.counter', { n: shown });

      addrEl.hidden = mode !== 'address';
      nameEl.hidden = mode !== 'name';

      var label = (input.value || '').trim().toLowerCase();
      var problem = labelProblem(label);
      if (problem) {
        price.hidden = false;
        price.className = 'price-line invalid';
        price.textContent = problem;
      } else if (label) {
        price.hidden = false;
        price.className = 'price-line';
        price.innerHTML = t('panel.price', { len: label.length, price: coin(priceFor(PRICES_REG, label.length)) }) +
          ' <a class="link" href="/app">' + t('panel.check_free') + '</a>';
      } else {
        price.hidden = true;
      }
    }

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        mode = tab.dataset.mode;
        tabs.forEach(function (tb) {
          var on = tb === tab;
          tb.classList.toggle('on', on);
          tb.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        render();
      });
    });

    input.addEventListener('input', function () {
      // Switching to the name view on first keystroke: typing a name and watching the raw
      // address stay put would read as the control being broken.
      if (mode === 'address' && input.value) {
        document.querySelector('.switch button[data-mode="name"]').click();
        return;
      }
      render();
    });
    zone.addEventListener('change', render);


    onRedraw(render);
    render();
  }());

  /* ═══════════════════════ 2. spot the difference ═══════════════════════ */
  (function game() {
    var root = $('game');
    if (!root) { return; }

    var elA = $('gameA'), elB = $('gameB');
    var rowA = elA.closest('.game-row'), rowB = elB.closest('.game-row');
    var result = $('gameResult'), reveal = $('gameReveal'), again = $('gameNew');
    var nameA = $('gameNameA'), nameB = $('gameNameB');
    var buttons = root.querySelectorAll('[data-answer]');
    var state = {};

    // Deliberately the SHORTEST address a real wallet produces. If the single-receiver case
    // is already unreadable, the 213-character one needs no further argument.
    function makeAddr() { return makeSample(ADDR_LEN); }

    function newRound() {
      var a = makeAddr();
      var differs = Math.random() < 0.5;
      var b = a, idx = -1;

      if (differs) {
        // Somewhere in the middle: the first and last few characters are the part everyone
        // actually checks, so changing those would not make the point.
        idx = 12 + Math.floor(Math.random() * (a.length - 24));
        var replacement;
        do {
          replacement = ALPHABET.charAt(Math.floor(Math.random() * ALPHABET.length));
        } while (replacement === a.charAt(idx));
        b = a.slice(0, idx) + replacement + a.slice(idx + 1);
      }

      state = { a: a, b: b, differs: differs, idx: idx, start: Date.now(), answered: false, seconds: 0, right: null };

      elA.textContent = a;
      elB.textContent = b;
      rowA.classList.remove('correct', 'wrong');
      rowB.classList.remove('correct', 'wrong');
      result.textContent = '';
      result.className = 'game-result';
      reveal.hidden = true;
      again.hidden = true;
      buttons.forEach(function (btn) { btn.disabled = false; });
    }

    // Split out so a language change can re-say the verdict without replaying the round.
    function renderVerdict() {
      if (!state.answered) { return; }
      result.className = 'game-result ' + (state.right ? 'good' : 'bad');
      result.innerHTML = state.right
        ? t('game.correct', { n: state.seconds })
        : t(state.differs ? 'game.wrong_diff' : 'game.wrong_same');
      nameA.textContent = EXAMPLE_NAME;
      nameB.textContent = state.differs ? 'b0b.krgn' : EXAMPLE_NAME;
    }

    function answer(said) {
      if (state.answered) { return; }
      state.answered = true;
      state.seconds = Math.max(1, Math.round((Date.now() - state.start) / 1000));
      state.right = (said === 'diff') === state.differs;

      if (state.differs) {
        // Re-render B with the changed character marked, so the eye finally gets to see
        // what it was hunting for.
        elB.innerHTML = '';
        elB.append(document.createTextNode(state.b.slice(0, state.idx)));
        var m = document.createElement('mark');
        m.className = 'diff';
        m.textContent = state.b.charAt(state.idx);
        elB.append(m, document.createTextNode(state.b.slice(state.idx + 1)));
        rowB.classList.add(state.right ? 'correct' : 'wrong');
      } else {
        rowA.classList.add('correct');
        rowB.classList.add('correct');
      }

      renderVerdict();
      reveal.hidden = false;
      again.hidden = false;
      buttons.forEach(function (btn) { btn.disabled = true; });
    }

    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () { answer(btn.dataset.answer); });
    });
    again.addEventListener('click', newRound);

    onRedraw(renderVerdict);
    newRound();
  }());

  /* ═══════════════════════════ 3. pricing ═══════════════════════════ */
  (function pricing() {
    var body = $('priceRows');
    if (!body) { return; }

    function draw() {
      body.textContent = '';
      for (var len = 1; len <= 7; len++) {
        var tr = document.createElement('tr');

        var label = document.createElement('td');
        label.textContent = len === 7 ? t('pricing.len_max')
                          : len === 1 ? t('pricing.len_one')
                          : t('pricing.len_n', { n: len });

        var reg = document.createElement('td');
        reg.className = 'reg';
        reg.textContent = coin(priceFor(PRICES_REG, len)) + ' KRGN';

        var upd = document.createElement('td');
        upd.textContent = coin(priceFor(PRICES_UPD, len)) + ' KRGN';

        tr.append(label, reg, upd);
        body.append(tr);
      }
    }

    onRedraw(draw);
    draw();
  }());

  initLocalization();
}());
