import { generateMnemonic, validateMnemonic } from './vendor/bip39.js';
import { wordlist } from './vendor/wordlist.js';
import * as ed25519 from './vendor/ed25519.js';
import { sha512 } from './vendor/hashes.js';
import { bech32m } from './vendor/bech32.js';

// Set up the required hash function for the ed25519 library.
// The library calls it with several arrays - sign() derives its nonce as sha512Sync(prefix,
// message) - and noble-hashes' sha512 hashes only its first argument. Passed as it was, the
// nonce never saw the message: every signature from one key carried the same R, and any two
// of them (every command memo is readable with the registrar's published viewing key) give
// away the private key. So the arrays are joined first, as noble-ed25519's README does it;
// signatures are RFC 8032 again (section 7.1, TEST 2). Set once: the library ignores a
// second assignment.
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

const HTML_ESCAPE_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c]);
}

// Lowercase only, matching the indexer's Protocol::isValidEd25519Pubkey and the circuit. Hex is
// case-insensitive, so an uppercase key names the same point - but the protocol accepts exactly
// one spelling, and a command carrying the other is rejected on-chain AFTER it has been paid
// for. Callers taking a key from user input lowercase it first (see the CHG flow).
function isValidEd25519PubKey(pubkey) {
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
        return false;
    }
    try {
        // Decoding is not enough: the indexer converts the key with libsodium's
        // crypto_sign_ed25519_pk_to_curve25519, which refuses a point of small order (the
        // identity among them) and one with a small-order part added to it. Both decode
        // here, so a CHG to one would be paid for and then rejected on-chain.
        const point = ed25519.ExtendedPoint.fromHex(pubkey);
        return !point.isSmallOrder() && point.isTorsionFree();
    } catch (e) {
        return false;
    }
}

// --- LOCALIZATION FRAMEWORK ---
let defaultLanguageData = {};
let currentLanguageData = {};

let APP_VERSION = "1.0.8";

async function initAppVersion() {
    try {
        const response = await fetch(`./version.json?t=${Date.now()}`, { cache: 'no-store' });
        if (response.ok) {
            const data = await response.json();
            if (data && data.version) {
                APP_VERSION = data.version;
            }
        }
    } catch (e) {
        console.warn("Could not fetch version.json at startup, using default:", e);
    }
}

async function fetchLanguageFile(lang) {
    try {
        const response = await fetch(`./lang/${lang}.json?v=${APP_VERSION}`);
        if (!response.ok) throw new Error(`Could not load ${lang}.json`);
        return await response.json();
    } catch (e) {
        console.warn(`Language file for '${lang}' could not be loaded, using English fallback:`, e);
        return {};
    }
}

// Fallback lookup function
// Bech32m prefix users should see in guidance strings, e.g. "ks1". Reads the network lazily
// so it reflects whatever the registrar reported by the time a string is rendered.
function addressPrefix() {
    return (KERRIGAN_ADDRESS_RULES[kerriganNetwork] ?? KERRIGAN_ADDRESS_RULES.mainnet).hrp + '1';
}

function t(key, replacements = {}) {
    const keys = key.split('.');
    let value = currentLanguageData;
    let fallbackValue = defaultLanguageData;
    
    // Resolve key path in current language
    for (let k of keys) {
        value = value ? value[k] : undefined;
    }
    
    // Resolve key path in default language (English fallback)
    for (let k of keys) {
        fallbackValue = fallbackValue ? fallbackValue[k] : undefined;
    }
    
    let result = value !== undefined ? value : fallbackValue;
    
    if (result === undefined) {
        console.warn(`Missing translation key: ${key}`);
        return key;
    }
    
    // Replace placeholders. Values are inserted verbatim: t() is the plain-text accessor and
    // its result is safe for textContent. Use tSafe() when interpolating into an innerHTML
    // template, and note that some translation strings intentionally contain markup (<b>, <span>).
    // {prefix} is always available: several address strings name the expected Bech32m prefix,
    // which depends on the network the registrar reports, and two of them are applied
    // declaratively via data-i18n where no caller can pass replacements. Supplying it here
    // keeps those strings correct on both networks instead of rendering a literal {prefix}.
    // An explicit replacement still wins.
    const withDefaults = { prefix: addressPrefix(), ...replacements };

    Object.keys(withDefaults).forEach(placeholder => {
        result = result.replace(new RegExp(`{${placeholder}}`, 'g'), withDefaults[placeholder]);
    });

    return result;
}

// innerHTML-safe variant of t(): escapes the interpolated values while preserving any markup
// that the translation string itself legitimately contains.
function tSafe(key, replacements = {}) {
    const escaped = {};
    Object.keys(replacements).forEach(k => { escaped[k] = escapeHtml(replacements[k]); });
    return t(key, escaped);
}

// Apply translations to all data-i18n annotated DOM elements
function applyTranslations() {
    // 1. Text elements
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        
        if (el.tagName === 'TITLE') {
            document.title = t(key);
        } else if (key === 'hero.title_part1' || key === 'hero.title_part2' || key === 'status.next_check' || key === 'qr_modal.warning' || key === 'auth_modal.create_warning' || key.startsWith('onboarding.bullet') || key === 'onboarding.slogan') {
            // These contain span templates, warnings, or dynamic child elements
            el.innerHTML = t(key);
        } else if (key === 'my_names_view.on_sale') {
            const price = el.getAttribute('data-price');
            el.textContent = t(key, { price: price });
        } else if (key === 'balance_modal.fee_label') {
            el.textContent = t(key, { fee: currentRefundFeePercent });
        } else if (key === 'balance_modal.min_withdrawal') {
            el.textContent = t(key, { amount: formatBalanceDisplay(currentMinWithdrawal) });
        } else {
            el.textContent = t(key);
        }
    });
    
    // 2. Placeholders
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        el.placeholder = t(key);
    });
    
    // 3. Tooltips
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        el.title = t(key);
    });
}

// Load and change active language
async function setLanguage(lang) {
    localStorage.setItem('kerrigan_lang', lang);
    currentLanguageData = await fetchLanguageFile(lang);
    applyTranslations();
    
    // Set select dropdown value
    const langSelect = document.getElementById('langSelect');
    if (langSelect) langSelect.value = lang;
}

// Initialization of localization
async function initLocalization() {
    // 1. Initialize APP_VERSION from version.json
    await initAppVersion();
    
    // 2. Load English as default base fallback
    defaultLanguageData = await fetchLanguageFile('en');
    
    let activeLang = localStorage.getItem('kerrigan_lang');
    if (!activeLang) {
        // First open: detect browser language
        const supported = ['en', 'de', 'es', 'pt', 'tr', 'az', 'ru', 'be', 'uk', 'vi', 'zh', 'ko', 'ja'];
        const browserLang = (navigator.language || '').toLowerCase();
        const prefix = browserLang.split('-')[0];
        activeLang = supported.includes(prefix) ? prefix : 'en';
    }
    
    await setLanguage(activeLang);
    
    // Event listener for language select dropdown
    const langSelect = document.getElementById('langSelect');
    if (langSelect) {
        langSelect.addEventListener('change', (e) => {
            setLanguage(e.target.value);
        });
    }

    // Hide and remove preloader once loaded
    const preloader = document.getElementById('appPreloader');
    if (preloader) {
        preloader.classList.add('opacity-0', 'pointer-events-none');
        setTimeout(() => {
            preloader.remove();
        }, 700);
    }
}

// --- WALLET SESSION MANAGEMENT ---
class SecureWalletSession {
    // The seed phrase itself is deliberately NOT retained: only the derived key pair is
    // needed at runtime, so keeping the mnemonic in memory would widen the disclosure
    // surface for no functional benefit.
    #privateKeyHex = null;
    #publicKeyHex = null;

    async unlock(seedPhrase) {
        // Derive Ed25519 private key (32 bytes) from the SHA-256 hash of the seed phrase
        const seedBuffer = new TextEncoder().encode(seedPhrase);
        const hashBuffer = await crypto.subtle.digest('SHA-256', seedBuffer);
        const privKeyBytes = new Uint8Array(hashBuffer);
        
        // Generate Public Key
        const pubKeyBytes = await ed25519.getPublicKey(privKeyBytes);
        
        // Store as hex strings in private memory
        this.#privateKeyHex = Array.from(privKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        this.#publicKeyHex = Array.from(pubKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    lock() {
        this.#privateKeyHex = null;
        this.#publicKeyHex = null;
    }

    isUnlocked() {
        return this.#privateKeyHex !== null;
    }

    getPublicKey() {
        return this.#publicKeyHex;
    }

    async sign(messageStr) {
        if (!this.#privateKeyHex) throw new Error("Wallet is locked");
        const msgBytes = new TextEncoder().encode(messageStr);
        
        // Convert stored hex key back to Uint8Array for signing
        const privKeyBytes = new Uint8Array(this.#privateKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const sigBytes = await ed25519.sign(msgBytes, privKeyBytes);
        
        return Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

// Initialize globally for app access
const walletSession = new SecureWalletSession();

// --- API CONFIGURATION ---

// The registrar that a copy of this app run from the user's own computer talks to (see
// isLocalCopy()). app.html's CSP connect-src must keep allowing it.
const PRODUCTION_REGISTRAR = "https://registrar.kerrigan-name.space";

// True when the page does not come from a real domain: localhost, an IP address or a file
// opened from disk. That is how someone runs the code checked out from GitHub instead of
// the copy kerrigan-name.space serves (security.html explains how).
function isLocalCopy() {
    const hostname = window.location.hostname;
    return !hostname
        || hostname === 'localhost'
        || hostname.endsWith('.localhost')
        || hostname.startsWith('[')                            // IPv6, e.g. [::1]
        || /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);   // IPv4
}

function getDynamicAPIBaseURL() {
    const hostname = window.location.hostname;
    const protocol = window.location.protocol;

    // A local copy uses the production registrar, so it shows the same names, balance and
    // history as the website. The developer's test setup is served from kerrigan-name.loc and
    // takes the derived branch below, which is why app.html's CSP also lists *.kerrigan-name.loc
    // (a name that exists only on the developer's machine).
    if (isLocalCopy()) {
        return PRODUCTION_REGISTRAR;
    }

    // The registrar host is derived from whatever domain the page is being served from, so the
    // app follows the deployment automatically. www is redirected to the apex by nginx in
    // production, so the hostname here is already canonical and needs no normalising.
    return `${protocol}//registrar.${hostname}`;
}
const API_BASE_URL = getDynamicAPIBaseURL();

// Test data in place of the registrar, for working on the interface without a backend.
// Only on a local copy, and only after it was opened with ?mock=1 (?mock=0 switches it
// off); the choice lasts until the tab is closed. js/dev-mock.js then answers every
// registrar request itself and labels the page, so nothing reaches the registrar. The
// site, and a local copy opened without ?mock=1, never load that file.
function mockModeRequested() {
    if (!isLocalCopy()) return false;
    try {
        const flag = new URLSearchParams(window.location.search).get('mock');
        if (flag === '1') sessionStorage.setItem('mock_mode', '1');
        if (flag === '0') sessionStorage.removeItem('mock_mode');
        return sessionStorage.getItem('mock_mode') === '1';
    } catch {
        return false;
    }
}
if (mockModeRequested()) {
    // Awaited at the top level so the mock is in place before the first registrar request
    // below. Only getters are passed: most of what they return is declared further down.
    const { installMock } = await import('./dev-mock.js');
    installMock({
        apiBase: API_BASE_URL,
        getZones: () => BUILTIN_ZONES,
        getCachedPublicKey: () => getCachedPublicKey(),
    });
}

// Confirmation thresholds the registrar applies before a transaction is considered
// settled: its NET_TX_CONFIRMATION_THRESHOLD and NET_TX_REFUND_THRESHOLD. The registrar
// serves both from getPaymentAddress, and fetchPaymentAddress() adopts them, so the counts
// shown follow the deployment rather than a copy that can drift from it. The values here
// are only the fallback until that answer arrives - the registrar's production config, where
// Kerrigan requires 40 (as PIVX does; ZCash 20), so they cannot be shared between the
// front-ends of the three coins. Named
// here because the count is shown in two unrelated places (the payment status poller and the
// My Transactions table) and they previously drifted.
let PAYMENT_CONFIRMATIONS = 40;
let REFUND_CONFIRMATIONS  = 120;
// Either count above drops to this once a ChainLock covers the payment's block: the
// registrar's NET_TX_CHAINLOCK_CONFIRMATION_THRESHOLD, adopted the same way.
let CHAINLOCK_CONFIRMATIONS = 2;

// Service fee, in percent, the registrar deducts from a withdrawal. Unlike the thresholds
// above it is not mirrored here: the registrar serves its REFUND_SERVICE_FEE_PERCENT with the
// balance, so the "you will receive" estimate and the label stating the rate follow the
// deployment instead of a copy that could drift. The default only covers the moment before
// the first balance response, or a registrar too old to report the fee; it matches the
// server's current value. Declared up here because applyTranslations() reads it.
const DEFAULT_REFUND_FEE_PERCENT = 5;
let currentRefundFeePercent = DEFAULT_REFUND_FEE_PERCENT;
// The least balance, in KRGN, the registrar accepts a withdrawal of. Served with the balance
// for the same reason as the fee; 0 until then, or from a registrar too old to report it, which
// leaves the decision to the registrar.
let currentMinWithdrawal = 0;

// Pending action memory (to resume flow after login/unlock)
let pendingAction = null;

// --- UI & Domain Search Logic ---

document.getElementById('year').textContent = new Date().getFullYear();

let currentRegistrationDomain = "";
let currentRegistrationPrice = "0";
let currentTransactionType = "REG"; // "REG", "BUY", or "ULT"
// The address the name points to when its destination is being changed (UPD): paying to set
// the same one again is refused by the protocol and only comes back as a refund, minus the
// withdrawal fee.
let currentUpdAddress = "";

// Elements
const form = document.getElementById('registrationForm');
const input = document.getElementById('kerriganName');
const domainZoneSelect = document.getElementById('domainZone');
const btn = document.getElementById('checkBtn');
const btnText = document.getElementById('btnText');
const resultMessage = document.getElementById('resultMessage');
const sliderWrapper = document.getElementById('sliderWrapper');
const claimSliderTrack = document.getElementById('claimSliderTrack');

const slide1 = document.getElementById('slide1');
const slideAddress = document.getElementById('slideAddress');
const slidePayment = document.getElementById('slidePayment');
const slideStatus = document.getElementById('slideStatus');

const targetAddressInput = document.getElementById('targetAddressInput');
const addressErrorMsg = document.getElementById('addressErrorMsg');
const btnNextToPayment = document.getElementById('btnNextToPayment');
const btnBackToSearchFromAddress = document.getElementById('btnBackToSearchFromAddress');

const payMemoInput = document.getElementById('payMemo');
const btnBackToAddress = document.getElementById('btnBackToAddress');

// --- Dynamic Height Resizing Logic via ResizeObserver ---
let activeSlideElement = slide1;

const slideResizeObserver = new ResizeObserver((entries) => {
    for (let entry of entries) {
        const target = entry.target;
        if (target === activeSlideElement && currentActiveTab === 'register') {
            sliderWrapper.style.height = target.offsetHeight + 'px';
        }
    }
});

function updateSlideFocusability() {
    const slides = [
        { el: slide1, active: activeSlideElement === slide1 },
        { el: slideAddress, active: activeSlideElement === slideAddress },
        { el: slidePayment, active: activeSlideElement === slidePayment },
        { el: slideStatus, active: activeSlideElement === slideStatus }
    ];
    
    slides.forEach(({ el, active }) => {
        if (!el) return;
        if (active) {
            el.removeAttribute('aria-hidden');
            el.removeAttribute('inert');
            const focusables = el.querySelectorAll('input, select, button, textarea, a[href]');
            focusables.forEach(item => {
                if (item.hasAttribute('data-original-tabindex')) {
                    const orig = item.getAttribute('data-original-tabindex');
                    if (orig === 'none') {
                        item.removeAttribute('tabindex');
                    } else {
                        item.setAttribute('tabindex', orig);
                    }
                } else {
                    item.removeAttribute('tabindex');
                }
            });
        } else {
            el.setAttribute('aria-hidden', 'true');
            el.setAttribute('inert', '');
            const focusables = el.querySelectorAll('input, select, button, textarea, a[href]');
            focusables.forEach(item => {
                if (!item.hasAttribute('data-original-tabindex')) {
                    item.setAttribute('data-original-tabindex', item.getAttribute('tabindex') || 'none');
                }
                item.setAttribute('tabindex', '-1');
            });
        }
    });
}

function setActiveSlide(newActiveSlide, transformValue) {
    if (activeSlideElement) {
        slideResizeObserver.unobserve(activeSlideElement);
    }
    claimSliderTrack.style.transform = transformValue;
    activeSlideElement = newActiveSlide;
    slideResizeObserver.observe(activeSlideElement);
    sliderWrapper.style.height = activeSlideElement.offsetHeight + 'px';
    updateSlideFocusability();
}

// Lock scroll on sliderWrapper to prevent browser auto-scroll on keyboard TAB navigation
if (sliderWrapper) {
    sliderWrapper.addEventListener('scroll', () => {
        sliderWrapper.scrollLeft = 0;
        sliderWrapper.scrollTop = 0;
    });
}

// Initialize slider height dynamics and focus management
if (slide1 && sliderWrapper) {
    slideResizeObserver.observe(slide1);
    sliderWrapper.style.height = slide1.offsetHeight + 'px';
    updateSlideFocusability();
}

setTimeout(() => {
    if (sliderWrapper) {
        sliderWrapper.classList.add('transition-[height]', 'duration-500', 'ease-in-out');
    }
}, 100);

// --- Reset Registration Flow ---
function resetRegistrationFlow() {
    if (input) input.value = '';
    if (resultMessage) {
        resultMessage.style.opacity = '0';
        resultMessage.innerHTML = '';
    }
    
    // Reset address input and validation states
    if (typeof targetAddressInput !== 'undefined' && targetAddressInput) {
        targetAddressInput.value = '';
    }
    if (typeof addressErrorMsg !== 'undefined' && addressErrorMsg) {
        addressErrorMsg.classList.add('hidden');
    }
    if (typeof btnNextToPayment !== 'undefined' && btnNextToPayment) {
        btnNextToPayment.disabled = true;
    }
    
    // Clear status intervals
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    if (countdownInterval) {
        clearInterval(countdownInterval);
        countdownInterval = null;
    }
    
    // Reset state & view
    currentTransactionType = "REG";
    const payAddressGroup = document.getElementById('payAddressGroup');
    if (payAddressGroup) payAddressGroup.classList.remove('hidden');
    
    // Slide back to slide1
    if (typeof slide1 !== 'undefined' && slide1) {
        setActiveSlide(slide1, 'translateX(0)');
    }
    setStep('check');
}

// --- Header Logo Home-Reset Navigation ---
const logoLink = document.getElementById('headerLogoLink');
if (logoLink) {
    logoLink.addEventListener('click', (e) => {
        e.preventDefault();
        
        // 1. Reset search fields
        if (typeof marketSearchInput !== 'undefined' && marketSearchInput) marketSearchInput.value = '';
        if (typeof marketSearchClearBtn !== 'undefined' && marketSearchClearBtn) marketSearchClearBtn.classList.add('hidden');
        if (typeof marketSearchError !== 'undefined' && marketSearchError) {
            marketSearchError.style.opacity = '0';
            marketSearchError.innerHTML = '';
        }
        currentMarketSearch = '';

        if (typeof myNamesSearchInput !== 'undefined' && myNamesSearchInput) myNamesSearchInput.value = '';
        if (typeof myNamesSearchClearBtn !== 'undefined' && myNamesSearchClearBtn) myNamesSearchClearBtn.classList.add('hidden');
        if (typeof myNamesSearchError !== 'undefined' && myNamesSearchError) {
            myNamesSearchError.style.opacity = '0';
            myNamesSearchError.innerHTML = '';
        }
        currentMyNamesSearch = '';
        
        resetRegistrationFlow();
        switchTab('register');
    });
}

// Dynamically enforce 64 character total length limit
function updateMaxLength() {
    input.maxLength = 64 - domainZoneSelect.value.length;
}
domainZoneSelect.addEventListener('change', () => {
    updateMaxLength();
    if (input.value) input.dispatchEvent(new Event('input')); 
});
updateMaxLength();

function setStep(step) {
    const steps = ['check', 'pay', 'yours'];
    steps.forEach(s => {
        const el = document.getElementById('stepIcon' + s.charAt(0).toUpperCase() + s.slice(1));
        if (s === step) {
            el.classList.remove('text-purple-200/40');
            el.classList.add('text-purple-200');
            el.querySelector('svg').classList.add('drop-shadow-[0_0_8px_rgba(245,158,11,0.6)]');
        } else {
            el.classList.add('text-purple-200/40');
            el.classList.remove('text-purple-200');
            el.querySelector('svg').classList.remove('drop-shadow-[0_0_8px_rgba(245,158,11,0.6)]');
        }
    });
}

// Robust Copy to Clipboard Logic with fallbacks and clean event delegation
// Toasts are always plain text, so the message is escaped here rather than at every call site.
window.showToast = function(msg) {
    const toast = document.createElement('div');
    toast.className = 'bg-black/30 backdrop-blur-3xl border border-white/20 text-white px-5 py-3 rounded-full shadow-2xl shadow-purple-900/50 text-sm font-semibold animate-slide-up-fade flex items-center gap-2 pointer-events-auto';
    toast.innerHTML = `<svg class="w-5 h-5 text-green-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg><span>${escapeHtml(msg)}</span>`;
    document.getElementById('toastContainer').appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('opacity-0', 'transition-opacity', 'duration-300');
        setTimeout(() => toast.remove(), 300);
    }, 2500);
};

// --- AUTOMATIC APP VERSION CHECKER & PERSISTENT UPDATE TOAST ---
let updateCheckInProgress = false;
let isUpdateToastShown = false;

function showPersistentUpdateToast(newVersion) {
    if (isUpdateToastShown) return;
    isUpdateToastShown = true;
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;
    
    const existing = document.getElementById('persistentUpdateToast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.id = 'persistentUpdateToast';
    toast.className = 'bg-[#140828]/95 backdrop-blur-2xl border border-purple-500/40 text-white px-5 py-4 rounded-2xl shadow-2xl shadow-purple-950/80 text-sm animate-slide-up-fade flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pointer-events-auto max-w-lg w-full z-[9999]';
    
    const msg = tSafe('toasts.update_available', { version: `v${newVersion}` });
    const reloadText = t('toasts.btn_reload') || 'Reload';
    const closeText = t('toasts.btn_close') || 'Close';
    
    toast.innerHTML = `
        <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center flex-shrink-0 text-purple-400">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
            </div>
            <span class="font-medium text-white/90 text-xs sm:text-sm leading-snug">${msg}</span>
        </div>
        <div class="flex items-center gap-2 w-full sm:w-auto justify-end flex-shrink-0">
            <button id="updateToastReloadBtn" class="px-4 py-2 bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-400 hover:to-purple-500 text-white font-bold text-xs rounded-xl shadow-md transition-all active:scale-95 flex items-center gap-1.5 cursor-pointer">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9"></path></svg>
                <span>${reloadText}</span>
            </button>
            <button id="updateToastCloseBtn" class="p-2 text-white/50 hover:text-white bg-white/5 hover:bg-white/10 rounded-xl transition-colors text-xs font-semibold cursor-pointer" title="${closeText}">
                ✕
            </button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    document.getElementById('updateToastReloadBtn')?.addEventListener('click', () => {
        window.location.reload();
    });
    
    document.getElementById('updateToastCloseBtn')?.addEventListener('click', () => {
        sessionStorage.setItem('update_toast_dismissed', newVersion);
        toast.classList.add('opacity-0', 'transition-opacity', 'duration-300');
        setTimeout(() => {
            toast.remove();
            isUpdateToastShown = false;
        }, 300);
    });
}

async function checkForAppUpdates() {
    if (updateCheckInProgress || isUpdateToastShown) return;
    updateCheckInProgress = true;
    try {
        const response = await fetch(`./version.json?t=${Date.now()}`, { cache: 'no-store' });
        if (response.ok) {
            const data = await response.json();
            if (data && data.version && data.version !== APP_VERSION) {
                const dismissedVer = sessionStorage.getItem('update_toast_dismissed');
                if (dismissedVer !== data.version) {
                    showPersistentUpdateToast(data.version);
                }
            }
        }
    } catch (e) {
        // Silent catch for offline or network glitches
    } finally {
        updateCheckInProgress = false;
    }
}

// Check for updates 5s after startup, every 2 minutes, and when returning to browser tab
setTimeout(checkForAppUpdates, 5000);
setInterval(checkForAppUpdates, 120000);
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        checkForAppUpdates();
    }
});

document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = btn.getAttribute('data-target');
        const inputEl = document.getElementById(targetId);
        if (!inputEl) return;

        const textToCopy = inputEl.value;
        // The destination address arrives from the API, so it can legitimately be empty if
        // that request failed. Copying an empty string would look like it worked.
        if (textToCopy === '') {
            window.showToast(t('toasts.copy_failed'));
            return;
        }

        try {
            copyTextToClipboard(textToCopy);

            let successMsg = t('toasts.copied');
            if (targetId === 'payAddress') successMsg = t('toasts.copied_address');
            if (targetId === 'payAmount') successMsg = t('toasts.copied_amount');
            if (targetId === 'payMemo') successMsg = t('toasts.copied_memo');
            if (targetId === 'consoleCommand') successMsg = t('toasts.copied_command');

            window.showToast(successMsg);

            if (!btn.hasAttribute('data-original-html')) {
                btn.setAttribute('data-original-html', btn.innerHTML);
            }
            
            btn.innerHTML = `<svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
            
            setTimeout(() => {
                btn.innerHTML = btn.getAttribute('data-original-html');
            }, 2000);

        } catch (error) {
            console.error("Copy operation failed:", error);
            window.showToast(t('toasts.copy_failed'));
        }
    });
});

// --- MEMO BUDGET & AMOUNT LIMITS ---

const SATOSHIS_PER_KRGN = 100000000;
// A satoshi amount as the registrar serves it, shown in KRGN without trailing zeros.
function formatSats(sats) {
    return parseFloat((Number(sats) / SATOSHIS_PER_KRGN).toFixed(8)).toString();
}
// Upper bound on a marketplace listing price.
//
// This is an ARITHMETIC bound, not a supply figure, kept from PIVX Name, which has no fixed
// cap to use. It keeps the satoshi conversion safe: 5e7 * 1e8 = 5e15, comfortably inside
// Number.MAX_SAFE_INTEGER (9.007e15). That guarantees no price can reach a signed memo as
// an imprecise or exponential-notation value, which would make the memo unverifiable. It is
// also below Kerrigan's MAX_MONEY of 52,560,000 KRGN, so no sensible price is refused.
//
// Lower it freely if a tighter product limit is wanted — nothing depends on this exact
// value except the error message in `address.price_error`, which must stay in agreement.
const MAX_KRGN_AMOUNT = 50000000;

// A Kerrigan shielded (Sapling) memo field is exactly 512 bytes.
const KERRIGAN_MEMO_MAX_BYTES = 512;
const ED25519_PUBKEY_HEX_LEN = 64;  // 32 bytes, hex encoded
const ED25519_SIG_HEX_LEN = 128;    // 64 bytes, hex encoded

// Longest destination address that still lets the signed memo fit the 512-byte field.
// The address is the flexible component here: a shorter domain buys a longer address.
// Layout: {MARKER}:1:{TYPE}:{domain}:{addr}:{pubkey}:{nonce}:{sig}
function maxAddressLengthFor(domain, type = 'REG') {
    const nonceLen = String(Math.floor(Date.now() / 1000)).length;
    const overhead =
        `${protocolMarker()}:1:${type}:`.length +
        (domain || '').length + 1 +   // domain + separator
        1 +                            // separator after the address
        ED25519_PUBKEY_HEX_LEN + 1 +
        nonceLen + 1 +
        ED25519_SIG_HEX_LEN;
    return KERRIGAN_MEMO_MAX_BYTES - overhead;
}

// Accepted Kerrigan Sapling address shape per network. These MUST match kns-core's
// EXPECTED_HRP / EXPECTED_ADDRESS_LEN, which the circuit enforces, and the indexer's
// Protocol::NETWORK_ADDRESS_RULES. If this form is looser than the circuit's, a user pays
// for a command the prover then cannot prove.
//
// Lengths are derived, not arbitrary: a Sapling payment address is 43 bytes (11-byte
// diversifier + 32-byte pk_d), which bech32m encodes as ceil(43*8/5)=69 data characters plus
// a 6-character checksum plus the separator — so hrp length + 76.
const KERRIGAN_ADDRESS_RULES = {
    mainnet: { hrp: 'ks',           len: 78 },
    testnet: { hrp: 'ktestsapling', len: 88 },
};
const SAPLING_PAYLOAD_LEN = 43;

// Which network this front-end validates against. Served by the registrar rather than
// hardcoded, so it cannot drift from the deployment — see fetchPaymentAddress().
let kerriganNetwork = 'mainnet';

// Marker at the head of every signed memo. MUST match kns-core's MESSAGE_PREFIX and the
// indexer's PROTOCOL_MARKER: the prefix differs per network so a signature produced against
// testnet can never be replayed onto mainnet. Getting this wrong makes every signature fail
// verification, so it is derived from the served network rather than written out inline.
function protocolMarker() {
    return kerriganNetwork === 'testnet' ? 'tKNS' : 'KNS';
}

// Pass maxLength = null to skip the length check (used for balance withdrawals, which do not
// embed the address in a memo and so are not bound by the memo budget).
function isValidKerriganAddress(addr, maxLength) {
    if (!addr || typeof addr !== 'string') return false;
    const cleanAddr = addr.trim();
    if (maxLength !== null && cleanAddr.length > maxLength) return false;

    const rules = KERRIGAN_ADDRESS_RULES[kerriganNetwork];
    if (cleanAddr.length !== rules.len) return false;

    // Bech32m checksums are case-insensitive, so the uppercase spelling of an address
    // decodes to the same payload. Refuse it: two spellings of one address would hash to
    // two different leaves in the tree.
    if (cleanAddr !== cleanAddr.toLowerCase()) return false;

    let decoded;
    try {
        // bech32m, NOT bech32: Kerrigan encodes Sapling addresses with bech32m (BIP 350),
        // and accepting both would give one address two valid checksums. The second
        // argument raises the library's default 90-character limit.
        decoded = bech32m.decode(cleanAddr, 1023);
    } catch {
        return false;
    }
    if (decoded.prefix !== rules.hrp) return false;

    // Character length does not imply payload length: bech32m pads to 5-bit groups, so this
    // check is a separate condition rather than a restatement of the one above.
    try {
        return bech32m.fromWords(decoded.words).length === SAPLING_PAYLOAD_LEN;
    } catch {
        return false;
    }
}

// Address, Owner PubKey and Price Validation Logic
function validateSlide2Input() {
    const type = currentTransactionType || "REG";
    let isValid = false;
    
    if (type === 'REG' || type === 'BUY' || type === 'UPD') {
        const addr = targetAddressInput.value.trim();
        const maxAddrLen = maxAddressLengthFor(currentRegistrationDomain, type);
        const isTooLong = addr.length > maxAddrLen;
        const isSameAddress = type === 'UPD' && addr.length > 0 && addr === currentUpdAddress;
        isValid = isValidKerriganAddress(addr, maxAddrLen) && !isSameAddress;

        if (addr.length > 0 && !isValid) {
            if (isSameAddress) {
                addressErrorMsg.textContent = t('address.same_address_error');
            } else if (isTooLong) {
                addressErrorMsg.textContent = t('address.error_too_long');
            } else {
                addressErrorMsg.textContent = t('address.error_msg');
            }
            addressErrorMsg.classList.remove('hidden');
        } else {
            addressErrorMsg.classList.add('hidden');
        }
        btnNextToPayment.disabled = !isValid || addr.length === 0;
        
    } else if (type === 'CHG') {
        const pubkeyInput = document.getElementById('newOwnerInput');
        const newOwnerErrorMsg = document.getElementById('newOwnerErrorMsg');
        // Lowercased before anything else: the protocol only accepts the lowercase spelling, and
        // the "same as your own key" check below must not be dodged by changing the case.
        const pubkey = pubkeyInput ? pubkeyInput.value.trim().toLowerCase() : '';
        const currentPubKey = getCachedPublicKey();
        
        if (pubkey.length === 0) {
            isValid = false;
            if (newOwnerErrorMsg) newOwnerErrorMsg.classList.add('hidden');
        } else if (pubkey === currentPubKey) {
            isValid = false;
            if (newOwnerErrorMsg) {
                newOwnerErrorMsg.textContent = t('address.new_owner_same_error') || "You entered your public key, operation is pointless.";
                newOwnerErrorMsg.setAttribute('data-i18n', 'address.new_owner_same_error');
                newOwnerErrorMsg.classList.remove('hidden');
            }
        } else {
            isValid = isValidEd25519PubKey(pubkey);
            if (!isValid) {
                if (newOwnerErrorMsg) {
                    newOwnerErrorMsg.textContent = t('address.new_owner_error') || "Public key must be a valid 64-character Ed25519 Public Key.";
                    newOwnerErrorMsg.setAttribute('data-i18n', 'address.new_owner_error');
                    newOwnerErrorMsg.classList.remove('hidden');
                }
            } else {
                if (newOwnerErrorMsg) newOwnerErrorMsg.classList.add('hidden');
            }
        }
        btnNextToPayment.disabled = !isValid || pubkey.length === 0;
        
    } else if (type === 'LST') {
        const priceInput = document.getElementById('desiredPriceInput');
        const priceErrorMsg = document.getElementById('priceErrorMsg');
        const priceStr = priceInput ? priceInput.value.trim() : '';
        const priceFloat = parseFloat(priceStr);
        isValid = /^\d+(\.\d{1,8})?$/.test(priceStr) && priceFloat > 0 && priceFloat <= MAX_KRGN_AMOUNT;

        if (priceStr.length > 0 && !isValid) {
            if (priceErrorMsg) priceErrorMsg.classList.remove('hidden');
        } else {
            if (priceErrorMsg) priceErrorMsg.classList.add('hidden');
        }
        btnNextToPayment.disabled = !isValid || priceStr.length === 0;
    }
}

function setupSlide2Inputs() {
    const type = currentTransactionType || "REG";
    
    const standardAddrGroup = document.getElementById('standardAddressInputGroup');
    const newOwnerGroup = document.getElementById('newOwnerInputGroup');
    const priceGroup = document.getElementById('marketplacePriceInputGroup');
    
    if (standardAddrGroup) standardAddrGroup.classList.add('hidden');
    if (newOwnerGroup) newOwnerGroup.classList.add('hidden');
    if (priceGroup) priceGroup.classList.add('hidden');
    
    if (type === 'REG' || type === 'BUY' || type === 'UPD') {
        if (standardAddrGroup) standardAddrGroup.classList.remove('hidden');
        const header = document.querySelector('#slideAddress h2');
        if (header) {
            header.setAttribute('data-i18n', 'address.title');
            header.textContent = t('address.title');
        }
    } else if (type === 'CHG') {
        if (newOwnerGroup) newOwnerGroup.classList.remove('hidden');
        const header = document.querySelector('#slideAddress h2');
        if (header) {
            header.setAttribute('data-i18n', 'address.new_owner_title');
            header.textContent = t('address.new_owner_title');
        }
    } else if (type === 'LST') {
        if (priceGroup) priceGroup.classList.remove('hidden');
        const header = document.querySelector('#slideAddress h2');
        if (header) {
            header.setAttribute('data-i18n', 'address.price_title');
            header.textContent = t('address.price_title');
        }
    }
    
    validateSlide2Input();
}

targetAddressInput.addEventListener('input', validateSlide2Input);

const newOwnerInput = document.getElementById('newOwnerInput');
if (newOwnerInput) {
    newOwnerInput.addEventListener('input', validateSlide2Input);
}

const desiredPriceInput = document.getElementById('desiredPriceInput');
if (desiredPriceInput) {
    desiredPriceInput.addEventListener('input', validateSlide2Input);
}

// Next to Payment Logic (Handles Auth & Sliding)
btnNextToPayment.addEventListener('click', () => {
    const proceedToPayment = async () => {
        const fullDomain = currentRegistrationDomain;
        const pubKey = walletSession.getPublicKey();
        const nonce = Math.floor(Date.now() / 1000);
        const type = currentTransactionType || "REG";
        
        let baseMemo = '';
        if (type === 'REG' || type === 'BUY' || type === 'UPD') {
            const targetAddr = targetAddressInput.value.trim();
            baseMemo = `${protocolMarker()}:1:${type}:${fullDomain}:${targetAddr}:${pubKey}:${nonce}`;
        } else if (type === 'CHG') {
            // Same normalisation the validator saw, so the signed memo carries the spelling the
            // protocol accepts rather than whatever case the key was pasted in.
            const newOwner = document.getElementById('newOwnerInput').value.trim().toLowerCase();
            baseMemo = `${protocolMarker()}:1:CHG:${fullDomain}:${newOwner}:${nonce}`;
        } else if (type === 'LST') {
            const enteredPrice = document.getElementById('desiredPriceInput').value.trim();
            const priceFloat = parseFloat(enteredPrice);
            const priceZat = Math.round(priceFloat * SATOSHIS_PER_KRGN);
            // Refuse to sign a price that cannot be represented exactly: an unsafe integer
            // would stringify imprecisely (or in exponential notation) inside the memo.
            if (!(priceFloat > 0) || priceFloat > MAX_KRGN_AMOUNT || !Number.isSafeInteger(priceZat)) {
                console.error("Refusing to build memo: listing price out of representable range:", enteredPrice);
                showErrorAlert(t('address.price_error'));
                return;
            }
            baseMemo = `${protocolMarker()}:1:LST:${fullDomain}:${pubKey}:${priceZat}:${nonce}`;
        }

        // Fail closed rather than emit a memo the wallet would reject or silently truncate.
        const projectedMemoLen = baseMemo.length + 1 + ED25519_SIG_HEX_LEN;
        if (projectedMemoLen > KERRIGAN_MEMO_MAX_BYTES) {
            console.error(`Refusing to build memo: ${projectedMemoLen} bytes exceeds the ${KERRIGAN_MEMO_MAX_BYTES}-byte Kerrigan memo limit.`);
            showErrorAlert(t('address.error_too_long'));
            return;
        }

        try {
            const sigHex = await walletSession.sign(baseMemo);
            const fullMemo = `${baseMemo}:${sigHex}`;
            payMemoInput.value = fullMemo;

            document.getElementById('payAmount').value = currentRegistrationPrice;
            
            // Dynamic payment title
            const paymentTitle = document.getElementById('paymentTitle');
            if (paymentTitle) {
                if (type === 'REG') {
                    paymentTitle.setAttribute('data-i18n', 'payment.title');
                    paymentTitle.textContent = t('payment.title');
                } else {
                    paymentTitle.setAttribute('data-i18n', 'payment.title_process');
                    paymentTitle.textContent = t('payment.title_process');
                }
            }
            
            setActiveSlide(slidePayment, 'translateX(-200%)');
            setStep('pay');
        } catch (err) {
            console.error("Signature failed:", err);
            showErrorAlert(t('toasts.sign_failed'));
        }
    };

    if (!localStorage.getItem('kerrigan_encrypted_account')) {
        pendingAction = proceedToPayment;
        openModal(); 
    } else if (!walletSession.isUnlocked()) {
        pendingAction = proceedToPayment;
        headerUnlockBtn.click();
    } else {
        proceedToPayment();
    }
});

// Show QR Modal Logic
function toBase64Url(str) {
    // Encode as UTF-8 bytes before base64: btoa() only accepts Latin-1, and the legacy
    // unescape(encodeURIComponent(...)) idiom relies on a deprecated global.
    const bytes = new TextEncoder().encode(str);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const showQrBtn = document.getElementById('showQrBtn');
const qrModalOverlay = document.getElementById('qrModalOverlay');
const qrModalContainer = document.getElementById('qrModalContainer');
const closeQrModalBtn = document.getElementById('closeQrModalBtn');
const qrcodeDiv = document.getElementById('qrcode');

async function openQrModal() {
    const addressField = document.getElementById('payAddress');
    let destAddress = addressField.value.trim();
    // Retry here rather than giving up: a request that failed at page load would otherwise
    // leave payment permanently broken for the whole session.
    if (destAddress === '') {
        try {
            destAddress = await fetchPaymentAddress();
            addressField.value = destAddress;
        } catch {
            showErrorAlert(t('errors.request_failed'));
            return;
        }
    }
    const amount = document.getElementById('payAmount').value.trim();
    const memo = document.getElementById('payMemo').value.trim();
    
    // The memo travels as base64url without padding (ZIP 321): that is how Kerrigan Core
    // and TrekPay read the memo of a kerrigan: URI, and they refuse a URI whose memo does
    // not decode. Unlike PIVX, a plain-text memo here would make the wallet reject the scan.
    const base64Memo = toBase64Url(memo);
    const qrString = `kerrigan:${destAddress}?amount=${amount}&memo=${base64Memo}`;

    qrcodeDiv.innerHTML = ''; 
    new QRCode(qrcodeDiv, {
        text: qrString,
        width: 260,
        height: 260,
        colorDark : "#000000",
        colorLight : "#ffffff",
        correctLevel : QRCode.CorrectLevel.L
    });

    qrModalOverlay.classList.remove('hidden');
    qrModalOverlay.classList.add('flex');
    void qrModalOverlay.offsetWidth; // Reflow
    qrModalOverlay.classList.remove('opacity-0');
    qrModalContainer.classList.remove('scale-95');
    qrModalContainer.classList.add('scale-100');
}

function closeQrModal() {
    qrModalOverlay.classList.add('opacity-0');
    qrModalContainer.classList.remove('scale-100');
    qrModalContainer.classList.add('scale-95');
    setTimeout(() => {
        qrModalOverlay.classList.add('hidden');
        qrModalOverlay.classList.remove('flex');
    }, 300);
}

showQrBtn.addEventListener('click', openQrModal);
closeQrModalBtn.addEventListener('click', closeQrModal);
qrModalOverlay.addEventListener('click', (e) => {
    if (e.target === qrModalOverlay) closeQrModal();
});

// Kerrigan Core Console Modal Logic
//
// The same payment as the QR code, as one z_sendmany line for Kerrigan Core's console
// (Window -> Console). Same form as masternode.space's Kerrigan pay dialog. z_sendmany takes
// the memo only as hex; the wallet pads it with zeros to 512 bytes, and the registrar reads
// that back as the same text. The fromaddress has no "any" form, so YOUR_ADDRESS stays for the
// payer to replace with their own shielded (ks1...) or transparent (K...) address. Single
// quotes work in the Qt console's parser and in a shell alike.
function toHex(str) {
    const bytes = new TextEncoder().encode(str);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

// The amount as a JSON number in plain decimal with at most 8 places. The price strings come
// from Number.toString(), which writes a tiny marketplace price in exponent notation (1e-7).
function toPlainKrgnAmount(amount) {
    const value = Number(amount);
    if (!Number.isFinite(value) || value <= 0) return null;
    return value.toFixed(8).replace(/\.?0+$/, '');
}

const showConsoleBtn = document.getElementById('showConsoleBtn');
const consoleModalOverlay = document.getElementById('consoleModalOverlay');
const consoleModalContainer = document.getElementById('consoleModalContainer');
const closeConsoleModalBtn = document.getElementById('closeConsoleModalBtn');
const consoleCommandField = document.getElementById('consoleCommand');

async function openConsoleModal() {
    const addressField = document.getElementById('payAddress');
    let destAddress = addressField.value.trim();
    // Retried here as in openQrModal(), so a request that failed at page load does not leave
    // this way of paying broken for the whole session.
    if (destAddress === '') {
        try {
            destAddress = await fetchPaymentAddress();
            addressField.value = destAddress;
        } catch {
            showErrorAlert(t('errors.request_failed'));
            return;
        }
    }
    const amount = toPlainKrgnAmount(document.getElementById('payAmount').value.trim());
    const memo = document.getElementById('payMemo').value.trim();
    // The address goes inside quotes in a line the payer runs in their wallet, so only a
    // well-formed Kerrigan shielded address is let into it.
    if (!isValidKerriganAddress(destAddress, null) || amount === null || memo === '') {
        showErrorAlert(t('errors.request_failed'));
        return;
    }

    consoleCommandField.value = `z_sendmany "YOUR_ADDRESS" `
        + `'[{"address":"${destAddress}","amount":${amount},"memo":"${toHex(memo)}"}]'`;
    consoleCommandField.scrollTop = 0;

    consoleModalOverlay.classList.remove('hidden');
    consoleModalOverlay.classList.add('flex');
    void consoleModalOverlay.offsetWidth; // Reflow
    consoleModalOverlay.classList.remove('opacity-0');
    consoleModalContainer.classList.remove('scale-95');
    consoleModalContainer.classList.add('scale-100');
}

function closeConsoleModal() {
    consoleModalOverlay.classList.add('opacity-0');
    consoleModalContainer.classList.remove('scale-100');
    consoleModalContainer.classList.add('scale-95');
    setTimeout(() => {
        consoleModalOverlay.classList.add('hidden');
        consoleModalOverlay.classList.remove('flex');
    }, 300);
}

showConsoleBtn.addEventListener('click', openConsoleModal);
closeConsoleModalBtn.addEventListener('click', closeConsoleModal);
consoleModalOverlay.addEventListener('click', (e) => {
    if (e.target === consoleModalOverlay) closeConsoleModal();
});

const iPaidBtn = document.getElementById('iPaidBtn');
const statusHeading = document.getElementById('statusHeading');
const statusDescription = document.getElementById('statusDescription');
const statusSpinner = document.getElementById('statusSpinner');
const statusSuccessIcon = document.getElementById('statusSuccessIcon');
const statusErrorIcon = document.getElementById('statusErrorIcon');
const statusCountdownContainer = document.getElementById('statusCountdownContainer');
const statusCountdownText = document.getElementById('statusCountdownText');

let pollInterval;
let countdownInterval;
let currentTxId = null;
let secondsRemaining = 30;
let isPolling = false;

function updateStatusUI(heading, description, showSpinner = true, type = 'normal') {
    statusHeading.textContent = heading;
    statusDescription.textContent = description;
    
    if (showSpinner) {
        statusSpinner.classList.remove('hidden');
        statusSuccessIcon.classList.add('hidden');
        statusErrorIcon.classList.add('hidden');
        statusCountdownContainer.classList.remove('opacity-0');
    } else {
        statusSpinner.classList.add('hidden');
        statusCountdownContainer.classList.add('opacity-0');
        if (type === 'success') {
            statusSuccessIcon.classList.remove('hidden');
            statusErrorIcon.classList.add('hidden');
        } else if (type === 'error') {
            statusErrorIcon.classList.remove('hidden');
            statusSuccessIcon.classList.add('hidden');
        }
    }
}

function formatTime(totalSeconds) {
    const m = Math.floor(totalSeconds / 60);
    const s = totalSeconds % 60;
    if (m === 1 && s === 1) return t('status.time_format_singular_both', { m, s });
    if (m === 1) return t('status.time_format_singular_m', { m, s });
    if (s === 1) return t('status.time_format_singular_s', { m, s });
    return t('status.time_format', { m, s });
}

async function pollTransactionStatus() {
    if (isPolling) return; // avoid overlapping with a still in-flight poll (immediate re-check vs. the 30s interval)
    isPolling = true;
    secondsRemaining = 30;
    statusCountdownText.innerHTML = tSafe('status.next_check', { seconds: secondsRemaining });

    try {
        let payload = {};
        if (currentTxId) {
            payload = { tx_id: currentTxId };
        } else {
            const memo = document.getElementById('payMemo').value;
            payload = { reg_id: btoa(memo) }; // Base64 encode memo
        }

        const response = await fetch(`${API_BASE_URL}/v1.0/check/${currentRegistrationDomain}`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();

        if (!data.response || Object.keys(data.response).length === 0) return;

        // TX ID Discovered
        if (data.response.tx_id && !currentTxId) {
            currentTxId = data.response.tx_id;
            updateStatusUI(t('status.detected_title'), t('status.detected_desc'));
            isPolling = false;
            await pollTransactionStatus(); // Immediately request the status without waiting 30 seconds!
            return;
        }

        // Process Status Codes
        if (data.response.status !== undefined) {
            const status = data.response.status;

            if (status === 0 || status === 7) {
                let confCount = PAYMENT_CONFIRMATIONS;
                let confText = t('status.confs_payment_desc');
                if (status === 7) {
                    confCount = REFUND_CONFIRMATIONS;
                    confText = t('status.confs_refund_desc');
                }
                const confs = data.response.confirmations || 0;
                // The registrar does not say whether the block is ChainLocked yet, so the
                // shorter count is told rather than shown as the total.
                confText += ' ' + t('status.confs_chainlock_note', { cl: CHAINLOCK_CONFIRMATIONS });
                updateStatusUI(t('status.confs_title', { confs: confs, total: confCount }), confText);
            } 
            else if (status === 1 || status === 2) {
                const timeStr = data.response.seconds ? t('status.zk_pending_desc', { time: formatTime(data.response.seconds) }) : t('status.zk_pending_desc_soon');
                updateStatusUI(t('status.zk_pending_title'), timeStr);
            }
            else if (status === 3) {
                updateStatusUI(t('status.zk_processing_title'), t('status.zk_processing_desc'));
            }
            else if (status === 4) {
                updateStatusUI(t('status.zk_submitting_title'), t('status.zk_submitting_desc'));
            }
            else if (status === 5) {
                clearInterval(pollInterval);
                clearInterval(countdownInterval);
                setStep('yours');
                const successKey = `status.success_desc_${currentTransactionType || "REG"}`;
                let successMsg = t(successKey, { domain: currentRegistrationDomain });
                if (successMsg === successKey) {
                    successMsg = t('status.success_desc', { domain: currentRegistrationDomain });
                }
                updateStatusUI(t('status.success_title'), successMsg, false, 'success');
            }
            else if (status === 8) {
                clearInterval(pollInterval);
                clearInterval(countdownInterval);
                updateStatusUI(t('status.refunded_title'), t('status.refunded_desc'), false, 'error');
            }
            else if (status === 6) {
                clearInterval(pollInterval);
                clearInterval(countdownInterval);
                updateStatusUI(t('status.failed_title'), t('status.failed_desc'), false, 'error');
            }
            // TX_STATUS_ERROR: the registrar refused the command outright. Terminal like
            // status 6, so the pollers stop, but it is not a network mishap - the payment
            // was seen and rejected on its merits, and the wording has to say so.
            else if (status === 9) {
                clearInterval(pollInterval);
                clearInterval(countdownInterval);
                updateStatusUI(t('status.rejected_title'), t('status.rejected_desc'), false, 'error');
            }
        }
    } catch (err) {
        console.error("Polling error:", err);
    } finally {
        isPolling = false;
    }
}

iPaidBtn.addEventListener('click', () => {
    // Clear any timers from a previous attempt: re-entering this handler (double-click, or
    // returning to the payment slide) would otherwise orphan them to poll forever.
    if (pollInterval) clearInterval(pollInterval);
    if (countdownInterval) clearInterval(countdownInterval);

    currentTxId = null;
    updateStatusUI(t('status.scanning_title'), t('status.scanning_desc'));
    
    // Slide to 4th pane (-300%)
    setActiveSlide(slideStatus, 'translateX(-300%)');
    setStep('pay');

    // Start Timers
    secondsRemaining = 30;
    statusCountdownText.innerHTML = tSafe('status.next_check', { seconds: secondsRemaining });
    pollTransactionStatus(); // Immediate first check

    countdownInterval = setInterval(() => {
        secondsRemaining--;
        if (secondsRemaining <= 0) secondsRemaining = 30;
        statusCountdownText.innerHTML = tSafe('status.next_check', { seconds: secondsRemaining });
    }, 1000);

    pollInterval = setInterval(pollTransactionStatus, 30000);
});

// Name Availability Search Logic
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = input.value.trim().toLowerCase();
    const zone = domainZoneSelect.value;
    const fullDomain = name + zone;

    if (!name) return;

    // Strict format and length validation check
    const nameRegex = /^[a-z0-9]+(-[a-z0-9]+)*$/;
    if (!nameRegex.test(name) || fullDomain.length > 64) {
        resultMessage.style.opacity = '1';
        resultMessage.innerHTML = `
            <div class="mt-4 flex w-full">
                <span class="text-red-400 flex items-start gap-1.5 min-w-0">
                    <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> 
                    <span class="min-w-0 break-words">${t('search.invalid_name_error')}</span>
                </span>
            </div>
        `;
        return;
    }

    btn.disabled = true;
    btnText.innerHTML = `<span class="loader"></span> ${t('search.btn_checking')}`;
    resultMessage.style.opacity = '0';
    setStep('check'); 
    
    try {
        let response;
        if (localStorage.getItem('kerrigan_encrypted_account')) {
            response = await fetch(`${API_BASE_URL}/v1.0/check/${fullDomain}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ with_pubkey: true })
            });
        } else {
            response = await fetch(`${API_BASE_URL}/v1.0/check/${fullDomain}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });
        }
        const data = await response.json();

        resultMessage.style.opacity = '1';

        // Standard API Error Handling
        if (data.error) {
            const errMsg = (typeof data.error === 'object' && data.error.error_message) ? data.error.error_message : data.error;
            showErrorAlert(errMsg);
            resultMessage.style.opacity = '0';
            return;
        }
        
        if (data.response && data.response.exists === true) {
            if (data.response.price && data.response.price !== "0" && data.response.price !== 0) {
                const priceZat = parseFloat(data.response.price);
                const priceZec = priceZat / 100000000;
                const priceFormatted = parseFloat(priceZec.toFixed(8)).toString();
                const price = priceFormatted;
                const responsePubkey = data.response.pubkey;
                const myPubkey = getCachedPublicKey();
                const isOwnDomain = myPubkey && responsePubkey && (responsePubkey.toLowerCase() === myPubkey.toLowerCase());
                
                if (isOwnDomain) {
                    resultMessage.innerHTML = `
                        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between w-full p-3 mt-4 rounded-xl bg-purple-500/10 border border-purple-500/20 gap-4">
                            <div class="text-purple-400 flex items-start gap-2 min-w-0 w-full sm:w-auto flex-1">
                                <svg class="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                                <div class="min-w-0 break-words flex-1 leading-snug">
                                    <span class="text-white text-base font-bold break-all">${escapeHtml(fullDomain)}</span>
                                    <span class="inline-block mt-1 sm:mt-0 sm:ml-1">${tSafe('search.listed_msg', { price: price })}</span>
                                </div>
                            </div>
                            <button type="button" id="triggerUnlistNowBtn" class="w-full sm:w-auto flex-shrink-0 bg-purple-600 hover:bg-purple-500 text-white px-5 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-purple-900/30 whitespace-nowrap active:scale-95">
                                ${t('search.unlist_now')}
                            </button>
                        </div>
                    `;

                    // Unlisting is an update: check serves its price with the name.
                    const updatePriceSats = data.response.update_price;
                    document.getElementById('triggerUnlistNowBtn').addEventListener('click', () => {
                        handleRemoveFromSale(fullDomain, updatePriceSats);
                    });
                } else {
                    resultMessage.innerHTML = `
                        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between w-full p-3 mt-4 rounded-xl bg-purple-500/10 border border-purple-500/20 gap-4">
                            <div class="text-purple-400 flex items-start gap-2 min-w-0 w-full sm:w-auto flex-1">
                                <svg class="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                                <div class="min-w-0 break-words flex-1 leading-snug">
                                    <span class="text-white text-base font-bold break-all">${escapeHtml(fullDomain)}</span>
                                    <span class="inline-block mt-1 sm:mt-0 sm:ml-1">${tSafe('search.listed_msg', { price: price })}</span>
                                </div>
                            </div>
                            <button type="button" id="triggerBuyNowBtn" class="w-full sm:w-auto flex-shrink-0 bg-purple-600 hover:bg-purple-500 text-white px-5 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-purple-900/30 whitespace-nowrap active:scale-95">
                                ${t('search.buy_now')}
                            </button>
                        </div>
                    `;

                    document.getElementById('triggerBuyNowBtn').addEventListener('click', () => {
                        handleBuyDomain(fullDomain, price);
                    });
                }
            } else {
                resultMessage.innerHTML = `
                    <div class="mt-4 flex w-full">
                        <span class="text-red-400 flex items-start gap-1.5 min-w-0">
                            <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> 
                            <span class="min-w-0 break-words">${tSafe('search.taken_msg', { domain: fullDomain })}</span>
                        </span>
                    </div>
                `;
            }
        } else if (data.response && data.response.exists === false && data.response.reg_pending === true) {
            // Free, but someone has already paid to register it and the registration is on its
            // way. Only one payment can win the name, so no pay button: a second one would only
            // come back as a refund, less the withdrawal fee.
            resultMessage.innerHTML = `
                <div class="flex w-full p-3 mt-4 rounded-xl bg-amber-500/10 border border-amber-500/20">
                    <div class="text-amber-300 flex items-start gap-2 min-w-0 flex-1">
                        <svg class="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <div class="min-w-0 break-words flex-1 leading-snug">
                            <span class="text-white text-base font-bold break-all">${escapeHtml(fullDomain)}</span>
                            <span class="inline-block mt-1 sm:mt-0 sm:ml-1">${t('search.reg_pending_msg')}</span>
                        </div>
                    </div>
                </div>
            `;
        } else if (data.response && data.response.exists === false) {
            const priceZat = parseFloat(data.response.price) || 0;
            const priceZec = priceZat / 100000000;
            const priceFormatted = parseFloat(priceZec.toFixed(8)).toString();
            const price = priceFormatted;
            resultMessage.innerHTML = `
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between w-full p-3 mt-4 rounded-xl bg-green-500/10 border border-green-500/20 gap-4">
                    <div class="text-green-400 flex items-start gap-2 min-w-0 w-full sm:w-auto flex-1">
                        <svg class="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <div class="min-w-0 break-words flex-1 leading-snug">
                            <span class="text-white text-base font-bold break-all">${escapeHtml(fullDomain)}</span>
                            <span class="inline-block mt-1 sm:mt-0 sm:ml-1">${tSafe('search.available_msg', { price: price })}</span>
                        </div>
                    </div>
                    <button type="button" id="triggerPayBtn" class="w-full sm:w-auto flex-shrink-0 bg-green-500 hover:bg-green-600 text-white px-5 py-2 rounded-lg text-sm font-bold transition-all shadow-lg shadow-green-900/30 whitespace-nowrap active:scale-95">
                        ${t('search.get_now')}
                    </button>
                </div>
            `;

            document.getElementById('triggerPayBtn').addEventListener('click', () => {
                currentRegistrationDomain = fullDomain;
                currentRegistrationPrice = price;
                currentTransactionType = "REG";
                setupSlide2Inputs();
                
                // Restore destination address field visibility
                document.getElementById('payAddressGroup').classList.remove('hidden');
                
                setActiveSlide(slideAddress, 'translateX(-100%)');
                setStep('check');
                
                targetAddressInput.value = '';
                targetAddressInput.dispatchEvent(new Event('input'));
            });
        } else {
            throw new Error("Invalid API response format");
        }
    } catch (err) {
        console.error("API Check Error:", err);
        btn.disabled = false;
        btnText.textContent = t('search.btn');
        resultMessage.style.opacity = '1';
        resultMessage.innerHTML = `<div class="mt-4 flex w-full"><span class="text-red-400 flex items-start gap-1.5"><svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> <span>${t('search.conn_error')}</span></span></div>`;
    } finally {
        btn.disabled = false;
        btnText.textContent = t('search.btn');
    }
});

input.addEventListener('input', () => {
    let val = input.value;
    
    // Convert to lowercase
    val = val.toLowerCase();
    
    // Strip out characters that are not a-z, 0-9 or hyphen
    val = val.replace(/[^a-z0-9-]/g, '');
    
    // Merge consecutive hyphens
    val = val.replace(/-{2,}/g, '-');
    
    // Remove leading hyphen
    if (val.startsWith('-')) {
        val = val.substring(1);
    }
    
    if (input.value !== val) {
        input.value = val;
    }

    if (resultMessage.style.opacity !== '0') {
        resultMessage.style.opacity = '0';
        setTimeout(() => {
            resultMessage.innerHTML = '';
        }, 300);
    }
    setActiveSlide(slide1, 'translateX(0)');
    setStep('check');
});

btnBackToSearchFromAddress.addEventListener('click', () => {
    currentTransactionType = "REG";
    setupSlide2Inputs();
    setActiveSlide(slide1, 'translateX(0)');
    setStep('check');
});

btnBackToAddress.addEventListener('click', () => {
    if (currentTransactionType === "ULT") {
        switchTab('register');
        currentTransactionType = "REG";
        setupSlide2Inputs();
        const payAddressGroup = document.getElementById('payAddressGroup');
        if (payAddressGroup) payAddressGroup.classList.remove('hidden');
        setActiveSlide(slide1, 'translateX(0)');
        setStep('check');
    } else {
        setActiveSlide(slideAddress, 'translateX(-100%)');
        setStep('check'); 
    }
});

window.addEventListener('scroll', () => {
    const headerBg = document.getElementById('headerBg');
    // The at-the-top state matches #headerBg in style.css; the green hairline under the
    // purple rule is kept in both.
    if (window.scrollY > 10) {
        headerBg.style.background = 'rgba(0, 0, 0, 0.78)';
        headerBg.style.boxShadow = '0 1px 0 rgba(67, 222, 120, 0.45), 0 6px 20px rgba(0, 0, 0, 0.6)';
    } else {
        headerBg.style.background = 'rgba(0, 0, 0, 0.55)';
        headerBg.style.boxShadow = '0 1px 0 rgba(67, 222, 120, 0.3)';
    }
});

// --- Authentication & Modal Logic ---

// DOM Elements
const authControlsGuest = document.getElementById('authControlsGuest');
const authControlsUser = document.getElementById('authControlsUser');
const authControlsLocked = document.getElementById('authControlsLocked');
const accountMenuBtn = document.getElementById('accountMenuBtn');
const accountDropdown = document.getElementById('accountDropdown');

// Dropdown Menu Buttons
const menuMyNamesBtn = document.getElementById('menuMyNamesBtn');
const menuChangePwdBtn = document.getElementById('menuChangePwdBtn');
const menuRevealSeedBtn = document.getElementById('menuRevealSeedBtn');
const menuLockBtn = document.getElementById('menuLockBtn');

const headerUnlockBtn = document.getElementById('headerUnlockBtn');
const headerLoginBtn = document.getElementById('headerLoginBtn');
const headerLogoutBtn = document.getElementById('headerLogoutBtn');
const headerLockedLogoutBtn = document.getElementById('headerLockedLogoutBtn');

const modalOverlay = document.getElementById('authModalOverlay');
const modalContainer = document.getElementById('authModalContainer');
const closeModalBtn = document.getElementById('closeModalBtn');

// Modal Views
const viewSelection = document.getElementById('modalViewSelection');
const viewCreate = document.getElementById('modalViewCreate');
const viewUnlock = document.getElementById('modalViewUnlock');
const viewImportSeed = document.getElementById('modalViewImportSeed');
const viewImportPassword = document.getElementById('modalViewImportPassword');
const viewChangePassword = document.getElementById('modalViewChangePassword');
const viewRevealSeedAuth = document.getElementById('modalViewRevealSeedAuth');
const viewRevealSeedShow = document.getElementById('modalViewRevealSeedShow');

const btnShowCreate = document.getElementById('btnShowCreate');
const btnBackToSelection = document.getElementById('btnBackToSelection');
const btnShowImport = document.getElementById('btnShowImport');
const btnBackToSelectionFromImport = document.getElementById('btnBackToSelectionFromImport');
const btnBackToImportSeed = document.getElementById('btnBackToImportSeed');
const btnNextToImportPassword = document.getElementById('btnNextToImportPassword');

const regSeedPhrase = document.getElementById('regSeedPhrase');
const regPassword1 = document.getElementById('regPassword1');
const regPassword2 = document.getElementById('regPassword2');
const regConfirmSaved = document.getElementById('regConfirmSaved');
const regErrorMsg = document.getElementById('regErrorMsg');
const doCreateAccountBtn = document.getElementById('doCreateAccountBtn');
const createBtnText = document.getElementById('createBtnText');

const unlockPassword = document.getElementById('unlockPassword');
const unlockErrorMsg = document.getElementById('unlockErrorMsg');
const doUnlockBtn = document.getElementById('doUnlockBtn');
const unlockBtnText = document.getElementById('unlockBtnText');

const seedInputContainer = document.getElementById('seedInputContainer');
const importSeedErrorMsg = document.getElementById('importSeedErrorMsg');
const importPassword1 = document.getElementById('importPassword1');
const importPassword2 = document.getElementById('importPassword2');
const importPwdErrorMsg = document.getElementById('importPwdErrorMsg');
const doImportAccountBtn = document.getElementById('doImportAccountBtn');
const importBtnText = document.getElementById('importBtnText');

// Change Password Form Elements
const changePwdOld = document.getElementById('changePwdOld');
const changePwdNew1 = document.getElementById('changePwdNew1');
const changePwdNew2 = document.getElementById('changePwdNew2');
const changePwdErrorMsg = document.getElementById('changePwdErrorMsg');
const doChangePwdBtn = document.getElementById('doChangePwdBtn');
const changePwdBtnText = document.getElementById('changePwdBtnText');

// Reveal Seed Form Elements
const revealSeedPassword = document.getElementById('revealSeedPassword');
const revealSeedErrorMsg = document.getElementById('revealSeedErrorMsg');
const doRevealSeedAuthBtn = document.getElementById('doRevealSeedAuthBtn');
const revealSeedAuthBtnText = document.getElementById('revealSeedAuthBtnText');
const revealSeedTextarea = document.getElementById('revealSeedTextarea');
const btnDoneRevealSeed = document.getElementById('btnDoneRevealSeed');

const seedInputs = [];
// A phrase is 12 words or 24 (TrekPay makes 12 or 24). The key is the same either way - SHA-256 of the
// words joined by single spaces (SecureWalletSession.unlock) - so only the form has to know.
// The last 12 boxes stay hidden until a 24-word phrase is pasted or the toggle asks for them.
const SEED_LENGTHS = [12, 24];
let seedLength = 12;
const btnSeedLength = document.getElementById('btnSeedLength');

for (let i = 1; i <= 24; i++) {
    const wrapper = document.createElement('div');
    wrapper.className = 'relative flex items-center transition-z duration-75';
    wrapper.innerHTML = `
        <span class="absolute left-3 text-white/40 text-xs w-4 text-right select-none">${i}</span>
        <input type="text" class="seed-word-input w-full bg-black/20 border border-white/10 rounded-lg py-2 pl-9 pr-2 text-white text-sm focus:outline-none focus:border-purple-500 transition-colors" autocomplete="off" spellcheck="false" />
        <ul class="suggestion-list absolute top-[calc(100%+4px)] left-0 right-0 z-[100] bg-[#140828] border border-purple-500/30 rounded-lg shadow-2xl hidden max-h-36 overflow-y-auto custom-scroll m-0 p-1 flex flex-col gap-0.5"></ul>
    `;
    if (i > 12) wrapper.classList.add('hidden');
    seedInputContainer.appendChild(wrapper);
    seedInputs.push({ input: wrapper.querySelector('input'), wrapper });
}

// The boxes the phrase is read from: the first 12, or all 24.
function activeSeedInputs() {
    return seedInputs.slice(0, seedLength);
}

function setSeedLength(length) {
    seedLength = length;
    seedInputs.forEach((item, index) => {
        const shown = index < length;
        item.wrapper.classList.toggle('hidden', !shown);
        // A word left in a hidden box would never be seen again, nor read.
        if (!shown) item.input.value = '';
    });
    const key = length === 24 ? 'auth_modal.import_use_12' : 'auth_modal.import_use_24';
    btnSeedLength.setAttribute('data-i18n', key);
    btnSeedLength.textContent = t(key);
}

btnSeedLength.addEventListener('click', () => {
    setSeedLength(seedLength === 24 ? 12 : 24);
    validateImportSeedForm();
    seedInputs[seedLength === 24 ? 12 : 0].input.focus();
});

function closeDropdown() {
    accountDropdown.classList.add('opacity-0', 'invisible', 'scale-95');
    accountDropdown.classList.remove('opacity-100', 'visible', 'scale-100');
}

function openDropdown() {
    accountDropdown.classList.remove('opacity-0', 'invisible', 'scale-95');
    accountDropdown.classList.add('opacity-100', 'visible', 'scale-100');
}

function checkAuthState() {
    if (localStorage.getItem('kerrigan_encrypted_account')) {
        authControlsGuest.classList.add('hidden');
        
        if (walletSession.isUnlocked()) {
            authControlsUser.classList.remove('hidden');
            authControlsUser.classList.add('flex');
            authControlsLocked.classList.add('hidden');
            authControlsLocked.classList.remove('flex');
        } else {
            authControlsUser.classList.add('hidden');
            authControlsUser.classList.remove('flex');
            authControlsLocked.classList.remove('hidden');
            authControlsLocked.classList.add('flex');
        }
    } else {
        authControlsGuest.classList.remove('hidden');
        authControlsUser.classList.add('hidden');
        authControlsUser.classList.remove('flex');
        authControlsLocked.classList.add('hidden');
        authControlsLocked.classList.remove('flex');
    }
    closeDropdown();
}
checkAuthState();

accountMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (accountDropdown.classList.contains('opacity-0')) {
        openDropdown();
    } else {
        closeDropdown();
    }
});

document.addEventListener('click', (e) => {
    if (!accountDropdown.contains(e.target) && !accountMenuBtn.contains(e.target)) {
        closeDropdown();
    }
});

menuLockBtn.addEventListener('click', () => {
    walletSession.lock();
    checkAuthState();
    resetUIState();
    resetModalViews();
});

function openModal() {
    modalOverlay.classList.remove('hidden');
    modalOverlay.classList.add('flex');
    void modalOverlay.offsetWidth; 
    modalOverlay.classList.remove('opacity-0');
    modalContainer.classList.remove('translate-y-10');
    resetModalViews();
}

function closeModal() {
    modalOverlay.classList.add('opacity-0');
    modalContainer.classList.add('translate-y-10');
    resetModalViews();
    setTimeout(() => {
        modalOverlay.classList.add('hidden');
        modalOverlay.classList.remove('flex');
    }, 300);
}

headerLoginBtn.addEventListener('click', openModal);
closeModalBtn.addEventListener('click', () => {
    closeModal();
    pendingAction = null;
});

modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
        closeModal();
        pendingAction = null;
    }
});

function resetModalViews() {
    const allViews = [
        viewCreate, viewUnlock, viewImportSeed, viewImportPassword, 
        viewSelection, viewChangePassword, viewRevealSeedAuth, viewRevealSeedShow
    ];
    
    allViews.forEach(view => {
        view.classList.add('hidden');
        view.classList.remove('flex');
    });
    
    viewSelection.classList.remove('hidden');
    viewSelection.classList.add('flex');
    
    document.querySelectorAll('.toggle-password').forEach(btn => {
        const input = btn.previousElementSibling;
        if (input) {
            const eyeIcon = btn.querySelector('.eye-icon');
            const eyeOffIcon = btn.querySelector('.eye-off-icon');
            input.type = 'password';
            if (eyeIcon) eyeIcon.classList.remove('hidden');
            if (eyeOffIcon) eyeOffIcon.classList.add('hidden');
        }
    });
    
    regPassword1.value = '';
    regPassword2.value = '';
    regConfirmSaved.checked = false;
    unlockPassword.value = '';
    unlockErrorMsg.classList.add('hidden');
    
    seedInputs.forEach(item => item.input.value = '');
    setSeedLength(12);
    importSeedErrorMsg.classList.add('hidden');
    importPassword1.value = '';
    importPassword2.value = '';
    importPwdErrorMsg.classList.add('hidden');
    
    changePwdOld.value = '';
    changePwdNew1.value = '';
    changePwdNew2.value = '';
    changePwdErrorMsg.classList.add('hidden');
    
    revealSeedPassword.value = '';
    revealSeedErrorMsg.classList.add('hidden');
    revealSeedTextarea.value = '';
    
    validateRegistrationForm();
    validateImportSeedForm();
    validateImportPasswordForm();
    validateChangePwdForm();
}

// --- Change Password Modal Logic ---
menuChangePwdBtn.addEventListener('click', () => {
    closeDropdown();
    openModal();
    viewSelection.classList.add('hidden');
    viewSelection.classList.remove('flex');
    viewChangePassword.classList.remove('hidden');
    viewChangePassword.classList.add('flex', 'animate-slide-up-fade');
    changePwdOld.focus();
});

function validateChangePwdForm() {
    const oldP = changePwdOld.value;
    const p1 = changePwdNew1.value;
    const p2 = changePwdNew2.value;
    let isValid = true;
    
    if (p1.length > 0 && p1.length < 8) {
        changePwdErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_length');
        changePwdErrorMsg.classList.remove('hidden');
        isValid = false;
    } else if (p1 && p2 && p1 !== p2) {
        changePwdErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_match');
        changePwdErrorMsg.classList.remove('hidden');
        isValid = false;
    } else {
        changePwdErrorMsg.classList.add('hidden');
    }

    if (!oldP || !p1 || p1.length < 8 || p1 !== p2) {
        isValid = false;
    }

    doChangePwdBtn.disabled = !isValid;
}

changePwdOld.addEventListener('input', validateChangePwdForm);
changePwdNew1.addEventListener('input', validateChangePwdForm);
changePwdNew2.addEventListener('input', validateChangePwdForm);

doChangePwdBtn.addEventListener('click', async () => {
    doChangePwdBtn.disabled = true;
    changePwdBtnText.innerHTML = `<span class="loader"></span> ${t('auth_modal.btn_change_pwd_saving')}`;
    changePwdErrorMsg.classList.add('hidden');

    try {
        const encryptedDataStr = localStorage.getItem('kerrigan_encrypted_account');
        if (!encryptedDataStr) throw new Error("No account found");
        
        const seed = await decryptSeed(encryptedDataStr, changePwdOld.value);
        const newEncryptedData = await encryptSeed(seed, changePwdNew1.value);
        newEncryptedData.pubKeyHex = walletSession.getPublicKey();

        localStorage.setItem('kerrigan_encrypted_account', JSON.stringify(newEncryptedData));
        
        setTimeout(() => {
            closeModal();
            window.showToast(t('toasts.pwd_changed'));
            doChangePwdBtn.disabled = false;
            changePwdBtnText.textContent = t('auth_modal.btn_change_pwd');
        }, 500);

    } catch (err) {
        setTimeout(() => {
            changePwdErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_incorrect');
            changePwdErrorMsg.classList.remove('hidden');
            doChangePwdBtn.disabled = false;
            changePwdBtnText.textContent = t('auth_modal.btn_change_pwd');
        }, 500);
    }
});

// --- Reveal Seed Phrase Modal Logic ---
menuRevealSeedBtn.addEventListener('click', () => {
    closeDropdown();
    openModal();
    viewSelection.classList.add('hidden');
    viewSelection.classList.remove('flex');
    viewRevealSeedAuth.classList.remove('hidden');
    viewRevealSeedAuth.classList.add('flex', 'animate-slide-up-fade');
    revealSeedPassword.focus();
});

doRevealSeedAuthBtn.addEventListener('click', async () => {
    const pwd = revealSeedPassword.value;
    if (!pwd) return;

    doRevealSeedAuthBtn.disabled = true;
    // We can translate 'Verifying...' state using active locale lookup logic
    revealSeedAuthBtnText.innerHTML = `<span class="loader"></span> ${t('search.btn_checking')}`;
    revealSeedErrorMsg.classList.add('hidden');

    try {
        const encryptedDataStr = localStorage.getItem('kerrigan_encrypted_account');
        if (!encryptedDataStr) throw new Error("No account found");
        
        const seed = await decryptSeed(encryptedDataStr, pwd);
        
        setTimeout(() => {
            revealSeedTextarea.value = seed;
            
            viewRevealSeedAuth.classList.add('hidden');
            viewRevealSeedAuth.classList.remove('flex');
            viewRevealSeedShow.classList.remove('hidden');
            viewRevealSeedShow.classList.add('flex', 'animate-fade-in');
            
            doRevealSeedAuthBtn.disabled = false;
            revealSeedAuthBtnText.textContent = t('auth_modal.btn_next');
        }, 500);

    } catch (err) {
        setTimeout(() => {
            revealSeedErrorMsg.textContent = t('auth_modal.reveal_seed_err_incorrect');
            revealSeedErrorMsg.classList.remove('hidden');
            doRevealSeedAuthBtn.disabled = false;
            revealSeedAuthBtnText.textContent = t('auth_modal.btn_next');
        }, 500);
    }
});

revealSeedPassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        doRevealSeedAuthBtn.click();
    }
});

btnDoneRevealSeed.addEventListener('click', () => {
    closeModal();
});

btnShowCreate.addEventListener('click', () => {
    const mnemonic = generateMnemonic(wordlist, 128);
    regSeedPhrase.value = mnemonic;

    viewSelection.classList.add('hidden');
    viewSelection.classList.remove('flex');
    viewCreate.classList.remove('hidden');
    viewCreate.classList.add('flex');

    regSeedPhrase.style.height = 'auto';
    regSeedPhrase.style.height = (regSeedPhrase.scrollHeight + 10) + 'px';

    viewCreate.classList.remove('animate-slide-up-fade');
    void viewCreate.offsetWidth;
    viewCreate.classList.add('animate-slide-up-fade');
});

btnBackToSelection.addEventListener('click', () => {
    viewCreate.classList.add('hidden');
    viewCreate.classList.remove('flex');
    viewSelection.classList.remove('hidden');
    viewSelection.classList.add('flex');

    viewSelection.classList.remove('animate-fade-in');
    void viewSelection.offsetWidth;
    viewSelection.classList.add('animate-fade-in');
});

btnShowImport.addEventListener('click', () => {
    viewSelection.classList.add('hidden');
    viewSelection.classList.remove('flex');
    viewImportSeed.classList.remove('hidden');
    viewImportSeed.classList.add('flex');
    
    viewImportSeed.classList.remove('animate-slide-up-fade');
    void viewImportSeed.offsetWidth;
    viewImportSeed.classList.add('animate-slide-up-fade');
    
    seedInputs[0].input.focus();
});

btnBackToSelectionFromImport.addEventListener('click', () => {
    viewImportSeed.classList.add('hidden');
    viewImportSeed.classList.remove('flex');
    viewSelection.classList.remove('hidden');
    viewSelection.classList.add('flex');

    viewSelection.classList.remove('animate-fade-in');
    void viewSelection.offsetWidth;
    viewSelection.classList.add('animate-fade-in');
});

btnNextToImportPassword.addEventListener('click', () => {
    viewImportSeed.classList.add('hidden');
    viewImportSeed.classList.remove('flex');
    viewImportPassword.classList.remove('hidden');
    viewImportPassword.classList.add('flex');

    viewImportPassword.classList.remove('animate-slide-up-fade');
    void viewImportPassword.offsetWidth;
    viewImportPassword.classList.add('animate-slide-up-fade');
    
    importPassword1.focus();
});

btnBackToImportSeed.addEventListener('click', () => {
    viewImportPassword.classList.add('hidden');
    viewImportPassword.classList.remove('flex');
    viewImportSeed.classList.remove('hidden');
    viewImportSeed.classList.add('flex');

    viewImportSeed.classList.remove('animate-fade-in');
    void viewImportSeed.offsetWidth;
    viewImportSeed.classList.add('animate-fade-in');
});

headerUnlockBtn.addEventListener('click', () => {
    openModal();
    viewSelection.classList.add('hidden');
    viewSelection.classList.remove('flex');
    viewUnlock.classList.remove('hidden');
    viewUnlock.classList.add('flex');
    unlockPassword.focus();
});

function validateRegistrationForm() {
    const p1 = regPassword1.value;
    const p2 = regPassword2.value;
    const isChecked = regConfirmSaved.checked;
    
    let isValid = true;
    
    if (p1.length > 0 && p1.length < 8) {
        regErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_length');
        regErrorMsg.classList.remove('hidden');
        isValid = false;
    } else if (p1 && p2 && p1 !== p2) {
        regErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_match');
        regErrorMsg.classList.remove('hidden');
        isValid = false;
    } else {
        regErrorMsg.classList.add('hidden');
    }

    if (!p1 || p1.length < 8 || p1 !== p2 || !isChecked) {
        isValid = false;
    }

    doCreateAccountBtn.disabled = !isValid;
}

regPassword1.addEventListener('input', validateRegistrationForm);
regPassword2.addEventListener('input', validateRegistrationForm);
regConfirmSaved.addEventListener('change', validateRegistrationForm);

regPassword1.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        if (regPassword1.value.length >= 8) {
            if (!regPassword2.value || regPassword1.value !== regPassword2.value) {
                regPassword2.focus();
            } else if (!doCreateAccountBtn.disabled) {
                doCreateAccountBtn.click();
            }
        }
    }
});

regPassword2.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !doCreateAccountBtn.disabled) {
        e.preventDefault();
        doCreateAccountBtn.click();
    }
});

function validateImportSeedForm() {
    const active = activeSeedInputs();
    const words = active.map(item => item.input.value.trim().toLowerCase());
    const allFilled = words.every(w => w.length > 0);
    
    if (allFilled) {
        const mnemonic = words.join(' ');
        if (validateMnemonic(mnemonic, wordlist)) {
            btnNextToImportPassword.disabled = false;
            importSeedErrorMsg.classList.add('hidden');
            seedInputs.forEach(item => item.input.classList.remove('border-red-500/50'));
        } else {
            btnNextToImportPassword.disabled = true;
            importSeedErrorMsg.classList.remove('hidden');
            active.forEach(item => item.input.classList.add('border-red-500/50'));
        }
    } else {
        btnNextToImportPassword.disabled = true;
        importSeedErrorMsg.classList.add('hidden');
        seedInputs.forEach(item => item.input.classList.remove('border-red-500/50'));
    }
}

seedInputs[0].input.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text');
    const words = text.trim().split(/\s+/).filter(w => w.length > 0);
    
    if (words.length > 0) {
        // A whole phrase decides how many boxes there are; part of one fills what is shown.
        if (SEED_LENGTHS.includes(words.length)) {
            setSeedLength(words.length);
        } else if (words.length > seedLength) {
            setSeedLength(24);
        }
        for (let i = 0; i < Math.min(words.length, seedLength); i++) {
            seedInputs[i].input.value = words[i].toLowerCase();
        }
        validateImportSeedForm();
        
        if (words.length < seedLength) {
            seedInputs[words.length].input.focus();
        } else {
            btnNextToImportPassword.focus();
        }
    }
});

seedInputs.forEach(({ input, wrapper }, index) => {
    const suggestionBox = input.nextElementSibling;
    let currentFocus = -1;

    const closeSuggestions = () => {
        suggestionBox.classList.add('hidden');
        suggestionBox.innerHTML = '';
    };

    const selectWord = (word) => {
        input.value = word;
        closeSuggestions();
        validateImportSeedForm();
        
        if (index < seedLength - 1) {
            seedInputs[index + 1].input.focus();
        } else {
            input.blur();
            btnNextToImportPassword.focus();
        }
    };

    input.addEventListener('input', function() {
        let val = this.value.replace(/\s+/g, '').toLowerCase(); 
        this.value = val;
        validateImportSeedForm();
        
        closeSuggestions();
        if (!val) return;

        const matches = wordlist.filter(w => w.startsWith(val)).slice(0, 4);
        if (matches.length === 0) return;

        currentFocus = 0;
        suggestionBox.classList.remove('hidden');

        matches.forEach((match, i) => {
            const li = document.createElement('li');
            li.className = `px-3 py-1.5 text-sm cursor-pointer transition-colors rounded-md ${i === currentFocus ? 'bg-purple-600 text-white font-medium' : 'text-white/80 hover:bg-white/10'}`;
            li.innerHTML = `<span class="text-white">${match.substring(0, val.length)}</span><span class="text-white/50">${match.substring(val.length)}</span>`;
            li.dataset.word = match;
            
            li.addEventListener('mousedown', (e) => {
                e.preventDefault(); 
                selectWord(match);
            });
            
            suggestionBox.appendChild(li);
        });
    });

    input.addEventListener('keydown', function(e) {
        const items = suggestionBox.querySelectorAll('li');
        
        if (!suggestionBox.classList.contains('hidden') && items.length > 0) {
            if (e.key === 'ArrowDown') {
                currentFocus++;
                if (currentFocus >= items.length) currentFocus = 0;
                updateActive(items);
                e.preventDefault();
            } else if (e.key === 'ArrowUp') {
                currentFocus--;
                if (currentFocus < 0) currentFocus = items.length - 1;
                updateActive(items);
                e.preventDefault();
            } else if (e.key === 'Enter' || e.key === 'Tab') {
                e.preventDefault();
                if (currentFocus > -1) {
                    selectWord(items[currentFocus].dataset.word);
                }
            }
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (index < seedLength - 1) seedInputs[index + 1].input.focus();
            else btnNextToImportPassword.focus();
        }
    });

    function updateActive(items) {
        items.forEach((item, i) => {
            if (i === currentFocus) {
                item.classList.add('bg-purple-600', 'text-white', 'font-medium');
                item.classList.remove('text-white/80', 'hover:bg-white/10');
            } else {
                item.classList.remove('bg-purple-600', 'text-white', 'font-medium');
                item.classList.add('text-white/80', 'hover:bg-white/10');
            }
        });
    }

    input.addEventListener('focus', function() {
        wrapper.classList.add('z-50');
        if (this.value) this.dispatchEvent(new Event('input'));
    });

    input.addEventListener('blur', () => {
        wrapper.classList.remove('z-50');
        closeSuggestions();
    });
});

function validateImportPasswordForm() {
    const p1 = importPassword1.value;
    const p2 = importPassword2.value;
    
    let isValid = true;
    
    if (p1.length > 0 && p1.length < 8) {
        importPwdErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_length');
        importPwdErrorMsg.classList.remove('hidden');
        isValid = false;
    } else if (p1 && p2 && p1 !== p2) {
        importPwdErrorMsg.textContent = t('auth_modal.btn_change_pwd_err_match');
        importPwdErrorMsg.classList.remove('hidden');
        isValid = false;
    } else {
        importPwdErrorMsg.classList.add('hidden');
    }

    if (!p1 || p1.length < 8 || p1 !== p2) {
        isValid = false;
    }

    doImportAccountBtn.disabled = !isValid;
}

importPassword1.addEventListener('input', validateImportPasswordForm);
importPassword2.addEventListener('input', validateImportPasswordForm);

importPassword1.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        if (importPassword1.value.length >= 8) {
            if (!importPassword2.value || importPassword1.value !== importPassword2.value) {
                importPassword2.focus();
            } else if (!doImportAccountBtn.disabled) {
                doImportAccountBtn.click();
            }
        }
    }
});

importPassword2.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !doImportAccountBtn.disabled) {
        e.preventDefault();
        doImportAccountBtn.click();
    }
});

// Iteration count for password-based key derivation of the stored seed. Must stay in sync
// between encryptSeed and decryptSeed: changing it invalidates already-encrypted accounts.
const PBKDF2_ITERATIONS = 600000;

async function encryptSeed(seed, password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256"},
        keyMaterial, {name: "AES-GCM", length: 256}, false, ["encrypt"]
    );
    
    const ciphertext = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv}, key, enc.encode(seed)
    );
    
    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        salt: btoa(String.fromCharCode(...salt)),
        iv: btoa(String.fromCharCode(...iv))
    };
}

async function decryptSeed(encryptedDataStr, password) {
    const encryptedData = JSON.parse(encryptedDataStr);
    const enc = new TextEncoder();
    
    const salt = Uint8Array.from(atob(encryptedData.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(encryptedData.ciphertext), c => c.charCodeAt(0));
    
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
        {name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256"},
        keyMaterial, {name: "AES-GCM", length: 256}, false, ["decrypt"]
    );
    
    const decryptedBuffer = await crypto.subtle.decrypt(
        {name: "AES-GCM", iv}, key, ciphertext
    );
    
    return new TextDecoder().decode(decryptedBuffer);
}

doCreateAccountBtn.addEventListener('click', async () => {
    doCreateAccountBtn.disabled = true;
    createBtnText.innerHTML = `<span class="loader"></span> ${t('auth_modal.btn_create_securing')}`;

    try {
        const seed = regSeedPhrase.value;
        const pwd = regPassword1.value;
        
        const encryptedData = await encryptSeed(seed, pwd);
        
        await walletSession.unlock(seed);
        encryptedData.pubKeyHex = walletSession.getPublicKey();
        
        localStorage.setItem('kerrigan_encrypted_account', JSON.stringify(encryptedData));
        
        setTimeout(() => {
            closeModal();
            checkAuthState();
            createBtnText.textContent = t('auth_modal.btn_create_action');
            doCreateAccountBtn.disabled = false;
            
            if (pendingAction) {
                pendingAction();
                pendingAction = null;
            }
        }, 800);

    } catch (err) {
        console.error("Encryption failed", err);
        showErrorAlert(t('toasts.key_securing_failed'));
        createBtnText.textContent = t('auth_modal.btn_create_action');
        doCreateAccountBtn.disabled = false;
    }
});

doImportAccountBtn.addEventListener('click', async () => {
    doImportAccountBtn.disabled = true;
    importBtnText.innerHTML = `<span class="loader"></span> ${t('auth_modal.btn_import_securing')}`;

    try {
        const mnemonic = activeSeedInputs().map(item => item.input.value.trim().toLowerCase()).join(' ');
        const pwd = importPassword1.value;
        
        const encryptedData = await encryptSeed(mnemonic, pwd);

        await walletSession.unlock(mnemonic);
        encryptedData.pubKeyHex = walletSession.getPublicKey();

        localStorage.setItem('kerrigan_encrypted_account', JSON.stringify(encryptedData));
        
        setTimeout(() => {
            closeModal();
            checkAuthState();
            importBtnText.textContent = t('auth_modal.btn_import_action');
            doImportAccountBtn.disabled = false;
            
            if (pendingAction) {
                pendingAction();
                pendingAction = null;
            }
        }, 800);

    } catch (err) {
        console.error("Encryption failed", err);
        showErrorAlert(t('toasts.import_failed'));
        importBtnText.textContent = t('auth_modal.btn_import_action');
        doImportAccountBtn.disabled = false;
    }
});

doUnlockBtn.addEventListener('click', async () => {
    const pwd = unlockPassword.value;
    if (!pwd) return;

    doUnlockBtn.disabled = true;
    unlockBtnText.innerHTML = `<span class="loader"></span> ${t('auth_modal.btn_unlock_securing')}`;
    unlockErrorMsg.classList.add('hidden');

    try {
        const encryptedDataStr = localStorage.getItem('kerrigan_encrypted_account');
        if (!encryptedDataStr) throw new Error("No account found");
        
        const seed = await decryptSeed(encryptedDataStr, pwd);
        
        await walletSession.unlock(seed);
        
        // Cache pubKeyHex if missing
        const encryptedData = JSON.parse(encryptedDataStr);
        if (!encryptedData.pubKeyHex) {
            encryptedData.pubKeyHex = walletSession.getPublicKey();
            localStorage.setItem('kerrigan_encrypted_account', JSON.stringify(encryptedData));
        }
        
        setTimeout(() => {
            closeModal();
            checkAuthState();
            
            doUnlockBtn.disabled = false;
            unlockBtnText.textContent = t('auth_modal.btn_unlock');
            unlockPassword.value = '';
            
            if (pendingAction) {
                pendingAction();
                pendingAction = null;
            }
        }, 500);

    } catch (err) {
        setTimeout(() => {
            unlockErrorMsg.classList.remove('hidden');
            doUnlockBtn.disabled = false;
            unlockBtnText.textContent = t('auth_modal.btn_unlock');
        }, 500);
    }
});

unlockPassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        doUnlockBtn.click();
    }
});

function resetUIState() {
    // Reset search fields and validation states
    input.value = '';
    if (resultMessage) {
        resultMessage.style.opacity = '0';
        resultMessage.innerHTML = '';
    }
    
    targetAddressInput.value = '';
    addressErrorMsg.classList.add('hidden');
    if (typeof btnNextToPayment !== 'undefined' && btnNextToPayment) {
        btnNextToPayment.disabled = true;
    }
    
    // Clear status intervals
    if (pollInterval) clearInterval(pollInterval);
    if (countdownInterval) clearInterval(countdownInterval);
    
    // Reset state & view
    currentTransactionType = "REG";
    setupSlide2Inputs();
    const payAddressGroup = document.getElementById('payAddressGroup');
    if (payAddressGroup) payAddressGroup.classList.remove('hidden');
    
    // Clear user private name list contents
    const grid = document.getElementById('myNamesPageGrid');
    if (grid) {
        grid.innerHTML = '';
        grid.classList.add('hidden');
        grid.classList.remove('flex', 'flex-col');
    }
    
    // Clear pagination displays
    document.querySelectorAll('.my-names-pagination-top, .my-names-pagination-bottom').forEach(el => el.innerHTML = '');
    
    // Clear balance fields
    const balanceValueEl = document.getElementById('balanceValue');
    if (balanceValueEl) {
        balanceValueEl.textContent = '0';
    }
    const withdrawFeeBlock = document.getElementById('withdrawFeeBlock');
    if (withdrawFeeBlock) {
        withdrawFeeBlock.classList.add('hidden');
    }
    const withdrawAddressInput = document.getElementById('withdrawAddressInput');
    if (withdrawAddressInput) {
        withdrawAddressInput.value = '';
        withdrawAddressInput.classList.remove('border-red-500');
    }
    const withdrawAddressErrorMsg = document.getElementById('withdrawAddressErrorMsg');
    if (withdrawAddressErrorMsg) {
        withdrawAddressErrorMsg.classList.add('hidden');
    }
    const withdrawBlock = document.getElementById('withdrawBlock');
    if (withdrawBlock) {
        withdrawBlock.classList.add('opacity-40', 'pointer-events-none');
    }
    const withdrawBtn = document.getElementById('withdrawBtn');
    if (withdrawBtn) {
        withdrawBtn.disabled = true;
    }
    
    // Navigate back to landing screen
    switchTab('register');
    setActiveSlide(slide1, 'translateX(0)');
    setStep('check');
}

const logoutHandler = () => {
    localStorage.removeItem('kerrigan_encrypted_account');
    walletSession.lock();
    checkAuthState();
    resetUIState();
    resetModalViews();
};

headerLogoutBtn.addEventListener('click', logoutHandler);
headerLockedLogoutBtn.addEventListener('click', logoutHandler);

// Setup Password Toggle Functionality
document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', function(e) {
        e.preventDefault(); 
        const input = this.previousElementSibling;
        const eyeIcon = this.querySelector('.eye-icon');
        const eyeOffIcon = this.querySelector('.eye-off-icon');
        
        if (input.type === 'password') {
            input.type = 'text';
            eyeIcon.classList.add('hidden');
            eyeOffIcon.classList.remove('hidden');
        } else {
            input.type = 'password';
            eyeIcon.classList.remove('hidden');
            eyeOffIcon.classList.add('hidden');
        }
        
        input.focus(); 
    });
});

// Initialize Localization Framework immediately on script load
const localizationReady = initLocalization();

// --- TABS & MARKETPLACE CONTROLLER LOGIC ---

let cachedPrices = null;
// The protocol payment address, served by the registrar from INCOME_WALLET. Held for the
// lifetime of the page with no TTL, unlike prices: rotating it is a deployment-level event,
// and a tab that kept an old address would send funds somewhere no longer scanned - so the
// value is fetched once and reused rather than refreshed on a timer.
// The in-flight promise is what gets cached, not the resolved value: the startup fill and
// a user opening the QR modal can overlap, and caching the promise makes the second caller
// join the first request instead of issuing its own. Cleared on failure so a later attempt
// can retry rather than replaying the rejection forever.
let cachedPayAddress = null;

// The zones a name can be registered in, without the dot. The registrar serves them from
// getPaymentAddress (see applyProtocolZones); this built-in list stands until it answers, and
// for a registrar too old to send them.
const BUILTIN_ZONES = ['kerrigan', 'krgn', 'private', 'secure', 'safe'];
let protocolZones = BUILTIN_ZONES;
// The most items the registrar returns per list page, also from getPaymentAddress. The page
// sizes below are well under its usual limit, so this only matters to a registrar set lower.
let apiMaxCount = Infinity;

function fetchPaymentAddress() {
    if (cachedPayAddress) return cachedPayAddress;

    cachedPayAddress = (async () => {
        const response = await fetch(`${API_BASE_URL}/v1.0/getPaymentAddress`);
        if (!response.ok) throw new Error("Failed to fetch the payment address");

        const data = await response.json();
        const address = data?.response?.address;
        if (typeof address !== 'string' || address === '') throw new Error("Invalid payment address format");

        // Adopt the network the registrar reports, so client-side address validation is
        // driven by the deployment rather than a hardcoded guess. An unrecognised value is
        // ignored rather than trusted: falling back to the mainnet default is safer than
        // validating against rules nobody defined.
        const network = data?.response?.network;
        if (network === 'mainnet' || network === 'testnet') {
            kerriganNetwork = network;
        } else if (network !== undefined) {
            console.warn(`Registrar reported an unknown network "${network}"; keeping ${kerriganNetwork}`);
        }

        // The confirmation counts the registrar actually waits for. Anything but a positive
        // integer is ignored, keeping the fallback.
        const paymentConfs = data?.response?.payment_confirmations;
        if (Number.isInteger(paymentConfs) && paymentConfs > 0) {
            PAYMENT_CONFIRMATIONS = paymentConfs;
        }
        const refundConfs = data?.response?.refund_confirmations;
        if (Number.isInteger(refundConfs) && refundConfs > 0) {
            REFUND_CONFIRMATIONS = refundConfs;
        }
        const chainLockConfs = data?.response?.chainlock_confirmations;
        if (Number.isInteger(chainLockConfs) && chainLockConfs > 0) {
            CHAINLOCK_CONFIRMATIONS = chainLockConfs;
        }

        // The zones a name can be registered in, and the most items a list returns per
        // page. A registrar from before they were served keeps the built-in values, and so
        // does a malformed answer.
        const zones = data?.response?.zones;
        if (Array.isArray(zones) && zones.length > 0 && zones.every(z => typeof z === 'string' && /^[a-z]+$/.test(z))) {
            applyProtocolZones(zones);
        }
        const maxCount = data?.response?.max_count;
        if (Number.isInteger(maxCount) && maxCount > 0) {
            apiMaxCount = maxCount;
        }

        return address;
    })().catch((err) => {
        cachedPayAddress = null;
        throw err;
    });

    return cachedPayAddress;
}

// Every payment panel - registration, marketplace purchase, ultimatum - reuses the same
// #payAddress field, so filling it once at startup covers all of them.
//
// The request is issued immediately, in parallel with localization; only the failure
// message waits on it, since t() falls back to the raw key when no language is loaded yet.
async function initPaymentAddress(localizationReady) {
    const addressField = document.getElementById('payAddress');
    if (!addressField) return;
    try {
        addressField.value = await fetchPaymentAddress();
    } catch (err) {
        console.error("Payment address fetch failed:", err);
        addressField.value = '';
        await localizationReady;
        addressField.placeholder = t('errors.request_failed');
    }
}

// Invoked here rather than beside initLocalization() above: cachedPayAddress is a `let`,
// so calling any earlier would read it inside its temporal dead zone and throw.
initPaymentAddress(localizationReady);

let cachedPricesFetchedAt = 0;
const PRICES_CACHE_TTL_MS = 5 * 60 * 1000; // re-fetch periodically so a long-lived tab doesn't act on stale pricing

async function fetchPrices() {
    if (cachedPrices && (Date.now() - cachedPricesFetchedAt) < PRICES_CACHE_TTL_MS) return cachedPrices;
    try {
        const response = await fetch(`${API_BASE_URL}/v1.0/prices`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: "upd" })
        });
        if (!response.ok) throw new Error("Failed to fetch prices");
        const data = await response.json();
        if (data && data.response) {
            cachedPrices = {};
            for (const key in data.response) {
                const satoshiVal = parseFloat(data.response[key]);
                cachedPrices[key] = parseFloat((satoshiVal / 100000000).toFixed(8)).toString();
            }
            cachedPricesFetchedAt = Date.now();
            return cachedPrices;
        } else {
            throw new Error("Invalid prices format");
        }
    } catch (err) {
        console.error("Prices fetch failed:", err);
        showErrorAlert(t('errors.request_failed'));
        throw err;
    }
}

function getUpdPriceForDomain(domain, prices) {
    const dotIdx = domain.indexOf('.');
    const label = dotIdx !== -1 ? domain.substring(0, dotIdx) : domain;
    const len = label.length;
    
    const keys = Object.keys(prices).map(Number).sort((a, b) => a - b);
    if (keys.length === 0) return "0";
    
    const maxKey = keys[keys.length - 1];
    const keyToUse = len >= maxKey ? maxKey : len;
    
    return (prices[keyToUse.toString()] || "0").toString();
}

// What an update, transfer, listing or unlisting of `domain` costs, in KRGN. The registrar
// serves it with each name (`tx_price` in the lists, `update_price` from check), so its own
// label-length rule decides; the price table and the copy of that rule above are only for a
// registrar too old to serve it.
async function updPriceFor(domain, txPriceSats) {
    if (Number.isInteger(txPriceSats) && txPriceSats > 0) return formatSats(txPriceSats);
    return getUpdPriceForDomain(domain, await fetchPrices());
}

// Page sizes are shared between each list's fetch payload and its pagination maths; keeping
// them in one place stops the two from drifting apart and mis-numbering the pages.
const MARKETPLACE_PAGE_SIZE = 20;
const MY_NAMES_PAGE_SIZE = 20;
const TRANSACTIONS_PAGE_SIZE = 10;

let currentActiveTab = 'register'; // 'register', 'marketplace', or 'my_names'
let currentMarketpage = 1;
let currentMarketSearch = "";
let currentMyNamesSearch = "";
let marketRequestId = 0; // guards against a stale/overlapping fetch overwriting a newer page's results
// Where each marketplace page starts, by page number: the `next` the page before it returned.
// Asking from there rather than by offset keeps the pages from shifting while listings come and
// go, so stepping forward never shows a name twice or skips one. A page with no entry, e.g. one
// jumped to, is asked for by number. Valid only for the search and filters it was taken under,
// so it is cleared whenever they change.
const marketCursors = new Map();

const tabRegister = document.getElementById('tabRegister');
const tabMarketplace = document.getElementById('tabMarketplace');
const registerView = document.getElementById('registerView');
const marketplaceView = document.getElementById('marketplaceView');

function getCachedPublicKey() {
    if (walletSession && walletSession.isUnlocked()) {
        return walletSession.getPublicKey();
    }
    const accountStr = localStorage.getItem('kerrigan_encrypted_account');
    if (accountStr) {
        try {
            const data = JSON.parse(accountStr);
            if (data.pubKeyHex) return data.pubKeyHex;
        } catch (e) {
            console.error("Error parsing encrypted account", e);
        }
    }
    return null;
}

function switchTab(tab) {
    if (currentActiveTab === tab) return;
    
    if (currentActiveTab === 'register' && tab !== 'register') {
        resetRegistrationFlow();
    }

    // A list's filters last only while its screen is shown: back on it, it starts unfiltered.
    if (currentActiveTab === 'marketplace') {
        marketFilterWidget.reset();
    } else if (currentActiveTab === 'my_names') {
        myNamesFilterWidget.reset();
    }

    currentActiveTab = tab;

    const heroSubtitle = document.getElementById('heroSubtitle');
    const myNamesView = document.getElementById('myNamesView');
    const onboardingLinkContainer = document.getElementById('onboardingLinkContainer');
    const transactionsView = document.getElementById('transactionsView');
    const mainViewSelector = document.getElementById('mainViewSelector');
    const transactionsViewSelector = document.getElementById('transactionsViewSelector');
    const heroTitle = document.getElementById('heroTitle');

    if (tab === 'register') {
        tabRegister.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-white bg-purple-600 shadow-lg shadow-purple-900/30';
        tabMarketplace.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        
        registerView.classList.remove('hidden');
        registerView.classList.add('flex');
        marketplaceView.classList.add('hidden');
        marketplaceView.classList.remove('flex');
        if (myNamesView) {
            myNamesView.classList.add('hidden');
            myNamesView.classList.remove('flex');
        }
        if (transactionsView) {
            transactionsView.classList.add('hidden');
            transactionsView.classList.remove('flex', 'flex-col');
        }
        
        if (heroTitle) {
            heroTitle.classList.remove('hidden');
        }
        if (heroSubtitle) {
            heroSubtitle.setAttribute('data-i18n', 'hero.subtitle');
            heroSubtitle.textContent = t('hero.subtitle');
            heroSubtitle.classList.remove('mb-10');
            heroSubtitle.classList.add('mb-2');
        }
        if (onboardingLinkContainer) {
            onboardingLinkContainer.classList.remove('hidden');
        }
        if (mainViewSelector) {
            mainViewSelector.classList.remove('hidden');
            mainViewSelector.classList.add('flex');
        }
        if (transactionsViewSelector) {
            transactionsViewSelector.classList.add('hidden');
            transactionsViewSelector.classList.remove('flex');
        }

        // Trigger height observer update on sliderWrapper
        sliderWrapper.style.height = activeSlideElement.offsetHeight + 'px';
    } else if (tab === 'marketplace') {
        tabMarketplace.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-white bg-purple-600 shadow-lg shadow-purple-900/30';
        tabRegister.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        
        marketplaceView.classList.remove('hidden');
        marketplaceView.classList.add('flex');
        registerView.classList.add('hidden');
        registerView.classList.remove('flex');
        if (myNamesView) {
            myNamesView.classList.add('hidden');
            myNamesView.classList.remove('flex');
        }
        if (transactionsView) {
            transactionsView.classList.add('hidden');
            transactionsView.classList.remove('flex', 'flex-col');
        }
        
        if (heroTitle) {
            heroTitle.classList.remove('hidden');
        }
        if (heroSubtitle) {
            heroSubtitle.setAttribute('data-i18n', 'hero.subtitle_marketplace');
            heroSubtitle.textContent = t('hero.subtitle_marketplace');
            heroSubtitle.classList.remove('mb-2');
            heroSubtitle.classList.add('mb-10');
        }
        if (onboardingLinkContainer) {
            onboardingLinkContainer.classList.add('hidden');
        }
        if (mainViewSelector) {
            mainViewSelector.classList.remove('hidden');
            mainViewSelector.classList.add('flex');
        }
        if (transactionsViewSelector) {
            transactionsViewSelector.classList.add('hidden');
            transactionsViewSelector.classList.remove('flex');
        }

        // Reset sliderWrapper height constraint
        sliderWrapper.style.height = 'auto';
        
        // Load marketplace domains
        currentMarketpage = 1;
        marketCursors.clear();
        loadMarketplaceDomains(currentMarketpage, currentMarketSearch);
    } else if (tab === 'my_names') {
        tabRegister.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        tabMarketplace.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        
        registerView.classList.add('hidden');
        registerView.classList.remove('flex');
        marketplaceView.classList.add('hidden');
        marketplaceView.classList.remove('flex');
        if (myNamesView) {
            myNamesView.classList.remove('hidden');
            myNamesView.classList.add('flex');
        }
        if (transactionsView) {
            transactionsView.classList.add('hidden');
            transactionsView.classList.remove('flex', 'flex-col');
        }
        
        if (heroTitle) {
            heroTitle.classList.remove('hidden');
        }
        if (heroSubtitle) {
            heroSubtitle.setAttribute('data-i18n', 'my_names_page.desc');
            heroSubtitle.textContent = t('my_names_page.desc');
            heroSubtitle.classList.remove('mb-2');
            heroSubtitle.classList.add('mb-10');
        }
        if (onboardingLinkContainer) {
            onboardingLinkContainer.classList.add('hidden');
        }
        if (mainViewSelector) {
            mainViewSelector.classList.remove('hidden');
            mainViewSelector.classList.add('flex');
        }
        if (transactionsViewSelector) {
            transactionsViewSelector.classList.add('hidden');
            transactionsViewSelector.classList.remove('flex');
        }

        // Reset sliderWrapper height constraint
        sliderWrapper.style.height = 'auto';
        
        // Load my names
        currentMyNamesPage = 1;
        loadMyNamesList(currentMyNamesPage, currentMyNamesSearch);
    } else if (tab === 'my_transactions') {
        tabRegister.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        tabMarketplace.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        
        registerView.classList.add('hidden');
        registerView.classList.remove('flex');
        marketplaceView.classList.add('hidden');
        marketplaceView.classList.remove('flex');
        if (myNamesView) {
            myNamesView.classList.add('hidden');
            myNamesView.classList.remove('flex');
        }
        if (transactionsView) {
            transactionsView.classList.remove('hidden');
            transactionsView.classList.add('flex', 'flex-col');
        }
        
        if (heroTitle) {
            heroTitle.classList.add('hidden');
        }
        if (heroSubtitle) {
            heroSubtitle.setAttribute('data-i18n', 'transactions.hero_subtitle');
            heroSubtitle.textContent = t('transactions.hero_subtitle');
            heroSubtitle.classList.remove('mb-2');
            heroSubtitle.classList.add('mb-10');
        }
        if (onboardingLinkContainer) {
            onboardingLinkContainer.classList.add('hidden');
        }
        if (mainViewSelector) {
            mainViewSelector.classList.add('hidden');
            mainViewSelector.classList.remove('flex');
        }
        if (transactionsViewSelector) {
            transactionsViewSelector.classList.remove('hidden');
            transactionsViewSelector.classList.add('flex');
        }

        // Reset sliderWrapper height constraint
        sliderWrapper.style.height = 'auto';
        
        // Load incoming transactions list by default
        currentTransactionsTab = "in";
        currentTransactionsPage = 1;
        
        const tabIncoming = document.getElementById('tabIncoming');
        const tabRefunds = document.getElementById('tabRefunds');
        if (tabIncoming && tabRefunds) {
            tabIncoming.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-white bg-purple-600 shadow-lg shadow-purple-900/30';
            tabRefunds.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        }
        
        const subTitleText = document.getElementById('transactionsSubTitleText');
        if (subTitleText) {
            subTitleText.setAttribute('data-i18n', 'transactions.incoming_title');
            subTitleText.textContent = t('transactions.incoming_title');
        }
        
        loadTransactionsList(currentTransactionsPage);
    }
}

if (tabRegister && tabMarketplace) {
    tabRegister.addEventListener('click', () => switchTab('register'));
    tabMarketplace.addEventListener('click', () => switchTab('marketplace'));
}

async function loadMarketplaceDomains(page, search = "") {
    const marketLoading = document.getElementById('marketLoading');
    const marketError = document.getElementById('marketError');
    const marketEmpty = document.getElementById('marketEmpty');
    const marketDomainGrid = document.getElementById('marketDomainGrid');
    
    if (!marketLoading || !marketError || !marketEmpty || !marketDomainGrid) return;

    const requestId = ++marketRequestId;

    // Show loading
    marketLoading.classList.remove('hidden');
    marketLoading.classList.add('flex');
    marketError.classList.add('hidden');
    marketError.classList.remove('flex');
    marketEmpty.classList.add('hidden');
    marketEmpty.classList.remove('flex');
    marketDomainGrid.classList.add('hidden');
    marketDomainGrid.classList.remove('flex', 'flex-col');
    
    // Clear pagination displays
    document.querySelectorAll('.market-pagination-top, .market-pagination-bottom').forEach(el => el.innerHTML = '');

    try {
        const userPubKey = getCachedPublicKey();
        const pageSize = Math.min(MARKETPLACE_PAGE_SIZE, apiMaxCount);
        const payload = {
            type: "marketplace",
            page: page,
            count: pageSize
        };
        if (listOptionsSupported) {
            // The registrar returns the owner of every listing, so the user's own ones are told
            // apart here and the key never has to leave the device.
            payload.sort = marketFilters.sort;
            payload.order = marketFilters.order;
            payload.zone = marketFilters.zone;
            const after = marketCursors.get(page);
            if (after) {
                payload.after = after;
            }
        } else if (userPubKey) {
            // A registrar from before the options returns owners only to a client sending its key.
            payload.pubkey = userPubKey;
        }
        if (search) {
            payload.search = search;
        }

        const response = await fetch(`${API_BASE_URL}/v1.0/domains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        let data;
        try {
            data = await response.json();
        } catch (jsonErr) {
            // Not JSON
        }

        if (requestId !== marketRequestId) return; // a newer request has since superseded this one

        if (data && data.error && data.error.error_message) {
            throw new Error(data.error.error_message);
        }

        if (!response.ok) throw new Error("Network response was not OK");

        // A registrar that knows the options echoes the ones it applied. One from before drops
        // them without a word, and returns owners only for a key it is sent: ask it again the
        // old way, with the filters gone, as they would change nothing.
        if (listOptionsSupported && data && data.response && data.response.sort === undefined) {
            disableListOptions();
            return loadMarketplaceDomains(page, search);
        }

        if (data && data.response) {
            if (typeof data.response.next === 'string' && data.response.next !== '') {
                marketCursors.set(page + 1, data.response.next);
            } else {
                marketCursors.delete(page + 1);
            }
        }

        // A page past the first that came back empty: the list got shorter under the user
        // (listings sold or withdrawn) since its page count was shown. Start over at the top.
        if (page > 1 && data && data.response && Array.isArray(data.response.domains) && data.response.domains.length === 0) {
            currentMarketpage = 1;
            marketCursors.clear();
            return loadMarketplaceDomains(currentMarketpage, search);
        }

        marketLoading.classList.add('hidden');
        marketLoading.classList.remove('flex');

        if (!data.response || !data.response.domains || data.response.domains.length === 0) {
            const emptyText = marketEmpty.querySelector('p');
            const emptyBtn = document.getElementById('marketEmptyActionBtn');
            if (search || isListFilterActive(marketFilters)) {
                if (emptyText) {
                    emptyText.setAttribute('data-i18n', 'marketplace.no_results');
                    emptyText.textContent = t('marketplace.no_results');
                }
                if (emptyBtn) emptyBtn.classList.add('hidden');
            } else {
                if (emptyText) {
                    emptyText.setAttribute('data-i18n', 'marketplace.no_results_empty');
                    emptyText.textContent = t('marketplace.no_results_empty');
                }
                if (emptyBtn) {
                    emptyBtn.setAttribute('data-i18n', 'marketplace.empty_action_sell');
                    emptyBtn.textContent = t('marketplace.empty_action_sell');
                    emptyBtn.classList.remove('hidden');
                }
            }
            marketEmpty.classList.remove('hidden');
            marketEmpty.classList.add('flex');
            return;
        }

        const totalCount = data.response.count || 0;
        const domains = data.response.domains;

        // Render Cards
        marketDomainGrid.innerHTML = '';
        domains.forEach(d => {
            const domainCard = document.createElement('div');

            const zoneClass = zoneBadgeClass(d.domain);

            const zoneName = d.domain.substring(d.domain.lastIndexOf('.'));
            const safeDomain = escapeHtml(d.domain);
            const safeZoneName = escapeHtml(zoneName);

            const priceZec = parseFloat(d.price) / 100000000;
            const priceFormatted = parseFloat(priceZec.toFixed(8)).toString();
            const formattedPrice = priceFormatted;

            const isOwnDomain = userPubKey && d.pubkey && (d.pubkey.toLowerCase() === userPubKey.toLowerCase());

            let actionButton = '';
            if (isOwnDomain) {
                // What changing or withdrawing the listing costs, in satoshi; empty when the
                // registrar didn't say, which leaves it to the price table.
                const txPriceSats = Number.isInteger(d.tx_price) ? d.tx_price : '';
                actionButton = `
                    <div class="flex flex-col gap-2 w-full">
                        <button class="change-price-btn w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-2.5 px-4 rounded-lg text-xs transition-all flex items-center justify-center gap-1.5 active:scale-95" data-domain="${safeDomain}" data-tx-price="${txPriceSats}">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                            <span data-i18n="my_names_actions.change_price">Change Sell Price</span>
                        </button>
                        <button class="remove-sale-btn w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-2.5 px-4 rounded-lg text-xs transition-all flex items-center justify-center gap-1.5 active:scale-95" data-domain="${safeDomain}" data-tx-price="${txPriceSats}">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                            <span data-i18n="marketplace.remove_sale">Unlist from sale</span>
                        </button>
                    </div>
                `;
            } else {
                actionButton = `
                    <button class="buy-domain-btn w-full bg-green-600 hover:bg-green-500 text-white font-bold py-2.5 px-4 rounded-lg text-xs transition-all flex items-center justify-center gap-1.5 active:scale-95" data-domain="${safeDomain}" data-price="${priceFormatted}">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                        <span data-i18n="marketplace.buy_domain">Buy Domain</span>
                    </button>
                `;
            }

            domainCard.className = 'market-card bg-white/5 border border-white/10 rounded-2xl p-4 sm:p-5 flex flex-col justify-between gap-3 text-left';
            domainCard.innerHTML = `
                <div class="flex items-start justify-between gap-2">
                    <span class="font-bold text-white text-base sm:text-lg break-all flex-1">${safeDomain}</span>
                    <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${zoneClass}">${safeZoneName}</span>
                </div>
                <div class="flex flex-col gap-3">
                    <div class="flex items-baseline justify-between border-t border-white/5 pt-3">
                        <span class="text-purple-200/50 text-[11px] font-semibold uppercase tracking-wider" data-i18n="address.price_label">${t('address.price_label')}</span>
                        <span class="text-white text-sm sm:text-base font-bold">${formattedPrice} <span class="text-xs text-purple-300">KRGN</span></span>
                    </div>
                    ${actionButton}
                </div>
            `;
            
            marketDomainGrid.appendChild(domainCard);
        });

        // Set up click handlers for card actions
        marketDomainGrid.querySelectorAll('.buy-domain-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const domain = btn.getAttribute('data-domain');
                const price = btn.getAttribute('data-price');
                handleBuyDomain(domain, price);
            });
        });

        marketDomainGrid.querySelectorAll('.change-price-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const domain = btn.getAttribute('data-domain');
                handleMyNameList(domain, Number(btn.getAttribute('data-tx-price')));
            });
        });

        marketDomainGrid.querySelectorAll('.remove-sale-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const domain = btn.getAttribute('data-domain');
                handleRemoveFromSale(domain, Number(btn.getAttribute('data-tx-price')));
            });
        });

        marketDomainGrid.classList.remove('hidden');
        marketDomainGrid.classList.add('flex', 'flex-col');

        // Apply dynamic translation update to elements we just rendered
        applyTranslations();

        // Render top/bottom pagination
        renderMarketPagination(totalCount, pageSize);

    } catch (err) {
        if (requestId !== marketRequestId) return; // a newer request has since superseded this one
        console.error("Marketplace fetch error:", err);
        marketLoading.classList.add('hidden');
        marketLoading.classList.remove('flex');

        if (marketSearchError && err.message && err.message !== "Network response was not OK") {
            marketSearchError.style.opacity = '1';
            marketSearchError.innerHTML = `
                <div class="mt-2 flex w-full">
                    <span class="text-red-400 flex items-start gap-1.5 min-w-0">
                        <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> 
                        <span class="min-w-0 break-words">${escapeHtml(err.message)}</span>
                    </span>
                </div>
            `;
        } else {
            marketError.classList.remove('hidden');
            marketError.classList.add('flex');
        }
    }
}

function handleBuyDomain(domain, price) {
    showConfirm(t('marketplace.buy_domain'), t('marketplace.buy_action_confirm', { domain, price }), () => {
        // Redirect to registration checkout
        switchTab('register');
        
        currentRegistrationDomain = domain;
        currentRegistrationPrice = price;
        currentTransactionType = "BUY";
        setupSlide2Inputs();
        
        // Restore destination address field visibility
        document.getElementById('payAddressGroup').classList.remove('hidden');
        
        // Fill input
        const dotIndex = domain.indexOf('.');
        const namePart = domain.substring(0, dotIndex);
        const zonePart = domain.substring(dotIndex);
        
        input.value = namePart;
        domainZoneSelect.value = zonePart;
        
        setActiveSlide(slideAddress, 'translateX(-100%)');
        setStep('check');
        
        targetAddressInput.value = '';
        targetAddressInput.dispatchEvent(new Event('input'));
        
        window.showToast(t('marketplace.buy_success', { domain }));
    }, () => {});
}

async function handleRemoveFromSale(domain, txPriceSats) {
    try {
        const determinedPrice = await updPriceFor(domain, txPriceSats);
        
        showConfirm(t('marketplace.remove_sale'), t('marketplace.remove_action_confirm'), () => {
            const proceedRemoval = async () => {
                try {
                    const userPubKey = getCachedPublicKey();
                    const nonce = Math.floor(Date.now() / 1000);
                    
                    // Memo format: KNS:1:ULT:{domain_name}:{pubkey}:{nonce}
                    const baseMemo = `${protocolMarker()}:1:ULT:${domain}:${userPubKey}:${nonce}`;
                    const sig = await walletSession.sign(baseMemo);
                    
                    // Full memo format: KNS:1:ULT:{domain_name}:{pubkey}:{nonce}:{signature}
                    const fullMemo = `${baseMemo}:${sig}`;
                    
                    // Pre-fill Payment details (Slide 3)
                    payMemoInput.value = fullMemo;
                    document.getElementById('payAmount').value = determinedPrice;
                    
                    // Set transaction type
                    currentTransactionType = "ULT";
                    currentRegistrationDomain = domain;
                    
                    // Dynamic payment title
                    const paymentTitle = document.getElementById('paymentTitle');
                    if (paymentTitle) {
                        paymentTitle.setAttribute('data-i18n', 'payment.title_process');
                        paymentTitle.textContent = t('payment.title_process');
                    }
                    
                    // Redirect and navigate directly to step 3 (pay)
                    switchTab('register');
                    setActiveSlide(slidePayment, 'translateX(-200%)');
                    setStep('pay');
                } catch (err) {
                    console.error("Removal signature failed:", err);
                    showErrorAlert(t('toasts.sign_failed'));
                }
            };

            if (!localStorage.getItem('kerrigan_encrypted_account')) {
                pendingAction = proceedRemoval;
                openModal(); 
            } else if (!walletSession.isUnlocked()) {
                pendingAction = proceedRemoval;
                headerUnlockBtn.click();
            } else {
                proceedRemoval();
            }
        }, () => {});
    } catch (err) {
        console.error("Unlist setup failed:", err);
    }
}

// --- SHARED PAGINATION RENDERER ---

const PAGINATION_ARROW_CLASS = 'pagination-btn px-2.5 py-1.5 bg-white/5 border border-white/10 hover:bg-white/10 rounded-lg text-purple-300 font-semibold disabled:opacity-30 disabled:pointer-events-none transition-colors';
const PAGINATION_PAGE_WINDOW = 5; // how many numbered buttons to show at once

// Renders the prev / numbered / next control into every container matching `selector`.
// The marketplace, my-names and transactions views all share this widget and differ only in
// their container, page size, page-state variable and the loader to call, so those are passed in.
function renderPagination({ selector, totalCount, pageSize, getPage, setPage, reload }) {
    const totalPages = Math.ceil(totalCount / pageSize);

    document.querySelectorAll(selector).forEach(container => {
        container.innerHTML = '';
        if (totalPages <= 1) return;

        const currentPage = getPage();
        const goTo = (page) => { setPage(page); reload(); };

        const addArrow = (label, targetPage, isDisabled) => {
            const btn = document.createElement('button');
            btn.className = PAGINATION_ARROW_CLASS;
            btn.textContent = label;
            btn.disabled = isDisabled;
            btn.addEventListener('click', () => goTo(targetPage));
            container.appendChild(btn);
        };

        addArrow('<', currentPage - 1, currentPage === 1);

        // Keep the current page roughly centred in a fixed-size window of page numbers
        let startPage = Math.max(1, currentPage - 2);
        let endPage = Math.min(totalPages, startPage + PAGINATION_PAGE_WINDOW - 1);
        if (endPage - startPage < PAGINATION_PAGE_WINDOW - 1) {
            startPage = Math.max(1, endPage - (PAGINATION_PAGE_WINDOW - 1));
        }

        for (let i = startPage; i <= endPage; i++) {
            const pageBtn = document.createElement('button');
            pageBtn.className = `pagination-btn px-3 py-1.5 border rounded-lg font-bold transition-all ${i === currentPage ? 'active' : 'bg-white/5 border-white/10 text-purple-300'}`;
            pageBtn.textContent = i;
            pageBtn.addEventListener('click', () => goTo(i));
            container.appendChild(pageBtn);
        }

        addArrow('>', currentPage + 1, currentPage === totalPages);
    });
}

function renderMarketPagination(totalCount, pageSize) {
    renderPagination({
        selector: '.market-pagination-top, .market-pagination-bottom',
        totalCount,
        pageSize,
        getPage: () => currentMarketpage,
        setPage: (page) => { currentMarketpage = page; },
        reload: () => loadMarketplaceDomains(currentMarketpage, currentMarketSearch)
    });
}

// Search Logic
const marketSearchInput = document.getElementById('marketSearchInput');
const marketSearchClearBtn = document.getElementById('marketSearchClearBtn');
const marketSearchBtn = document.getElementById('marketSearchBtn');
const marketSearchError = document.getElementById('marketSearchError');

// The marketplace and my-names search widgets are behaviourally identical: same input
// sanitising, same inline validation message, same clear button and Enter-to-search. This
// binder wires one of them up and returns its trigger function.
function bindSearchWidget({ input, clearBtn, searchBtn, errorEl, onSearch }) {
    // The fade-out below empties the message 300ms later. That timer must be cancellable:
    // otherwise typing and then immediately searching lets the stale timer wipe the freshly
    // shown validation message, leaving a visible but empty error area.
    let pendingErrorClear = null;
    const cancelPendingClear = () => {
        if (pendingErrorClear !== null) {
            clearTimeout(pendingErrorClear);
            pendingErrorClear = null;
        }
    };

    const showInvalidName = () => {
        if (!errorEl) return;
        cancelPendingClear();
        errorEl.style.opacity = '1';
        errorEl.innerHTML = `
            <div class="mt-2 flex w-full">
                <span class="text-red-400 flex items-start gap-1.5 min-w-0">
                    <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span class="min-w-0 break-words">${t('search.invalid_search_error')}</span>
                </span>
            </div>
        `;
    };

    const clearError = () => {
        if (!errorEl) return;
        cancelPendingClear();
        errorEl.style.opacity = '0';
        errorEl.innerHTML = '';
    };

    const trigger = () => {
        let searchVal = input ? input.value.trim().toLowerCase() : "";
        // A bare dot asks for nothing: the registrar would list every name for it.
        if (searchVal === '.') searchVal = '';
        if (searchVal) {
            // A label, or part of one, and optionally a dot and the start of a zone: "alex",
            // "alex.ke", "alex.kerrigan", or ".krgn" for a whole zone. A pasted full name is found.
            const searchRegex = /^([a-z0-9]+(-[a-z0-9]+)*)?(\.[a-z]*)?$/;
            if (!searchRegex.test(searchVal) || searchVal.length > 64) {
                showInvalidName();
                return;
            }
        }
        clearError();
        onSearch(searchVal);
    };

    if (input) {
        input.addEventListener('input', () => {
            // Mirror the registration field's sanitising: lowercase, allowed charset only,
            // no doubled or leading hyphens. One dot may follow, and after it only the
            // letters a zone is made of.
            let val = input.value.toLowerCase()
                .replace(/[^a-z0-9.-]/g, '');
            const dotIdx = val.indexOf('.');
            if (dotIdx !== -1) {
                val = val.substring(0, dotIdx + 1) + val.substring(dotIdx + 1).replace(/[^a-z]/g, '');
            }
            val = val.replace(/-{2,}/g, '-');
            if (val.startsWith('-')) val = val.substring(1);
            if (input.value !== val) input.value = val;

            if (clearBtn) clearBtn.classList.toggle('hidden', val.length === 0);

            if (errorEl && errorEl.style.opacity !== '0') {
                cancelPendingClear();
                errorEl.style.opacity = '0';
                pendingErrorClear = setTimeout(() => {
                    errorEl.innerHTML = '';
                    pendingErrorClear = null;
                }, 300);
            }
        });

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                trigger();
            }
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            if (input) input.value = '';
            clearBtn.classList.add('hidden');
            clearError();
            trigger();
        });
    }

    if (searchBtn) {
        searchBtn.addEventListener('click', () => trigger());
    }

    return trigger;
}

// --- LIST FILTERS (marketplace and my names) ---

// The registrar's own defaults: every name, A to Z. Each list keeps its filters apart, and
// they go back to these whenever its screen is left.
const LIST_FILTER_DEFAULTS = Object.freeze({ zone: '', status: 'all', sort: 'name', order: 'asc' });
const marketFilters = { ...LIST_FILTER_DEFAULTS };
const myNamesFilters = { ...LIST_FILTER_DEFAULTS };

// Turned off for good by a registrar that answers a list without echoing the options it
// applied: one from before them, which ignores them (see disableListOptions).
let listOptionsSupported = true;

function isListFilterActive(filters) {
    return Object.keys(LIST_FILTER_DEFAULTS).some(key => filters[key] !== LIST_FILTER_DEFAULTS[key]);
}

// The badge colours style.css has per zone. A zone the registrar starts serving later gets the
// neutral one until it is given its own.
const ZONE_BADGE_CLASSES = {
    kerrigan: 'badge-zone-kerrigan',
    krgn: 'badge-zone-krgn',
    private: 'badge-zone-private',
    secure: 'badge-zone-secure',
    safe: 'badge-zone-safe'
};

function zoneBadgeClass(domain) {
    return ZONE_BADGE_CLASSES[domain.substring(domain.lastIndexOf('.') + 1)] || 'badge-zone-default';
}

// Wires one list's filters button and the panel it opens. A chip sets `filters` and calls
// onChange right away, with no separate apply step; the reset button restores the defaults.
// The chosen chips are marked with aria-pressed and the open state with aria-expanded, which
// style.css draws from.
function bindListFilters({ button, panel, filters, onChange }) {
    if (!button || !panel) {
        return { reset: () => {}, renderZones: () => {}, disable: () => {} };
    }
    const dot = button.querySelector('.list-filter-dot');
    const zoneGroup = panel.querySelector('[data-filter-group="zone"]');
    const resetBtn = panel.querySelector('[data-filter-reset]');

    const setOpen = (open) => {
        panel.classList.toggle('hidden', !open);
        panel.classList.toggle('flex', open);
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
    };

    const sync = () => {
        panel.querySelectorAll('[data-filter-group]').forEach(group => {
            const name = group.getAttribute('data-filter-group');
            const current = name === 'sort' ? `${filters.sort}:${filters.order}` : filters[name];
            group.querySelectorAll('.list-filter-chip').forEach(chip => {
                chip.setAttribute('aria-pressed', chip.getAttribute('data-value') === current ? 'true' : 'false');
            });
        });
        const active = isListFilterActive(filters);
        if (dot) dot.classList.toggle('hidden', !active);
        if (resetBtn) resetBtn.disabled = !active;
    };

    // One chip per zone after the static "All" one.
    const renderZones = () => {
        if (!zoneGroup) return;
        // A zone the registrar no longer serves can't stay chosen.
        if (filters.zone !== '' && !protocolZones.includes(filters.zone)) {
            filters.zone = LIST_FILTER_DEFAULTS.zone;
        }
        zoneGroup.querySelectorAll('[data-zone-chip]').forEach(chip => chip.remove());
        protocolZones.forEach(zone => {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'list-filter-chip';
            chip.setAttribute('data-zone-chip', '');
            chip.setAttribute('data-value', zone);
            chip.textContent = `.${zone}`;
            zoneGroup.appendChild(chip);
        });
        sync();
    };

    const reset = () => {
        Object.assign(filters, LIST_FILTER_DEFAULTS);
        setOpen(false);
        sync();
    };

    panel.addEventListener('click', (e) => {
        const chip = e.target.closest('.list-filter-chip');
        const group = chip ? chip.closest('[data-filter-group]') : null;
        if (!group) return;
        const name = group.getAttribute('data-filter-group');
        const value = chip.getAttribute('data-value');
        if (name === 'sort') {
            const [sort, order] = value.split(':');
            if (filters.sort === sort && filters.order === order) return;
            filters.sort = sort;
            filters.order = order;
        } else {
            if (filters[name] === value) return;
            filters[name] = value;
        }
        sync();
        onChange();
    });

    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (!isListFilterActive(filters)) return;
            Object.assign(filters, LIST_FILTER_DEFAULTS);
            sync();
            onChange();
        });
    }

    button.addEventListener('click', () => setOpen(button.getAttribute('aria-expanded') !== 'true'));

    renderZones();

    return {
        // Back to the defaults with the panel closed, and nothing reloaded: for leaving the screen.
        reset,
        renderZones,
        // For a registrar that can't apply the options: there is nothing to offer.
        disable: () => {
            reset();
            button.classList.add('hidden');
        }
    };
}

const marketFilterWidget = bindListFilters({
    button: document.getElementById('marketFilterBtn'),
    panel: document.getElementById('marketFilterPanel'),
    filters: marketFilters,
    onChange: () => {
        currentMarketpage = 1;
        marketCursors.clear();
        loadMarketplaceDomains(currentMarketpage, currentMarketSearch);
    }
});

const myNamesFilterWidget = bindListFilters({
    button: document.getElementById('myNamesFilterBtn'),
    panel: document.getElementById('myNamesFilterPanel'),
    filters: myNamesFilters,
    onChange: () => {
        currentMyNamesPage = 1;
        loadMyNamesList(currentMyNamesPage, currentMyNamesSearch);
    }
});

// The registrar answered a list without echoing the options: it predates them and ignores them,
// so the filters are put away and the lists asked for as they were before.
function disableListOptions() {
    listOptionsSupported = false;
    marketCursors.clear();
    marketFilterWidget.disable();
    myNamesFilterWidget.disable();
}

// Adopts the zone list the registrar serves: the registration form's zone picker and the zone
// filters both follow it, so a zone it adds shows up without a new release of the app.
function applyProtocolZones(zones) {
    if (zones.join() === protocolZones.join()) return;
    protocolZones = zones;

    const selected = domainZoneSelect.value;
    domainZoneSelect.innerHTML = '';
    zones.forEach(zone => {
        const option = document.createElement('option');
        option.value = `.${zone}`;
        option.className = 'bg-[#140828] text-white';
        option.textContent = `.${zone}`;
        domainZoneSelect.appendChild(option);
    });
    if (zones.includes(selected.substring(1))) {
        domainZoneSelect.value = selected;
    }
    // Re-applies the length limit for the zone now selected, as a choice by the user would.
    domainZoneSelect.dispatchEvent(new Event('change'));

    marketFilterWidget.renderZones();
    myNamesFilterWidget.renderZones();
}

const triggerMarketplaceSearch = bindSearchWidget({
    input: marketSearchInput,
    clearBtn: marketSearchClearBtn,
    searchBtn: marketSearchBtn,
    errorEl: marketSearchError,
    onSearch: (searchVal) => {
        currentMarketSearch = searchVal;
        currentMarketpage = 1;
        marketCursors.clear();
        loadMarketplaceDomains(currentMarketpage, currentMarketSearch);
    }
});

// My Names Search Logic
const myNamesSearchInput = document.getElementById('myNamesSearchInput');
const myNamesSearchClearBtn = document.getElementById('myNamesSearchClearBtn');
const myNamesSearchBtn = document.getElementById('myNamesSearchBtn');
const myNamesSearchError = document.getElementById('myNamesSearchError');

const triggerMyNamesSearch = bindSearchWidget({
    input: myNamesSearchInput,
    clearBtn: myNamesSearchClearBtn,
    searchBtn: myNamesSearchBtn,
    errorEl: myNamesSearchError,
    onSearch: (searchVal) => {
        currentMyNamesSearch = searchVal;
        currentMyNamesPage = 1;
        loadMyNamesList(currentMyNamesPage, currentMyNamesSearch);
    }
});

const marketError = document.getElementById('marketError');
if (marketError) {
    marketError.addEventListener('click', () => {
        loadMarketplaceDomains(currentMarketpage, currentMarketSearch);
    });
}


// --- MY NAMES VIEW LOGIC ---

let currentMyNamesPage = 1;
let myNamesRequestId = 0; // guards against a stale/overlapping fetch overwriting a newer page's results

if (menuMyNamesBtn) {
    menuMyNamesBtn.addEventListener('click', () => {
        closeDropdown();
        switchTab('my_names');
    });
}

const myNamesPageError = document.getElementById('myNamesPageError');
if (myNamesPageError) {
    myNamesPageError.addEventListener('click', () => {
        loadMyNamesList(currentMyNamesPage, currentMyNamesSearch);
    });
}

const myNamesPageEmptyActionBtn = document.getElementById('myNamesPageEmptyActionBtn');
if (myNamesPageEmptyActionBtn) {
    myNamesPageEmptyActionBtn.addEventListener('click', () => {
        switchTab('register');
    });
}

const marketEmptyActionBtn = document.getElementById('marketEmptyActionBtn');
if (marketEmptyActionBtn) {
    marketEmptyActionBtn.addEventListener('click', () => {
        switchTab('my_names');
    });
}

async function loadMyNamesList(page, search = "") {
    const loading = document.getElementById('myNamesPageLoading');
    const error = document.getElementById('myNamesPageError');
    const empty = document.getElementById('myNamesPageEmpty');
    const grid = document.getElementById('myNamesPageGrid');
    
    if (!loading || !error || !empty || !grid) return;

    const requestId = ++myNamesRequestId;

    loading.classList.remove('hidden');
    loading.classList.add('flex');
    error.classList.add('hidden');
    error.classList.remove('flex');
    empty.classList.add('hidden');
    empty.classList.remove('flex');
    grid.classList.add('hidden');
    grid.classList.remove('flex', 'flex-col');

    // Clear pagination displays
    document.querySelectorAll('.my-names-pagination-top, .my-names-pagination-bottom').forEach(el => el.innerHTML = '');

    try {
        const userPubKey = getCachedPublicKey();
        if (!userPubKey) {
            loading.classList.add('hidden');
            loading.classList.remove('flex');
            empty.classList.remove('hidden');
            empty.classList.add('flex');
            return;
        }

        const pageSize = Math.min(MY_NAMES_PAGE_SIZE, apiMaxCount);
        const payload = {
            type: "my",
            page: page,
            count: pageSize,
            pubkey: userPubKey
        };
        if (listOptionsSupported) {
            payload.sort = myNamesFilters.sort;
            payload.order = myNamesFilters.order;
            payload.zone = myNamesFilters.zone;
            payload.status = myNamesFilters.status;
        }
        if (search) {
            payload.search = search;
        }

        const response = await fetch(`${API_BASE_URL}/v1.0/domains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        let data;
        try {
            data = await response.json();
        } catch (jsonErr) {
            // Not JSON
        }

        if (requestId !== myNamesRequestId) return; // a newer request has since superseded this one

        if (data && data.error && data.error.error_message) {
            throw new Error(data.error.error_message);
        }

        if (!response.ok) throw new Error("Failed to fetch my registered names");

        // A registrar from before the options ignores them and echoes none back (see
        // loadMarketplaceDomains): ask it again without them, the filters put away.
        if (listOptionsSupported && data && data.response && data.response.sort === undefined) {
            disableListOptions();
            return loadMyNamesList(page, search);
        }

        // A page past the first that came back empty: names went away (sold, given away) since
        // its page count was shown. Start over at the top.
        if (page > 1 && data && data.response && Array.isArray(data.response.domains) && data.response.domains.length === 0) {
            currentMyNamesPage = 1;
            return loadMyNamesList(currentMyNamesPage, search);
        }

        loading.classList.add('hidden');
        loading.classList.remove('flex');

        if (!data.response || !data.response.domains || data.response.domains.length === 0) {
            const emptyText = empty.querySelector('p');
            const emptyBtn = document.getElementById('myNamesPageEmptyActionBtn');
            if (search || isListFilterActive(myNamesFilters)) {
                if (emptyText) {
                    emptyText.setAttribute('data-i18n', 'marketplace.no_results');
                    emptyText.textContent = t('marketplace.no_results');
                }
                if (emptyBtn) emptyBtn.classList.add('hidden');
            } else {
                if (emptyText) {
                    emptyText.setAttribute('data-i18n', 'my_names_view.empty');
                    emptyText.textContent = t('my_names_view.empty');
                }
                if (emptyBtn) emptyBtn.classList.remove('hidden');
            }
            empty.classList.remove('hidden');
            empty.classList.add('flex');
            return;
        }

        const totalCount = data.response.count || 0;
        const domains = data.response.domains;

        grid.innerHTML = '';
        domains.forEach(item => {
            const isListed = item.price && item.price !== "0" && item.price !== 0;
            const priceZec = isListed ? parseFloat(item.price) / 100000000 : null;
            const formattedPrice = isListed ? parseFloat(priceZec.toFixed(8)).toString() : null;
            
            const itemEl = document.createElement('div');
            itemEl.className = 'market-card bg-white/5 border border-white/10 rounded-2xl p-4 sm:p-5 flex flex-col justify-between gap-3 text-left';
            
            const zoneClass = zoneBadgeClass(item.domain);
            
            const zoneName = item.domain.substring(item.domain.lastIndexOf('.'));
            const safeDomain = escapeHtml(item.domain);
            const safeZoneName = escapeHtml(zoneName);
            const safeAddress = escapeHtml(item.address || '');
            // What any change to the name costs, in satoshi, as the registrar priced it; left
            // undefined when it didn't, which falls back to the price table.
            const txPriceSats = Number.isInteger(item.tx_price) ? item.tx_price : undefined;

            let statusBadge = `<span class="bg-green-500/20 border border-green-500/30 text-green-300 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider" data-i18n="my_names_view.active">${t('my_names_view.active')}</span>`;
            if (isListed) {
                statusBadge = `<span class="bg-purple-500/20 border border-purple-500/30 text-purple-300 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider" data-i18n="my_names_view.on_sale" data-price="${formattedPrice}">${tSafe('my_names_view.on_sale', { price: formattedPrice })}</span>`;
            }
            
            let buttonsHtml = '';
            let buttonsContainerClass = '';
            
            if (isListed) {
                buttonsContainerClass = 'grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2 pt-2 border-t border-white/5';
                buttonsHtml = `
                    <button class="change-price-btn py-2.5 px-4 bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/30 hover:border-purple-500/50 text-purple-200 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 active:scale-95 w-full" data-domain="${safeDomain}">
                        <svg class="w-3.5 h-3.5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span data-i18n="my_names_actions.change_price">Change Sell Price</span>
                    </button>
                    <button class="unlist-btn py-2.5 px-4 bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/30 hover:border-purple-500/50 text-purple-200 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 active:scale-95 w-full" data-domain="${safeDomain}">
                        <svg class="w-3.5 h-3.5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        <span data-i18n="my_names_actions.unlist_marketplace">Unlist from Marketplace</span>
                    </button>
                `;
            } else {
                buttonsContainerClass = 'grid grid-cols-1 sm:grid-cols-3 gap-2 mt-2 pt-2 border-t border-white/5';
                buttonsHtml = `
                    <button class="change-address-btn py-2.5 px-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 active:scale-95 w-full" data-domain="${safeDomain}" data-address="${safeAddress}">
                        <svg class="w-3.5 h-3.5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>
                        <span data-i18n="my_names_actions.change_address">Change Destination</span>
                    </button>
                    <button class="change-owner-btn py-2.5 px-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 active:scale-95 w-full" data-domain="${safeDomain}">
                        <svg class="w-3.5 h-3.5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path></svg>
                        <span data-i18n="my_names_actions.change_owner">Change Owner</span>
                    </button>
                    <button class="list-btn py-2.5 px-4 bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/30 hover:border-purple-500/50 text-purple-200 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 active:scale-95 w-full" data-domain="${safeDomain}">
                        <svg class="w-3.5 h-3.5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                        <span data-i18n="my_names_actions.list_marketplace">List on Marketplace</span>
                    </button>
                `;
            }
            
            itemEl.innerHTML = `
                <div class="flex items-start justify-between gap-2">
                    <div class="flex flex-col gap-1 min-w-0">
                        <span class="font-bold text-white text-base sm:text-lg break-all">${safeDomain}</span>
                        <div class="flex items-center gap-1.5 mt-0.5">
                            <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${zoneClass}">${safeZoneName}</span>
                            ${statusBadge}
                        </div>
                    </div>
                </div>
                <div class="flex items-center justify-between gap-3 bg-black/20 rounded-xl p-3 my-1">
                    <div class="flex flex-col min-w-0 flex-1">
                        <span class="text-[10px] text-purple-300/80 font-bold uppercase tracking-wider" data-i18n="my_names_view.col_address">Resolves To</span>
                        <span class="text-xs text-white/90 font-mono truncate select-all">${safeAddress}</span>
                    </div>
                    <button class="my-names-copy-btn hover:text-white text-purple-300 transition-colors flex-shrink-0 p-1.5 hover:bg-white/5 rounded-lg" data-i18n-title="tooltips.copy_address" title="${t('tooltips.copy_address')}" data-text="${safeAddress}">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
                    </button>
                </div>
                <div class="${buttonsContainerClass}">
                    ${buttonsHtml}
                </div>
            `;
            
            // Copy resolver address handler
            itemEl.querySelector('.my-names-copy-btn').addEventListener('click', function(e) {
                e.preventDefault();
                const copyText = this.getAttribute('data-text');
                if (!copyText) return;
                try {
                    copyTextToClipboard(copyText);
                    window.showToast(t('my_names_view.copied'));
                } catch(err) {
                    console.error(err);
                }
            });

            // Actions handlers:
            if (!isListed) {
                itemEl.querySelector('.change-address-btn').addEventListener('click', () => {
                    handleMyNameChangeAddress(item.domain, item.address || '', txPriceSats);
                });

                itemEl.querySelector('.change-owner-btn').addEventListener('click', () => {
                    handleMyNameChangeOwner(item.domain, txPriceSats);
                });

                itemEl.querySelector('.list-btn').addEventListener('click', () => {
                    handleMyNameList(item.domain, txPriceSats);
                });
            } else {
                itemEl.querySelector('.change-price-btn').addEventListener('click', () => {
                    handleMyNameList(item.domain, txPriceSats);
                });
                itemEl.querySelector('.unlist-btn').addEventListener('click', () => {
                    handleRemoveFromSale(item.domain, txPriceSats);
                });
            }
            
            grid.appendChild(itemEl);
        });

        grid.classList.remove('hidden');
        grid.classList.add('flex', 'flex-col');
        
        applyTranslations();
        renderMyNamesPagination(totalCount, pageSize);

    } catch (err) {
        if (requestId !== myNamesRequestId) return; // a newer request has since superseded this one
        console.error("My Names load error:", err);
        loading.classList.add('hidden');
        loading.classList.remove('flex');

        if (myNamesSearchError && err.message && err.message !== "Failed to fetch my registered names" && err.message !== "Network response was not OK") {
            myNamesSearchError.style.opacity = '1';
            myNamesSearchError.innerHTML = `
                <div class="mt-2 flex w-full">
                    <span class="text-red-400 flex items-start gap-1.5 min-w-0">
                        <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg> 
                        <span class="min-w-0 break-words">${escapeHtml(err.message)}</span>
                    </span>
                </div>
            `;
        } else {
            error.classList.remove('hidden');
            error.classList.add('flex');
            showErrorAlert(t('errors.request_failed'));
        }
    }
}

function renderMyNamesPagination(totalCount, pageSize) {
    renderPagination({
        selector: '.my-names-pagination-top, .my-names-pagination-bottom',
        totalCount,
        pageSize,
        getPage: () => currentMyNamesPage,
        setPage: (page) => { currentMyNamesPage = page; },
        reload: () => loadMyNamesList(currentMyNamesPage, currentMyNamesSearch)
    });
}

async function handleMyNameChangeAddress(domain, currentAddress, txPriceSats) {
    try {
        const price = await updPriceFor(domain, txPriceSats);
        
        currentRegistrationDomain = domain;
        currentRegistrationPrice = price;
        currentTransactionType = "UPD";
        currentUpdAddress = currentAddress;
        
        // Clear fields on Slide 2
        targetAddressInput.value = '';
        
        setupSlide2Inputs();
        
        switchTab('register');
        setActiveSlide(slideAddress, 'translateX(-100%)');
        setStep('check');
    } catch (err) {
        console.error("Change Destination setup failed:", err);
    }
}

async function handleMyNameChangeOwner(domain, txPriceSats) {
    try {
        const price = await updPriceFor(domain, txPriceSats);
        
        currentRegistrationDomain = domain;
        currentRegistrationPrice = price;
        currentTransactionType = "CHG";
        
        // Reset inputs
        const ownerInput = document.getElementById('newOwnerInput');
        if (ownerInput) ownerInput.value = '';
        
        setupSlide2Inputs();
        
        switchTab('register');
        setActiveSlide(slideAddress, 'translateX(-100%)');
        setStep('check');
    } catch (err) {
        console.error("Change Owner setup failed:", err);
    }
}

async function handleMyNameList(domain, txPriceSats) {
    try {
        const price = await updPriceFor(domain, txPriceSats);
        
        currentRegistrationDomain = domain;
        currentRegistrationPrice = price;
        currentTransactionType = "LST";
        
        const priceInput = document.getElementById('desiredPriceInput');
        if (priceInput) priceInput.value = '';
        
        setupSlide2Inputs();
        
        switchTab('register');
        setActiveSlide(slideAddress, 'translateX(-100%)');
        setStep('check');
    } catch (err) {
        console.error("List Domain setup failed:", err);
    }
}

// Reusable Custom Confirm Dialog Popup
function showConfirm(title, message, onConfirm, onCancel = null) {
    const overlay = document.getElementById('confirmModalOverlay');
    const container = document.getElementById('confirmModalContainer');
    const titleEl = document.getElementById('confirmModalTitle');
    const msgEl = document.getElementById('confirmModalMessage');
    const confirmBtn = document.getElementById('confirmModalConfirmBtn');
    const cancelBtn = document.getElementById('confirmModalCancelBtn');

    if (!overlay || !container || !titleEl || !msgEl || !confirmBtn || !cancelBtn) {
        if (confirm(message)) {
            if (onConfirm) onConfirm();
        } else {
            if (onCancel) onCancel();
        }
        return;
    }

    titleEl.textContent = title;
    // Callers pass plain text (including raw API error strings), so escape here rather than
    // trusting every call site to do it.
    msgEl.textContent = message;

    const cleanup = () => {
        overlay.classList.add('opacity-0');
        container.classList.remove('scale-100');
        container.classList.add('scale-95');
        setTimeout(() => {
            overlay.classList.add('hidden');
            overlay.classList.remove('flex');
        }, 300);
    };

    const handleConfirm = () => {
        cleanup();
        if (onConfirm) onConfirm();
    };

    const handleCancel = () => {
        cleanup();
        if (onCancel) onCancel();
    };

    const newConfirmBtn = confirmBtn.cloneNode(true);
    const newCancelBtn = cancelBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
    cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);

    if (onCancel === null) {
        newCancelBtn.classList.add('hidden');
        newConfirmBtn.textContent = t('confirm_modal.ok');
        newConfirmBtn.setAttribute('data-i18n', 'confirm_modal.ok');
    } else {
        newCancelBtn.classList.remove('hidden');
        newConfirmBtn.textContent = t('confirm_modal.confirm');
        newConfirmBtn.setAttribute('data-i18n', 'confirm_modal.confirm');
        newCancelBtn.textContent = t('confirm_modal.cancel');
        newCancelBtn.setAttribute('data-i18n', 'confirm_modal.cancel');
    }

    newConfirmBtn.addEventListener('click', handleConfirm);
    newCancelBtn.addEventListener('click', handleCancel);

    overlay.classList.remove('hidden');
    overlay.classList.add('flex');
    void overlay.offsetWidth;
    overlay.classList.remove('opacity-0');
    container.classList.remove('scale-95');
    container.classList.add('scale-100');
}

function showErrorAlert(message) {
    // showConfirm renders the message as text, so raw API strings are safe to pass through.
    showConfirm(t('confirm_modal.error_title') || 'Error', message, () => {}, null);
}

// --- MY TRANSACTIONS VIEW CONTROLLER ---

let currentTransactionsPage = 1;
let currentTransactionsTab = "in"; // "in" or "ref"
let transactionsRequestId = 0; // guards against a stale/overlapping fetch overwriting a newer page's results

const menuTransactionsBtn = document.getElementById('menuTransactionsBtn');
const transactionsView = document.getElementById('transactionsView');
const transactionsViewSelector = document.getElementById('transactionsViewSelector');
const tabIncoming = document.getElementById('tabIncoming');
const tabRefunds = document.getElementById('tabRefunds');
const refreshTransactionsBtn = document.getElementById('refreshTransactionsBtn');
const refreshTransactionsIcon = document.getElementById('refreshTransactionsIcon');
const transactionsTableLoading = document.getElementById('transactionsTableLoading');
const transactionsTableHead = document.getElementById('transactionsTableHead');
const transactionsTableBody = document.getElementById('transactionsTableBody');
const transactionsTableEmpty = document.getElementById('transactionsTableEmpty');
const transactionsTableError = document.getElementById('transactionsTableError');

const memoModalOverlay = document.getElementById('memoModalOverlay');
const memoModalContainer = document.getElementById('memoModalContainer');
const memoModalTextarea = document.getElementById('memoModalTextarea');
const memoModalCopyBtn = document.getElementById('memoModalCopyBtn');
const memoModalCloseBtn = document.getElementById('memoModalCloseBtn');
const closeMemoModalXBtn = document.getElementById('closeMemoModalXBtn');

// Fallback path: document.execCommand('copy') is deprecated but is still the only option in
// insecure contexts (plain http) and older browsers where navigator.clipboard is unavailable.
function legacyCopyToClipboard(text) {
    const tempTextarea = document.createElement("textarea");
    tempTextarea.value = text;
    tempTextarea.style.position = "fixed";
    tempTextarea.style.left = "-9999px";
    tempTextarea.setAttribute("readonly", "");
    document.body.appendChild(tempTextarea);
    tempTextarea.focus();
    tempTextarea.select();
    try {
        tempTextarea.setSelectionRange(0, 99999);
    } catch (err) { /* not supported on every input type */ }
    try {
        document.execCommand("copy");
    } finally {
        // Always detach, even if the copy command threw, so the node is never leaked.
        document.body.removeChild(tempTextarea);
    }
}

function copyTextToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).catch(err => {
            console.warn("Clipboard API failed, falling back to execCommand:", err);
            try {
                legacyCopyToClipboard(text);
            } catch (fallbackErr) {
                console.error("Copy failed:", fallbackErr);
            }
        });
        return;
    }
    try {
        legacyCopyToClipboard(text);
    } catch (err) {
        console.error("Copy failed:", err);
    }
}

if (menuTransactionsBtn) {
    menuTransactionsBtn.addEventListener('click', () => {
        closeDropdown();
        switchTab('my_transactions');
    });
}

function switchTransactionsTab(subtab) {
    if (currentTransactionsTab === subtab) return;
    currentTransactionsTab = subtab;
    currentTransactionsPage = 1;

    const subTitleText = document.getElementById('transactionsSubTitleText');

    if (subtab === 'in') {
        tabIncoming.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-white bg-purple-600 shadow-lg shadow-purple-900/30';
        tabRefunds.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        if (subTitleText) {
            subTitleText.setAttribute('data-i18n', 'transactions.incoming_title');
            subTitleText.textContent = t('transactions.incoming_title');
        }
    } else {
        tabRefunds.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-white bg-purple-600 shadow-lg shadow-purple-900/30';
        tabIncoming.className = 'flex items-center justify-center gap-2 flex-1 py-2 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all text-purple-200 hover:text-white hover:bg-white/5';
        if (subTitleText) {
            subTitleText.setAttribute('data-i18n', 'transactions.refunds_title');
            subTitleText.textContent = t('transactions.refunds_title');
        }
    }
    loadTransactionsList(currentTransactionsPage);
}

if (tabIncoming && tabRefunds) {
    tabIncoming.addEventListener('click', () => switchTransactionsTab('in'));
    tabRefunds.addEventListener('click', () => switchTransactionsTab('ref'));
}

async function loadTransactionsList(page) {
    if (!transactionsTableLoading || !transactionsTableHead || !transactionsTableBody || !transactionsTableEmpty || !transactionsTableError) return;

    const requestId = ++transactionsRequestId;

    transactionsTableLoading.classList.remove('hidden');
    transactionsTableLoading.classList.add('flex');
    transactionsTableEmpty.classList.remove('flex');
    transactionsTableEmpty.classList.add('hidden');
    transactionsTableError.classList.remove('flex');
    transactionsTableError.classList.add('hidden');
    
    document.querySelectorAll('.transactions-pagination').forEach(el => el.innerHTML = '');

    try {
        const userPubKey = getCachedPublicKey();
        if (!userPubKey) {
            transactionsTableLoading.classList.add('hidden');
            transactionsTableLoading.classList.remove('flex');
            transactionsTableEmpty.classList.remove('hidden');
            transactionsTableEmpty.classList.add('flex');
            return;
        }

        const count = TRANSACTIONS_PAGE_SIZE;
        // Shaped like the withdrawal: the protocol marker (which carries the network, so a
        // testnet request is not one on mainnet), a version, an operation code the memo parser
        // does not know, and the time - the registrar takes it within a minute of its own
        // clock, so a request seen once cannot be replayed later. Unix seconds.
        const nonce = Math.floor(Date.now() / 1000);
        const msg = `${protocolMarker()}:1:TXS:${currentTransactionsTab}:${userPubKey}:${page}:${count}:${nonce}`;

        let signature = "";
        try {
            signature = await walletSession.sign(msg);
        } catch (signErr) {
            console.error("Failed to sign transaction list request:", signErr);
            throw new Error("Signature failed");
        }

        const payload = {
            type: currentTransactionsTab,
            pubkey: userPubKey,
            page: page,
            count: count,
            nonce: nonce,
            signature: signature
        };

        const response = await fetch(`${API_BASE_URL}/v1.0/transactions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        let data;
        try {
            data = await response.json();
        } catch (jsonErr) {
            // Not JSON
        }

        if (requestId !== transactionsRequestId) return; // a newer request has since superseded this one

        if (data && data.error && data.error.error_message) {
            throw new Error(data.error.error_message);
        }

        if (!response.ok) throw new Error("Failed to fetch transactions");

        transactionsTableLoading.classList.add('hidden');
        transactionsTableLoading.classList.remove('flex');

        if (!data.response || !data.response.tx || data.response.tx.length === 0) {
            transactionsTableBody.innerHTML = '';
            transactionsTableEmpty.classList.remove('hidden');
            transactionsTableEmpty.classList.add('flex');
            return;
        }

        const totalCount = data.response.count || 0;
        const txList = data.response.tx;

        renderTransactionsTable(txList);
        renderTransactionsPagination(totalCount, count);

    } catch (err) {
        if (requestId !== transactionsRequestId) return; // a newer request has since superseded this one
        console.error("Transactions load error:", err);
        transactionsTableLoading.classList.add('hidden');
        transactionsTableLoading.classList.remove('flex');
        transactionsTableError.classList.remove('hidden');
        transactionsTableError.classList.add('flex');

        showErrorAlert(err.message === "Signature failed" ? t('toasts.sign_failed') : t('errors.request_failed'));
    }
}

// A unix time as the day it falls on in UTC, e.g. "2026-11-03 UTC".
function formatUtcDate(ts) {
    const dateObj = new Date(ts * 1000);
    const yyyy = dateObj.getUTCFullYear();
    const mm = String(dateObj.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(dateObj.getUTCDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd} UTC`;
}

// A long id or address cut to its ends for a table cell; the whole of it is copied on click.
function shortenMiddle(text) {
    return text.length > 8 ? `${text.substring(0, 4)}...${text.substring(text.length - 4)}` : text;
}

function renderTransactionsTable(txList) {
    transactionsTableHead.innerHTML = '';
    transactionsTableBody.innerHTML = '';

    if (currentTransactionsTab === 'in') {
        // When and how much was paid. A registrar from before it served them sends neither,
        // and the columns are left out rather than shown empty.
        const hasPaymentDetails = txList.some(item => item.amount !== undefined);
        transactionsTableHead.innerHTML = `
            ${hasPaymentDetails ? `<th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_date">${t('transactions.th_date')}</th>` : ''}
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_name">${t('transactions.th_name')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_op">${t('transactions.th_op')}</th>
            ${hasPaymentDetails ? `<th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_amount">${t('transactions.th_amount')}</th>` : ''}
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_confs">${t('transactions.th_confs')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_status">${t('transactions.th_status')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_txid">${t('transactions.th_txid')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_memo">${t('transactions.th_memo')}</th>
        `;

        txList.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-white/5 transition-colors border-b border-white/5';
            
            let statusText = '';
            let statusIcon = '';
            switch(item.status) {
                case 0: statusText = t('transactions.status_confirming'); break;
                case 1: statusText = t('transactions.status_pending_proof'); break;
                case 2: statusText = t('transactions.status_queued_proof'); break;
                case 3: statusText = t('transactions.status_processing_proof'); break;
                case 4: statusText = t('transactions.status_submit_proof'); break;
                case 5: 
                    statusText = t('transactions.status_done'); 
                    statusIcon = `<svg class="w-4 h-4 text-green-400 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path></svg>`;
                    break;
                case 6: 
                    statusText = t('transactions.status_orphaned'); 
                    statusIcon = `<svg class="w-4 h-4 text-red-400 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
                    break;
                case 7: statusText = t('transactions.status_pending_refund'); break;
                case 8: statusText = t('transactions.status_refunded'); break;
                case 9:
                    statusText = t('transactions.status_rejected');
                    statusIcon = `<svg class="w-4 h-4 text-red-400 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
                    break;
                default: statusText = String(item.status);
            }

            let confsText = String(item.confirmations || 0);
            if (item.status === 0) {
                confsText += ` / ${PAYMENT_CONFIRMATIONS}`;
            } else if (item.status === 7) {
                confsText += ` / ${REFUND_CONFIRMATIONS}`;
            }

            const fullTxId = item.tx_id || "";
            const safeFullTxId = escapeHtml(fullTxId);
            const safeTrimmedTxId = escapeHtml(shortenMiddle(fullTxId));

            // The block's time; null for a payment stored before it was kept, whose time
            // couldn't be filled in.
            const dateStr = Number.isInteger(item.time) && item.time > 0 ? formatUtcDate(item.time) : '—';
            const amountStr = Number.isInteger(item.amount) ? formatSats(item.amount) : '—';
            // A listing also carries the price it puts the name on sale for.
            const listPriceHint = item.op === 'LST' && Number.isInteger(item.price) && item.price > 0
                ? `<span class="block mt-1.5 text-[11px] text-purple-300/70 whitespace-nowrap">${escapeHtml(t('transactions.list_price', { price: formatSats(item.price) }))}</span>`
                : '';

            tr.innerHTML = `
                ${hasPaymentDetails ? `<td class="px-6 py-4 font-semibold text-white/90 font-mono whitespace-nowrap">${dateStr}</td>` : ''}
                <td class="px-6 py-4 font-medium text-white">${escapeHtml(item.domain_name || "")}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 bg-purple-500/10 border border-purple-500/20 text-purple-300 rounded text-xs font-bold">${escapeHtml(item.op || "")}</span>${listPriceHint}</td>
                ${hasPaymentDetails ? `<td class="px-6 py-4 font-medium text-white font-mono">${amountStr}</td>` : ''}
                <td class="px-6 py-4 font-semibold text-white/90">${confsText}</td>
                <td class="px-6 py-4 flex items-center gap-1 mt-0.5">${statusIcon}<span>${statusText}</span></td>
                <td class="px-6 py-4">
                    <button class="txid-copy-btn text-purple-300 hover:text-white transition-colors underline font-mono select-none" data-txid="${safeFullTxId}">${safeTrimmedTxId}</button>
                </td>
                <td class="px-6 py-4">
                    <button class="memo-show-btn bg-purple-600/20 hover:bg-purple-600/40 text-purple-200 hover:text-white font-bold py-1 px-3 rounded-lg text-xs transition-colors" data-memo="${escapeHtml(item.memo || '')}">Show</button>
                </td>
            `;

            tr.querySelector('.txid-copy-btn').addEventListener('click', function(e) {
                e.preventDefault();
                const txid = this.getAttribute('data-txid');
                if (txid) {
                    copyTextToClipboard(txid);
                    window.showToast(t('transactions.copied') || "Copied to clipboard!");
                }
            });

            tr.querySelector('.memo-show-btn').addEventListener('click', function(e) {
                e.preventDefault();
                const memo = this.getAttribute('data-memo');
                openMemoModal(memo);
            });

            transactionsTableBody.appendChild(tr);
        });
    } else {
        // Where each withdrawal went: the user's own address. Left out for a registrar that
        // doesn't serve it yet.
        const hasAddress = txList.some(item => typeof item.address === 'string');
        transactionsTableHead.innerHTML = `
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_date">${t('transactions.th_date')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_amount">${t('transactions.th_amount')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_fee">${t('transactions.th_fee')}</th>
            ${hasAddress ? `<th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_address">${t('transactions.th_address')}</th>` : ''}
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_txid">${t('transactions.th_txid')}</th>
            <th class="px-6 py-4 font-semibold tracking-wider text-left border-b border-white/10" data-i18n="transactions.th_status">${t('transactions.th_status')}</th>
        `;

        txList.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-white/5 transition-colors border-b border-white/5';

            let dateStr = "";
            if (item.date) {
                dateStr = formatUtcDate(item.date);
            }

            let amt = "0";
            if (item.amount) {
                const amtZec = parseFloat(item.amount) / 100000000;
                amt = parseFloat(amtZec.toFixed(8)).toString();
            }

            let feeVal = item.fee !== undefined ? String(item.fee).replace('%', '') : "";

            let statusText = '';
            let statusIcon = '';
            // The registrar's TX_REFUND_* statuses: 0 waiting, 1 queued, 2 sending, 3 paid,
            // 4 error (the amount went back to the balance), 5 queued to go out alone after a
            // batch the node refused. Sending and the retry are still on their way, so they read
            // as queued. This used to number them from paid = 2, showing a payout in flight as
            // paid, a paid one as an error, and an error as a bare "4".
            switch(item.status) {
                case 0: statusText = t('transactions.status_waiting'); break;
                case 1:
                case 2:
                case 5: statusText = t('transactions.status_queued'); break;
                case 3: statusText = t('transactions.status_paid'); break;
                case 4: 
                    statusText = t('transactions.status_error'); 
                    statusIcon = `<svg class="w-4 h-4 text-red-400 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
                    break;
                default: statusText = String(item.status);
            }

            const fullTxId = item.tx_id || "";
            const safeFullTxId = escapeHtml(fullTxId);
            const safeTrimmedTxId = escapeHtml(shortenMiddle(fullTxId));
            const fullAddress = typeof item.address === 'string' ? item.address : '';

            tr.innerHTML = `
                <td class="px-6 py-4 font-semibold text-white/90 font-mono">${dateStr}</td>
                <td class="px-6 py-4 font-medium text-white font-mono">${amt}</td>
                <td class="px-6 py-4 font-medium text-white/80 font-mono">${escapeHtml(feeVal)}</td>
                ${hasAddress ? `<td class="px-6 py-4">
                    <button class="address-copy-btn text-purple-300 hover:text-white transition-colors underline font-mono select-none" data-address="${escapeHtml(fullAddress)}" data-i18n-title="tooltips.copy_address" title="${escapeHtml(t('tooltips.copy_address'))}">${escapeHtml(shortenMiddle(fullAddress))}</button>
                </td>` : ''}
                <td class="px-6 py-4">
                    <button class="txid-copy-btn text-purple-300 hover:text-white transition-colors underline font-mono select-none" data-txid="${safeFullTxId}">${safeTrimmedTxId}</button>
                </td>
                <td class="px-6 py-4 flex items-center gap-1 mt-0.5">${statusIcon}<span>${statusText}</span></td>
            `;

            tr.querySelector('.txid-copy-btn').addEventListener('click', function(e) {
                e.preventDefault();
                const txid = this.getAttribute('data-txid');
                if (txid) {
                    copyTextToClipboard(txid);
                    window.showToast(t('transactions.copied') || "Copied to clipboard!");
                }
            });

            const addressCopyBtn = tr.querySelector('.address-copy-btn');
            if (addressCopyBtn) {
                addressCopyBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    const address = this.getAttribute('data-address');
                    if (address) {
                        copyTextToClipboard(address);
                        window.showToast(t('my_names_view.copied'));
                    }
                });
            }

            transactionsTableBody.appendChild(tr);
        });
    }
}

function renderTransactionsPagination(totalCount, pageSize) {
    renderPagination({
        selector: '.transactions-pagination',
        totalCount,
        pageSize,
        getPage: () => currentTransactionsPage,
        setPage: (page) => { currentTransactionsPage = page; },
        reload: () => loadTransactionsList(currentTransactionsPage)
    });
}

function openMemoModal(memo) {
    if (!memoModalOverlay || !memoModalContainer || !memoModalTextarea) return;
    
    memoModalTextarea.value = memo || "";
    
    memoModalOverlay.classList.remove('hidden');
    memoModalOverlay.classList.add('flex');
    void memoModalOverlay.offsetWidth;
    memoModalOverlay.classList.remove('opacity-0');
    
    memoModalContainer.classList.remove('scale-95');
    memoModalContainer.classList.add('scale-100');
}

function closeMemoModal() {
    if (!memoModalOverlay || !memoModalContainer) return;
    
    memoModalOverlay.classList.add('opacity-0');
    memoModalContainer.classList.remove('scale-100');
    memoModalContainer.classList.add('scale-95');
    
    setTimeout(() => {
        memoModalOverlay.classList.remove('flex');
        memoModalOverlay.classList.add('hidden');
        memoModalTextarea.value = "";
    }, 300);
}

if (memoModalCloseBtn) {
    memoModalCloseBtn.addEventListener('click', closeMemoModal);
}
if (closeMemoModalXBtn) {
    closeMemoModalXBtn.addEventListener('click', closeMemoModal);
}
if (memoModalCopyBtn) {
    memoModalCopyBtn.addEventListener('click', () => {
        if (memoModalTextarea) {
            copyTextToClipboard(memoModalTextarea.value);
            window.showToast(t('transactions.copied') || "Copied to clipboard!");
        }
    });
}

if (refreshTransactionsBtn) {
    refreshTransactionsBtn.addEventListener('click', () => {
        refreshTransactionsBtn.disabled = true;
        const originalRefreshHTML = refreshTransactionsBtn.innerHTML;
        refreshTransactionsBtn.innerHTML = `<svg class="w-4 h-4 animate-spin text-purple-300" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> <span data-i18n="transactions.refresh">${t('transactions.refresh')}</span>`;
        
        currentTransactionsPage = 1;
        loadTransactionsList(currentTransactionsPage).finally(() => {
            refreshTransactionsBtn.disabled = false;
            refreshTransactionsBtn.innerHTML = originalRefreshHTML;
        });
    });
}

if (transactionsTableError) {
    transactionsTableError.addEventListener('click', () => {
        loadTransactionsList(currentTransactionsPage);
    });
}

// --- MY BALANCE MODAL CONTROLLER ---
const balanceModalOverlay = document.getElementById('balanceModalOverlay');
const balanceModalContainer = document.getElementById('balanceModalContainer');
const closeBalanceModalBtn = document.getElementById('closeBalanceModalBtn');
const menuBalanceBtn = document.getElementById('menuBalanceBtn');
const refreshBalanceBtn = document.getElementById('refreshBalanceBtn');
const balanceValueEl = document.getElementById('balanceValue');
const withdrawBlock = document.getElementById('withdrawBlock');
const withdrawAddressInput = document.getElementById('withdrawAddressInput');
const withdrawAddressErrorMsg = document.getElementById('withdrawAddressErrorMsg');
const withdrawBtn = document.getElementById('withdrawBtn');
const withdrawFeeBlock = document.getElementById('withdrawFeeBlock');
const withdrawPaidAmount = document.getElementById('withdrawPaidAmount');
const withdrawMinMsg = document.getElementById('withdrawMinMsg');

let currentBalanceAmount = 0;

// What a withdrawal of `amount` KRGN pays out once the service fee is taken. An estimate for
// display only - the registrar computes the real payout.
function netAfterRefundFee(amount) {
    // In whole satoshi and rounded down, as the registrar pays it: rounding to the nearest showed
    // a satoshi more than arrives, e.g. 0.00100001 for a balance of 0.00105264, which pays 0.001.
    const sats = Math.round(amount * SATOSHIS_PER_KRGN);
    const net = Math.floor(sats * (100 - currentRefundFeePercent) / 100) / SATOSHIS_PER_KRGN;
    return parseFloat(net.toFixed(8)).toString(); // remove trailing zeros reliably
}

// The label states the rate in words, so it is re-rendered whenever the served fee changes.
function renderRefundFeeLabel() {
    document.querySelectorAll('[data-i18n="balance_modal.fee_label"]').forEach(el => {
        el.textContent = t('balance_modal.fee_label', { fee: currentRefundFeePercent });
    });
}

function openBalanceModal() {
    if (!balanceModalOverlay || !balanceModalContainer) return;
    
    // Reset inputs
    withdrawAddressInput.value = '';
    withdrawAddressErrorMsg.classList.add('hidden');
    withdrawAddressInput.classList.remove('border-red-500');
    validateWithdrawInput();
    
    // Show loading state
    balanceValueEl.textContent = "...";
    updateWithdrawBlockState(0);
    
    balanceModalOverlay.classList.remove('hidden');
    balanceModalOverlay.classList.add('flex');
    void balanceModalOverlay.offsetWidth;
    balanceModalOverlay.classList.remove('opacity-0');
    
    balanceModalContainer.classList.remove('scale-95');
    balanceModalContainer.classList.add('scale-100');
    
    // Fetch initial balance
    fetchUserBalance(false);
}

function closeBalanceModal() {
    if (!balanceModalOverlay || !balanceModalContainer) return;
    
    balanceModalOverlay.classList.add('opacity-0');
    balanceModalContainer.classList.remove('scale-100');
    balanceModalContainer.classList.add('scale-95');
    
    setTimeout(() => {
        balanceModalOverlay.classList.remove('flex');
        balanceModalOverlay.classList.add('hidden');
    }, 300);
}

function formatBalanceDisplay(balanceStr) {
    const num = parseFloat(balanceStr);
    if (isNaN(num)) return balanceStr;
    if (num % 1 === 0) {
        return num.toString();
    }
    let s = num.toFixed(8);
    s = s.replace(/\.?0+$/, "");
    return s;
}

function updateWithdrawBlockState(balance) {
    const numericBalance = parseFloat(balance) || 0;
    // A balance below the minimum stays on the account until refunds add up to it: the registrar
    // refuses to pay it out, as each payout costs it a network fee.
    const belowMinimum = numericBalance > 0 && numericBalance < currentMinWithdrawal;
    if (withdrawMinMsg) {
        withdrawMinMsg.textContent = t('balance_modal.min_withdrawal', { amount: formatBalanceDisplay(currentMinWithdrawal) });
        withdrawMinMsg.classList.toggle('hidden', !belowMinimum);
    }
    if (numericBalance > 0 && !belowMinimum) {
        withdrawBlock.classList.remove('opacity-40', 'pointer-events-none');
        if (withdrawFeeBlock && withdrawPaidAmount) {
            withdrawPaidAmount.textContent = `~ ${netAfterRefundFee(numericBalance)} KRGN`;
            withdrawFeeBlock.classList.remove('hidden');
        }
    } else {
        withdrawBlock.classList.add('opacity-40', 'pointer-events-none');
        if (withdrawFeeBlock) {
            withdrawFeeBlock.classList.add('hidden');
        }
    }
}

async function fetchUserBalance(showToast = false) {
    const userPubKey = getCachedPublicKey();
    if (!userPubKey) {
        showErrorAlert(t('errors.not_logged_in'));
        return;
    }
    
    // Disable refresh button & show spinner
    refreshBalanceBtn.disabled = true;
    const originalRefreshHTML = refreshBalanceBtn.innerHTML;
    refreshBalanceBtn.innerHTML = `<svg class="w-5 h-5 animate-spin text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;
    
    try {
        const response = await fetch(`${API_BASE_URL}/v1.0/balance`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: "get",
                pubkey: userPubKey
            })
        });
        
        const data = await response.json();
        if (data.error) {
            const errMsg = (typeof data.error === 'object' && data.error.error_message) ? data.error.error_message : data.error;
            showErrorAlert(errMsg);
            balanceValueEl.textContent = t('confirm_modal.error_title') || "Error";
            updateWithdrawBlockState(0);
        } else if (data.response && data.response.balance !== undefined) {
            // Adopt the fee the registrar reports before anything renders the estimate. A
            // missing or nonsensical value keeps the previous one rather than zeroing it -
            // overstating the payout would be the one wrong direction to fail in.
            const fee = parseFloat(data.response.fee);
            if (Number.isFinite(fee) && fee >= 0 && fee < 100) {
                currentRefundFeePercent = fee;
                renderRefundFeeLabel();
            }
            const minWithdrawal = parseInt(data.response.min_withdrawal, 10);
            if (Number.isSafeInteger(minWithdrawal) && minWithdrawal >= 0) {
                currentMinWithdrawal = minWithdrawal / 100000000;
            }
            currentBalanceAmount = parseFloat(data.response.balance) / 100000000;
            const formatted = formatBalanceDisplay(currentBalanceAmount);
            balanceValueEl.textContent = formatted;
            updateWithdrawBlockState(currentBalanceAmount);
            if (showToast) {
                window.showToast(t('toasts.balance_updated', { amount: formatted }));
            }
        }
    } catch (e) {
        console.error("Fetch balance failed:", e);
        showErrorAlert(t('errors.fetch_balance_failed'));
        balanceValueEl.textContent = t('confirm_modal.error_title') || "Error";
        updateWithdrawBlockState(0);
    } finally {
        refreshBalanceBtn.disabled = false;
        refreshBalanceBtn.innerHTML = originalRefreshHTML;
    }
}

// Validation function for withdrawal address
function validateWithdrawInput() {
    const addr = withdrawAddressInput.value.trim();
    // Withdrawals are not embedded in a memo, so the memo budget does not constrain them
    const isValid = isValidKerriganAddress(addr, null);
    
    if (addr.length > 0 && !isValid) {
        withdrawAddressErrorMsg.classList.remove('hidden');
        withdrawAddressInput.classList.add('border-red-500');
    } else {
        withdrawAddressErrorMsg.classList.add('hidden');
        withdrawAddressInput.classList.remove('border-red-500');
    }
    
    const isBtnDisabled = !isValid || addr.length === 0;
    withdrawBtn.disabled = isBtnDisabled;
    if (isBtnDisabled) {
        withdrawBtn.classList.add('opacity-50', 'pointer-events-none');
    } else {
        withdrawBtn.classList.remove('opacity-50', 'pointer-events-none');
    }
}

async function handleWithdraw() {
    const userPubKey = getCachedPublicKey();
    if (!userPubKey) {
        showErrorAlert(t('errors.not_logged_in'));
        return;
    }
    
    const address = withdrawAddressInput.value.trim();
    if (!address || currentBalanceAmount < currentMinWithdrawal) return;
    
    // Check if wallet session is unlocked
    if (!walletSession.isUnlocked()) {
        headerUnlockBtn.click();
        return;
    }
    
    const amountSatoshis = Math.round(parseFloat(currentBalanceAmount) * 100000000).toString();
    const amount = amountSatoshis;
    const nonce = Math.floor(Date.now() / 1000).toString();
    
    // Signed message: {MARKER}:1:WDR:{user_pubkey}:{address}:{amount}:{nonce}
    //
    // The marker/version/op head mirrors the memo commands and must match the registrar's
    // PROTOCOL_MARKER . ':1:WDR:' exactly. WDR is deliberately NOT in the indexer's OP_LIST,
    // so this string can never be mistaken for an on-chain command and vice versa.
    //
    // The prefix is what makes the artefact self-describing: this signature is the user's
    // only evidence in a payout dispute, and without it the request is four anonymous
    // colon-separated fields that name neither the service, the network nor the operation.
    // Deriving the marker from the served network (rather than inlining it) is what stops a
    // testnet-signed withdrawal from being replayable against mainnet.
    const message = `${protocolMarker()}:1:WDR:${userPubKey}:${address}:${amount}:${nonce}`;
    
    withdrawBtn.disabled = true;
    const originalBtnHTML = withdrawBtn.innerHTML;
    withdrawBtn.innerHTML = `<span class="loader"></span> ${t('balance_modal.btn_withdraw_processing')}`;
    
    try {
        const signature = await walletSession.sign(message);
        
        const response = await fetch(`${API_BASE_URL}/v1.0/balance`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: "withdraw",
                pubkey: userPubKey,
                address: address,
                amount: amount,
                nonce: parseInt(nonce, 10),
                signature: signature
            })
        });
        
        const data = await response.json();
        if (data.error) {
            const errMsg = (typeof data.error === 'object' && data.error.error_message) ? data.error.error_message : data.error;
            showErrorAlert(errMsg);
        } else if (data.response === 1) {
            const numericBalance = parseFloat(currentBalanceAmount) || 0; // KRGN, not the satoshi `amount` sent to the API
            window.showToast(t('toasts.withdraw_success', { amount: `~ ${netAfterRefundFee(numericBalance)}` }));
            // Automatically refresh balance after withdrawal
            await fetchUserBalance(false);
            withdrawAddressInput.value = '';
            validateWithdrawInput();
        } else {
            showErrorAlert(t('errors.withdraw_unexpected_err'));
        }
    } catch (e) {
        console.error("Withdrawal signature/request failed:", e);
        showErrorAlert(t('errors.sign_or_req_failed'));
    } finally {
        withdrawBtn.disabled = false;
        withdrawBtn.innerHTML = originalBtnHTML;
    }
}

// Bind events
if (menuBalanceBtn) {
    menuBalanceBtn.addEventListener('click', () => {
        closeDropdown();
        openBalanceModal();
    });
}
if (closeBalanceModalBtn) {
    closeBalanceModalBtn.addEventListener('click', closeBalanceModal);
}
if (refreshBalanceBtn) {
    refreshBalanceBtn.addEventListener('click', () => {
        fetchUserBalance(true);
    });
}
if (withdrawAddressInput) {
    withdrawAddressInput.addEventListener('input', validateWithdrawInput);
}
if (withdrawBtn) {
    withdrawBtn.addEventListener('click', handleWithdraw);
}

// --- ONBOARDING WIZARD CONTROLLER ---
let currentOnboardingSlide = 0;

function openOnboarding() {
    const modal = document.getElementById('onboardingModal');
    const card = document.getElementById('onboardingCard');
    if (!modal || !card) return;

    currentOnboardingSlide = 0;
    updateOnboardingUI(0, false);

    modal.classList.remove('pointer-events-none');
    modal.classList.add('flex');
    void modal.offsetWidth;
    modal.classList.remove('opacity-0');
    
    card.classList.remove('scale-95');
    card.classList.add('scale-100');
}

function closeOnboarding() {
    const modal = document.getElementById('onboardingModal');
    const card = document.getElementById('onboardingCard');
    if (!modal || !card) return;

    modal.classList.add('opacity-0');
    card.classList.remove('scale-100');
    card.classList.add('scale-95');
    
    setTimeout(() => {
        modal.classList.add('pointer-events-none');
        modal.classList.remove('flex');
    }, 300);

    localStorage.setItem('kerrigan_onboarded', 'true');
}

function updateOnboardingUI(targetSlideIdx = currentOnboardingSlide, animate = false) {
    const slides = document.querySelectorAll('.onboarding-slide');
    
    const updateControls = () => {
        const indicator = document.getElementById('onboardingStepIndicator');
        if (indicator) {
            indicator.textContent = `${currentOnboardingSlide + 1} / 4`;
        }

        const dotsContainer = document.getElementById('onboardingDots');
        if (dotsContainer) {
            dotsContainer.innerHTML = '';
            for (let i = 0; i < 4; i++) {
                const dot = document.createElement('span');
                if (i === currentOnboardingSlide) {
                    dot.className = 'w-6 h-2 rounded-full bg-purple-500 transition-all duration-300';
                } else {
                    dot.className = 'w-2 h-2 rounded-full bg-white/20 transition-all duration-300';
                }
                dotsContainer.appendChild(dot);
            }
        }

        const skipBtn = document.getElementById('onboardingSkipBtn');
        const nextBtn = document.getElementById('onboardingNextBtn');
        const finishBtn = document.getElementById('onboardingFinishBtn');

        if (currentOnboardingSlide === 3) {
            if (skipBtn) skipBtn.classList.add('hidden');
            if (nextBtn) nextBtn.classList.add('hidden');
            if (finishBtn) finishBtn.classList.remove('hidden');
        } else {
            if (skipBtn) skipBtn.classList.remove('hidden');
            if (nextBtn) nextBtn.classList.remove('hidden');
            if (finishBtn) finishBtn.classList.add('hidden');
        }
    };

    /**
     * Show or hide one slide, including the bits that decide whether its contents can be
     * interacted with at all.
     *
     * Shared by both paths below on purpose. The two used to carry their own copies and
     * drifted: the animated path (what the Next button uses) moved the classes but never
     * cleared `inert`, `aria-hidden` or the `tabindex="-1"` it had stamped on every control.
     * Inert content is not hit-testable, so the last slide rendered normally while its
     * Telegram and Docs links silently refused to be clicked - and the wizard buttons kept
     * working, because they live outside the slides container.
     */
    const applySlideState = (slide, isActive) => {
        const focusables = slide.querySelectorAll('input, select, button, a[href]');
        if (isActive) {
            slide.classList.remove('hidden');
            // Reflow between un-hiding and marking active, so the opacity/transform
            // transition in .onboarding-slide actually runs instead of being coalesced.
            void slide.offsetWidth;
            slide.classList.add('active');
            slide.removeAttribute('aria-hidden');
            slide.removeAttribute('inert');
            focusables.forEach(item => item.removeAttribute('tabindex'));
        } else {
            slide.classList.add('hidden');
            slide.classList.remove('active');
            slide.setAttribute('aria-hidden', 'true');
            slide.setAttribute('inert', '');
            focusables.forEach(item => item.setAttribute('tabindex', '-1'));
        }
    };

    if (!animate || targetSlideIdx === currentOnboardingSlide) {
        currentOnboardingSlide = targetSlideIdx;
        slides.forEach(slide => {
            const slideIdx = parseInt(slide.getAttribute('data-slide') || '0');
            applySlideState(slide, slideIdx === currentOnboardingSlide);
        });
        updateControls();
    } else {
        const currentSlideEl = document.querySelector(`.onboarding-slide[data-slide="${currentOnboardingSlide}"]`);
        const nextSlideEl = document.querySelector(`.onboarding-slide[data-slide="${targetSlideIdx}"]`);
        
        if (currentSlideEl && nextSlideEl) {
            currentSlideEl.classList.remove('active');
            
            const skipBtn = document.getElementById('onboardingSkipBtn');
            const nextBtn = document.getElementById('onboardingNextBtn');
            if (skipBtn) skipBtn.style.pointerEvents = 'none';
            if (nextBtn) nextBtn.style.pointerEvents = 'none';
            
            setTimeout(() => {
                applySlideState(currentSlideEl, false);

                currentOnboardingSlide = targetSlideIdx;
                applySlideState(nextSlideEl, true);

                updateControls();
                
                if (skipBtn) skipBtn.style.pointerEvents = 'auto';
                if (nextBtn) nextBtn.style.pointerEvents = 'auto';
            }, 300);
        } else {
            currentOnboardingSlide = targetSlideIdx;
            updateOnboardingUI(currentOnboardingSlide, false);
        }
    }
}

// Bind onboarding events
const onboardingSkipBtn = document.getElementById('onboardingSkipBtn');
const onboardingNextBtn = document.getElementById('onboardingNextBtn');
const onboardingFinishBtn = document.getElementById('onboardingFinishBtn');
const openOnboardingBtn = document.getElementById('openOnboardingBtn');

if (onboardingSkipBtn) {
    onboardingSkipBtn.addEventListener('click', closeOnboarding);
}
if (onboardingNextBtn) {
    onboardingNextBtn.addEventListener('click', () => {
        if (currentOnboardingSlide < 3) {
            updateOnboardingUI(currentOnboardingSlide + 1, true);
        }
    });
}

if (onboardingFinishBtn) {
    onboardingFinishBtn.addEventListener('click', closeOnboarding);
}
if (openOnboardingBtn) {
    openOnboardingBtn.addEventListener('click', (e) => {
        e.preventDefault();
        openOnboarding();
    });
}

// Auto-open onboarding if not done yet
if (localStorage.getItem('kerrigan_onboarded') !== 'true') {
    openOnboarding();
}
