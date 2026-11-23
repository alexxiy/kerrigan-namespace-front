// The stored seed's encryption: encryptSeed() and decryptSeed() lifted out of js/app.js by marker
// (so the test breaks if they move rather than testing a stale copy), run with Node's WebCrypto.
// - a round trip, for an ASCII and a non-ASCII password and for 12- and 24-word phrases;
// - a wrong password, and a changed ciphertext, IV or salt, are refused (AES-GCM's tag);
// - every encryption draws a new salt and IV;
// - the stored format against an independent implementation (node:crypto's PBKDF2 and
//   AES-256-GCM, ciphertext followed by the 16-byte tag, base64): what the app stores decrypts
//   there, and what that stores decrypts in the app - an account saved by an earlier release keeps
//   opening only while both agree;
// - PBKDF2_ITERATIONS is still 600000: changing it locks every stored account out.
//
//   node scripts/seed_crypto.test.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { entropyToMnemonic } from "../js/vendor/bip39.js";
import { wordlist } from "../js/vendor/wordlist.js";

const ROOT = path.join(import.meta.dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "js", "app.js"), "utf8");

const from = src.indexOf("// Iteration count for password-based key derivation of the stored seed.");
const to = src.indexOf("doCreateAccountBtn.addEventListener('click'");
if (from < 0 || to < from || !src.slice(from, to).includes("async function decryptSeed(")) {
    throw new Error("markers not found - did app.js change?");
}
const { encryptSeed, decryptSeed, PBKDF2_ITERATIONS } = new Function("crypto", "TextEncoder", "TextDecoder", "btoa", "atob",
    `${src.slice(from, to)}\nreturn { encryptSeed, decryptSeed, PBKDF2_ITERATIONS };`)(
    globalThis.crypto, TextEncoder, TextDecoder, globalThis.btoa, globalThis.atob);

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? "  PASS  " : "  FAIL  ") + name); cond ? pass++ : fail++; };
const refused = async (promise) => { try { await promise; return false; } catch { return true; } };
const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => Buffer.from(s, "base64");

check("PBKDF2_ITERATIONS is 600000 (a change locks stored accounts out)", PBKDF2_ITERATIONS === 600000);

const phrase12 = entropyToMnemonic(new Uint8Array(16).fill(7), wordlist);
const phrase24 = entropyToMnemonic(new Uint8Array(32).fill(9), wordlist);
const PASSWORD = "correct horse battery staple";
const UNICODE = "пароль-密码-🔑 with spaces";

for (const [what, phrase, password] of [["12 words, ASCII password", phrase12, PASSWORD],
                                        ["24 words, non-ASCII password", phrase24, UNICODE]]) {
    const stored = await encryptSeed(phrase, password);
    const str = JSON.stringify(stored);
    check(`${what}: round trip`, await decryptSeed(str, password) === phrase);
    check(`${what}: 16-byte salt, 12-byte IV, ciphertext = text + 16-byte tag`,
        unb64(stored.salt).length === 16 && unb64(stored.iv).length === 12 &&
        unb64(stored.ciphertext).length === Buffer.byteLength(phrase) + 16);
    check(`${what}: the phrase is not in what is stored`, !str.includes(phrase.split(" ")[0] + " "));
    check(`${what}: a wrong password is refused`, await refused(decryptSeed(str, password + "x")));
    check(`${what}: an empty password is refused`, await refused(decryptSeed(str, "")));

    const flip = (field) => {
        const bytes = unb64(stored[field]);
        bytes[bytes.length - 1] ^= 1;
        return JSON.stringify({ ...stored, [field]: b64(bytes) });
    };
    check(`${what}: a changed ciphertext is refused`, await refused(decryptSeed(flip("ciphertext"), password)));
    check(`${what}: a changed IV is refused`, await refused(decryptSeed(flip("iv"), password)));
    check(`${what}: a changed salt is refused`, await refused(decryptSeed(flip("salt"), password)));

    // The stored format, read by another implementation.
    const key = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), unb64(stored.salt), 600000, 32, "sha256");
    const ct = unb64(stored.ciphertext);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, unb64(stored.iv));
    decipher.setAuthTag(ct.subarray(ct.length - 16));
    const plain = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]).toString("utf8");
    check(`${what}: node:crypto decrypts what the app stores`, plain === phrase);

    // ... and written by it.
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
    const key2 = crypto.pbkdf2Sync(Buffer.from(password, "utf8"), salt, 600000, 32, "sha256");
    const cipher = crypto.createCipheriv("aes-256-gcm", key2, iv);
    const body = Buffer.concat([cipher.update(phrase, "utf8"), cipher.final(), cipher.getAuthTag()]);
    const foreign = JSON.stringify({ ciphertext: b64(body), salt: b64(salt), iv: b64(iv) });
    check(`${what}: the app decrypts what node:crypto stores`, await decryptSeed(foreign, password) === phrase);
}

const a = await encryptSeed(phrase12, PASSWORD), b = await encryptSeed(phrase12, PASSWORD);
check("a new salt and IV every time", a.salt !== b.salt && a.iv !== b.iv && a.ciphertext !== b.ciphertext);
// The stored account carries pubKeyHex beside these fields (unlock and change-password add it);
// a field more is ignored.
check("a field beside the three is ignored",
    await decryptSeed(JSON.stringify({ ...a, pubKeyHex: "00".repeat(32) }), PASSWORD) === phrase12);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
