// Known-answer tests for the crypto bundles in js/vendor/ (esm.sh builds of the npm packages
// named in THIRD_PARTY_NOTICES.md), run with app.js's own sha512Sync hook, lifted by marker:
// - SHA-512 of "" and "abc" (FIPS 180-2);
// - RFC 8032 section 7.1, TEST 1-3: public keys, signatures, verification;
// - BIP-39: the all-zero-entropy phrase, its checksum, and its seed with the passphrase "TREZOR";
// - the SHA-256 of every vendored file against the checksums listed in THIRD_PARTY_NOTICES.md.
// The expected values were also checked against libsodium (PHP) and Python's hashlib.
//
//   node scripts/vendor_kat.test.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as ed25519 from "../js/vendor/ed25519.js";
import { sha512 } from "../js/vendor/hashes.js";
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "../js/vendor/bip39.js";
import { wordlist } from "../js/vendor/wordlist.js";

const ROOT = path.join(import.meta.dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "js", "app.js"), "utf8");
const hook = src.match(/^ed25519\.etc\.sha512Sync = .*;$/m);
if (!hook) throw new Error("sha512Sync hook not found in app.js - did it move?");
new Function("ed25519", "sha512", hook[0])(ed25519, sha512);

let pass = 0, fail = 0;
const check = (name, cond) => { console.log((cond ? "  PASS  " : "  FAIL  ") + name); cond ? pass++ : fail++; };
const hex = (b) => Buffer.from(b).toString("hex");
const bytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));

check("SHA-512 of the empty string",
    hex(sha512(new Uint8Array(0))) === "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
check("SHA-512 of \"abc\"",
    hex(sha512(new TextEncoder().encode("abc"))) === "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

const RFC8032 = [
    ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
    ["4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"],
    ["c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"],
];
RFC8032.forEach(([sk, msg, pk, sig], i) => {
    const n = `RFC 8032 TEST ${i + 1}`;
    check(`${n}: public key`, hex(ed25519.getPublicKey(bytes(sk))) === pk);
    check(`${n}: signature`, hex(ed25519.sign(bytes(msg), bytes(sk))) === sig);
    check(`${n}: verifies`, ed25519.verify(bytes(sig), bytes(msg), bytes(pk)) === true);
    const other = bytes(msg + "00");
    check(`${n}: does not verify another message`, ed25519.verify(bytes(sig), other, bytes(pk)) === false);
});
// Each message gets its own R (the first half of the signature).
const [sk2] = RFC8032[1];
const rA = hex(ed25519.sign(bytes("01"), bytes(sk2))).slice(0, 64);
const rB = hex(ed25519.sign(bytes("02"), bytes(sk2))).slice(0, 64);
check("two messages of one key carry different R", rA !== rB);

const ZERO_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
check("BIP-39 word list: 2048 words, abandon ... zoo", wordlist.length === 2048 && wordlist[0] === "abandon" && wordlist[2047] === "zoo");
check("BIP-39 all-zero entropy -> the abandon ... about phrase", entropyToMnemonic(new Uint8Array(16), wordlist) === ZERO_PHRASE);
check("BIP-39 phrase -> all-zero entropy", hex(mnemonicToEntropy(ZERO_PHRASE, wordlist)) === "00".repeat(16));
check("BIP-39 checksum: valid phrase accepted", validateMnemonic(ZERO_PHRASE, wordlist) === true);
check("BIP-39 checksum: wrong last word refused", validateMnemonic(ZERO_PHRASE.replace(/about$/, "abandon"), wordlist) === false);
check("BIP-39 seed with passphrase TREZOR",
    hex(mnemonicToSeedSync(ZERO_PHRASE, "TREZOR")) === "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
const fresh = generateMnemonic(wordlist, 128);
check("BIP-39 generated phrase: 12 words with a valid checksum", fresh.split(" ").length === 12 && validateMnemonic(fresh, wordlist));

// The checksums THIRD_PARTY_NOTICES.md lists, in `sha256sum` format, against the files.
const notices = fs.readFileSync(path.join(ROOT, "THIRD_PARTY_NOTICES.md"), "utf8");
const listed = [...notices.matchAll(/^([0-9a-f]{64}) {2}(js\/vendor\/\S+)$/gm)];
const vendorFiles = fs.readdirSync(path.join(ROOT, "js", "vendor")).map((f) => `js/vendor/${f}`).sort();
check("every file in js/vendor/ has a listed checksum",
    JSON.stringify(listed.map((m) => m[2]).sort()) === JSON.stringify(vendorFiles));
for (const [, sum, file] of listed) {
    const actual = crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT, file))).digest("hex");
    check(`${file}: SHA-256 as listed`, actual === sum);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
