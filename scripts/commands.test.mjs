// The commands and requests the front signs, against the indexer and the registrar that take them.
// Everything on this side is lifted out of js/app.js by marker - the key derivation
// (SecureWalletSession), the sha512 hook and every template that starts with the protocol marker -
// so a change to any of them is tested as it stands, not as a copy retyped here. For each network
// it signs the six command shapes (REG, BUY, UPD, CHG, LST, ULT) over several names and prices, a
// TXS request for both tabs and WDR requests over several amounts, and hands them to
// commands_check.php, which runs them through the indexer's own Protocol::parseCommand and builds
// the registrar's TXS/WDR strings with the expressions lifted from its API.
//
// Needs PHP 8.4+ with sodium, and the indexer's tree with its vendor/ installed:
//
//   INDEXER=/path/to/kerrigan-name-indexer node scripts/commands.test.mjs
//
// INDEXER defaults to ../kerrigan-name-indexer, beside this checkout.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as ed25519 from "../js/vendor/ed25519.js";
import { sha512 } from "../js/vendor/hashes.js";
import { entropyToMnemonic } from "../js/vendor/bip39.js";
import { wordlist } from "../js/vendor/wordlist.js";

const ROOT = path.join(import.meta.dirname, "..");
const INDEXER = path.resolve(process.env.INDEXER || path.join(ROOT, "..", "kerrigan-name-indexer"));
if (!fs.existsSync(path.join(INDEXER, "include", "Protocol.php")) ||
    !fs.existsSync(path.join(INDEXER, "vendor", "autoload.php"))) {
    console.error(`No indexer tree with vendor/ at ${INDEXER}: set INDEXER to one.`);
    process.exit(2);
}

const src = fs.readFileSync(path.join(ROOT, "js", "app.js"), "utf8");
const hook = src.match(/^ed25519\.etc\.sha512Sync = .*;$/m);
if (!hook) throw new Error("sha512Sync hook not found in app.js - did it move?");
new Function("ed25519", "sha512", hook[0])(ed25519, sha512);

const clsFrom = src.indexOf("class SecureWalletSession {");
const clsTo = src.indexOf("// Initialize globally for app access");
if (clsFrom < 0 || clsTo < clsFrom) throw new Error("SecureWalletSession not found in app.js - did it move?");
const Session = new Function("ed25519", "crypto", "TextEncoder",
    `${src.slice(clsFrom, clsTo)}\nreturn SecureWalletSession;`)(ed25519, globalThis.crypto, TextEncoder);

// Every template literal that starts with the protocol marker, in source order; each shape must be
// found exactly once.
const templates = [...src.matchAll(/`\$\{protocolMarker\(\)\}:1:[^`]*`/g)].map((m) => m[0]);
const pick = (needle) => {
    const found = templates.filter((t) => t.includes(needle));
    if (found.length !== 1) throw new Error(`template with ${needle}: ${found.length} found in app.js, 1 expected`);
    return found[0];
};
const T = {
    REGBUYUPD: pick(":1:${type}:${fullDomain}"),
    CHG: pick(":1:CHG:"),
    LST: pick(":1:LST:"),
    ULT: pick(":1:ULT:"),
    TXS: pick(":1:TXS:"),
    WDR: pick(":1:WDR:"),
};
// A template is rendered with exactly the names it uses: one the test does not give fails here.
const render = (tpl, vars) => new Function(...Object.keys(vars), `return ${tpl};`)(...Object.values(vars));

// Real addresses, from the corpus the circuit and the indexer are checked against.
const ADDR = {
    mainnet: ["ks1zakp8l6gscp7kamwzyqxe67sk35xmmfvdvfj5e8erjc57n6ge9d8alzh0x2ut4vuh3fhvdrrnwf",
              "ks14ge6h7x58v3le8zyrvxejha5gkvqvwy9emt23sudwxe5up44flxww0vuzv0rwgrqcd5m2mjtg44"],
    testnet: ["ktestsapling1xfxjd5wc803pt47xq3tsqt5k3qp9jkdmjrqv9u8l9jqhgftkzhs8ekjnpzcysz2gcz9qvx5kj0y",
              "ktestsapling197dutnjl4e58a6ayshfhk9wu5edr7h90m4jtp27cd3ysqc2dsglph64vtmqm5sm27dgwv6mhr2t"],
};

const phraseA = entropyToMnemonic(new Uint8Array(16).fill(1), wordlist);
const phraseB = entropyToMnemonic(new Uint8Array(32).fill(2), wordlist); // 24 words
const A = new Session(); await A.unlock(phraseA);
const B = new Session(); await B.unlock(phraseB);

const out = { keys: [], cases: [], requests: [] };
for (const [phrase, s] of [[phraseA, A], [phraseB, B]]) out.keys.push({ phrase, pub: s.getPublicKey() });

const nonce = 1780000000;
for (const net of ["mainnet", "testnet"]) {
    const marker = net === "testnet" ? "tKNS" : "KNS";
    const protocolMarker = () => marker;
    const [addr1, addr2] = ADDR[net];
    const longest = "a".repeat(64 - ".private".length) + ".private"; // the indexer's 64-byte cap
    const add = async (name, op, session, tpl, vars) => {
        const base = render(tpl, { protocolMarker, ...vars });
        out.cases.push({ net, name, op, memo: `${base}:${await session.sign(base)}` });
    };
    for (const domain of ["a.krgn", "b.kerrigan", "bob.safe", "x-1.secure", longest]) {
        for (const type of ["REG", "BUY", "UPD"]) {
            await add(`${type} ${domain}`, type, A, T.REGBUYUPD,
                { type, fullDomain: domain, targetAddr: addr1, pubKey: A.getPublicKey(), nonce });
        }
        await add(`CHG ${domain}`, "CHG", A, T.CHG, { fullDomain: domain, newOwner: B.getPublicKey(), nonce });
        for (const priceSat of [1, 600000000, 5e15]) {
            await add(`LST ${domain} ${priceSat}`, "LST", A, T.LST, { fullDomain: domain, pubKey: A.getPublicKey(), priceSat, nonce });
        }
        await add(`ULT ${domain}`, "ULT", A, T.ULT, { domain, userPubKey: A.getPublicKey(), nonce });
    }
    // Requests the registrar checks: the history (both tabs) and withdrawals. The front sends the
    // amount as the digit string of the balance in satoshi (handleWithdraw).
    for (const currentTransactionsTab of ["in", "ref"]) {
        const msg = render(T.TXS, { protocolMarker, currentTransactionsTab, userPubKey: A.getPublicKey(), page: 3, count: 25, nonce });
        out.requests.push({ net, kind: "TXS", fields: { type: currentTransactionsTab, pubkey: A.getPublicKey(), page: 3, count: 25, nonce },
            signature: await A.sign(msg) });
    }
    for (const amountSats of [1, 52631579, 12345678901, Number.MAX_SAFE_INTEGER]) {
        const amount = String(amountSats);
        const msg = render(T.WDR, { protocolMarker, userPubKey: A.getPublicKey(), address: addr2, amount, nonce: String(nonce) });
        out.requests.push({ net, kind: "WDR", fields: { pubkey: A.getPublicKey(), address: addr2, amount, nonce },
            signature: await A.sign(msg) });
    }
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kerrigan-name-commands-"));
const vectors = path.join(dir, "vectors.json");
let failed = 0;
try {
    fs.writeFileSync(vectors, JSON.stringify(out));
    for (const net of ["mainnet", "testnet"]) {
        const r = spawnSync("php", [path.join(import.meta.dirname, "commands_check.php"), vectors],
            { env: { ...process.env, NET: net, INDEXER }, encoding: "utf8" });
        process.stdout.write(r.stdout || "");
        process.stderr.write(r.stderr || "");
        if (r.error) console.error(`php could not be run: ${r.error.message}`);
        if (r.status !== 0) failed++;
    }
} finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
console.log(failed === 0 ? "\nall passed" : `\n${failed} network(s) failed`);
process.exit(failed === 0 ? 0 : 1);
