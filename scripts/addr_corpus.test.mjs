// Checks the front-end's isValidKerriganAddress against the same corpus kns-core (the circuit)
// and the indexer's Protocol::isAddressValid are checked against.
//
// The three implementations must agree exactly. A front-end looser than the circuit lets a
// user pay for a command the prover cannot prove; a stricter one rejects valid addresses.
//
//   ADDR_CORPUS=/path/to/addr_corpus.json node scripts/addr_corpus.test.mjs
//
// The corpus and its verdicts come from kerrigan-name-prover/docs/reference/gen_addr_corpus.py.
import fs from "node:fs";
import path from "node:path";
import { bech32m } from "../js/vendor/bech32.js";

const SRC = path.join(import.meta.dirname, "..", "js", "app.js");
const src = fs.readFileSync(SRC, "utf8");

// Lift the real implementation out of app.js by marker, so this test breaks loudly if the
// source moves rather than silently testing a stale copy.
const from = src.indexOf("// Accepted Kerrigan Sapling address shape per network.");
const to = src.indexOf("// Pass maxLength = null to skip the length check");
const end = src.indexOf("\n}", src.indexOf("function isValidKerriganAddress")) + 2;
if (from < 0 || to < from || end < to) throw new Error("markers not found — did app.js change?");
const block = src.slice(from, end);

const factory = new Function("bech32m", `${block}
  return { isValidKerriganAddress, setNetwork: (n) => { kerriganNetwork = n; } };`);
const { isValidKerriganAddress, setNetwork } = factory(bech32m);

// Defaults to the fixture shipped beside this test, so the suite runs anywhere with no
// setup. ADDR_CORPUS overrides it when checking against a freshly generated corpus.
const corpusPath = process.env.ADDR_CORPUS
  ?? path.join(import.meta.dirname, "fixtures", "addr_corpus.json");
const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));

let failed = 0;
for (const net of ["mainnet", "testnet"]) {
  setNetwork(net);
  const bad = [];
  for (const c of corpus) {
    // maxLength null: the corpus tests the address form, not the memo budget.
    const got = isValidKerriganAddress(c.addr, null);
    if (got !== c[net]) bad.push(`${c.addr.slice(0, 30)} (${c.why}): expected ${c[net]}, got ${got}`);
  }
  console.log(`  ${corpus.length} corpus cases (${net}): ${bad.length === 0 ? "all agree" : `${bad.length} DISAGREE`}`);
  for (const b of bad.slice(0, 10)) console.log(`    ${b}`);
  failed += bad.length;
}

process.exit(failed === 0 ? 0 : 1);
