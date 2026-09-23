#!/usr/bin/env node
/**
 * Independent jsonld.js verifier for OpenIdentity JSON-LD context candidate.
 *
 * Usage:
 *   npm install
 *   node verify_openidentity_context.mjs ../../contexts/openidentity-v1.jsonld
 */
import fs from "node:fs/promises";
import process from "node:process";
import jsonld from "jsonld";

const NS = "https://openidentity.foundation/ns#";
const XSD_INT = "http://www.w3.org/2001/XMLSchema#integer";
const URL = "https://openidentity.foundation/ns/v1";

function fail(m) {
    console.error("\nFAILED\n------\n" + m + "\n");
    process.exit(1);
}

function ok(m) {
    console.log("  " + m + ": PASS");
}

const file = process.argv[2];
if (!file) fail("Usage: node verify_openidentity_context.mjs <context-file>");

let ctx;
try {
    ctx = JSON.parse(await fs.readFile(file, "utf8"));
} catch (e) {
    fail("Unable to load context: " + e.message);
}

const documentLoader = async url => {
    if (url === URL) return {contextUrl: null, documentUrl: url, document: ctx};
    throw new Error("Remote context blocked by verifier: " + url);
};

console.log("\nOpenIdentity jsonld.js Context Verification\n" + "=".repeat(48));

const c = ctx["@context"];
const required = ["openIdentityVerificationPolicy", "appliesTo", "threshold", "Single", "Threshold"];
if (!c || typeof c !== "object" || c["@protected"] !== true || required.some(x => !(x in c)))
    fail("J01 context structure invalid");
ok("J01 context structure/load");

const local = {
    id: "@id", type: "@type",
    verificationMethod: {
        "@id": "https://www.w3.org/ns/did#verificationMethod",
        "@type": "@id", "@container": "@set"
    },
    capabilityInvocation: {
        "@id": "https://www.w3.org/ns/did#capabilityInvocation",
        "@type": "@id", "@container": "@set"
    }
};
const tc = [URL, local];

const thresholdDoc = {
    "@context": tc,
    id: "did:open:zExample#controller-policy",
    type: "Threshold",
    appliesTo: "capabilityInvocation",
    threshold: 2,
    verificationMethod: ["did:open:zExample#vm-A", "did:open:zExample#vm-B"]
};

let expanded;
try {
    expanded = await jsonld.expand(thresholdDoc, {documentLoader});
} catch (e) {
    fail("J02 expansion failed: " + e.message);
}
if (!expanded.length || !(expanded[0]["@type"] || []).includes(NS + "Threshold"))
    fail("J02 Threshold type expansion incorrect");
const tv = expanded[0][NS + "threshold"];
if (!tv?.length || tv[0]["@value"] !== 2 || tv[0]["@type"] !== XSD_INT)
    fail("J02 threshold datatype/value incorrect");
ok("J02 Threshold expansion");

const singleDoc = {...thresholdDoc, type: "Single", verificationMethod: ["did:open:zExample#vm-A"]};
delete singleDoc.threshold;
let sx;
try {
    sx = await jsonld.expand(singleDoc, {documentLoader});
} catch (e) {
    fail("J03 SINGLE expansion failed: " + e.message);
}
if (!sx.length || !(sx[0]["@type"] || []).includes(NS + "Single"))
    fail("J03 Single type expansion incorrect");
ok("J03 SINGLE expansion");

let compact, reexpanded;
try {
    compact = await jsonld.compact(expanded, tc, {documentLoader});
    reexpanded = await jsonld.expand(compact, {documentLoader});
} catch (e) {
    fail("J04 round trip failed: " + e.message);
}
const canon = x => JSON.stringify(x, (k, v) => {
    if (Array.isArray(v)) return v.map(y => y);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)));
    return v;
});
if (canon(expanded) !== canon(reexpanded)) fail("J04 semantic round trip changed expansion");
ok("J04 semantic round trip");

const bad = {"@context": [URL, {threshold: "https://evil.example/threshold"}], threshold: 2};
let rejected = false;
try {
    await jsonld.expand(bad, {documentLoader});
} catch {
    rejected = true;
}
if (!rejected) fail("J05 protected term redefinition accepted");
ok("J05 protected-term redefinition rejected");

if ("@vocab" in c) fail("J06 context MUST NOT define @vocab");
let ux;
try {
    ux = await jsonld.expand({"@context": URL, totallyUnknownOpenIdentityTerm: "value"}, {documentLoader});
} catch (e) {
    fail("J06 unknown-term expansion failed: " + e.message);
}
if (ux.length && (NS + "totallyUnknownOpenIdentityTerm") in ux[0])
    fail("J06 unknown term leaked into OpenIdentity namespace");
ok("J06 no accidental vocabulary leakage");

const vp = c.openIdentityVerificationPolicy;
if (vp && typeof vp === "object" && vp["@type"] === "@id")
    fail("J07 openIdentityVerificationPolicy incorrectly coerces embedded object to @id");
ok("J07 embedded policy property has no @id coercion");

console.log("\n" + "=".repeat(48));
console.log("OPENIDENTITY JSONLD.JS CONTEXT CANDIDATE PASSED");
console.log("=".repeat(48) + "\n");
