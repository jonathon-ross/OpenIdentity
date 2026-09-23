package org.openidentity.vectors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

/**
 * Generates P01 from the frozen OI-002 normative V01 vector.
 */
public final class W3cProjectionVectors {
    private static final String SPEC = "OpenIdentity W3C Identity Projection";
    private static final String VERSION = "0.1";
    private static final String OI_CONTEXT = "https://openidentity.foundation/ns/v1";
    private static final long ED25519_PUB_MULTICODEC = 0xEDL;
    private static final long ML_DSA_65_PUB_MULTICODEC = 0x1211L;

    private W3cProjectionVectors() {
    }

    public static void main(String[] args) {
        System.out.println("\nOpenIdentity W3C Projection Vector Generator\n============================================\n");
        try {
            Path root = projectRoot();
            Path source = root.resolve("test-vectors/cryptographic-agility-v0.1.json");
            Path output = root.resolve("test-vectors/w3c-projection-v0.1.json");
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> oi002 = mapper.readValue(source.toFile(), new TypeReference<Map<String, Object>>() {
            });
            Map<String, Object> v02 = requireVector(oi002, "V02");
            Map<String, Object> v03 = requireVector(oi002, "V03");
            Map<String, Object> v04 = requireVector(oi002, "V04");
            Map<String, Object> p01 = generateP01(requireVector(oi002, "V01"));
            Map<String, Object> p02 = generateP02(v02);
            Map<String, Object> p03 = generateP03(v03, v02, p02);
            Map<String, Object> p04 = generateP04(v04, p02);
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("specification", SPEC);
            doc.put("version", VERSION);
            doc.put("sourceSpecification", oi002.get("specification"));
            doc.put("sourceVersion", oi002.get("version"));
            doc.put("openIdentityContext", OI_CONTEXT);
            doc.put("vectors", List.of(p01, p02, p03, p04));
            new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(output.toFile(), doc);
            System.out.println("  [OK] Loaded frozen OI-002 V01-V04");
            System.out.println("  [OK] Derived P01 SINGLE Ed25519 projection");
            System.out.println("  [OK] Derived P02 hybrid Ed25519 + ML-DSA-65 projection");
            System.out.println("  [OK] ML-DSA-65 multicodec 0x1211 -> varint 91 24");
            System.out.println("  [OK] P03 consumed reversed V03 method/proof input order");
            System.out.println("  [OK] P03 canonical projection matches P02");
            System.out.println("  [OK] P04 preserves root DID across controller rotation");
            System.out.println("  [OK] P04 removes old controller methods and projects only new methods");
            System.out.println("  [OK] P04 preserves Threshold 2-of-2 semantics");
            System.out.println("  [OK] Generated " + output + "\n\nP01-P04 GENERATED SUCCESSFULLY");
        } catch (IOException e) {
            throw new IllegalStateException("Unable to generate W3C projection vectors", e);
        }
    }

    private static Map<String, Object> generateP01(Map<String, Object> v01) {
        byte[] identity = hex(req(v01, "identityHex")), methodId = hex(req(v01, "ed25519MethodIdHex")), pk = hex(req(v01, "ed25519PublicKeyHex"));
        len("V01 identity", identity, 32);
        len("V01 Ed25519 method ID", methodId, 16);
        len("V01 Ed25519 public key", pk, 32);
        String rootDid = "did:open:" + multibase58(identity);
        String fragment = "vm-u" + Base64.getUrlEncoder().withoutPadding().encodeToString(methodId);
        String methodUrl = rootDid + "#" + fragment;
        String publicKeyMultibase = multibase58(concat(varint(ED25519_PUB_MULTICODEC), pk));

        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("id", methodUrl);
        vm.put("type", "Multikey");
        vm.put("controller", rootDid);
        vm.put("publicKeyMultibase", publicKeyMultibase);
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("id", rootDid + "#controller-policy");
        policy.put("type", "Single");
        policy.put("appliesTo", "capabilityInvocation");
        policy.put("verificationMethod", List.of(methodUrl));
        Map<String, Object> did = new LinkedHashMap<>();
        did.put("@context", List.of("https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", OI_CONTEXT));
        did.put("id", rootDid);
        did.put("verificationMethod", List.of(vm));
        did.put("capabilityInvocation", List.of(methodUrl));
        did.put("openIdentityVerificationPolicy", policy);

        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", "P01");
        p.put("sourceVector", "V01");
        p.put("description", "SINGLE Ed25519 W3C projection");
        p.put("identityHex", req(v01, "identityHex"));
        p.put("rootDid", rootDid);
        p.put("methodIdHex", req(v01, "ed25519MethodIdHex"));
        p.put("methodFragment", fragment);
        p.put("methodDidUrl", methodUrl);
        p.put("algorithm", "Ed25519");
        p.put("publicKeyHex", req(v01, "ed25519PublicKeyHex"));
        p.put("publicKeyMultibase", publicKeyMultibase);
        p.put("capabilityInvocation", List.of(methodUrl));
        p.put("verificationPolicy", policy);
        p.put("didDocument", did);
        return p;
    }


    private static Map<String, Object> generateP02(Map<String, Object> v02) {
        byte[] identity = hex(req(v02, "identityHex"));
        byte[] edId = hex(req(v02, "ed25519MethodIdHex"));
        byte[] mlId = hex(req(v02, "mlDsa65MethodIdHex"));
        byte[] edPk = hex(req(v02, "ed25519PublicKeyHex"));
        byte[] mlPk = hex(req(v02, "mlDsa65PublicKeyHex"));

        len("V02 identity", identity, 32);
        len("V02 Ed25519 method ID", edId, 16);
        len("V02 ML-DSA-65 method ID", mlId, 16);
        len("V02 Ed25519 public key", edPk, 32);
        len("V02 ML-DSA-65 public key", mlPk, 1952);

        String rootDid = "did:open:" + multibase58(identity);

        Map<String, Object> ed = projectMethod(
                rootDid, edId, edPk, "Ed25519",
                ED25519_PUB_MULTICODEC, false);
        Map<String, Object> ml = projectMethod(
                rootDid, mlId, mlPk, "ML-DSA-65",
                ML_DSA_65_PUB_MULTICODEC, true);

        List<Map<String, Object>> projected = new ArrayList<>(List.of(ed, ml));
        projected.sort((a, b) -> compareUnsigned(
                hex((String) a.get("methodIdHex")),
                hex((String) b.get("methodIdHex"))));

        List<Map<String, Object>> vms = new ArrayList<>();
        List<String> urls = new ArrayList<>();
        for (Map<String, Object> m : projected) {
            urls.add((String) m.get("methodDidUrl"));
            Map<String, Object> vm = new LinkedHashMap<>();
            vm.put("id", m.get("methodDidUrl"));
            vm.put("type", "Multikey");
            vm.put("controller", rootDid);
            vm.put("publicKeyMultibase", m.get("publicKeyMultibase"));
            vms.add(vm);
        }

        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("id", rootDid + "#controller-policy");
        policy.put("type", "Threshold");
        policy.put("appliesTo", "capabilityInvocation");
        policy.put("threshold", 2);
        policy.put("verificationMethod", urls);

        Map<String, Object> did = new LinkedHashMap<>();
        did.put("@context", List.of(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                OI_CONTEXT));
        did.put("id", rootDid);
        did.put("verificationMethod", vms);
        did.put("capabilityInvocation", urls);
        did.put("openIdentityVerificationPolicy", policy);

        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", "P02");
        p.put("sourceVector", "V02");
        p.put("description",
                "Hybrid Ed25519 + ML-DSA-65 Threshold 2-of-2 W3C projection");
        p.put("identityHex", req(v02, "identityHex"));
        p.put("rootDid", rootDid);
        p.put("verificationMethods", projected);
        p.put("canonicalVerificationMethodOrder", urls);
        p.put("capabilityInvocation", urls);
        p.put("verificationPolicy", policy);
        p.put("didDocument", did);
        return p;
    }


    /**
     * P03 proves projection invariance under V03's deliberately reversed
     * construction order. V03 is an ordering vector and therefore carries the
     * reversed-order metadata plus canonical OI-002 outputs; the key material
     * is the same material established by V02. We require V03 to state the
     * expected reversed order, deliberately construct the projection in that
     * order, then canonicalize by the unsigned 16-byte method ID.
     */
    private static Map<String, Object> generateP03(
            Map<String, Object> v03,
            Map<String, Object> v02,
            Map<String, Object> p02) {

        List<String> expectedReversed = List.of("ML-DSA-65", "Ed25519");
        List<String> inputMethodOrder = stringList(v03, "inputMethodOrder");
        List<String> inputProofOrder = stringList(v03, "inputProofOrder");

        if (!inputMethodOrder.equals(expectedReversed)) {
            throw new IllegalStateException(
                    "V03 inputMethodOrder must be [ML-DSA-65, Ed25519]");
        }
        if (!inputProofOrder.equals(expectedReversed)) {
            throw new IllegalStateException(
                    "V03 inputProofOrder must be [ML-DSA-65, Ed25519]");
        }

        byte[] identity = hex(req(v02, "identityHex"));
        byte[] edId = hex(req(v02, "ed25519MethodIdHex"));
        byte[] mlId = hex(req(v02, "mlDsa65MethodIdHex"));
        byte[] edPk = hex(req(v02, "ed25519PublicKeyHex"));
        byte[] mlPk = hex(req(v02, "mlDsa65PublicKeyHex"));

        len("V03/V02 identity", identity, 32);
        len("V03/V02 Ed25519 method ID", edId, 16);
        len("V03/V02 ML-DSA-65 method ID", mlId, 16);
        len("V03/V02 Ed25519 public key", edPk, 32);
        len("V03/V02 ML-DSA-65 public key", mlPk, 1952);

        String rootDid = "did:open:" + multibase58(identity);

        // Deliberately construct in V03's reversed input order.
        Map<String, Object> ml = projectMethod(
                rootDid, mlId, mlPk, "ML-DSA-65",
                ML_DSA_65_PUB_MULTICODEC, true);
        Map<String, Object> ed = projectMethod(
                rootDid, edId, edPk, "Ed25519",
                ED25519_PUB_MULTICODEC, false);

        List<Map<String, Object>> projected =
                new ArrayList<>(List.of(ml, ed));

        List<String> observedConstructionOrder = projected.stream()
                .map(m -> (String) m.get("algorithm"))
                .toList();
        if (!observedConstructionOrder.equals(expectedReversed)) {
            throw new IllegalStateException(
                    "P03 did not begin in the V03 reversed method order");
        }

        // Canonicalize exactly as P02 does: unsigned lexicographic method ID.
        projected.sort((a, b) -> compareUnsigned(
                hex((String) a.get("methodIdHex")),
                hex((String) b.get("methodIdHex"))));

        List<Map<String, Object>> vms = new ArrayList<>();
        List<String> urls = new ArrayList<>();
        for (Map<String, Object> m : projected) {
            urls.add((String) m.get("methodDidUrl"));
            Map<String, Object> vm = new LinkedHashMap<>();
            vm.put("id", m.get("methodDidUrl"));
            vm.put("type", "Multikey");
            vm.put("controller", rootDid);
            vm.put("publicKeyMultibase", m.get("publicKeyMultibase"));
            vms.add(vm);
        }

        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("id", rootDid + "#controller-policy");
        policy.put("type", "Threshold");
        policy.put("appliesTo", "capabilityInvocation");
        policy.put("threshold", 2);
        policy.put("verificationMethod", urls);

        Map<String, Object> did = new LinkedHashMap<>();
        did.put("@context", List.of(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                OI_CONTEXT));
        did.put("id", rootDid);
        did.put("verificationMethod", vms);
        did.put("capabilityInvocation", urls);
        did.put("openIdentityVerificationPolicy", policy);

        // Generator-side invariant: P03 semantic projection MUST equal P02.
        if (!Objects.equals(rootDid, p02.get("rootDid"))
                || !Objects.equals(projected, p02.get("verificationMethods"))
                || !Objects.equals(urls, p02.get("capabilityInvocation"))
                || !Objects.equals(policy, p02.get("verificationPolicy"))
                || !Objects.equals(did, p02.get("didDocument"))) {
            throw new IllegalStateException(
                    "P03 canonical projection does not match P02");
        }

        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", "P03");
        p.put("sourceVector", "V03");
        p.put("description",
                "Canonical projection invariance with reversed method and proof input");
        p.put("inputMethodOrder", inputMethodOrder);
        p.put("inputProofOrder", inputProofOrder);
        p.put("rootDid", rootDid);
        p.put("verificationMethods", projected);
        p.put("canonicalVerificationMethodOrder", urls);
        p.put("capabilityInvocation", urls);
        p.put("verificationPolicy", policy);
        p.put("didDocument", did);
        p.put("canonicalProjectionMatches", "P02");
        return p;
    }


    /**
     * P04 projects the resulting controller state of normative V04.
     * The root identity remains stable while all old controller methods are
     * removed from the active projection and replaced by the new controller
     * methods proven by V04's ROTATE_CONTROLLER operation.
     */
    private static Map<String, Object> generateP04(
            Map<String, Object> v04,
            Map<String, Object> p02) {

        byte[] identity = hex(req(v04, "identityHex"));
        byte[] oldEdId = hex(req(v04, "oldEd25519MethodIdHex"));
        byte[] oldMlId = hex(req(v04, "oldMlDsa65MethodIdHex"));
        byte[] newEdId = hex(req(v04, "newEd25519MethodIdHex"));
        byte[] newMlId = hex(req(v04, "newMlDsa65MethodIdHex"));
        byte[] newEdPk = hex(req(v04, "newEd25519PublicKeyHex"));
        byte[] newMlPk = hex(req(v04, "newMlDsa65PublicKeyHex"));

        len("V04 identity", identity, 32);
        len("V04 old Ed25519 method ID", oldEdId, 16);
        len("V04 old ML-DSA-65 method ID", oldMlId, 16);
        len("V04 new Ed25519 method ID", newEdId, 16);
        len("V04 new ML-DSA-65 method ID", newMlId, 16);
        len("V04 new Ed25519 public key", newEdPk, 32);
        len("V04 new ML-DSA-65 public key", newMlPk, 1952);

        int oldThreshold = intValue(v04, "oldControllerThreshold");
        int newThreshold = intValue(v04, "newControllerThreshold");
        if (oldThreshold != 2 || newThreshold != 2) {
            throw new IllegalStateException(
                    "V04 must preserve controller threshold 2");
        }

        String rootDid = "did:open:" + multibase58(identity);
        if (!Objects.equals(rootDid, p02.get("rootDid"))) {
            throw new IllegalStateException(
                    "V04 rotation changed the stable root DID");
        }

        Map<String, Object> newEd = projectMethod(
                rootDid, newEdId, newEdPk, "Ed25519",
                ED25519_PUB_MULTICODEC, false);
        Map<String, Object> newMl = projectMethod(
                rootDid, newMlId, newMlPk, "ML-DSA-65",
                ML_DSA_65_PUB_MULTICODEC, true);

        List<Map<String, Object>> projected =
                new ArrayList<>(List.of(newEd, newMl));
        projected.sort((a, b) -> compareUnsigned(
                hex((String) a.get("methodIdHex")),
                hex((String) b.get("methodIdHex"))));

        List<Map<String, Object>> vms = new ArrayList<>();
        List<String> newUrls = new ArrayList<>();
        for (Map<String, Object> m : projected) {
            newUrls.add((String) m.get("methodDidUrl"));
            Map<String, Object> vm = new LinkedHashMap<>();
            vm.put("id", m.get("methodDidUrl"));
            vm.put("type", "Multikey");
            vm.put("controller", rootDid);
            vm.put("publicKeyMultibase", m.get("publicKeyMultibase"));
            vms.add(vm);
        }

        List<String> removedUrls = new ArrayList<>(List.of(
                rootDid + "#vm-u" + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(oldEdId),
                rootDid + "#vm-u" + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(oldMlId)));
        removedUrls.sort(String::compareTo);

        Set<String> active = new HashSet<>(newUrls);
        for (String oldUrl : removedUrls) {
            if (active.contains(oldUrl)) {
                throw new IllegalStateException(
                        "P04 old controller method remained active: " + oldUrl);
            }
        }

        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("id", rootDid + "#controller-policy");
        policy.put("type", "Threshold");
        policy.put("appliesTo", "capabilityInvocation");
        policy.put("threshold", newThreshold);
        policy.put("verificationMethod", newUrls);

        Map<String, Object> did = new LinkedHashMap<>();
        did.put("@context", List.of(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                OI_CONTEXT));
        did.put("id", rootDid);
        did.put("verificationMethod", vms);
        did.put("capabilityInvocation", newUrls);
        did.put("openIdentityVerificationPolicy", policy);

        // Ensure none of the previous P02 active method URLs survive.
        Object previousCaps = p02.get("capabilityInvocation");
        if (!(previousCaps instanceof List<?> oldActive)
                || oldActive.size() != removedUrls.size()
                || !new HashSet<>(oldActive).equals(new HashSet<>(removedUrls))) {
            throw new IllegalStateException(
                    "V04 old controller methods do not correspond to P02");
        }
        for (Object oldUrl : oldActive) {
            if (newUrls.contains(oldUrl)) {
                throw new IllegalStateException(
                        "P04 capabilityInvocation still contains old authority");
            }
        }

        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", "P04");
        p.put("sourceVector", "V04");
        p.put("description", "Controller rotation W3C projection");
        p.put("previousProjection", "P02");
        p.put("sequence", intValue(v04, "sequence"));
        p.put("identityHex", req(v04, "identityHex"));
        p.put("rootDid", rootDid);
        p.put("removedVerificationMethods", removedUrls);
        p.put("verificationMethods", projected);
        p.put("canonicalVerificationMethodOrder", newUrls);
        p.put("capabilityInvocation", newUrls);
        p.put("verificationPolicy", policy);
        p.put("didDocument", did);
        return p;
    }

    private static int intValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Number number)) {
            throw new IllegalStateException(
                    "Missing required numeric field: " + key);
        }
        return number.intValue();
    }

    private static List<String> stringList(
            Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof List<?> list)) {
            throw new IllegalStateException("Missing required array field: " + key);
        }
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String s) || s.isBlank()) {
                throw new IllegalStateException(
                        "Field " + key + " must contain only non-empty strings");
            }
            out.add(s);
        }
        return List.copyOf(out);
    }

    private static Map<String, Object> projectMethod(
            String rootDid, byte[] methodId, byte[] publicKey,
            String algorithm, long multicodec, boolean useBase64Url) {

        String fragment = "vm-u" +
                Base64.getUrlEncoder().withoutPadding().encodeToString(methodId);
        String didUrl = rootDid + "#" + fragment;
        byte[] prefix = varint(multicodec);

        if (algorithm.equals("ML-DSA-65")
                && !Arrays.equals(prefix, new byte[]{(byte) 0x91, 0x24})) {
            throw new IllegalStateException(
                    "ML-DSA-65 multicodec 0x1211 must encode as uvarint 0x91 0x24");
        }

        byte[] encodedKey = concat(prefix, publicKey);
        String publicKeyMultibase = useBase64Url
                ? "u" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(encodedKey)
                : multibase58(encodedKey);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("algorithm", algorithm);
        out.put("methodIdHex", toHex(methodId));
        out.put("methodFragment", fragment);
        out.put("methodDidUrl", didUrl);
        out.put("publicKeyHex", toHex(publicKey));
        out.put("multicodec",
                algorithm.equals("ML-DSA-65") ? "0x1211" : "0xed");
        out.put("multibaseEncoding",
                useBase64Url ? "base64url-no-pad" : "base58btc");
        out.put("publicKeyMultibase", publicKeyMultibase);
        return out;
    }

    private static int compareUnsigned(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int ai = Byte.toUnsignedInt(a[i]);
            int bi = Byte.toUnsignedInt(b[i]);
            if (ai != bi) return Integer.compare(ai, bi);
        }
        return Integer.compare(a.length, b.length);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder s = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) s.append(String.format("%02x", b & 0xff));
        return s.toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> requireVector(Map<String, Object> d, String id) {
        Object x = d.get("valid");
        if (!(x instanceof List<?> l)) throw new IllegalStateException("OI-002 document does not contain valid[]");
        for (Object o : l) if (o instanceof Map<?, ?> m && id.equals(m.get("id"))) return (Map<String, Object>) m;
        throw new IllegalStateException("Missing OI-002 vector " + id);
    }

    private static String req(Map<String, Object> m, String k) {
        Object v = m.get(k);
        if (!(v instanceof String s) || s.isBlank()) throw new IllegalStateException("Missing required field: " + k);
        return s;
    }

    private static Path projectRoot() {
        Path c = Path.of("").toAbsolutePath().normalize();
        if (Files.exists(c.resolve("test-vectors/cryptographic-agility-v0.1.json"))) return c;
        Path p = c.resolve("../..").normalize();
        if (Files.exists(p.resolve("test-vectors/cryptographic-agility-v0.1.json"))) return p;
        throw new IllegalStateException("Unable to locate test-vectors/cryptographic-agility-v0.1.json from " + c);
    }

    private static byte[] hex(String s) {
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("Odd hex");
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++) {
            int a = Character.digit(s.charAt(2 * i), 16), b = Character.digit(s.charAt(2 * i + 1), 16);
            if (a < 0 || b < 0) throw new IllegalArgumentException("Invalid hex");
            o[i] = (byte) ((a << 4) | b);
        }
        return o;
    }

    private static void len(String n, byte[] v, int e) {
        if (v.length != e) throw new IllegalStateException(n + " length expected " + e + " but got " + v.length);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    private static byte[] varint(long v) {
        byte[] t = new byte[10];
        int n = 0;
        do {
            int b = (int) (v & 0x7f);
            v >>>= 7;
            if (v != 0) b |= 0x80;
            t[n++] = (byte) b;
        } while (v != 0);
        return Arrays.copyOf(t, n);
    }

    private static String multibase58(byte[] b) {
        return "z" + base58(b);
    }

    private static String base58(byte[] in) {
        if (in.length == 0) return "";
        String a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        BigInteger n = new BigInteger(1, in), base = BigInteger.valueOf(58);
        StringBuilder s = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] q = n.divideAndRemainder(base);
            s.append(a.charAt(q[1].intValue()));
            n = q[0];
        }
        for (byte b : in) {
            if (b == 0) s.append('1');
            else break;
        }
        return s.reverse().toString();
    }
}
