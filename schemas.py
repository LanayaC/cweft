"""
Per-CWE repair knowledge for L3a (free-text) and L3b (structured schema).

CRITICAL: Each CWE entry has a `prose` field and a `schema` field that
encode IDENTICAL repair knowledge in different forms. The L3a vs. L3b
experimental contrast depends on this content parity:

    - prose:  a paragraph of natural language describing the canonical fix
    - schema: the same information as four typed fields:
              root_cause, canonical_repair, constraints, what_to_avoid

Knowledge sourced from:
    1. APR4Vul's mined fix-pattern tables [Bui et al. 2024]
    2. MITRE CWE remediation guidance for CWEs APR4Vul did not study
    3. OWASP secure-coding cheat sheets for canonical-repair specifics

When adding a new CWE entry, write the four schema fields FIRST, then
compose the prose so that every fact in the prose appears verbatim or
in close paraphrase among the four fields. This keeps the L3a/L3b
content contrast clean.
"""

from typing import Dict


# ──────────────────────────────────────────────────────────────────────
# Schema type (informal — Python doesn't enforce dict shape)
#
# CWE_SCHEMAS[cwe_id] = {
#     "prose":  str,                  # used by L3a
#     "schema": {                     # used by L3b
#         "root_cause":       str,
#         "canonical_repair": str,
#         "constraints":      str,
#         "what_to_avoid":    str,
#     },
# }
# ──────────────────────────────────────────────────────────────────────


CWE_SCHEMAS: Dict[str, Dict] = {

    # ──────────────────────────────────────────────────────────────────
    "CWE-19": {
        "prose": (
            "Data processing errors of this form arise when untrusted input "
            "flows into a parser, formatter, or transformation step that "
            "treats it as structurally trusted. The canonical repair is to "
            "validate the input against the expected structure before it "
            "reaches the parser, and to constrain dangerous parser features "
            "such as expression evaluation, recursive expansion, or external "
            "reference resolution. Preserve all caller-visible signatures and "
            "exception types; avoid catch-and-ignore patterns that mask the "
            "underlying parsing failure."
        ),
        "schema": {
            "root_cause":       "Untrusted input flows into a parser or transformation step that treats it as structurally trusted.",
            "canonical_repair": "Validate input against expected structure before parsing, and constrain dangerous parser features (expression evaluation, recursive expansion, external references).",
            "constraints":      "Preserve method signatures and declared exception types; do not break callers.",
            "what_to_avoid":    "Catch-and-ignore patterns; relying on output sanitization instead of input validation.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-20": {
        "prose": (
            "Improper input validation is fixed by adding explicit checks at "
            "the trust boundary before the input is used in a downstream "
            "operation. Validate type, length, range, format, and any "
            "structural invariants the downstream code relies on. Reject "
            "invalid input by throwing an appropriate exception or returning "
            "an error rather than silently sanitizing. Preserve the existing "
            "method signature and exception types so callers do not break, "
            "and avoid validating only some code paths while leaving sibling "
            "paths unchecked."
        ),
        "schema": {
            "root_cause":       "External input is consumed by downstream logic without prior validation of type, length, range, format, or structural invariants.",
            "canonical_repair": "Add explicit validation at the trust boundary before use; reject invalid input via exception or error return.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Silent sanitization; validating only some entry points while leaving others unchecked.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-22": {
        "prose": (
            "Path traversal is fixed by canonicalizing the user-supplied path "
            "and verifying that the result remains within an allowed base "
            "directory before any file operation. Use File.getCanonicalPath() "
            "or Path.normalize().toAbsolutePath() to resolve all . and .. "
            "segments, then check that the canonical result starts with the "
            "canonical base. Preserve the original method signature and "
            "exception types. Do not rely on String.contains(\"..\") checks "
            "or simple replace() calls — these can be bypassed with encoded "
            "or composite traversal sequences."
        ),
        "schema": {
            "root_cause":       "Untrusted path fragment used in file resolution without normalization against an allowed base.",
            "canonical_repair": "Canonicalize the resolved path (getCanonicalPath / normalize) and verify startsWith(canonical base) before any file operation.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "String.contains(\"..\") or replace(\"..\", \"\") checks; encoded variants bypass them.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-74": {
        "prose": (
            "Injection of special elements into a downstream component is "
            "fixed by separating data from control. Use parameterized APIs "
            "(prepared statements, builder interfaces) so the framework "
            "escapes data correctly, or apply a context-appropriate encoder "
            "to the data before it concatenates into the downstream string. "
            "Validate input against an allowlist of expected shapes where "
            "feasible. Preserve method signatures and exception types; avoid "
            "ad-hoc string replacement, which misses encoded variants."
        ),
        "schema": {
            "root_cause":       "Untrusted data is concatenated into a string passed to a downstream interpreter without separating data from control.",
            "canonical_repair": "Use parameterized APIs (prepared statements / builders) or a context-appropriate encoder; validate against an allowlist where feasible.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Ad-hoc string replacement; encoded variants bypass it.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-77": {
        "prose": (
            "Command injection is fixed by separating program arguments from "
            "the program string. Pass arguments as a list to ProcessBuilder "
            "or Runtime.exec(String[]) rather than concatenating into a shell "
            "command line. Where shell invocation is genuinely required, "
            "escape arguments with a quoting helper that handles single "
            "quotes, double quotes, backticks, and semicolons. Preserve the "
            "method signature and exception types. Do not rely on blocking "
            "specific characters — attackers vary their encoding."
        ),
        "schema": {
            "root_cause":       "Untrusted data is concatenated into a shell command string instead of being passed as a separated argument list.",
            "canonical_repair": "Pass arguments as a list to ProcessBuilder / Runtime.exec(String[]); if a shell is required, quote arguments with a helper that handles all metacharacters.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Character blocklists; attackers vary encoding to bypass them.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-79": {
        "prose": (
            "Cross-site scripting is fixed by applying context-appropriate "
            "output encoding to all untrusted data inserted into a page. "
            "HTML body text needs HTML entity encoding; attribute values need "
            "attribute-context encoding; JavaScript string literals need "
            "JS-string encoding; URLs need percent-encoding. Use an established "
            "encoder such as OWASP Java Encoder or the project's existing "
            "sanitizer rather than a hand-rolled function. Preserve method "
            "signatures and exception types. Do not strip tags as a primary "
            "defense — encoded or fragmented variants bypass tag-stripping."
        ),
        "schema": {
            "root_cause":       "Untrusted data is inserted into a page without context-appropriate output encoding.",
            "canonical_repair": "Apply HTML / attribute / JS-string / URL encoding via an established encoder library, matched to the insertion context.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Tag stripping as primary defense; encoded variants bypass it.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-200": {
        "prose": (
            "Information exposure is fixed by removing sensitive data from "
            "any output path reachable by an untrusted observer. Replace the "
            "exposed field with a redacted or aggregate value, or restrict "
            "the output to a privileged endpoint, depending on which observer "
            "is the threat. Preserve method signatures and exception types. "
            "Avoid the temptation to fix one observer while leaving the data "
            "in logs, error messages, or debug output where another observer "
            "can read it."
        ),
        "schema": {
            "root_cause":       "Sensitive data is included in an output path reachable by an unintended observer.",
            "canonical_repair": "Redact, aggregate, or restrict the output; remove sensitive fields from logs, error messages, and debug output as well.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Fixing only one output channel; the same data often leaks via logs or errors.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-254": {
        "prose": (
            "Weaknesses in security feature implementation are fixed by "
            "tightening the feature's enforcement rather than disabling it. "
            "If a check is missing, add it at the trust boundary; if a check "
            "is bypassable, close the bypass; if a default is unsafe, change "
            "the default. Preserve the public API and exception types. Do "
            "not introduce a new flag that allows callers to disable the "
            "check — opt-out flags are how the original vulnerability was "
            "introduced."
        ),
        "schema": {
            "root_cause":       "An existing security feature is incomplete, bypassable, or defaults to an unsafe configuration.",
            "canonical_repair": "Tighten the check at the trust boundary, close bypass paths, and change unsafe defaults to safe ones.",
            "constraints":      "Preserve public API and declared exception types.",
            "what_to_avoid":    "Opt-out flags that let callers disable the check; this reintroduces the original weakness.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-264": {
        "prose": (
            "Permission and access-control flaws are fixed by enforcing the "
            "authorization check at every entry point the protected resource "
            "is reachable from. Identify the principal making the request, "
            "look up the required permission, and reject the operation if "
            "the principal lacks it. Preserve method signatures and exception "
            "types. Do not rely on client-side checks, hidden URL paths, or "
            "framework defaults — attackers will reach the resource through "
            "whichever path enforces nothing."
        ),
        "schema": {
            "root_cause":       "A protected resource is reachable through an entry point that does not enforce the required authorization check.",
            "canonical_repair": "Enforce the authorization check at every entry point reaching the resource; reject the operation if the principal lacks the required permission.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Relying on client-side checks, hidden URLs, or framework defaults; attackers find unguarded entry points.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-269": {
        "prose": (
            "Improper privilege management is fixed by adjusting the privilege "
            "boundary so that elevated operations run with the minimum "
            "privilege necessary and revert to lower privilege immediately "
            "after. Verify that the principal is authorized to request the "
            "elevation before granting it, and that the elevated scope is "
            "narrow. Preserve method signatures and exception types. Do not "
            "elevate broadly and rely on downstream checks to constrain — the "
            "elevation window itself is the attack surface."
        ),
        "schema": {
            "root_cause":       "Code runs at higher privilege than required, or fails to revert to lower privilege after a privileged operation.",
            "canonical_repair": "Limit the elevated scope, verify the principal is authorized to request elevation, and revert to lower privilege immediately after.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Broad elevation with downstream-only constraints; the elevation window is the attack surface.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-284": {
        "prose": (
            "Improper access control is fixed by adding an authorization "
            "check at every entry to the protected resource. Identify the "
            "subject, look up the required permission, and enforce it before "
            "the operation proceeds. Preserve method signatures and exception "
            "types. Avoid implicit trust based on network position, request "
            "shape, or the presence of a session — attackers control all of "
            "these."
        ),
        "schema": {
            "root_cause":       "Resource access is granted without a check that the subject is authorized.",
            "canonical_repair": "Add an explicit authorization check at the resource boundary; reject unauthorized subjects.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Implicit trust based on network position, request shape, or session existence.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-287": {
        "prose": (
            "Improper authentication is fixed by verifying the asserted "
            "identity through a credential or token whose integrity and "
            "freshness are checked, rather than trusting an identity claim "
            "in isolation. Validate signatures, check expiration, and resolve "
            "the identity through the project's authentication subsystem "
            "rather than client-supplied fields. Preserve method signatures "
            "and exception types. Do not accept the alg=none JWT pattern, "
            "unsigned tokens, or self-asserted user IDs."
        ),
        "schema": {
            "root_cause":       "Identity is established from a self-asserted claim without verifying credential integrity and freshness.",
            "canonical_repair": "Verify signature, check expiration, and resolve identity through the authentication subsystem.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Accepting alg=none JWTs, unsigned tokens, or self-asserted identity fields.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-310": {
        "prose": (
            "Cryptographic weaknesses are fixed by replacing the broken or "
            "misconfigured primitive with a current secure choice. Use "
            "authenticated encryption (AES-GCM) instead of CBC without "
            "integrity; use a modern KDF (PBKDF2, scrypt, Argon2) instead "
            "of raw hashing; use SHA-256 or stronger instead of MD5 or SHA-1; "
            "use SecureRandom rather than Random. Preserve method signatures "
            "and exception types. Do not hand-roll cryptographic logic or "
            "extend a broken primitive with a counter or salt to make it "
            "appear safe — the underlying primitive is the problem."
        ),
        "schema": {
            "root_cause":       "Use of a broken or misconfigured cryptographic primitive (weak hash, missing integrity, predictable RNG, etc.).",
            "canonical_repair": "Replace with a current secure choice: AES-GCM for encryption, modern KDFs for password hashing, SHA-256+ for digests, SecureRandom for randomness.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Hand-rolling crypto; patching a broken primitive with counters or salts.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-345": {
        "prose": (
            "Insufficient verification of data authenticity is fixed by "
            "binding the data to its expected source via a verifiable "
            "credential — a signature, MAC, or cryptographic hash compared "
            "against a trusted reference. Verify before any decision that "
            "depends on the data's origin. Preserve method signatures and "
            "exception types. Do not rely on source IP, hostname, "
            "Content-Type, or other unauthenticated metadata to establish "
            "authenticity."
        ),
        "schema": {
            "root_cause":       "Data is acted on as authentic without verifying it against a credential bound to its expected source.",
            "canonical_repair": "Verify a signature, MAC, or hash before any decision that depends on origin.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Trusting source IP, hostname, Content-Type, or other unauthenticated metadata.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-352": {
        "prose": (
            "Cross-site request forgery is fixed by binding each state-"
            "changing request to a token the attacker cannot predict and "
            "the server can verify came from the legitimate session. "
            "Generate the token server-side, embed it in forms and AJAX "
            "headers, and reject any state-changing request whose token "
            "does not match. Preserve method signatures and exception types. "
            "Do not rely on the Referer or Origin header alone — they can be "
            "stripped or forged in some contexts."
        ),
        "schema": {
            "root_cause":       "State-changing requests are accepted without proof that they originated from the legitimate user session.",
            "canonical_repair": "Generate a per-session CSRF token, embed it in forms and headers, and verify it on every state-changing request.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Relying on Referer/Origin alone; they can be stripped or absent.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-502": {
        "prose": (
            "Deserialization of untrusted data is fixed by restricting which "
            "classes the deserializer is permitted to instantiate. Install "
            "an allowlist via ObjectInputFilter, a class blacklist as a "
            "secondary defense, or replace the unsafe serializer with a "
            "data-only format such as JSON with a strict schema. Preserve "
            "method signatures and exception types. Do not attempt to detect "
            "malicious payloads heuristically — the canonical attack uses "
            "gadget chains in classes the application already trusts."
        ),
        "schema": {
            "root_cause":       "Untrusted bytes are deserialized into arbitrary class instances, allowing gadget-chain attacks.",
            "canonical_repair": "Install a class allowlist (ObjectInputFilter), or replace the serializer with a data-only format such as JSON with a strict schema.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Heuristic payload detection; gadget chains use trusted classes.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-522": {
        "prose": (
            "Insufficiently protected credentials are fixed by ensuring that "
            "credentials are transmitted over an authenticated, encrypted "
            "channel, stored using a modern password-hashing KDF, and never "
            "logged or echoed back. Use the project's existing secrets "
            "infrastructure rather than introducing a new storage path. "
            "Preserve method signatures and exception types. Do not store "
            "credentials in reversible form unless decryption is operationally "
            "required, and even then constrain the decryption surface."
        ),
        "schema": {
            "root_cause":       "Credentials are transmitted, stored, or logged in a form that does not adequately protect them.",
            "canonical_repair": "Transmit over TLS, store using a modern KDF (PBKDF2/scrypt/Argon2), and remove from logs and debug output.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Reversible credential storage when not operationally required; logging credential values.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-532": {
        "prose": (
            "Sensitive information being written to logs is fixed by removing "
            "the sensitive field from the log statement, replacing it with a "
            "non-reversible identifier or omitting it entirely. Audit nearby "
            "log statements, exception messages, and debug-mode output for "
            "the same data. Preserve method signatures and exception types. "
            "Do not rely on log levels to hide sensitive data — log files "
            "are routinely consumed by tooling that ignores level filters."
        ),
        "schema": {
            "root_cause":       "Sensitive data is included in log statements where it can be read by anyone with log access.",
            "canonical_repair": "Remove the sensitive field, or replace with a non-reversible identifier; audit nearby log statements and exception messages.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Relying on log levels to hide data; downstream tooling often ignores them.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-611": {
        "prose": (
            "XML External Entity (XXE) vulnerabilities are fixed by disabling "
            "DTD processing and external entity resolution on the XML parser "
            "factory before any parse call. For Java, set "
            "FEATURE_SECURE_PROCESSING to true, disable "
            "external-general-entities and external-parameter-entities, and "
            "disallow-doctype-decl where the application does not need DTDs. "
            "Preserve method signatures and exception types. Do not rely on "
            "input filtering of < or & — the attacker controls the XML "
            "envelope and can use legitimate XML constructs."
        ),
        "schema": {
            "root_cause":       "XML parser resolves external entities or DTDs from untrusted input, allowing file disclosure and SSRF.",
            "canonical_repair": "Disable DTD processing and external-entity features on the parser factory (setFeature disallow-doctype-decl, external-general-entities, external-parameter-entities).",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Filtering raw characters like < or &; the attack uses legitimate XML constructs.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-835": {
        "prose": (
            "Loops with unreachable exit conditions are fixed by ensuring "
            "every iteration makes provable progress toward termination. "
            "Add a bound — a maximum iteration count, a shrinking input "
            "size, or a state transition that must change — and exit when "
            "the bound is reached. For parsers, validate that the input "
            "advances on every iteration. Preserve method signatures and "
            "exception types. Do not rely on the input being well-formed: "
            "the canonical attack supplies malformed input that confuses the "
            "loop's termination predicate."
        ),
        "schema": {
            "root_cause":       "Loop predicate can be false-forever under attacker-controlled input, e.g. parser does not advance on malformed bytes.",
            "canonical_repair": "Add a provable progress invariant: max iteration count, shrinking input window, or required state transition, with exit when violated.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Assuming input well-formedness; attackers craft malformed input to stall the loop.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-863": {
        "prose": (
            "Incorrect authorization is fixed by aligning the check that is "
            "performed with the operation being authorized. Often the bug is "
            "that the check resolves the wrong subject, the wrong resource, "
            "or the wrong permission name. Replace the check with one that "
            "uses the actual subject of the request and the actual resource "
            "the operation will touch. Preserve method signatures and "
            "exception types. Do not add a second check on top of the broken "
            "one — fix the resolution path so the existing check is correct."
        ),
        "schema": {
            "root_cause":       "The authorization check resolves the wrong subject, resource, or permission, so it passes when it should not.",
            "canonical_repair": "Fix the resolution path so the check evaluates the actual subject, the actual resource touched, and the correct permission name.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Layering a second check on top of a broken one; fix the resolution itself.",
        },
    },

    # ──────────────────────────────────────────────────────────────────
    "CWE-918": {
        "prose": (
            "Server-side request forgery is fixed by restricting which URLs "
            "the server may fetch on behalf of a user. Validate the target "
            "host against an allowlist of permitted hosts, resolve the host "
            "and reject IP addresses in private, loopback, or metadata "
            "ranges, and disable redirects to addresses outside the allowed "
            "set. Preserve method signatures and exception types. Do not rely "
            "on filtering by URL string — the attacker controls the encoding, "
            "DNS resolution, and redirect chain."
        ),
        "schema": {
            "root_cause":       "Server fetches a URL whose target is attacker-controlled and not constrained to an allowed set of destinations.",
            "canonical_repair": "Validate host against an allowlist; reject private/loopback/metadata IP ranges after DNS resolution; constrain redirects.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "URL-string filtering; attackers control encoding, DNS, and redirects.",
        },
    },
    # ──────────────────────────────────────────────────────────────────
    "CWE-78": {
        "prose": (
            "OS command injection is fixed by separating program arguments "
            "from the program string. Pass arguments as a list to "
            "ProcessBuilder or Runtime.exec(String[]) so the operating "
            "system never interprets them through a shell. Where shell "
            "invocation is genuinely required, escape arguments with a "
            "helper that quotes shell metacharacters (spaces, semicolons, "
            "backticks, $, &, |, redirections). Preserve the method "
            "signature and declared exception types. Do not rely on a "
            "blocklist of bad characters; attackers vary encoding and "
            "syntax to bypass them."
        ),
        "schema": {
            "root_cause":       "Untrusted data is concatenated into a string passed to the operating-system shell instead of being delivered as a separated argument list.",
            "canonical_repair": "Pass arguments as a list to ProcessBuilder / Runtime.exec(String[]); if a shell is required, quote arguments with a helper that handles all shell metacharacters.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Blocklists of bad characters; attackers bypass them via encoding and syntactic variants.",
        },
    },
    # ──────────────────────────────────────────────────────────────────
    "CWE-332": {
        "prose": (
            "Insufficient entropy in pseudo-random number generation is "
            "fixed by replacing the weak source with one that is "
            "cryptographically suitable. Use java.security.SecureRandom "
            "instead of java.util.Random for any value that must be "
            "unpredictable, including session identifiers, tokens, salts, "
            "and IVs. Generate enough bytes (at least 128 bits) for the "
            "security context. Preserve method signatures and exception "
            "types. Do not seed SecureRandom with predictable values such "
            "as System.currentTimeMillis(); doing so reduces it to the "
            "entropy of the seed."
        ),
        "schema": {
            "root_cause":       "A pseudo-random source with insufficient entropy is used for values that must be unpredictable (tokens, salts, IVs, session IDs).",
            "canonical_repair": "Replace with java.security.SecureRandom; generate at least 128 bits of entropy for the security context.",
            "constraints":      "Preserve method signature and declared exception types.",
            "what_to_avoid":    "Seeding SecureRandom with predictable values; using java.util.Random for security-sensitive values.",
        },
    },
}
# ──────────────────────────────────────────────────────────────────────
# Public accessors
# ──────────────────────────────────────────────────────────────────────

def get_prose(cwe_id: str) -> str:
    """Return the L3a free-text guidance for a CWE."""
    if cwe_id not in CWE_SCHEMAS:
        raise KeyError(f"No schema for {cwe_id}. Add an entry to CWE_SCHEMAS.")
    return CWE_SCHEMAS[cwe_id]["prose"]


def get_schema(cwe_id: str) -> Dict[str, str]:
    """Return the L3b structured schema for a CWE."""
    if cwe_id not in CWE_SCHEMAS:
        raise KeyError(f"No schema for {cwe_id}. Add an entry to CWE_SCHEMAS.")
    return CWE_SCHEMAS[cwe_id]["schema"]


def has_schema(cwe_id: str) -> bool:
    return cwe_id in CWE_SCHEMAS


# ──────────────────────────────────────────────────────────────────────
# Smoke test:  python schemas.py
# Verifies every CWE in the file has both fields populated and that
# CWE_SCHEMAS covers every CWE in our 46-vuln subset.
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ──────────────────────────────────────────────────────────────────
    # Sanity: every entry has both fields, with non-trivial content
    # ──────────────────────────────────────────────────────────────────
    print(f"Total CWE entries: {len(CWE_SCHEMAS)}")
    print()
    for cwe_id, entry in sorted(CWE_SCHEMAS.items()):
        assert "prose" in entry and "schema" in entry, f"{cwe_id} missing fields"
        s = entry["schema"]
        for field in ("root_cause", "canonical_repair", "constraints", "what_to_avoid"):
            assert field in s and len(s[field]) > 20, f"{cwe_id}.{field} too short"
        assert len(entry["prose"]) > 100, f"{cwe_id}.prose too short"
        print(f"  {cwe_id:<10}  prose={len(entry['prose'])}c  schema=4 fields  ✓")

    # ──────────────────────────────────────────────────────────────────
    # Coverage check 1: the 46-vuln v1 subset (single-file only)
    # ──────────────────────────────────────────────────────────────────
    print()
    print("Coverage check 1 — v1 subset (46 single-file vulns):")
    SUBSET_CWES = {
        "VUL4J-1":  "CWE-20",  "VUL4J-2":  "CWE-611", "VUL4J-6":  "CWE-835",
        "VUL4J-7":  "CWE-835", "VUL4J-8":  "CWE-835", "VUL4J-10": "CWE-20",
        "VUL4J-13": "CWE-835", "VUL4J-14": "CWE-20",  "VUL4J-15": "CWE-611",
        "VUL4J-16": "CWE-264", "VUL4J-18": "CWE-22",  "VUL4J-22": "CWE-284",
        "VUL4J-23": "CWE-79",  "VUL4J-24": "CWE-611", "VUL4J-25": "CWE-79",
        "VUL4J-26": "CWE-20",  "VUL4J-29": "CWE-264", "VUL4J-30": "CWE-20",
        "VUL4J-33": "CWE-77",  "VUL4J-34": "CWE-79",  "VUL4J-35": "CWE-352",
        "VUL4J-36": "CWE-835", "VUL4J-39": "CWE-200", "VUL4J-40": "CWE-287",
        "VUL4J-41": "CWE-22",  "VUL4J-43": "CWE-22",  "VUL4J-44": "CWE-310",
        "VUL4J-45": "CWE-74",  "VUL4J-47": "CWE-611", "VUL4J-48": "CWE-20",
        "VUL4J-49": "CWE-20",  "VUL4J-50": "CWE-79",  "VUL4J-52": "CWE-269",
        "VUL4J-53": "CWE-835", "VUL4J-55": "CWE-835", "VUL4J-57": "CWE-532",
        "VUL4J-59": "CWE-79",  "VUL4J-60": "CWE-79",  "VUL4J-61": "CWE-611",
        "VUL4J-62": "CWE-287", "VUL4J-66": "CWE-20",  "VUL4J-75": "CWE-19",
        "VUL4J-76": "CWE-22",  "VUL4J-77": "CWE-502", "VUL4J-78": "CWE-502",
        "VUL4J-79": "CWE-22",
    }
    missing = sorted({cwe for cwe in SUBSET_CWES.values() if cwe not in CWE_SCHEMAS})
    if missing:
        print(f"  MISSING: {missing}")
    else:
        unique_cwes = sorted(set(SUBSET_CWES.values()))
        print(f"  All {len(unique_cwes)} unique CWEs in v1 subset are covered.")
        print(f"  CWEs: {', '.join(unique_cwes)}")

    # ──────────────────────────────────────────────────────────────────
    # Coverage check 2: the extended 61-vuln set (incl. multi-file)
    # Source: all-green + mapped CWE entries in the Vul4J dataset.
    # ──────────────────────────────────────────────────────────────────
    print()
    print("Coverage check 2 — extended 61-vuln set (incl. multi-file):")
    EXTENDED_CWES = {
        "CWE-19", "CWE-20", "CWE-22", "CWE-74", "CWE-77", "CWE-78",
        "CWE-79", "CWE-200", "CWE-254", "CWE-264", "CWE-269", "CWE-284",
        "CWE-287", "CWE-310", "CWE-332", "CWE-345", "CWE-352", "CWE-502",
        "CWE-522", "CWE-532", "CWE-611", "CWE-835", "CWE-863", "CWE-918",
    }
    missing_ext = sorted(EXTENDED_CWES - set(CWE_SCHEMAS.keys()))
    if missing_ext:
        print(f"  MISSING: {missing_ext}")
    else:
        print(f"  All {len(EXTENDED_CWES)} CWEs in extended subset are covered.")