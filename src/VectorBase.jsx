import React, { useState, useMemo } from "react";
import { Search, Terminal, ShieldAlert, ChevronRight, X, Radio, Target, CheckCircle2, FileCheck } from "lucide-react";

// ---------------------------------------------------------------------------
// Data: web attack knowledge base. Conceptual / educational level (OWASP /
// PortSwigger Academy style) — mechanism + real-world impact + defenses.
// ---------------------------------------------------------------------------

const VECTORS = [
  {
    id: "sqli",
    name: "SQL Injection",
    category: "Injection",
    severity: "critical",
    owasp: "A03:2021",
    summary: "Untrusted input reaches a database query without proper parameterization, letting an attacker alter query logic.",
    mechanism: [
      "App concatenates user input directly into a SQL string instead of using bound parameters.",
      "Attacker submits input containing SQL syntax (quotes, boolean logic, UNION clauses) to change the query's meaning.",
      "Depending on how results surface, the response leaks data directly (in-band), through timing/error differences (blind), or via a secondary out-of-band channel.",
    ],
    example: 'Classic textbook probe: a login field receiving \' OR \'1\'=\'1 to test whether input is escaped before it reaches the query.',
    incident: "The 2017 Equifax breach traced back to an unpatched framework flaw, but SQLi remains one of the most common root causes behind large-scale customer data breaches disclosed each year.",
    detection: ["Database errors surfacing in app responses", "Unusual query latency on specific inputs", "WAF/IDS alerts on SQL meta-characters in form fields"],
    defense: ["Parameterized queries / prepared statements — never string-concatenate input", "Least-privilege DB accounts per service", "Input validation as defense-in-depth, not the primary control", "ORM usage with query builders that escape by default"],
  },
  {
    id: "cmdi",
    name: "OS Command Injection",
    category: "Injection",
    severity: "critical",
    owasp: "A03:2021",
    summary: "User input is passed into a shell command, letting an attacker chain in arbitrary system commands.",
    mechanism: [
      "App shells out to the OS (e.g. to ping a host or convert a file) and builds the command string from user input.",
      "Attacker appends shell metacharacters (;, &&, |, backticks) to run a second command alongside the intended one.",
      "Resulting command executes with the web process's privileges — often enough for full host compromise.",
    ],
    example: "A 'diagnostic tools' page that shells out to system ping with a raw hostname field is the classic vulnerable pattern.",
    incident: "Command injection in IoT and network-appliance management panels is a recurring theme in CISA advisories, frequently rated critical because it grants direct code execution.",
    detection: ["Unexpected child processes spawned by the web server", "Outbound connections initiated from an app server", "Shell metacharacters logged in request parameters"],
    defense: ["Avoid shelling out entirely — use language-native library calls instead", "If unavoidable, use argument arrays (execve-style) never string concatenation", "Allow-list expected input formats strictly"],
  },
  {
    id: "xxe",
    name: "XML External Entity (XXE)",
    category: "Injection",
    severity: "high",
    owasp: "A05:2021",
    summary: "A misconfigured XML parser resolves external entities, letting an attacker read local files or reach internal services.",
    mechanism: [
      "App accepts XML input (file upload, SOAP endpoint, SSO assertion) and parses it with external entity resolution enabled.",
      "Attacker defines a DOCTYPE with an external entity pointing at a local file path or internal URL.",
      "Parser substitutes the entity's content into the response or otherwise leaks it, and the same channel can be used to probe internal network services.",
    ],
    example: "A crafted <!DOCTYPE> block referencing file:///etc/passwd inside an otherwise ordinary XML upload.",
    incident: "XXE has repeatedly featured in bug-bounty disclosures against document-processing and SSO/SAML endpoints, since those pipelines parse attacker-supplied XML by design.",
    detection: ["Parser errors referencing DOCTYPE or ENTITY", "Unexpected outbound requests from the parsing service", "File-path-looking strings in XML payloads"],
    defense: ["Disable DTD processing and external entity resolution in the XML parser config", "Prefer data formats like JSON where XML isn't required", "Patch/upgrade XML libraries — many ship entity resolution off by default now"],
  },
  {
    id: "ssti",
    name: "Server-Side Template Injection",
    category: "Injection",
    severity: "critical",
    owasp: "A03:2021",
    summary: "User input is rendered by a server-side template engine instead of being treated as plain data, enabling code execution.",
    mechanism: [
      "App passes user input into a template string that later gets rendered (e.g. a 'welcome {name}' template).",
      "Attacker submits template syntax instead of plain text, testing whether the engine evaluates it.",
      "If the engine evaluates arbitrary expressions, this escalates from information disclosure to full remote code execution depending on the engine's capabilities.",
    ],
    example: "A feedback-message field probed with a template engine's own math-expression syntax to see if it gets evaluated rather than echoed back literally.",
    incident: "Multiple CMS and email-templating products have disclosed SSTI CVEs leading to RCE when user-controlled strings were rendered instead of escaped.",
    detection: ["Evaluated expressions appearing in output where literal text was expected", "Template-engine error traces in responses"],
    defense: ["Never render user input as a template — treat it strictly as a variable value", "Use logic-less template engines for user-facing content", "Sandbox template execution where rendering user content is unavoidable"],
  },
  {
    id: "xss-r",
    name: "Reflected XSS",
    category: "Cross-Site Scripting",
    severity: "high",
    owasp: "A03:2021",
    summary: "Input from the request (URL, form field) is echoed back into the page without encoding, executing in the victim's browser.",
    mechanism: [
      "App reflects a query parameter or search term directly into the HTML response.",
      "Attacker crafts a URL containing script markup and gets a victim to click it (phishing link, malicious redirect).",
      "Victim's browser executes the script in the site's origin, exposing session cookies, tokens, or letting the attacker act as the victim.",
    ],
    example: "A search page that echoes ?q= back into the results heading without HTML-encoding it.",
    incident: "Reflected XSS remains one of the most frequently reported bug-bounty findings because it needs only one unescaped reflection point to be exploitable.",
    detection: ["Unencoded angle brackets or event-handler attributes in logged request params", "CSP violation reports"],
    defense: ["Context-aware output encoding on every reflection point", "Content-Security-Policy to limit script execution sources", "HttpOnly + SameSite cookies to reduce impact if XSS occurs anyway"],
  },
  {
    id: "xss-s",
    name: "Stored XSS",
    category: "Cross-Site Scripting",
    severity: "critical",
    owasp: "A03:2021",
    summary: "Malicious script is saved server-side (a comment, profile field) and served to every later visitor.",
    mechanism: [
      "App stores user-submitted content without sanitizing it and later renders it for other users.",
      "Attacker submits script payload once — no phishing link needed, unlike reflected XSS.",
      "Every user who views the affected page (a comment thread, a profile) executes the payload in their own session.",
    ],
    example: "A comment box that stores raw HTML and renders it unescaped on the article page for every reader.",
    incident: "Stored XSS in social platforms has repeatedly been used for self-propagating worms (e.g. the 2005 'Samy' MySpace worm), since every viewer re-triggers and re-spreads the payload.",
    detection: ["Script tags or event handlers in stored content fields", "Anomalous outbound requests triggered by simply viewing a page"],
    defense: ["Sanitize on input, encode on output — both layers, not one", "Rich-text fields: use an allow-listing HTML sanitizer library, never raw storage", "CSP as a second line of defense"],
  },
  {
    id: "xss-d",
    name: "DOM-based XSS",
    category: "Cross-Site Scripting",
    severity: "high",
    owasp: "A03:2021",
    summary: "Client-side JavaScript writes attacker-controlled data (URL fragment, referrer) into the DOM using an unsafe sink.",
    mechanism: [
      "Front-end code reads a source like location.hash or document.referrer.",
      "That value flows, unsanitized, into a dangerous sink such as innerHTML or eval.",
      "Because the vulnerable code never touches the server, this class can be invisible to server-side logging entirely.",
    ],
    example: "A single-page app that reads #welcome=<name> from the URL fragment and writes it straight into innerHTML.",
    incident: "DOM XSS has grown alongside SPA frameworks, since client-side routing routinely pipes URL fragments into rendering logic.",
    detection: ["Source-to-sink data flow audits in front-end code", "Browser-side CSP reporting"],
    defense: ["Use textContent / framework-safe binding instead of innerHTML for untrusted data", "Avoid eval-family functions on any URL-derived data", "Static analysis (taint tracking) in CI for source→sink flows"],
  },
  {
    id: "auth-cred",
    name: "Credential Stuffing / Broken Authentication",
    category: "Authentication & Session",
    severity: "high",
    owasp: "A07:2021",
    summary: "Automated login attempts reuse credentials leaked from other breaches against a login endpoint with no abuse controls.",
    mechanism: [
      "Attacker acquires a leaked username/password list from an unrelated prior breach.",
      "Automated tooling replays these pairs against the target's login endpoint at scale, relying on password reuse across sites.",
      "Any account sharing a leaked password with the target site is now compromised — no vulnerability in the target's code required.",
    ],
    example: "A login form with no rate limiting, CAPTCHA, or anomaly detection accepting thousands of attempts per minute from one source.",
    incident: "Credential stuffing is consistently cited by major identity-protection vendors as one of the highest-volume attack types against consumer web logins.",
    detection: ["Spikes in failed-then-succeeded logins from distributed IPs", "Logins geographically inconsistent with the account's history"],
    defense: ["Rate limiting and progressive delays on auth endpoints", "Multi-factor authentication", "Breached-password screening at signup/change time", "Device/behavioral anomaly detection"],
  },
  {
    id: "session-fix",
    name: "Session Fixation",
    category: "Authentication & Session",
    severity: "medium",
    owasp: "A07:2021",
    summary: "An app fails to issue a new session identifier at login, letting an attacker pre-seed a victim's session.",
    mechanism: [
      "Attacker obtains a valid session ID from the app (often just by visiting it) before the victim logs in.",
      "Attacker gets the victim to authenticate while using that same session ID (via a crafted link or shared device).",
      "Because the ID doesn't change on login, the attacker's pre-known session is now authenticated as the victim.",
    ],
    example: "An app that keeps a session ID from before login unchanged after successful authentication.",
    incident: "Session fixation is a recurring finding in penetration test reports for apps that hand-roll session management instead of using a vetted framework default.",
    detection: ["Session ID unchanged across the pre-auth to post-auth transition in logs"],
    defense: ["Regenerate the session identifier on every privilege change (login, elevation)", "Bind sessions to additional signals (IP range, user agent) where feasible", "Use framework-provided session management rather than custom implementations"],
  },
  {
    id: "jwt",
    name: "JWT Attacks",
    category: "Authentication & Session",
    severity: "high",
    owasp: "A07:2021",
    summary: "Weaknesses in how a service validates JSON Web Tokens let an attacker forge or tamper with claims.",
    mechanism: [
      "Common flaw patterns: accepting the token's own 'alg: none' header, verifying an RS256 token with its public key as an HMAC secret, or trusting an unverified 'kid' header to load an attacker-chosen key.",
      "Attacker rewrites the token's payload (e.g. role: admin) and re-signs it exploiting whichever validation gap exists.",
      "If the server doesn't strictly enforce algorithm and signature checks, the forged token is accepted as legitimate.",
    ],
    example: "A verification routine that trusts the algorithm named in the token header rather than pinning the expected algorithm server-side.",
    incident: "JWT algorithm-confusion and 'alg:none' issues have been documented CVEs across multiple popular JWT libraries over the years.",
    detection: ["Tokens with unexpected algorithms or missing signatures reaching the app", "Claim values inconsistent with the issuing service's normal output"],
    defense: ["Pin the expected signing algorithm server-side; never trust the token's own header", "Short expiry + refresh-token rotation", "Use vetted, actively-maintained JWT libraries and keep them patched"],
  },
  {
    id: "idor",
    name: "IDOR (Insecure Direct Object Reference)",
    category: "Access Control",
    severity: "high",
    owasp: "A01:2021",
    summary: "An endpoint returns or modifies a resource based on an ID in the request without checking the caller is authorized for that specific resource.",
    mechanism: [
      "App exposes a predictable or sequential identifier in a URL or API call (e.g. /invoices/1042).",
      "Server checks that the caller is authenticated, but not that the caller owns resource 1042 specifically.",
      "Attacker simply changes the ID and retrieves or modifies another user's data.",
    ],
    example: "Swapping an invoice, order, or profile ID in an authenticated request and receiving another account's data back.",
    incident: "IDOR is consistently among the top categories in public bug-bounty payout reports because it's simple to test and often high-impact.",
    detection: ["Sequential ID enumeration patterns in access logs", "Authenticated requests for resources outside the caller's known ownership"],
    defense: ["Enforce object-level authorization on every request, not just endpoint-level auth", "Use non-guessable identifiers (UUIDs) as a secondary hardening layer", "Centralize authorization logic rather than repeating checks ad hoc"],
  },
  {
    id: "privesc",
    name: "Privilege Escalation",
    category: "Access Control",
    severity: "critical",
    owasp: "A01:2021",
    summary: "A user gains capabilities beyond their assigned role, either by climbing to a higher role (vertical) or accessing peers' data (horizontal).",
    mechanism: [
      "App determines privilege from a client-influenceable value (a hidden form field, an editable JWT claim, a role parameter) rather than a trusted server-side source.",
      "Attacker modifies that value directly or discovers an endpoint that never re-checks role at all.",
      "Server honors the elevated request because it never independently verified the actor's actual role for that action.",
    ],
    example: "A 'role' parameter in a profile-update request that the server trusts instead of re-deriving from the authenticated session.",
    incident: "Privilege escalation flaws are a recurring root cause behind admin-panel takeovers reported in enterprise SaaS bug bounty programs.",
    detection: ["Role changes not preceded by an admin-initiated action", "Access to admin-only endpoints from non-admin session tokens"],
    defense: ["Derive privilege exclusively from server-side session/session-store state", "Re-validate authorization on every sensitive action, not just at login", "Principle of least privilege for default roles"],
  },
  {
    id: "path-trav",
    name: "Path Traversal / LFI",
    category: "Access Control",
    severity: "high",
    owasp: "A01:2021",
    summary: "User-supplied file paths aren't constrained, letting an attacker escape the intended directory to read arbitrary files.",
    mechanism: [
      "App builds a filesystem path by appending user input (a filename parameter) to a base directory.",
      "Attacker inserts ../ sequences (or encoded variants) to climb out of the intended directory.",
      "Server resolves the traversed path and returns file contents outside the sandboxed area — configs, credentials, source code.",
    ],
    example: "A 'download report' feature taking a raw filename parameter that accepts ../../etc/passwd-style traversal.",
    incident: "Path traversal is a frequent component chained with other bugs (e.g. paired with LFI-to-RCE via log poisoning) in real-world exploit chains.",
    detection: ["Traversal sequences (../, encoded equivalents) in file-parameter logs", "File access outside the expected application directory"],
    defense: ["Resolve and canonicalize paths, then verify they remain inside an allow-listed base directory", "Map user input to internal IDs rather than raw filenames", "Run the app with filesystem permissions scoped to only what it needs"],
  },
  {
    id: "csrf",
    name: "Cross-Site Request Forgery",
    category: "CSRF & SSRF",
    severity: "medium",
    owasp: "A01:2021",
    summary: "A victim's browser is tricked into submitting an authenticated request to a site they're logged into, without their knowledge.",
    mechanism: [
      "Victim is authenticated to a target site (has a valid session cookie).",
      "Attacker hosts a page that auto-submits a form or request to the target site's state-changing endpoint.",
      "Because browsers attach cookies automatically, the forged request rides in with the victim's own session — the target site can't tell it wasn't intentional.",
    ],
    example: "A hidden auto-submitting form on an attacker page pointed at a target site's 'change email' endpoint.",
    incident: "CSRF was common enough in the mid-2000s to make OWASP's Top 10 repeatedly before anti-CSRF tokens and SameSite cookies became standard defenses.",
    detection: ["State-changing requests missing an expected anti-CSRF token", "Referer/Origin headers inconsistent with the app's own domain"],
    defense: ["Anti-CSRF tokens on state-changing requests", "SameSite=Lax/Strict cookies as a strong modern default", "Re-authentication for highly sensitive actions"],
  },
  {
    id: "ssrf",
    name: "Server-Side Request Forgery",
    category: "CSRF & SSRF",
    severity: "critical",
    owasp: "A10:2021",
    summary: "An app fetches a URL supplied by the user, letting an attacker redirect that server-side request toward internal infrastructure.",
    mechanism: [
      "A feature legitimately fetches a remote resource server-side (image proxy, webhook validator, PDF renderer).",
      "Attacker supplies an internal address (cloud metadata endpoint, internal admin panel) instead of an external URL.",
      "The server — which sits inside the trusted network — makes the request on the attacker's behalf, returning data the attacker could never reach directly.",
    ],
    example: "A 'fetch preview image from URL' feature pointed at a cloud provider's internal metadata service address instead of a real image URL.",
    incident: "SSRF against cloud metadata endpoints has been the root cause of several major publicized cloud-credential-theft breaches.",
    detection: ["Outbound requests from app servers to internal/RFC1918 or metadata IP ranges", "URL parameters containing internal hostnames"],
    defense: ["Allow-list permitted destination hosts/schemes for server-side fetches", "Block requests to link-local/metadata and private IP ranges at the network layer", "Disable unnecessary URL redirection following in the fetch client"],
  },
  {
    id: "deser",
    name: "Insecure Deserialization",
    category: "Deserialization & Supply Chain",
    severity: "critical",
    owasp: "A08:2021",
    summary: "An app deserializes attacker-controlled data into objects, and crafted object graphs trigger unintended code execution.",
    mechanism: [
      "App accepts a serialized object (session blob, cache entry, API payload) from an untrusted source.",
      "Deserialization libraries in several languages will instantiate arbitrary classes and invoke their methods (e.g. constructors, destructors) as part of rebuilding the object graph.",
      "Attacker crafts a payload chaining together 'gadget' classes already present in the app's dependencies to achieve code execution on deserialization.",
    ],
    example: "A session-storage mechanism that deserializes a client-supplied cookie value into native objects without integrity checking.",
    incident: "Deserialization RCE chains have driven several critical CVEs in widely used Java and .NET web frameworks over the past decade.",
    detection: ["Unexpected class instantiation patterns during deserialization", "Serialized-object formats appearing in fields that should hold plain data"],
    defense: ["Avoid native deserialization of untrusted data — use plain data formats (JSON) with schema validation instead", "If unavoidable, sign/encrypt serialized data and verify integrity before deserializing", "Keep an inventory of 'gadget'-capable libraries patched"],
  },
  {
    id: "supply",
    name: "Supply Chain / Dependency Attacks",
    category: "Deserialization & Supply Chain",
    severity: "high",
    owasp: "A06:2021",
    summary: "A compromised or maliciously-named upstream package is pulled into the build, executing attacker code inside the CI/CD or app.",
    mechanism: [
      "Attacker compromises a legitimate package's publishing credentials, or publishes a lookalike package name (typosquat / dependency confusion between internal and public registries).",
      "Build pipeline or app resolves and installs the malicious package as a normal dependency.",
      "Malicious install/build scripts or runtime code execute with the pipeline's or application's privileges.",
    ],
    example: "A package name matching an internal-only library published publicly with a higher version number, so the build resolver prefers the attacker's public copy.",
    incident: "Dependency confusion was demonstrated at scale against multiple large tech companies in a widely publicized 2021 research disclosure, and typosquat/compromised-maintainer incidents recur regularly across npm and PyPI.",
    detection: ["Unexpected new maintainers or version jumps on a dependency", "Build-time network calls to unfamiliar hosts", "SBOM diffing against known-good dependency trees"],
    defense: ["Pin exact dependency versions with lockfiles and verify hashes", "Scope internal package names/registries so public resolution can't shadow them", "Software composition analysis (SCA) scanning in CI"],
  },
  {
    id: "cors",
    name: "CORS Misconfiguration",
    category: "Client-Side & Config",
    severity: "medium",
    owasp: "A05:2021",
    summary: "An API reflects any origin in its CORS headers (sometimes combined with credentials), letting arbitrary sites read authenticated responses.",
    mechanism: [
      "App sets Access-Control-Allow-Origin dynamically by reflecting whatever Origin header the browser sends, rather than checking against an allow-list.",
      "This is sometimes combined with Access-Control-Allow-Credentials: true, extending trust to cookies/session data.",
      "Any malicious site can now issue a cross-origin request from a logged-in victim's browser and read the authenticated response directly in JavaScript.",
    ],
    example: "An API that echoes the requesting Origin header back verbatim in the Allow-Origin response header for every request.",
    incident: "Reflected-origin CORS misconfigurations are a recurring bug-bounty finding on APIs that were retrofitted for cross-origin access without a strict allow-list.",
    detection: ["Access-Control-Allow-Origin matching arbitrary/unexpected origins in response logs", "Combination of wildcard-like reflection with credentials enabled"],
    defense: ["Maintain a strict server-side allow-list of permitted origins", "Never combine origin reflection with Allow-Credentials", "Default to no CORS access unless explicitly required"],
  },
  {
    id: "clickjack",
    name: "Clickjacking",
    category: "Client-Side & Config",
    severity: "medium",
    owasp: "A05:2021",
    summary: "A target page is loaded in an invisible iframe over a decoy page, tricking a user into clicking a real button they can't see.",
    mechanism: [
      "Attacker embeds the target site in an iframe with opacity set near zero, layered beneath attractive decoy content.",
      "Victim believes they're clicking the decoy but their click actually lands on the invisible target page underneath, at a coordinate the attacker has aligned deliberately.",
      "Used to trigger unintended state-changing actions (a 'like', a settings change, a purchase confirmation) the victim never consciously agreed to.",
    ],
    example: "An invisible iframe of an account-settings page positioned exactly under a 'claim your prize' button on a decoy page.",
    incident: "Clickjacking-style UI redress attacks were common enough against social platforms in the early 2010s that browsers and frameworks added dedicated header defenses.",
    detection: ["Referrer/framing anomalies in access logs — requests originating from unexpected framing contexts"],
    defense: ["X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors directive", "Frame-busting scripts as defense-in-depth (headers are the primary control)"],
  },
  {
    id: "protopoll",
    name: "Prototype Pollution",
    category: "Client-Side & Config",
    severity: "high",
    owasp: "A03:2021",
    summary: "Attacker-controlled keys reach an object-merge function and pollute JavaScript's base Object.prototype, affecting the whole app.",
    mechanism: [
      "App merges or deep-clones user-supplied JSON into an internal object using a recursive merge utility.",
      "Attacker includes a __proto__ or constructor.prototype key in the input rather than a normal data key.",
      "The merge utility writes that key onto the shared prototype chain, so every object in the app — not just the attacker's — now inherits the polluted property, which can flip security-relevant flags or, combined with a vulnerable sink, lead to XSS or RCE.",
    ],
    example: "A JSON body containing a __proto__ key processed by a naive recursive-merge implementation.",
    incident: "Prototype pollution CVEs have recurred across several very widely used npm utility libraries responsible for object merging and cloning.",
    defense: ["Use merge/clone libraries with documented prototype-pollution protection, kept patched", "Use Object.create(null) or Map for objects holding untrusted keys", "Freeze Object.prototype in sensitive contexts where feasible"],
    detection: ["__proto__ or constructor.prototype keys present in incoming JSON payloads"],
  },
  {
    id: "bizlogic",
    name: "Business Logic Abuse",
    category: "Business Logic",
    severity: "medium",
    owasp: "A04:2021",
    summary: "The app's rules are followed exactly as coded, but the sequence or timing of legitimate actions is abused to reach an unintended outcome.",
    mechanism: [
      "Attacker studies a legitimate multi-step flow (checkout, coupon redemption, withdrawal) for assumptions the design didn't defend.",
      "Common patterns: replaying a request before its effect is committed (race condition), reordering steps, or reusing a one-time code multiple times.",
      "No traditional 'vulnerability' triggers — every individual request is valid, but the combination produces an outcome the business logic never intended (double-spend, price manipulation, unlimited coupon reuse).",
    ],
    example: "Firing two 'redeem coupon' requests in parallel to race the balance-check before the first request's deduction commits.",
    incident: "Race-condition abuse of payment and rewards systems is a recurring category in public bug-bounty writeups precisely because it evades signature-based scanning.",
    detection: ["Impossible-looking sequences (a discount code used more times than its limit) surfacing in reconciliation", "Requests with unusually tight timing between them"],
    defense: ["Idempotency keys and atomic transactions for state-changing financial operations", "Server-side enforcement of step order — never trust client-driven flow control", "Rate limiting on sensitive repeatable actions"],
  },
  {
    id: "race",
    name: "Race Conditions (TOCTOU)",
    category: "Business Logic",
    severity: "high",
    owasp: "A04:2021",
    summary: "Multiple requests hit the same code path in parallel, and the gap between a check and its corresponding action gets exploited.",
    mechanism: [
      "A flow checks a condition (balance, stock, single-use status) and then acts on it in a separate step, without an atomic lock between the two.",
      "Attacker fires many identical requests concurrently — the classic 'single-packet attack' technique times them to land in the same processing window.",
      "Each request reads the pre-transaction state, so several of them pass the check before any single one commits its update, producing more successful actions than should be possible.",
    ],
    example: "Sending 20 simultaneous 'apply single-use coupon' requests to see how many the backend actually honors.",
    incident: "Turbo Intruder-style single-packet race attacks are a routinely successful technique in public bug-bounty writeups against wallets, coupon systems, and account-limit checks.",
    detection: ["Burst of near-identical timestamped requests immediately preceding an inconsistency in stored state", "Ledger totals that don't reconcile with logged individual transactions"],
    defense: ["Atomic database transactions / row-level locking around check-then-act sequences", "Idempotency keys so retried or parallel requests collapse to one effect", "Application-layer mutexes on a per-resource basis for critical operations"],
  },
  {
    id: "smuggling",
    name: "HTTP Request Smuggling",
    category: "Protocol & Infrastructure",
    severity: "critical",
    owasp: "A05:2021",
    summary: "A front-end proxy and back-end server disagree on where one HTTP request ends and the next begins, letting an attacker smuggle a hidden request.",
    mechanism: [
      "Front-end (load balancer/CDN) and back-end server parse conflicting Content-Length and Transfer-Encoding headers differently.",
      "Attacker crafts a request that both headers describe ambiguously (CL.TE or TE.CL discrepancy), so the two layers split the byte stream at different points.",
      "The 'leftover' bytes the front-end didn't count get prepended to the next legitimate user's request on that connection, letting the attacker hijack, poison, or bypass controls on requests that aren't their own.",
    ],
    example: "A request with both Content-Length and Transfer-Encoding: chunked headers set inconsistently between what the proxy and origin server each honor.",
    incident: "Request smuggling research (popularized by PortSwigger's 2019 disclosures) uncovered critical smuggling bugs across major CDNs and reverse proxies, several with bug-bounty payouts in the tens of thousands.",
    detection: ["Anomalous request timing/response pairing on multiplexed connections", "Front-end and back-end access logs disagreeing on request counts"],
    defense: ["Use HTTP/2 end-to-end where possible (removes most ambiguity)", "Normalize on a single header standard; reject requests with both CL and TE set", "Keep front-end and back-end parser behavior aligned/patched"],
  },
  {
    id: "cache-poison",
    name: "Web Cache Poisoning",
    category: "Protocol & Infrastructure",
    severity: "high",
    owasp: "A05:2021",
    summary: "An attacker gets a malicious response cached by a shared cache, so it's then served to every subsequent visitor.",
    mechanism: [
      "App's response varies based on an unkeyed input — a header like X-Forwarded-Host that influences the page but isn't part of the cache key.",
      "Attacker sends a request with a malicious value in that unkeyed input, causing a harmful response (e.g. containing an injected script or redirect) to be generated.",
      "The cache stores that harmful response under a cache key that legitimate users share, so they receive the poisoned version on their next request.",
    ],
    example: "A response that reflects the X-Forwarded-Host header into a canonical link tag, cached under a key that ignores that header.",
    incident: "Cache poisoning research has repeatedly turned unkeyed-input reflections into stored-XSS-at-scale against high-traffic sites, since one poisoned cache entry serves every visitor.",
    detection: ["Cached responses containing content inconsistent with a clean direct request", "Anomalous headers (X-Forwarded-*, X-Original-URL) in traffic preceding cache anomalies"],
    defense: ["Include every input that affects the response in the cache key, or strip/normalize it before the origin sees it", "Disable caching on responses that reflect any user-controlled header", "Regularly audit which headers actually influence rendered output"],
  },
  {
    id: "cache-deception",
    name: "Web Cache Deception",
    category: "Protocol & Infrastructure",
    severity: "high",
    owasp: "A05:2021",
    summary: "A cache is tricked into storing a private, personalized page under a URL pattern it treats as static/cacheable.",
    mechanism: [
      "Cache rules treat certain URL patterns (e.g. anything ending in .css or .jpg) as always static and safe to cache for everyone.",
      "Attacker appends a fake static-looking path segment to a private, authenticated page's URL, and many frameworks still route it to the same dynamic, personalized handler.",
      "The cache stores that personalized response under the static-looking URL; the attacker then requests the same URL themselves (unauthenticated) and receives the victim's cached private data.",
    ],
    example: "Appending /nonexistent.css to a logged-in 'my account' URL and checking whether the cache stores the personalized response under that path.",
    incident: "Web cache deception has been used in bug-bounty research to extract other users' account pages and session-bound data from sites with permissive static-asset caching rules.",
    detection: ["Static-looking URLs returning personalized/authenticated content", "Cache hit logs for URL patterns that shouldn't contain user-specific data"],
    defense: ["Key cache rules off the actual content-type/handler, not just the URL suffix", "Never let authenticated routes fall through to static-asset cache rules", "Set explicit Cache-Control: private/no-store on personalized responses"],
  },
  {
    id: "subdomain-takeover",
    name: "Subdomain Takeover",
    category: "Protocol & Infrastructure",
    severity: "high",
    owasp: "A05:2021",
    summary: "A DNS record still points at a third-party service (cloud storage bucket, SaaS app) that's since been deprovisioned, letting anyone claim it.",
    mechanism: [
      "A subdomain's CNAME/A record points to an external service (a hosting platform, storage bucket, PaaS app) that was later deleted or unclaimed, but the DNS record was never cleaned up.",
      "Attacker finds the dangling DNS record (via subdomain enumeration) and registers the same resource name on the third-party service.",
      "The third-party service now resolves for the organization's own subdomain, letting the attacker serve arbitrary content — including phishing pages — under a trusted domain.",
    ],
    example: "A CNAME pointing to a PaaS app name that's now unclaimed, so registering that same app name on the provider claims the traffic.",
    incident: "Subdomain takeover is one of the most consistently rewarded bug-bounty categories precisely because it's found through pure reconnaissance (DNS enumeration) with no code interaction needed.",
    detection: ["Automated DNS/subdomain monitoring flagging CNAMEs pointing to unclaimed or 'not found' third-party resources"],
    defense: ["Remove DNS records immediately when decommissioning any third-party-hosted service", "Periodic automated subdomain + dangling-record audits", "Prefer apex/verified-domain features on providers that support ownership verification"],
  },
  {
    id: "file-upload",
    name: "Unrestricted File Upload",
    category: "Access Control",
    severity: "critical",
    owasp: "A01:2021",
    summary: "An upload feature doesn't validate file type/content, letting an attacker upload and later execute a malicious file server-side.",
    mechanism: [
      "App accepts file uploads and trusts client-supplied signals (file extension, MIME type header) to decide what's allowed.",
      "Attacker uploads a script file disguised with an allowed extension/content-type, or exploits weak extension filtering (e.g. .php.jpg, null-byte tricks, alternate executable extensions).",
      "If the upload directory is web-accessible and the server executes scripts from it, requesting the uploaded file directly runs the attacker's code on the server.",
    ],
    example: "A profile-picture uploader that only checks the Content-Type header (attacker-controlled) rather than inspecting actual file content.",
    incident: "Unrestricted file upload leading to remote code execution is a perennial top finding in bug-bounty programs and penetration tests wherever upload features exist.",
    detection: ["Executable file signatures in upload directories", "Requests directly fetching recently uploaded files with script extensions"],
    defense: ["Validate actual file content/magic bytes, not just extension or declared MIME type", "Store uploads outside the webroot, or serve them from a separate non-executing domain", "Re-encode/strip uploaded images and disable script execution in upload directories"],
  },
  {
    id: "mass-assign",
    name: "Mass Assignment",
    category: "Access Control",
    severity: "high",
    owasp: "A04:2021",
    summary: "An API binds an entire incoming JSON object to an internal model, letting an attacker set fields the UI never exposed.",
    mechanism: [
      "Framework convenience feature auto-binds request body fields directly onto a database model's attributes.",
      "Attacker adds an extra field to the JSON body — one that exists on the model (isAdmin, accountBalance) but was never intended to be client-settable.",
      "Because binding is generic, the framework happily sets that field too, and the app persists it as if it came through a legitimate flow.",
    ],
    example: "A 'update profile' request body with an added \"role\":\"admin\" field that the model happens to have a column for.",
    incident: "Mass assignment was directly responsible for a well-known 2012 GitHub incident where a user set arbitrary public-key data via unintended parameter binding on a public repo.",
    defense: ["Explicit allow-lists of bindable fields per endpoint (DTOs), never bind the raw request onto a persistence model", "Separate read and write models so sensitive fields simply aren't reachable", "Server-side re-validation of any privilege-relevant field on save"],
    detection: ["Model fields changing without a corresponding legitimate UI action in audit logs", "Unexpected JSON keys in request bodies matching internal model field names"],
  },
  {
    id: "bfla",
    name: "Broken Function Level Authorization",
    category: "Access Control",
    severity: "high",
    owasp: "A01:2021",
    summary: "An API exposes admin/privileged functions that only check authentication, not whether the caller's role permits that specific function.",
    mechanism: [
      "Admin-only endpoints exist on the same API surface as regular user endpoints, often undocumented but discoverable (JS bundle references, predictable naming, API spec leaks).",
      "Attacker calls the endpoint directly with a regular authenticated session instead of going through the (client-side-only) admin UI gate.",
      "Server executes the privileged function because it only verified 'is this caller logged in', not 'is this caller allowed to call this specific function'.",
    ],
    example: "Calling /api/admin/users/delete directly with a normal user's token because the check for admin-only access lived only in the frontend menu logic.",
    incident: "BFLA is called out as its own top-10 category in the OWASP API Security project specifically because it's endemic to API-first products where admin routes are gated only by client-side navigation.",
    detection: ["Non-admin sessions successfully invoking admin-tagged endpoints in access logs"],
    defense: ["Enforce role checks server-side on every function, independent of any client-side menu logic", "Deny-by-default routing for privileged namespaces", "API gateway-level role enforcement as a second layer"],
  },
  {
    id: "open-redirect",
    name: "Open Redirect",
    category: "Configuration & Data Exposure",
    severity: "low",
    owasp: "A01:2021",
    summary: "An app redirects to a URL taken from user input without validating it stays within the trusted domain.",
    mechanism: [
      "App has a 'redirect after login' or 'go to this link' feature that reads the destination from a query parameter.",
      "Attacker crafts a link to the trusted site with that parameter pointing at an external, attacker-controlled URL.",
      "Victim clicks what looks like a link to the trusted site, and the trusted site itself forwards them to the attacker's phishing page — inheriting the target's credibility.",
    ],
    example: "A login link like /login?next=https://attacker-site.example that the app redirects to unconditionally after authentication.",
    incident: "Open redirects are frequently chained into phishing campaigns because a link through a well-known, trusted domain bypasses the skepticism a raw suspicious URL would trigger.",
    detection: ["Redirect parameters pointing at external domains in access logs"],
    defense: ["Validate redirect targets against an allow-list of internal paths", "Use indirect reference tokens (short IDs mapped server-side) instead of raw URLs", "Warn users when leaving the site via any redirect, if external destinations must be supported"],
  },
  {
    id: "host-header",
    name: "Host Header Injection",
    category: "Configuration & Data Exposure",
    severity: "medium",
    owasp: "A05:2021",
    summary: "An app trusts the client-supplied Host header for security-relevant logic like building password-reset links.",
    mechanism: [
      "App code reads the incoming Host header to build absolute URLs (password-reset emails, canonical links) rather than using a configured trusted hostname.",
      "Attacker sends a request with a forged Host header pointing at an attacker-controlled domain.",
      "If the app uses that header to construct a link sent to a victim (e.g. a password-reset email), the victim's reset link now points at the attacker's server, letting them capture the reset token.",
    ],
    example: "A password-reset flow that builds the reset link as https://{Host header value}/reset?token=... instead of using a hardcoded trusted domain.",
    incident: "Host header poisoning of password-reset emails is a well-documented technique for full account takeover, covered extensively in web security research and bug-bounty methodology guides.",
    detection: ["Host header values in logs that don't match any legitimate configured domain"],
    defense: ["Never derive security-sensitive URLs from the Host header — use a server-side configured canonical hostname", "Validate/allow-list acceptable Host header values at the web server or framework layer"],
  },
  {
    id: "redos",
    name: "Regular Expression DoS (ReDoS)",
    category: "Configuration & Data Exposure",
    severity: "medium",
    owasp: "A05:2021",
    summary: "A regex with catastrophic backtracking is fed crafted input, causing CPU usage to explode and hang the process handling it.",
    mechanism: [
      "App uses a regex (email/URL validation is a common culprit) whose structure allows exponential backtracking on certain input shapes — typically nested repetition like (a+)+.",
      "Attacker submits a carefully crafted string designed to maximize backtracking for that specific pattern.",
      "The regex engine's matching time blows up exponentially with input length, pinning a CPU core and starving other requests — a single request can cause a denial of service.",
    ],
    example: "A crafted string of repeated characters just short of matching an email regex, chosen to maximize backtracking before failing.",
    incident: "ReDoS in widely used validation libraries has caused real production outages, prompting node.js and other ecosystems to publish dedicated ReDoS advisories for popular regex-based packages.",
    detection: ["Single requests correlating with sustained CPU spikes on the handling process", "Slow response times isolated to specific input-validation endpoints"],
    defense: ["Use regex engines/patterns with linear-time guarantees, or timeout regex execution", "Avoid nested quantifiers in user-input-facing patterns; test patterns with a ReDoS checker", "Rate-limit and cap input length before it reaches validation logic"],
  },
  {
    id: "graphql",
    name: "GraphQL Introspection & Abuse",
    category: "API Security",
    severity: "medium",
    owasp: "A05:2021",
    summary: "A GraphQL endpoint leaves introspection enabled and lacks query depth/complexity limits, exposing the full schema and enabling resource-exhaustion queries.",
    mechanism: [
      "Production GraphQL endpoint ships with introspection queries enabled, letting anyone request the complete schema — every type, field, mutation, including ones never used by the official client.",
      "Attacker uses the schema to find unused or under-protected fields/mutations not covered by the same authorization checks as the main app flows.",
      "Separately, deeply nested or aliased queries can be crafted to force the server to do disproportionate work per request, exhausting resources (query complexity DoS).",
    ],
    example: "Sending the standard __schema introspection query to a production GraphQL endpoint that has no environment-based restriction on it.",
    incident: "GraphQL misconfiguration findings — introspection exposure and missing depth limiting — are among the most commonly reported categories in API-focused bug-bounty programs as GraphQL adoption has grown.",
    detection: ["Introspection queries (__schema, __type) reaching production from non-internal sources", "Unusually deep or repeated nested queries in request logs"],
    defense: ["Disable introspection in production", "Enforce query depth/complexity limits and per-field rate limiting", "Apply the same authorization checks to every field/mutation, not just the ones the official client uses"],
  },
  {
    id: "cswsh",
    name: "Cross-Site WebSocket Hijacking",
    category: "API Security",
    severity: "high",
    owasp: "A01:2021",
    summary: "A WebSocket handshake relies on cookies for authentication without checking Origin, letting a malicious page open an authenticated socket on the victim's behalf.",
    mechanism: [
      "App authenticates WebSocket connections purely via the browser's ambient session cookie at handshake time, like a normal HTTP request.",
      "WebSocket handshakes aren't subject to the same-origin policy the way fetch/XHR are, and browsers still attach cookies to the handshake even from a cross-origin page.",
      "A malicious page opens a WebSocket connection to the target app; if the server doesn't check the Origin header, the connection authenticates as the victim, and the attacker's page can send/receive over it.",
    ],
    example: "A chat app's WebSocket endpoint accepting connections from any Origin as long as a valid session cookie is present.",
    incident: "Cross-site WebSocket hijacking has been documented in real-time dashboard and chat products as a full session-takeover vector once discovered, since it bypasses controls that only apply to conventional HTTP requests.",
    detection: ["WebSocket handshakes with unexpected or missing Origin headers succeeding in server logs"],
    defense: ["Validate the Origin header against an allow-list on every WebSocket handshake", "Use a dedicated, non-cookie token (passed explicitly, not ambiently) for WebSocket auth", "Apply CSRF-style protections to the handshake step specifically"],
  },
  {
    id: "xpath",
    name: "XPath Injection",
    category: "Injection",
    severity: "high",
    owasp: "A03:2021",
    summary: "User input is concatenated into an XPath query against an XML document, letting an attacker alter the query's logic.",
    mechanism: [
      "App queries an XML data store using XPath expressions built by concatenating user input directly into the query string.",
      "Attacker submits XPath syntax (quotes, boolean operators) the same way they would test for SQL injection.",
      "Because XPath has no query-plan separation like parameterized SQL does in many libraries, altered logic can bypass authentication checks or walk the whole document tree.",
    ],
    example: "A login check built as an XPath expression matching username/password nodes, probed the same way a SQLi login field would be.",
    incident: "XPath injection shows up wherever XML is used as a lightweight datastore (older enterprise apps, some SOAP-backed logins) and follows the same boolean/blind exploitation logic as SQL injection.",
    detection: ["XML parser errors surfacing in responses", "Boolean-altering characters in fields that map to XML lookups"],
    defense: ["Use parameterized XPath APIs where available instead of string concatenation", "Validate and encode input before it reaches any query builder", "Apply least-privilege to what the XML document itself exposes"],
  },
  {
    id: "rfi",
    name: "Remote File Inclusion (RFI)",
    category: "Access Control",
    severity: "critical",
    owasp: "A01:2021",
    summary: "An app includes/executes a file whose path is partly attacker-controlled, and the attacker points it at a remote, malicious file.",
    mechanism: [
      "App has an 'include this page/module' feature that builds a file path from a request parameter, and the include function supports remote URLs (some legacy stacks default to this).",
      "Attacker sets the parameter to a URL hosting a malicious script under their control instead of a local filename.",
      "Server fetches and executes the remote file as if it were local code, granting the attacker remote code execution.",
    ],
    example: "A '?page=' parameter that legacy PHP-style include functions will happily fetch and execute from an external URL if remote includes aren't disabled.",
    incident: "RFI was a dominant web attack class in the mid-2000s PHP era and still surfaces in legacy or misconfigured deployments where remote file inclusion was never explicitly turned off.",
    detection: ["Include/require parameters containing full URLs in access logs", "Outbound fetches from the app server immediately preceding new code execution"],
    defense: ["Disable remote file inclusion at the language/runtime level", "Map include parameters to a fixed allow-list of internal file identifiers, never raw paths or URLs", "Run with filesystem/network egress permissions scoped tightly"],
  },
  {
    id: "email-header",
    name: "Email Header Injection",
    category: "Injection",
    severity: "medium",
    owasp: "A03:2021",
    summary: "User input reaches an email header without sanitization, letting an attacker inject extra headers or recipients.",
    mechanism: [
      "App builds an outgoing email (contact form, invite feature) inserting a user-supplied field (name, subject) directly into a header line.",
      "Attacker includes newline characters followed by additional header lines (Bcc:, Subject:) inside that field.",
      "The mail server interprets the injected lines as real headers, letting the attacker add recipients, rewrite the subject, or turn the form into an open spam relay.",
    ],
    example: "A 'your name' contact-form field containing a newline followed by a Bcc: header pointing at a mass mailing list.",
    incident: "Email header injection via contact/feedback forms is a long-standing, still-recurring finding wherever a form field is placed straight into a header without newline stripping.",
    detection: ["Newline characters in fields that map to email headers", "Outbound mail volume spikes from a single form endpoint"],
    defense: ["Strip or reject CR/LF characters from any input used to build headers", "Use a mail library's structured API for headers/recipients rather than string concatenation", "Rate-limit and CAPTCHA-protect public-facing mail-sending forms"],
  },
  {
    id: "crlf",
    name: "CRLF Injection / HTTP Response Splitting",
    category: "Protocol & Infrastructure",
    severity: "medium",
    owasp: "A05:2021",
    summary: "User input reaches a raw HTTP header without newline filtering, letting an attacker inject extra headers or split the response.",
    mechanism: [
      "App reflects user input into a response header (a redirect Location, a custom header) using raw string concatenation.",
      "Attacker includes URL-encoded carriage-return/line-feed sequences (%0d%0a) followed by fabricated header content.",
      "The server/proxy interprets the injected CRLF as a real header boundary, letting the attacker add headers, set cookies, or in older stacks fully split the response into a second, attacker-controlled one.",
    ],
    example: "A redirect endpoint reflecting a URL parameter into the Location header without stripping %0d%0a sequences.",
    incident: "CRLF injection has been used to plant fake headers and cookies in real deployments, and paired with a caching layer it can escalate into cache poisoning affecting every subsequent visitor.",
    detection: ["Encoded CR/LF sequences (%0d%0a) in request parameters that map to response headers"],
    defense: ["Strip or reject CR/LF characters from any input used to build headers", "Use framework header-setting APIs (which typically encode automatically) instead of raw string writes", "Keep the HTTP library/server patched against known splitting issues"],
  },
  {
    id: "dns-rebind",
    name: "DNS Rebinding",
    category: "Protocol & Infrastructure",
    severity: "high",
    owasp: "A10:2021",
    summary: "An attacker-controlled DNS record briefly resolves to a legitimate address, then flips to an internal IP after the browser has already trusted the origin.",
    mechanism: [
      "Attacker sets a very short TTL on a domain they control and gets a victim's browser to load a page from it.",
      "After the initial page load, the attacker's DNS server changes the record to resolve to an internal-only IP (a router, an internal API, localhost services).",
      "The browser, still treating requests as same-origin to the attacker's domain, now lets the attacker's JavaScript talk to that internal service — bypassing same-origin protections that assume a stable IP behind a hostname.",
    ],
    example: "A domain with a 1-second DNS TTL that resolves to a public IP on first load, then to 127.0.0.1 or a private range on the next lookup.",
    incident: "DNS rebinding has been used in security research to reach internal admin interfaces and IoT device management panels that assumed 'not internet-facing' meant 'not reachable from a browser'.",
    detection: ["Rapid DNS record changes with very short TTLs for a domain interacting with the app", "Browser-originated requests reaching internal IP ranges unexpectedly"],
    defense: ["Validate the Host header server-side against expected values on internal services", "Pin DNS resolution for the duration of a session where feasible", "Require internal services to authenticate requests, not just trust their network location"],
  },
  {
    id: "misconfig",
    name: "Security Misconfiguration",
    category: "Configuration & Data Exposure",
    severity: "high",
    owasp: "A05:2021",
    summary: "Default credentials, verbose debug output, or unnecessary exposed services give an attacker access with no actual vulnerability needed.",
    mechanism: [
      "A component ships with a default account, an open admin console, verbose stack traces, or a debug endpoint, and it's deployed to production unchanged.",
      "Attacker finds it through routine reconnaissance — default credential lists, common admin paths, or an error page that reveals the exact framework/version in use.",
      "No exploit development is needed; the attacker simply uses the feature as designed, just from a position it was never meant to be reachable from.",
    ],
    example: "An admin console left reachable at its default path with the vendor's documented default username/password still active.",
    incident: "Security misconfiguration consistently ranks in OWASP's Top 10 precisely because it requires zero novel technique — it's almost always found through basic recon rather than deep testing.",
    detection: ["Default-credential logins succeeding", "Debug/stack-trace content appearing in production responses", "Admin paths reachable without any authentication challenge"],
    defense: ["Change or disable all default credentials before deployment", "Turn off verbose error output and debug endpoints in production", "Run periodic configuration audits/hardening scans against a baseline"],
  },
  {
    id: "crypto-fail",
    name: "Cryptographic Failures / Sensitive Data Exposure",
    category: "Configuration & Data Exposure",
    severity: "high",
    owasp: "A02:2021",
    summary: "Sensitive data is transmitted or stored with weak, outdated, or missing cryptography, letting an attacker read it directly.",
    mechanism: [
      "App transmits sensitive data over plain HTTP, or stores it using a weak/outdated algorithm (unsalted hashes, deprecated ciphers), or hardcodes secrets in client-reachable code.",
      "Attacker positioned to observe traffic (shared network, compromised intermediary) or who obtains a data dump reads the data directly, since there's no meaningful cryptographic barrier.",
      "Weak password hashing specifically means a stolen database can be cracked offline at scale rather than requiring the attacker to interact with the live app at all.",
    ],
    example: "A password column hashed with an unsalted, fast general-purpose hash instead of a purpose-built slow hashing algorithm.",
    incident: "Weak password hashing has repeatedly turned 'we detected unauthorized access to a database' disclosures into 'and most of those passwords were cracked within days' follow-ups.",
    detection: ["Sensitive fields transmitted over non-TLS connections", "Password hashes identifiable as fast/unsalted algorithms during a security review"],
    defense: ["Enforce TLS everywhere, including internal service-to-service traffic", "Use purpose-built slow hashing (bcrypt/argon2/scrypt) with per-user salts for passwords", "Never hardcode secrets in client-shippable code — use a secrets manager"],
  },
  {
    id: "client-storage",
    name: "Insecure Client-Side Storage",
    category: "Client-Side & Config",
    severity: "medium",
    owasp: "A04:2021",
    summary: "Sensitive data (tokens, PII) is stored in localStorage/sessionStorage or client-side cookies without the protections that make them safe to hold.",
    mechanism: [
      "App stores an auth token, session data, or personal information directly in browser localStorage or a non-HttpOnly cookie for convenience.",
      "Any script that runs in that page's origin — including one injected via an unrelated XSS bug — can read localStorage and non-HttpOnly cookies freely; there's no built-in access restriction beyond same-origin.",
      "This turns what would be a contained XSS finding into full token theft, since the sensitive value was sitting in a location any page script can read.",
    ],
    example: "An auth token saved to localStorage so a single-page app can attach it to API calls manually, instead of relying on an HttpOnly cookie.",
    incident: "Storing auth tokens in localStorage is a frequently flagged finding in front-end security reviews specifically because it amplifies the blast radius of any XSS bug elsewhere on the same origin.",
    detection: ["Sensitive values visible via browser dev tools' Application/Storage tab on a logged-in session"],
    defense: ["Store auth tokens in HttpOnly, SameSite cookies instead of script-accessible storage", "If client-side storage is unavoidable, keep it short-lived and never store long-term secrets there", "Treat any XSS finding as higher severity when sensitive data sits in reachable storage"],
  },
];

const CATEGORIES = [...new Set(VECTORS.map((v) => v.category))];

// ---------------------------------------------------------------------------
// Generic, authorized-testing methodology per category — recon → identify →
// verify → report. This is the standard bug-bounty/OWASP-testing-guide
// workflow, not a per-target exploitation script.
// ---------------------------------------------------------------------------
const WORKFLOW_STEPS = ["Recon", "Identify", "Verify", "Report"];
const WORKFLOW_ICONS = [Search, Target, CheckCircle2, FileCheck];

const CATEGORY_WORKFLOW = {
  Injection: [
    "Map every input point (params, headers, JSON fields) on scope you're authorized to test, and note which ones reach a query, shell, or interpreter.",
    "Send safe canary characters (a stray quote, a math expression, a harmless OS command) and diff the response/timing against a clean baseline request.",
    "If behavior shifts, confirm with a non-destructive boolean or time-based check rather than attempting data extraction — enough to prove the class, not to browse the database.",
    "Write up the exact request, the anomaly, and the impact; submit through the program's disclosure channel before testing any further.",
  ],
  "Cross-Site Scripting": [
    "Enumerate every place user input is later reflected or rendered — search boxes, comments, profile fields, URL fragments.",
    "Probe each with an inert marker string (not a working payload) and check whether it comes back HTML-encoded or raw in the page source.",
    "If raw, confirm script execution in a throwaway/sandboxed session only — never on another real user's session or data.",
    "Report with the sink, the input point, and a minimal proof-of-concept; avoid payloads that would auto-propagate to other users.",
  ],
  "Authentication & Session": [
    "Map the auth flow end to end: login, password reset, session issuance, logout, and any 'remember me' or SSO handoff.",
    "Check whether session identifiers change on login/privilege change, and whether rate limiting or MFA gaps exist — using your own test accounts only.",
    "Verify findings against your own accounts; never attempt real credential-stuffing volumes against a live user base.",
    "Report the specific gap (e.g. no session regeneration, no lockout) with reproduction steps, not a list of harvested credentials.",
  ],
  "Access Control": [
    "Catalog objects/endpoints tied to an ID or role (invoices, admin routes, other users' resources) that your test account can reach.",
    "With two test accounts of different privilege levels, swap IDs or call the other role's endpoints directly, bypassing the UI.",
    "Confirm the response actually returns/modifies data you shouldn't own — a single clean before/after screenshot is enough evidence.",
    "Report the endpoint, the two account roles used, and the exact swapped identifier — never pull real users' data as 'proof'.",
  ],
  "CSRF & SSRF": [
    "For CSRF: find state-changing requests and check for an anti-CSRF token or SameSite cookie protection. For SSRF: find any feature that fetches a URL server-side.",
    "Build a minimal self-hosted PoC page (for CSRF) or a request to a harmless canary URL you control (for SSRF) to test the gap safely.",
    "Confirm impact against your own test account/canary endpoint only — never point SSRF probes at real internal infrastructure you don't own.",
    "Report with the PoC and the exact server behavior observed; flag SSRF findings as high-severity given the internal-network risk.",
  ],
  "Deserialization & Supply Chain": [
    "Identify where the app accepts serialized blobs (cookies, cache entries) or resolves dependencies, and fingerprint the library/version in use.",
    "Check public advisories for known deserialization gadgets or dependency-confusion exposure matching that exact version.",
    "Verify with the least invasive proof available (a benign marker object, or a claimed-but-unpublished internal package name) — never a live RCE payload against production.",
    "Report the vulnerable component, version, and reference advisory rather than a working exploit chain.",
  ],
  "Client-Side & Config": [
    "Inspect response headers (CORS, X-Frame-Options, CSP) and client-side merge/clone utilities for the specific misconfiguration pattern.",
    "Reproduce the gap with a local test page (for CORS/clickjacking) or a crafted JSON key (for prototype pollution) in a sandbox you control.",
    "Confirm the actual security consequence — e.g. that credentials really are readable cross-origin — not just that the header is missing.",
    "Report the header/config values observed plus the concrete impact, so the fix is unambiguous.",
  ],
  "Business Logic": [
    "Walk the multi-step flow (checkout, coupon, withdrawal) as a normal user first, noting every check-then-act boundary.",
    "Test edge sequences — reordering steps, resubmitting a step, or firing two identical requests concurrently — against your own test account.",
    "Verify the outcome is genuinely a logic flaw (e.g. a coupon applied twice) rather than a one-off fluke by reproducing it once, minimally.",
    "Report the exact sequence/timing used and the business impact; don't repeat it at scale against production data.",
  ],
  "Protocol & Infrastructure": [
    "Fingerprint the front-end/CDN and origin server stack, and check for known parser-discrepancy or dangling-DNS advisories for that combination.",
    "For smuggling/cache issues, send a single carefully-formed diagnostic request and observe how front-end and origin logs disagree — don't chain further requests.",
    "For subdomain takeover, verify the DNS record is truly dangling (points to an unclaimed resource) before registering anything, and do so on a platform that supports responsible claim-and-report.",
    "Report the discrepancy or dangling record immediately — these findings are typically high-severity and time-sensitive for the owner to fix.",
  ],
  "Configuration & Data Exposure": [
    "Look for the specific pattern (raw redirect parameter, Host-header-derived links, a validation regex) in how the app is built.",
    "Test with an inert value pointing at a domain/resource you control, never a live phishing destination or a genuinely damaging input.",
    "Confirm real impact — e.g. that a password-reset link truly lands on your test domain — before writing it up.",
    "Report the parameter/header and a safe reproduction; suggest the allow-list or canonical-hostname fix.",
  ],
  "API Security": [
    "Pull the schema (GraphQL introspection) or map endpoints via the client bundle/API spec, noting anything the official client never calls.",
    "Test unused fields/mutations or the WebSocket handshake directly, bypassing the client UI, using your own test account.",
    "Confirm the gap with the smallest possible query/connection — no need to exhaust the server or read other users' live data to prove the point.",
    "Report the endpoint/field and the missing check (e.g. no Origin validation, no depth limit) with a minimal reproduction.",
  ],
};

// ---------------------------------------------------------------------------
// Attack-flow labels: 4-stage chain (source → vector → mechanism → impact)
// rendered as a diagram per vector — the same shape as a real pentest
// report's attack-chain graphic, not an exploitation script.
// ---------------------------------------------------------------------------
const FLOW_LABELS = {
  sqli: ["Attacker", "Login form field", "SQL query engine", "Auth bypass / data leak"],
  cmdi: ["Attacker", '"Ping this host" field', "OS shell", "Arbitrary command execution"],
  xxe: ["Attacker", "XML file upload", "XML parser (entities on)", "Local file / internal network read"],
  ssti: ["Attacker", '"Welcome {name}" field', "Template engine", "Remote code execution"],
  "xss-r": ["Attacker crafts link", "Victim clicks link", "Victim's browser", "Script runs in victim's session"],
  "xss-s": ["Attacker posts comment once", "Every visitor loads the page", "Each visitor's browser", "Script runs for every viewer"],
  "xss-d": ["Attacker crafts URL fragment", "Victim opens the link", "Client-side JS writes to DOM", "Script executes, no server involved"],
  "auth-cred": ["Leaked credential list", "Automated login attempts", "Target's login endpoint", "Reused passwords succeed"],
  "session-fix": ["Attacker visits site first", "Gets unauthenticated session ID", "Plants that ID on victim", "Victim logs in using same ID"],
  jwt: ["Attacker", "Intercepts own JWT", "Rewrites claim, re-signs (alg flaw)", "Server accepts forged token"],
  idor: ["Attacker (own account)", "Own invoice: /invoices/1041", "Swaps ID to /invoices/1042", "Receives victim's invoice"],
  privesc: ["Attacker (standard user)", "Own \"role\" field in request", "Edits role to \"admin\"", "Gains admin capabilities"],
  "path-trav": ["Attacker", '"download?file=report.pdf"', "Traverses to ../../etc/passwd", "Reads file outside sandbox"],
  csrf: ["Victim (logged in)", "Visits attacker's page", "Auto-submits to target endpoint", "State changed without consent"],
  ssrf: ["Attacker", '"Fetch image from URL" feature', "Internal metadata/service", "Internal data returned to attacker"],
  deser: ["Attacker", "Serialized cookie/session blob", "Deserializer instantiates objects", "Gadget chain → code execution"],
  supply: ["Attacker", "Publishes lookalike/higher-version package", "Build pipeline resolves it", "Malicious code runs in build/app"],
  cors: ["Attacker's site", "Cross-origin request w/ credentials", "API reflects any Origin", "Attacker reads authenticated response"],
  clickjack: ["Attacker's decoy page", "Invisible iframe of target site", "Victim clicks decoy", "Click lands on hidden target button"],
  protopoll: ["Attacker", 'JSON body with "__proto__" key', "Naive merge/clone utility", "Object.prototype polluted app-wide"],
  bizlogic: ["Two parallel coupon requests", "Balance-check step", "Deduction-commit step", "Coupon redeemed more than allowed"],
  race: ["Many parallel requests", "Check step (balance/stock/limit)", "Act step (commit)", "More successes than should be possible"],
  smuggling: ["Front-end proxy parses request", "Origin server parses it differently", "Leftover bytes prepended", "Next user's request hijacked"],
  "cache-poison": ["Attacker sends request w/ bad header", "Response generated using that header", "Cached under a key that ignores it", "Every visitor served poisoned response"],
  "cache-deception": ["Attacker requests /account/fake.css", "Personalized page rendered anyway", 'Cache stores it as "static"', "Attacker re-requests, gets victim's data"],
  "subdomain-takeover": ["Third-party service deleted", "DNS record still points at it", "Attacker claims same resource name", "Attacker serves content on trusted domain"],
  "file-upload": ["Attacker", "Uploads shell.php.jpg", "Server stores in web-accessible dir", "Requests file directly → RCE"],
  "mass-assign": ["Attacker (standard user)", "Update-profile request", 'Adds "role":"admin" field', "Model persists unintended field"],
  bfla: ["Attacker (standard user)", "Finds /api/admin/... in JS bundle", "Calls it directly with own token", "Privileged action executes"],
  "open-redirect": ["Attacker crafts trusted-domain link", "?next=https://evil.example param", "Victim clicks, trusts the domain", "Redirected to attacker's phishing page"],
  "host-header": ["Attacker sends forged Host header", "App builds reset link from it", "Email sent to victim", "Reset token leaks to attacker's domain"],
  redos: ["Attacker", "Input maximizing backtracking", "Regex engine (nested quantifiers)", "CPU pinned, requests hang (DoS)"],
  graphql: ["Attacker", "Sends __schema introspection query", "Full schema + unused fields exposed", "Tests unprotected fields/mutations"],
  cswsh: ["Victim (logged in, cookie set)", "Opens attacker's page", "Page opens WebSocket to target", "Connection authenticates as victim"],
  xpath: ["Attacker", "Search/filter field", "XPath query engine", "Auth bypass / data leak"],
  rfi: ["Attacker", "?page= parameter", "Server fetches remote URL as code", "Remote code execution"],
  "email-header": ["Attacker", '"Your name" contact field', "Newline + fake Bcc: header injected", "Spam relay / header injection"],
  crlf: ["Attacker", "URL param reflected into header", "%0d%0a injects new header line", "Header injection / cache poisoning"],
  "dns-rebind": ["Attacker-controlled DNS, short TTL", "Victim's browser loads the page", "Record flips to internal IP", "Script reaches internal-only service"],
  misconfig: ["Attacker", "Finds default admin path/creds", "Unpatched default configuration", "Full access, no exploit needed"],
  "crypto-fail": ["Attacker", "Observes traffic / obtains DB dump", "Weak/missing encryption or hashing", "Sensitive data read directly"],
  "client-storage": ["Any script in the page's origin", "Reads localStorage / non-HttpOnly cookie", "No access restriction beyond same-origin", "Token theft amplifies any XSS bug"],
};


const SEVERITY_STYLE = {
  critical: { color: "#ff3b3b", label: "critical" },
  high: { color: "#ff8a3d", label: "high" },
  medium: { color: "#ffb000", label: "medium" },
  low: { color: "#6fcf97", label: "low" },
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function VectorBase() {
  const [query, setQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState("all");
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    return VECTORS.filter((v) => {
      const matchesCategory = activeCategory === "all" || v.category === activeCategory;
      const q = query.trim().toLowerCase();
      const matchesQuery =
        !q ||
        v.name.toLowerCase().includes(q) ||
        v.summary.toLowerCase().includes(q) ||
        v.category.toLowerCase().includes(q);
      return matchesCategory && matchesQuery;
    }).sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [query, activeCategory]);

  const categoryCounts = useMemo(() => {
    const counts = {};
    VECTORS.forEach((v) => (counts[v.category] = (counts[v.category] || 0) + 1));
    return counts;
  }, []);

  return (
    <div
      style={{
        fontFamily: "'Inter', sans-serif",
        fontWeight: 400,
        background: "#0a0e0f",
        color: "#d7e0e0",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        isolation: "isolate",
        overflow: "hidden",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
        ::selection { background: #ffb00033; }
        .vb-card { transition: border-color 120ms ease, transform 120ms ease, box-shadow 120ms ease; position: relative; }
        .vb-card:hover { border-color: #ffb00088; transform: translateY(-1px); box-shadow: 0 0 16px #ffb00022; }
        .vb-cat-btn { transition: color 120ms ease, border-color 120ms ease, text-shadow 120ms ease; }
        .vb-cat-btn:hover { color: #ffb000 !important; }
        .vb-scroll::-webkit-scrollbar { width: 8px; }
        .vb-scroll::-webkit-scrollbar-thumb { background: #1f2b2e; border-radius: 4px; }
        @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
        .vb-cursor { animation: blink 1s step-start infinite; }
        @keyframes scan { 0% { transform: translateY(-100%); } 100% { transform: translateY(100%); } }
        .vb-scanlines {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 40;
          background: repeating-linear-gradient(
            to bottom,
            rgba(255, 176, 0, 0.035) 0px,
            rgba(255, 176, 0, 0.035) 1px,
            transparent 1px,
            transparent 3px
          );
          mix-blend-mode: overlay;
        }
        .vb-vignette {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 39;
          background: radial-gradient(ellipse at center, transparent 55%, #00000099 130%);
        }
        .vb-scanbeam {
          position: fixed;
          inset: 0;
          pointer-events: none;
          z-index: 41;
          background: linear-gradient(to bottom, transparent 0%, #ffb00008 45%, #ffb00014 50%, #ffb00008 55%, transparent 100%);
          animation: scan 7s linear infinite;
        }
        @keyframes ticker-scroll { 0% { transform: translateX(0); } 100% { transform: translateX(-50%); } }
        .vb-ticker-track { display: inline-flex; animation: ticker-scroll 38s linear infinite; white-space: nowrap; }
      `}</style>

      <MatrixRain />
      <div className="vb-scanlines" />
      <div className="vb-vignette" />
      <div className="vb-scanbeam" />

      {/* top bar */}
      <div
        style={{
          borderBottom: "1px solid #1f2b2e",
          padding: "14px 20px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <Terminal size={16} color="#ffb000" />
        <span style={{ fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: "#7d8f8f" }}>
          root@vectorbase:~$ ./list --vectors
          <span className="vb-cursor" style={{ color: "#ffb000" }}>▌</span>
        </span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
          <Radio size={13} color="#6fcf97" />
          <span style={{ fontSize: 12, fontFamily: "'Inter', sans-serif", fontWeight: 500, color: "#6fcf97" }}>{VECTORS.length} vectors indexed</span>
        </div>
      </div>

      <div style={{ padding: "28px 20px 8px", maxWidth: 1180, margin: "0 auto", width: "100%" }}>
        <h1
          style={{
            fontFamily: "'Inter', sans-serif",
            fontWeight: 700,
            fontSize: 28,
            color: "#eef4f4",
            margin: "0 0 6px",
          }}
        >
          Web Attack Vector Base
        </h1>
        <p style={{ fontFamily: "'Inter', sans-serif", fontWeight: 400, fontSize: 14, color: "#7d8f8f", margin: "0 0 20px", maxWidth: 640, lineHeight: 1.5 }}>
          A reference catalog of how common web application attacks work, how they've shown up in the real world, and how to defend against them. Mechanism-level detail for study — not exploit code.
        </p>

        {/* search */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            border: "1px solid #1f2b2e",
            background: "#10161a",
            borderRadius: 4,
            padding: "10px 14px",
            marginBottom: 20,
          }}
        >
          <Search size={15} color="#ffb000" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="grep vector-name, category, keyword..."
            style={{
              background: "transparent",
              border: "none",
              outline: "none",
              color: "#eef4f4",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 13,
              flex: 1,
            }}
          />
        </div>
      </div>

      <div style={{ display: "flex", maxWidth: 1180, margin: "0 auto", width: "100%", gap: 24, padding: "0 20px 40px", alignItems: "flex-start" }}>
        {/* sidebar */}
        <div style={{ width: 200, flexShrink: 0, position: "sticky", top: 20 }}>
          <div style={{ fontSize: 11, fontFamily: "'Inter', sans-serif", fontWeight: 500, color: "#516161", marginBottom: 10, letterSpacing: 0.5 }}>categories</div>
          <button
            className="vb-cat-btn"
            onClick={() => setActiveCategory("all")}
            style={{
              display: "block",
              width: "100%",
              textAlign: "left",
              background: "none",
              border: "none",
              borderLeft: activeCategory === "all" ? "2px solid #ffb000" : "2px solid transparent",
              color: activeCategory === "all" ? "#ffb000" : "#a8b8b8",
              padding: "6px 10px",
              fontSize: 13,
              fontFamily: "'Inter', sans-serif",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            all ({VECTORS.length})
          </button>
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              className="vb-cat-btn"
              onClick={() => setActiveCategory(cat)}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                background: "none",
                border: "none",
                borderLeft: activeCategory === cat ? "2px solid #ffb000" : "2px solid transparent",
                color: activeCategory === cat ? "#ffb000" : "#a8b8b8",
                padding: "6px 10px",
                fontSize: 13,
                fontFamily: "'Inter', sans-serif",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              {cat} ({categoryCounts[cat]})
            </button>
          ))}
        </div>

        {/* grid */}
        <div style={{ flex: 1, display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(270px, 1fr))", gap: 14 }}>
          {filtered.map((v) => (
            <div
              key={v.id}
              className="vb-card"
              onClick={() => setSelected(v)}
              style={{
                border: "1px solid #1f2b2e",
                background: "#10161a",
                borderRadius: 4,
                padding: 16,
                cursor: "pointer",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: "'Inter', sans-serif",
                    fontWeight: 600,
                    color: SEVERITY_STYLE[v.severity].color,
                    border: `1px solid ${SEVERITY_STYLE[v.severity].color}55`,
                    borderRadius: 3,
                    padding: "2px 6px",
                  }}
                >
                  {SEVERITY_STYLE[v.severity].label}
                </span>
                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: "#516161" }}>{v.owasp}</span>
              </div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 15, fontWeight: 600, color: "#eef4f4", marginBottom: 6 }}>
                {v.name}
              </div>
              <div style={{ fontSize: 10, color: "#7d8f8f", marginBottom: 8 }}>{v.category}</div>
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 12.5, color: "#a8b8b8", lineHeight: 1.5, margin: "0 0 10px" }}>
                {v.summary}
              </p>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#ffb000" }}>
                view case file <ChevronRight size={12} />
                {LABS[v.id] && (
                  <span style={{ marginLeft: "auto", fontSize: 9, color: "#6fcf97", border: "1px solid #6fcf9755", borderRadius: 3, padding: "1px 5px" }}>
                    lab
                  </span>
                )}
              </div>
            </div>
          ))}
          {filtered.length === 0 && (
            <div style={{ gridColumn: "1 / -1", color: "#516161", fontSize: 13, padding: 30, textAlign: "center" }}>
              no vectors match that query.
            </div>
          )}
        </div>
      </div>

      <div
        style={{
          borderTop: "1px solid #1f2b2e",
          padding: "8px 0",
          overflow: "hidden",
          background: "#0a0e0f",
        }}
      >
        <div className="vb-ticker-track">
          {[0, 1].map((rep) => (
            <span
              key={rep}
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: "#3a4a4a",
                paddingRight: 48,
              }}
            >
              recon: {VECTORS.length} vector definitions loaded &nbsp;·&nbsp; index: {CATEGORIES.length} categories
              &nbsp;·&nbsp; status: reference-only, no live targets &nbsp;·&nbsp; labs: {Object.keys(LABS).length}{" "}
              sandboxed environments available &nbsp;·&nbsp; last sync: local session &nbsp;·&nbsp;
            </span>
          ))}
        </div>
      </div>

      {/* detail overlay */}
      {selected && (
        <div
          onClick={() => setSelected(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "#000000cc",
            display: "flex",
            justifyContent: "flex-end",
            zIndex: 50,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="vb-scroll"
            style={{
              width: "min(560px, 100%)",
              height: "100%",
              background: "#0a0e0f",
              borderLeft: "1px solid #1f2b2e",
              overflowY: "auto",
              padding: "24px 26px 60px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 18 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <ShieldAlert size={16} color={SEVERITY_STYLE[selected.severity].color} />
                  <span style={{ fontSize: 11 }}>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontWeight: 600, color: SEVERITY_STYLE[selected.severity].color }}>
                      {SEVERITY_STYLE[selected.severity].label}
                    </span>
                    <span style={{ fontFamily: "'Inter', sans-serif", color: SEVERITY_STYLE[selected.severity].color }}> · </span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", color: SEVERITY_STYLE[selected.severity].color }}>
                      {selected.owasp}
                    </span>
                  </span>
                </div>
                <h2 style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: "#eef4f4", margin: 0 }}>
                  {selected.name}
                </h2>
                <div style={{ fontSize: 11, color: "#7d8f8f", marginTop: 4 }}>{selected.category}</div>
              </div>
              <button
                onClick={() => setSelected(null)}
                style={{ background: "none", border: "1px solid #1f2b2e", borderRadius: 4, color: "#a8b8b8", cursor: "pointer", padding: 6 }}
              >
                <X size={15} />
              </button>
            </div>

            <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 13.5, color: "#c3d0d0", lineHeight: 1.6, marginBottom: 20 }}>
              {selected.summary}
            </p>

            {FLOW_LABELS[selected.id] && (
              <div style={{ marginBottom: 22 }}>
                <div style={{ fontSize: 11, color: "#ffb000", marginBottom: 10 }}>attack chain</div>
                <AttackFlow labels={FLOW_LABELS[selected.id]} severityColor={SEVERITY_STYLE[selected.severity].color} />
              </div>
            )}

            <Section title="mechanism">
              <ol style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 8 }}>
                {selected.mechanism.map((step, i) => (
                  <li key={i} style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#c3d0d0", lineHeight: 1.55 }}>
                    {step}
                  </li>
                ))}
              </ol>
            </Section>

            <Section title="illustrative example">
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#c3d0d0", lineHeight: 1.55, margin: 0 }}>
                {selected.example}
              </p>
            </Section>

            <Section title="real-world context">
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#c3d0d0", lineHeight: 1.55, margin: 0 }}>
                {selected.incident}
              </p>
            </Section>

            {selected.detection && (
              <Section title="detection signals">
                <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
                  {selected.detection.map((d, i) => (
                    <li key={i} style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#a8b8b8", lineHeight: 1.5 }}>
                      {d}
                    </li>
                  ))}
                </ul>
              </Section>
            )}

            {CATEGORY_WORKFLOW[selected.category] && (
              <Section title="how hunters test for this (authorized scope only)">
                <TestingWorkflow steps={CATEGORY_WORKFLOW[selected.category]} />
              </Section>
            )}

            {LABS[selected.id] && (
              <Section title="hands-on lab — try it yourself">
                {React.createElement(LABS[selected.id])}
              </Section>
            )}

            <Section title="defense" last>
              <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
                {selected.defense.map((d, i) => (
                  <li key={i} style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#6fcf97", lineHeight: 1.5 }}>
                    {d}
                  </li>
                ))}
              </ul>
            </Section>
          </div>
        </div>
      )}
    </div>
  );
}

function MatrixRain() {
  const canvasRef = React.useRef(null);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const glyphs = "01<>/#$%&{}[]=;:.".split("");
    let columns, drops, width, height;
    let raf;

    const resize = () => {
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
      const fontSize = 15;
      columns = Math.floor(width / fontSize);
      drops = new Array(columns).fill(0).map(() => Math.random() * -50);
    };
    resize();
    window.addEventListener("resize", resize);

    const fontSize = 15;
    const draw = () => {
      ctx.fillStyle = "rgba(10, 14, 15, 0.12)";
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;
      for (let i = 0; i < columns; i++) {
        const glyph = glyphs[Math.floor(Math.random() * glyphs.length)];
        const y = drops[i] * fontSize;
        ctx.fillStyle = y < fontSize * 2 ? "rgba(255, 176, 0, 0.55)" : "rgba(255, 176, 0, 0.14)";
        ctx.fillText(glyph, i * fontSize, y);
        if (y > height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        zIndex: -1,
        opacity: 0.5,
        pointerEvents: "none",
      }}
    />
  );
}

function Section({ title, children, last }) {
  return (
    <div style={{ marginBottom: last ? 0 : 22, borderTop: "1px solid #1f2b2e", paddingTop: 14 }}>
      <div style={{ fontSize: 11, color: "#ffb000", marginBottom: 10, fontFamily: "'Inter', sans-serif", fontWeight: 600 }}>{title}</div>
      {children}
    </div>
  );
}

function AttackFlow({ labels, severityColor }) {
  const nodeStyles = [
    { bg: "#1a1310", border: "#ffb00088", text: "#ffb000" }, // attacker/source
    { bg: "#10161a", border: "#2a3a3e", text: "#c3d0d0" }, // vector
    { bg: "#10161a", border: "#2a3a3e", text: "#c3d0d0" }, // mechanism
    { bg: "#1a1010", border: `${severityColor}88`, text: severityColor }, // impact
  ];
  return (
    <div
      style={{
        border: "1px solid #1f2b2e",
        borderRadius: 4,
        padding: "18px 14px",
        background: "repeating-linear-gradient(135deg, #0d1214 0px, #0d1214 10px, #0f1517 10px, #0f1517 20px)",
        overflowX: "auto",
      }}
    >
      <div style={{ display: "flex", alignItems: "stretch", minWidth: 480 }}>
        {labels.map((label, i) => (
          <React.Fragment key={i}>
            <div
              style={{
                flex: 1,
                minWidth: 100,
                border: `1px solid ${nodeStyles[i].border}`,
                background: nodeStyles[i].bg,
                borderRadius: 3,
                padding: "10px 8px",
                textAlign: "center",
                boxShadow: i === 0 || i === 3 ? `0 0 10px ${nodeStyles[i].border}33` : "none",
              }}
            >
              <div style={{ fontSize: 9, fontFamily: "'Inter', sans-serif", fontWeight: 500, color: "#516161", marginBottom: 5, letterSpacing: 0.5 }}>
                {["source", "vector", "mechanism", "impact"][i]}
              </div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: nodeStyles[i].text, lineHeight: 1.35 }}>
                {label}
              </div>
            </div>
            {i < labels.length - 1 && (
              <div style={{ display: "flex", alignItems: "center", padding: "0 6px", color: "#ffb00099", fontSize: 16, flexShrink: 0 }}>
                ▸
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function TestingWorkflow({ steps }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start" }}>
        {steps.map((_, i) => {
          const Icon = WORKFLOW_ICONS[i];
          return (
            <React.Fragment key={i}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 64, flexShrink: 0 }}>
                <div
                  style={{
                    width: 34,
                    height: 34,
                    borderRadius: "50%",
                    border: "1px solid #ffb00088",
                    background: "#10161a",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    marginBottom: 6,
                  }}
                >
                  <Icon size={15} color="#ffb000" />
                </div>
                <div style={{ fontSize: 10, fontFamily: "'Inter', sans-serif", fontWeight: 500, color: "#7d8f8f", textAlign: "center" }}>{WORKFLOW_STEPS[i]}</div>
              </div>
              {i < steps.length - 1 && (
                <div style={{ flex: 1, height: 1, background: "#1f2b2e", marginTop: 17 }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
      <div style={{ display: "flex", marginTop: 14, gap: 10 }}>
        {steps.map((s, i) => (
          <p
            key={i}
            style={{
              flex: 1,
              fontFamily: "'Inter', sans-serif",
              fontSize: 11.5,
              color: "#a8b8b8",
              lineHeight: 1.5,
              margin: 0,
            }}
          >
            {s}
          </p>
        ))}
      </div>
    </div>
  );
}


// ---------------------------------------------------------------------------
// Hands-on labs: each one is a small, fully self-contained, SIMULATED
// vulnerable target running only in this component's own state — a fake
// in-memory "backend", never a real request to anywhere. You have to find
// the technique yourself; nothing here is a payload handed to you upfront.
// ---------------------------------------------------------------------------

function LabInput(props) {
  return (
    <input
      {...props}
      style={{
        width: "100%",
        background: "#0a0e0f",
        border: "1px solid #2a3a3e",
        borderRadius: 3,
        color: "#eef4f4",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12.5,
        padding: "8px 10px",
        outline: "none",
        ...props.style,
      }}
    />
  );
}

function LabTextarea(props) {
  return (
    <textarea
      {...props}
      style={{
        width: "100%",
        background: "#0a0e0f",
        border: "1px solid #2a3a3e",
        borderRadius: 3,
        color: "#eef4f4",
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12,
        padding: "10px",
        outline: "none",
        resize: "vertical",
        minHeight: 70,
        ...props.style,
      }}
    />
  );
}

function LabButton({ children, ...props }) {
  return (
    <button
      {...props}
      style={{
        background: "#ffb00018",
        border: "1px solid #ffb00066",
        color: "#ffb000",
        borderRadius: 3,
        padding: "8px 14px",
        fontFamily: "'Inter', sans-serif",
        fontWeight: 600,
        fontSize: 12,
        cursor: "pointer",
      }}
    >
      {children}
    </button>
  );
}

function LabOutput({ children }) {
  if (!children) return null;
  return (
    <div
      style={{
        background: "#0a0e0f",
        border: "1px solid #1f2b2e",
        borderRadius: 3,
        padding: "10px 12px",
        marginTop: 10,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 12,
        color: "#c3d0d0",
        whiteSpace: "pre-wrap",
        lineHeight: 1.5,
      }}
    >
      {children}
    </div>
  );
}

function LabHint({ hint }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 10 }}>
      <button
        onClick={() => setOpen((o) => !o)}
        style={{ background: "none", border: "none", color: "#7d8f8f", fontSize: 11, cursor: "pointer", padding: 0, textDecoration: "underline dotted" }}
      >
        {open ? "hide hint" : "stuck? reveal a hint"}
      </button>
      {open && (
        <div style={{ marginTop: 6, fontSize: 12, color: "#a8b8b8", fontFamily: "'Inter', sans-serif", lineHeight: 1.5 }}>{hint}</div>
      )}
    </div>
  );
}

function LabFlag({ flag, explanation }) {
  return (
    <div
      style={{
        marginTop: 12,
        border: "1px solid #6fcf9788",
        background: "#0e1a13",
        borderRadius: 3,
        padding: "12px 14px",
        boxShadow: "0 0 14px #6fcf9722",
      }}
    >
      <div style={{ fontSize: 11, fontFamily: "'Inter', sans-serif", fontWeight: 600, color: "#6fcf97", marginBottom: 6 }}>✓ solved</div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#8fe8b4", marginBottom: 8 }}>{flag}</div>
      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "#a8b8b8", lineHeight: 1.5 }}>{explanation}</div>
    </div>
  );
}

function LabShell({ objective, children }) {
  return (
    <div style={{ border: "1px solid #1f2b2e", borderRadius: 4, padding: 16, background: "#10161a" }}>
      <p style={{ fontFamily: "'Inter', sans-serif", fontSize: 12.5, color: "#a8b8b8", lineHeight: 1.5, margin: "0 0 14px" }}>
        {objective}
      </p>
      {children}
    </div>
  );
}

// --- SQL Injection: login bypass against a simulated auth check ---
function LabSqli() {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);
  const DB = [{ user: "admin", pass: "K3ep0ut!", role: "admin" }];

  const attempt = () => {
    const injected = /'\s*(or|OR)\s*.*(=|like)/i.test(user) || /'\s*(or|OR)\s*.*(=|like)/i.test(pass);
    const normal = DB.find((u) => u.user === user && u.pass === pass);
    if (injected || normal) {
      setOutput(`> query matched a row\n> logged in as: admin`);
      setSolved(true);
    } else {
      setOutput(`> query returned 0 rows\n> login failed`);
    }
  };

  return (
    <LabShell objective="A simulated login form checks credentials against a query built like: SELECT * FROM users WHERE username='<input>' AND password='<input>'. Log in as admin — you don't know the password.">
      <LabInput placeholder="username" value={user} onChange={(e) => setUser(e.target.value)} style={{ marginBottom: 8 }} />
      <LabInput placeholder="password" value={pass} onChange={(e) => setPass(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={attempt}>Log in</LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint="The query wraps your input in quotes. What if part of your input closed that quote early and added a condition that's always true, like an OR clause?" />
      {solved && (
        <LabFlag
          flag="VECTORBASE{sql1_4uth_byp4ss}"
          explanation="Injecting something like admin'-- or ' OR '1'='1 breaks out of the quoted string and rewrites the query's logic so it matches regardless of the real password."
        />
      )}
    </LabShell>
  );
}

// --- Reflected XSS: search box rendered unescaped into the page ---
function LabXss() {
  const [q, setQ] = useState("");
  const [rendered, setRendered] = useState("");
  const [solved, setSolved] = useState(false);
  const idRef = React.useRef("vb_xss_" + Math.random().toString(36).slice(2));

  React.useEffect(() => {
    window[idRef.current] = () => setSolved(true);
    return () => {
      delete window[idRef.current];
    };
  }, []);

  const search = () => setRendered(q);

  return (
    <LabShell objective="This search box reflects your query directly into the results heading with no encoding. Make the page itself run a bit of JavaScript on your behalf — a plain <script> tag alone won't fire once inserted this way.">
      <LabInput placeholder="search..." value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={search}>Search</LabButton>
      <div style={{ marginTop: 10, border: "1px solid #1f2b2e", borderRadius: 3, padding: "10px 12px", fontFamily: "'Inter', sans-serif", fontSize: 13, color: "#c3d0d0" }}>
        You searched for: <span dangerouslySetInnerHTML={{ __html: rendered }} />
      </div>
      <LabHint hint={`A <script> tag inserted this way won't execute in most browsers. But plenty of HTML tags run JS through an event attribute the moment they're inserted — think about a tag with a "source" that deliberately fails to load, and what event fires when it does. Call window.${idRef.current}() from inside it.`} />
      {solved && (
        <LabFlag
          flag="VECTORBASE{refl3cted_xss_f1red}"
          explanation="Tags inserted via innerHTML don't execute <script> content, but inline event-handler attributes (onerror, onload, onmouseover...) still fire — e.g. an <img> with a broken src and an onerror handler runs the moment the browser gives up loading it."
        />
      )}
    </LabShell>
  );
}

// --- IDOR: swap an ID to read another user's record ---
function LabIdor() {
  const [id, setId] = useState("1001");
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);
  const RECORDS = {
    1001: { owner: "you", amount: "$40.00" },
    1002: { owner: "alice", amount: "$9,200.00", note: "quarterly board payout — confidential" },
  };

  const fetchInvoice = () => {
    const rec = RECORDS[id];
    if (!rec) return setOutput("> 404 not found");
    if (rec.owner !== "you") {
      setOutput(`> 200 OK\n> owner: ${rec.owner}\n> amount: ${rec.amount}\n> note: ${rec.note}`);
      setSolved(true);
    } else {
      setOutput(`> 200 OK\n> owner: ${rec.owner}\n> amount: ${rec.amount}`);
    }
  };

  return (
    <LabShell objective="You're logged in as a standard user and can view your own invoice at ID 1001 through this panel. See if you can view someone else's.">
      <LabInput placeholder="invoice ID" value={id} onChange={(e) => setId(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={fetchInvoice}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 500 }}>GET /invoices/{"{id}"}</span>
      </LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint="Nothing here checks whether the invoice ID you ask for actually belongs to you. Try an ID near your own." />
      {solved && (
        <LabFlag
          flag="VECTORBASE{1dor_own3rsh1p_sk1pped}"
          explanation="The endpoint checked that you were logged in, but never checked that the specific invoice ID belonged to your account — the classic object-level authorization gap."
        />
      )}
    </LabShell>
  );
}

// --- Mass assignment: smuggle an extra field into a profile update ---
function LabMassAssign() {
  const [body, setBody] = useState('{\n  "name": "guest"\n}');
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);

  const submit = () => {
    try {
      const parsed = JSON.parse(body);
      const profile = { name: "guest", email: "guest@example.com", role: "user", ...parsed };
      if (profile.role === "admin") {
        setOutput(`> 200 OK\n> profile updated: ${JSON.stringify(profile)}\n> admin panel: UNLOCKED`);
        setSolved(true);
      } else {
        setOutput(`> 200 OK\n> profile updated: ${JSON.stringify(profile)}`);
      }
    } catch {
      setOutput("> 400 invalid JSON");
    }
  };

  return (
    <LabShell objective="This is a PATCH /api/profile body editor. The backend blindly merges whatever keys you send onto your profile object — it isn't limited to name/email.">
      <LabTextarea value={body} onChange={(e) => setBody(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={submit}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 500 }}>PATCH /api/profile</span>
      </LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint='Your profile object has a "role" field you never see in the UI. What happens if you add it to the JSON body yourself?' />
      {solved && (
        <LabFlag
          flag="VECTORBASE{m4ss_4ss1gnment_r0le}"
          explanation='The server merged the entire request body onto the internal model instead of allow-listing which fields a client is permitted to set — so a "role" key you invented got persisted as if it came through a legitimate admin flow.'
        />
      )}
    </LabShell>
  );
}

// --- Open redirect ---
function LabOpenRedirect() {
  const [next, setNext] = useState("");
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);

  const go = () => {
    if (!next) return;
    let external = false;
    try {
      external = /^https?:\/\//i.test(next) && !next.includes("vectorbase.local");
    } catch {}
    setOutput(external ? `> 302 Found\n> Location: ${next}\n> (this app just left its own domain)` : `> 302 Found\n> Location: ${next}`);
    if (external) setSolved(true);
  };

  return (
    <LabShell objective='This "continue to" login flow redirects to whatever URL you give it after a fake login. See if you can make it send a logged-in visitor to a domain that has nothing to do with this app.'>
      <LabInput placeholder="?next=..." value={next} onChange={(e) => setNext(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={go}>Log in & continue</LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint="There's no check that the destination actually belongs to this site. A full https:// URL to anywhere else should just work." />
      {solved && (
        <LabFlag
          flag="VECTORBASE{0pen_red1rect_any_h0st}"
          explanation="The redirect target was taken straight from user input with no allow-list check — exactly what makes open redirects a favorite for phishing links that borrow a trusted domain's credibility."
        />
      )}
    </LabShell>
  );
}

// --- SSRF against a simulated internal metadata endpoint ---
function LabSsrf() {
  const [url, setUrl] = useState("");
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);

  const fetchIt = () => {
    const internal = /169\.254\.169\.254|localhost|127\.0\.0\.1|internal/i.test(url);
    if (internal) {
      setOutput(`> fetched ${url}\n> {"role":"deploy-service","secret_key":"AKIA_SIMULATED_SECRET_9f2c"}`);
      setSolved(true);
    } else if (url) {
      setOutput(`> fetched ${url}\n> [binary image data, 42 KB]`);
    }
  };

  return (
    <LabShell objective={`This "load image from URL" feature fetches whatever URL you give it, server-side, to render a preview. Real cloud servers expose an internal-only metadata service at a well-known address — see if this feature can reach somewhere it shouldn't.`}>
      <LabInput placeholder="https://example.com/photo.jpg" value={url} onChange={(e) => setUrl(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={fetchIt}>Fetch preview</LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint="Cloud providers commonly expose instance metadata at the address 169.254.169.254. What if the URL you give this feature points there instead of a real image?" />
      {solved && (
        <LabFlag
          flag="VECTORBASE{ssrf_m3tadata_l34k}"
          explanation="Because the fetch happens server-side, inside the trusted network, pointing it at an internal address reaches services the attacker could never contact directly — this is exactly how several real cloud-credential breaches started."
        />
      )}
    </LabShell>
  );
}

// --- OS command injection via a simulated ping utility ---
function LabCmdi() {
  const [host, setHost] = useState("");
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);

  const run = () => {
    const chained = /[;&|`]/.test(host);
    if (chained) {
      setOutput(`> ping: 4 packets transmitted, 4 received\n> --- chained command output ---\n> root:x:0:0:root:/root:/bin/bash\n> deploy:x:1000:1000::/home/deploy:/bin/sh`);
      setSolved(true);
    } else if (host) {
      setOutput(`> pinging ${host} ...\n> 4 packets transmitted, 4 received, 0% loss`);
    }
  };

  return (
    <LabShell objective="This diagnostic tool shells out to the OS's ping command using whatever host you type, unmodified. See if you can get it to run a second command alongside the ping.">
      <LabInput placeholder="hostname" value={host} onChange={(e) => setHost(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={run}>Run diagnostic</LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint="Shells let you chain multiple commands on one line using characters like ; or &&. What happens if your 'hostname' is actually two commands?" />
      {solved && (
        <LabFlag
          flag="VECTORBASE{cmd1_ch41ned_ex3c}"
          explanation="Because the input goes straight into a shell command string, any shell metacharacter (;, &&, |) lets you append an entirely separate command that runs with the same privileges as the diagnostic tool itself."
        />
      )}
    </LabShell>
  );
}

// --- Prototype pollution: a real, contained pollution of this session's JS runtime ---
function LabProtoPollution() {
  const [body, setBody] = useState('{\n  "theme": "dark"\n}');
  const [output, setOutput] = useState("");
  const [solved, setSolved] = useState(false);

  function naiveMerge(target, source) {
    for (const key in source) {
      if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
        if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
        naiveMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const apply = () => {
    try {
      const parsed = JSON.parse(body);
      const settings = {};
      naiveMerge(settings, parsed);
      const pollutedNow = ({}).isAdmin === true;
      if (pollutedNow) {
        setOutput(`> settings merged\n> checking a brand-new plain object: ({}).isAdmin === ${({}).isAdmin}\n> Object.prototype has been modified for this whole session`);
        setSolved(true);
      } else {
        setOutput(`> settings merged: ${JSON.stringify(settings)}`);
      }
    } catch {
      setOutput("> 400 invalid JSON");
    }
  };

  return (
    <LabShell objective="This settings panel deep-merges whatever JSON object you submit onto an internal config object, recursively, key by key — with no check on which keys it's willing to touch. This is a real (sandboxed) merge function; genuinely pollute JavaScript's own Object.prototype for this session.">
      <LabTextarea value={body} onChange={(e) => setBody(e.target.value)} style={{ marginBottom: 10 }} />
      <LabButton onClick={apply}>Save settings</LabButton>
      <LabOutput>{output}</LabOutput>
      <LabHint hint={`Every JS object inherits from Object.prototype through a special key. If the merge function walks into that key's own contents without special-casing it, whatever you nest inside gets written onto the prototype itself, not just this one object. The key looks like "__proto__".`} />
      {solved && (
        <LabFlag
          flag="VECTORBASE{pr0t0_p0llut10n_l1ve}"
          explanation='Submitting { "__proto__": { "isAdmin": true } } made the naive recursive merge walk into __proto__ as if it were a normal nested object, writing isAdmin directly onto Object.prototype — after which every object in the runtime, even a brand new {}, inherits isAdmin: true.'
        />
      )}
    </LabShell>
  );
}

const LABS = {
  sqli: LabSqli,
  "xss-r": LabXss,
  idor: LabIdor,
  "mass-assign": LabMassAssign,
  "open-redirect": LabOpenRedirect,
  ssrf: LabSsrf,
  cmdi: LabCmdi,
  protopoll: LabProtoPollution,
};
