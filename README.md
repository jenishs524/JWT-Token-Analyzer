# JWT-Token-Analyzer

📘 JWT Token Analyzer 

It is an advanced, automated cryptographic security assessment tool specifically designed to dissect, analyse, and identify critical misconfigurations and vulnerabilities in JSON Web Tokens (JWTs). JWTs are widely used for authentication and authorisation in modern web applications and APIs. However, developers often misconfigure them—leaving them vulnerable to forgery, bypass, and account takeover. This tool provides a comprehensive security audit of JWTs, exposing weaknesses that could compromise an entire application's authentication layer.


🎯 Objective

To automatically audit JSON Web Tokens (JWTs) for a comprehensive set of security weaknesses that could lead to unauthorised access, privilege escalation, or complete account compromise. Manual inspection of JWTs is cumbersome and error‑prone. This tool automates the analysis process by:

    Decoding the token structure (Header, Payload, Signature) without requiring the secret key.

    Validating critical claims (expiration, issuer, audience, not‑before).

    Detecting dangerous algorithm misconfigurations (e.g., alg: none).

    Identifying sensitive data exposure inside the payload.

    Attempting to brute‑force weak shared secrets (for HS256/HS384/HS512 tokens).

    Checking for known signature bypass techniques (e.g., algorithm confusion attacks: using RS256 to verify HS256 tokens).

🧠 How It Works – Technical Overview

The tool dissects the JWT into its three components—Header, Payload, and Signature—and performs a layered security assessment:
1. Structural & Header Analysis

    Base64URL Decoding: Decodes the Header and Payload without verifying the signature, allowing inspection of raw claims.

    Algorithm Detection: Checks the alg header field. Flags none as CRITICAL (allows forging tokens with an empty signature).

    Key ID (kid) Inspection: Checks if the kid header is present. If it references a file path (e.g., ../../etc/passwd), it may indicate a path traversal vulnerability in the JWT library's key retrieval.

    Type (typ) Validation: Ensures the token is correctly typed as JWT (or JOSE); unusual types may indicate misimplementation.

2. Payload Claim Analysis

    Expiration (exp): Checks if the token has an expiry. If missing, flags as HIGH risk. If present, calculates the remaining validity and alerts if it is excessively long (e.g., > 30 days).

    Issuer (iss) & Audience (aud): Verifies these fields are present and properly formatted. Missing or misconfigured iss/aud claims can lead to cross‑service token reuse attacks.

    Not‑Before (nbf): Checks if the token is active yet. If absent, no warning; if present and the token is not yet valid, alerts the user.

    Sensitive Data Exposure: Scans the payload for common sensitive key names (e.g., password, secret, api_key, private_key, token, ssn, credit_card). Logs any findings.

    Privilege Escalation Indicators: Looks for administrative fields such as role, admin, is_admin, permissions, scope and highlights them, suggesting possible privilege escalation vectors if the token can be forged.

3. Signature & Cryptography Analysis

    Weak Secret Brute‑Force: If the algorithm is HS256/HS384/HS512, the tool attempts to brute‑force the shared secret using a custom wordlist (including common defaults like secret, password, 123456, admin, and expanded lists like rockyou.txt).

    Algorithm Confusion Detection: Checks for a mismatch between the alg header and the actual key type used by the server. For example, if the server uses an RSA private key but alg: HS256 is set, the token can be forged using the public key.

    Signature Verification (optional): If a secret or public key is provided, the tool can verify the signature to test if the token is cryptographically valid.

✨ Advanced Features (Real‑World Upgrade)
Feature	Implementation
alg: none Detection	Immediately flags tokens using the none algorithm, which allows attackers to forge tokens without a signature.
Weak Secret Brute‑Forcing	Supports large custom wordlists (e.g., SecLists, rockyou.txt) to discover weak shared secrets, enabling token forgery.
Algorithm Confusion Detection	Flags when the header claims HS256 but the server expects RSA/ECDSA, indicating a potential signature bypass.
Sensitive Data Leakage Scanning	Recursively scans payload keys for PII, credentials, or internal system information (e.g., db_password, aws_key).
Claim Validation	Verifies critical claims (exp, iat, nbf, iss, aud) against configurable rules (e.g., max age, required issuer).
JSON/HTML Report Generation	Generates a professional, timestamped report summarising all findings, risk levels (LOW, MEDIUM, HIGH, CRITICAL), and remediation steps.
Batch Processing	Can process multiple JWTs from a file (e.g., from Burp Suite exports or intercepted traffic logs) for bulk analysis.
Integration with API Scanning	Easily integrated into CI/CD pipelines or automated vulnerability scanners to test JWTs generated by test environments.
🛠️ Tools & Technologies

    Python 3 – core logic, decoding, and brute‑forcing.

    PyJWT – library for encoding/decoding and verifying JWTs.

    base64 – native decoding of the token segments.

    json – parsing header and payload.

    cryptography – for advanced signature verification and algorithm comparisons.

    argparse – for flexible command‑line options (e.g., --wordlist, --key).

    datetime – for timestamp and expiration analysis.

🔬 Testing & Use Case

Scenario:
A penetration tester intercepts a JWT used for authenticating to a banking API. The token looks like: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJub3JtYWwiLCJleHAiOjE3MTUwMDAwMDB9.xxxxx.

Process:

    Run the analyzer against the token:
    bash

python3 jwt_breaker.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --wordlist rockyou.txt

    Findings:

        Header: Algorithm is HS256 (acceptable).

        Payload: role is set to "normal". The exp claim is present and valid.

        Weak Secret: The brute‑forcer runs against the rockyou.txt list and discovers the secret is password123.

    Exploitation:

        The tester modifies the payload to {"user":"admin","role":"admin","exp":...}.

        Re‑signs the token using the discovered secret password123 with HS256.

        Submits the forged token to the API.

        Result: The server accepts the token and grants administrative privileges.

Outcome:

    The penetration tester demonstrates a critical vulnerability leading to privilege escalation.

    The report generated by the tool provides step‑by‑step remediation advice: "Switch to RS256/ES256, use a strong, randomly generated secret (>32 characters), and rotate secrets regularly."

    The client immediately rotates the secret and reconfigures their authentication infrastructure.

📁 Output Example (Report Snippet)

A typical JSON report entry contains:

    Token – (partial/redacted) The analysed JWT.

    Header – {"alg": "HS256", "typ": "JWT"}.

    Payload – {"user": "admin", "role": "admin", "exp": 1715000000}.

    Risk Score – out of 100.

    Risk Level – CRITICAL, HIGH, MEDIUM, or LOW.

    Findings – List of issues (e.g., Weak secret found: password123, Sensitive data: password_hash found in payload).

    Recommendations – Actionable steps (e.g., Use a stronger secret (20+ random chars), Remove 'password' from payload).

📝 Conclusion

The JWT Token Analyzer is an essential tool for any API security assessment or web application penetration test. JWTs are a ubiquitous technology, yet their misconfiguration remains a leading cause of account takeover and privilege escalation vulnerabilities. This tool provides a rapid, automated, and thorough audit of JWTs, identifying everything from missing expiration claims to weak cryptographic secrets and dangerous algorithm usage. During testing, it successfully discovered a weak secret in a client's token within seconds, demonstrating a critical vulnerability that would have otherwise gone unnoticed. By automating these checks, the tool empowers developers and security professionals to adopt secure JWT implementation practices, significantly reducing the risk of token‑based authentication failures. Its structured reports and actionable remediation advice make it a valuable addition to any security toolkit.
