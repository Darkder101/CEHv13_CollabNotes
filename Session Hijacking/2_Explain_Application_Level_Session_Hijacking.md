# Explain Application-Level Session Hijacking

## a. Session Sniffing
Capturing network traffic to extract session IDs.

### i. Compromising Session IDs using Sniffing
- Use sniffers to capture unencrypted traffic and steal session cookies.

## b. Predictable Session Token
Attackers predict session IDs.

### i. Compromising Session IDs by Predicting Tokens
#### 1) Analyzing Token Patterns
- Sequential tokens
- Timestamp-based tokens

#### 2) Brute Force Attacks
- Small token space size
- Lack of rate limiting

#### 3) Weak Random Number Generators
- Predictable PRNG (Pseudo Random Number Generator)

## c. Man-in-the-Middle Attack
Intercepting communication between two parties.

## d. Man-in-Browser Attack
Malware inside browser manipulates sessions.

## e. Cross-Site Scripting (XSS)
Injecting malicious scripts to steal cookies.

## f. Cross-Site Request Forgery (CSRF)
Forcing authenticated users to execute unwanted actions.

## g. Session Replay Attack
Capturing and reusing valid session tokens.

## h. Session Fixation Attack
Forcing a user to use a known session ID.

## i. CRIME Attack
Exploiting compression in HTTPS to recover session tokens.

## j. Session Hijacking with Proxy Server
Manipulating traffic via proxy.

## k. Forbidden Attack
Accessing restricted resources via stolen session.

## l. Session Donation Attack
Legitimate user shares session with attacker.
