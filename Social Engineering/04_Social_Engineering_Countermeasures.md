# Social Engineering Countermeasures

## Various Mobile-Based Social Engineering Techniques

- **Publishing malicious apps**: Disguised as legit apps to trick users into installing them.
- **Repacking legitimate apps**: Modify real apps to inject malware and redistribute them.
- **Fake security applications**: Claim to protect users but actually steal data.
- **Smishing apps**: SMS-based phishing that tricks users into clicking malicious links.
- **QRL jacking**: Hijack login sessions by cloning QR codes.
  - **QR cloning tools**:
    - QR Tigers
    - Other online QR cloning platforms

## Social Engineering Countermeasures

- **Password policies**: Enforce strong, regularly changed passwords.
- **Physical security policies**: Limit unauthorized physical access to systems.
- **Defense strategy**: A multi-layered security approach (technical + human).
- **Additional countermeasures against social engineering**:
  - Security awareness training
  - Role-based access control
  - Email filtering and sandboxing
- **How to defend against social engineering**:
  - Verify identities before disclosing information
  - Be skeptical of urgent or emotional requests
  - Report suspicious activity immediately
- **Identity theft countermeasures**:
  - Monitor financial statements
  - Use credit freezes and fraud alerts
  - Don’t overshare on social media
- **Voice cloning countermeasures**:
  - Use voice biometrics + multifactor authentication
  - Train employees to detect unusual voice patterns
- **Deepfake countermeasures**:
  - Video forensics tools to detect deepfakes
  - Raise awareness about deepfake risks
- **How to detect phishing emails**:
  - Check sender’s address, grammar, tone, and suspicious links
  - Look for urgency, misspellings, or generic greetings
- **Indicators of phishing emails**:
  - Spoofed domains or links
  - Unexpected attachments
  - Requests for personal info
- **Anti-phishing toolbars**:
  - **Netcraft**: Detect and block known phishing websites.
  - **PhishTank**: Community-based phishing detection tool.
- **Audit organization’s security for phishing attacks using OhPhish**:
  - Simulate phishing campaigns internally
  - Identify vulnerabilities in employee awareness
  - Train based on simulation results

---

## Quick Tip for CEH Exam

1. **Know mobile-based attack types** – such as fake apps, smishing, and QR-based hijacks.
2. **Understand countermeasure layers** – including technical (toolbars, policies) and human (training, awareness).
3. **Common signs of phishing** – suspicious domains, urgency, poor grammar, fake branding.
4. **Differentiate between anti-phishing tools**:
   - **Netcraft**: Browser-based detection of phishing attempts.
   - **PhishTank**: Reports and verifies phishing URLs.
5. **QRL jacking**: Login hijack using cloned QR codes. Tools like QR Tigers are used for malicious cloning.
6. **OhPhish**: Tool to simulate phishing campaigns in your org to test and improve employee readiness.
