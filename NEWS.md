# The Shai-Hulud Attack: Analysis and Discovery Timeline

The Shai-Hulud attack represents the first known self-replicating worm to successfully propagate through the npm ecosystem. This comprehensive
analysis tracks the attack's evolution, from its precursor events to ongoing monitoring efforts, documenting how security researchers uncovered one of
the most sophisticated supply chain attacks in JavaScript history.

## Executive Summary

Starting September 14, 2025, a self-replicating malware dubbed "Shai-Hulud" began propagating through the npm ecosystem. Unlike previous supply chain
attacks, this worm automatically spreads to additional packages when it encounters npm tokens in compromised environments. Over 180 packages were
confirmed compromised, with the attack representing a significant evolution in supply chain attack sophistication.

## Complete Attack Timeline

### Phase 1: Precursor Events and Infrastructure Setup

**August 21, 2025**: Introduction of a vulnerable GitHub Actions workflow in the Nx project, allowing arbitrary code injection via specially crafted
pull request titles.[^1]

**August 24, 2025**: Attackers exploit this vulnerability to modify the `publish.yml` file and extract an npm publishing token.[^1]

**August 26, 2025, 10:32 PM UTC**: Beginning of the s1ngularity attack against Nx packages. Attackers publish malicious versions of Nx packages for 4
hours (until August 27, 12:37 AM UTC), establishing their infrastructure and testing propagation techniques.[^1][^2]

**August 27-28, 2025**: Creation of over 190 public repositories named "s1ngularity-repository" containing exfiltrated secrets from more than 1,700
developer victims. This phase served as proof-of-concept for automated secret exfiltration.[^2][^3]

### Phase 2: Patient Zero and Initial Propagation

**September 14, 2025, 5:58 PM UTC**: Publication of the **rxnt-authentication** package version 0.0.3, considered "Patient Zero" of the Shai-Hulud
attack. The maintainer `techsupportrxnt` becomes the starting point of this campaign.[^4][^5]

**September 15, 2025**: Detection of the attack by security researchers. The Shai-Hulud worm begins its automatic propagation through the npm
ecosystem, marking the first successful self-replicating attack in npm history.[^6][^7]

### Phase 3: Rapid Ecosystem Propagation

**September 15-16, 2025**: Rapid propagation of the worm through the npm ecosystem. Over 180 packages confirmed as compromised in less than 24 hours,
including high-profile packages with millions of downloads.[^6][^8]

**September 17, 2025**: Ongoing monitoring and cleanup efforts begin. Publication of the first detailed analyses by Unit42 and other security
researchers, revealing the unprecedented nature of this self-replicating attack.[^9][^10]

**September 18, 2025**: Publication of comprehensive analysis by Trend Micro, confirming the unprecedented scale of this self-replicating attack and
its potential for further propagation.[^11]

## Technical Analysis

### Self-Replication Mechanism

The "Shai-Hulud" worm uses an `NpmModule.updatePackage` function that:[^6][^7]

1. Downloads a maintainer's packages
2. Modifies the `package.json` file
3. Injects a local script (`bundle.js` of 3.6 MB)
4. Automatically republishes the compromised package
5. Propagates to other packages from the same maintainer

This automatic propagation mechanism represents a significant evolution from previous supply chain attacks, which required manual intervention for
each compromised package.

### Information Theft Techniques

The Shai-Hulud malware employs hijacked legitimate tools:[^8][^12][^7]

**TruffleHog Integration**: Uses this open source secrets scanner to identify AWS keys, GitHub tokens and other credentials on the file system,
weaponizing a trusted security tool for malicious purposes.[^12][^7]

**GitHub Exfiltration**: Creates public repositories named "Shai-Hulud" containing stolen data encoded in base64, making detection easier but also
demonstrating the attackers' confidence.[^7][^6]

**Malicious GitHub Actions**: Injects unauthorized GitHub Actions workflows to maintain persistence and continue propagation even after initial
detection.[^13][^7]

### Compromised Packages

More than 187 packages have been identified as compromised, including popular packages such as:[^6][^8]

- **@ctrl/tinycolor** (over 8 million monthly downloads)
- **@nativescript-community**, **@ngx** ecosystem packages
- Packages belonging to CrowdStrike and other major organizations

## Detection and Response Timeline

### Immediate Response (September 15-16, 2025)

**Security Community Response**: The security community reacted quickly to the unprecedented nature of the attack:[^14]

- **Aikido Security** and other automated scanning services began detecting anomalous package publications
- **Vercel** and other platform providers started identifying affected projects and purging build caches
- **npm** began removing malicious versions as they were identified

### Investigation Phase (September 17-18, 2025)

**Technical Analysis**: Security researchers published detailed technical analyses revealing:

- The first known self-replicating worm in the npm ecosystem
- Novel use of legitimate security tools (TruffleHog) for malicious purposes
- Automatic propagation capabilities that distinguish this attack from previous incidents

### Ongoing Monitoring (September 18+, 2025)

**Continued Discovery**: As analysis continues, researchers identify additional compromised packages and develop better detection mechanisms for
self-replicating malware in package managers.

## Indicators of Compromise (IoCs)

Several indicators of compromise have been identified for detection:[^14]

- **Malicious GitHub repositories**: Repositories named "Shai-Hulud" containing base64-encoded stolen data
- **File artifacts**: Presence of 3.6MB `bundle.js` files with specific SHA-256 hashes
- **Workflow artifacts**: Unauthorized GitHub Actions workflows named `shai-hulud-workflow.yml`
- **Detection command**: `rg -u --max-columns=80 _0x112fa8`

## Impact Assessment

### Scale and Scope

The Shai-Hulud attack represents:

- **First self-replicating npm worm**: Unprecedented automatic propagation capability
- **180+ compromised packages**: Affecting millions of downstream projects
- **Novel attack vector**: Weaponization of legitimate security scanning tools
- **Ecosystem-wide impact**: Potential for continued propagation through token theft

### Significance in Supply Chain Security

This attack marks a significant escalation in supply chain attack sophistication:

1. **Evolution from manual to automated**: Previous attacks required manual intervention for each package
2. **Self-sustaining propagation**: The worm can continue spreading without additional attacker intervention
3. **Legitimate tool weaponization**: First known case of security tools being systematically hijacked for attack propagation
4. **Ecosystem resilience testing**: Revealed vulnerabilities in npm's ability to contain rapidly spreading threats

## Security Recommendations

### For Developers

**Enhanced Token Management**: Implement strict npm token hygiene and regularly rotate publishing credentials.[^15]

**Dependency Monitoring**: Implement automated monitoring for unexpected package updates and verify package integrity.[^15]

**Build Environment Isolation**: Isolate build environments to prevent token exposure during the build process.

### For Organizations

**Software Composition Analysis (SCA)**: Integrate malware detection tools specifically designed to detect self-replicating behavior in CI/CD
pipelines.[^15]

**`--ignore-scripts` Policy**: Disable npm lifecycle script execution by default to prevent automatic malware execution.

**Incident Response Preparation**: Develop specific response procedures for self-replicating supply chain attacks.

## Lessons Learned and Future Implications

The Shai-Hulud attack demonstrates that the npm ecosystem faces a new category of threats: self-replicating malware that can propagate automatically
through the package dependency graph. This evolution requires:

1. **Enhanced detection capabilities**: Traditional static analysis is insufficient for detecting self-replicating behavior
2. **Improved ecosystem response**: Need for automated containment mechanisms that can respond faster than manual review processes
3. **Token security evolution**: Current npm token security models may be inadequate for preventing automated propagation attacks

The speed of detection and response from the security community helped limit the damage, but this incident highlights the urgent need for proactive
defense mechanisms specifically designed to counter self-replicating threats in package manager ecosystems.

## Ongoing Monitoring

As of the latest updates, security researchers continue to:

- Monitor for new package compromises using the established IoCs
- Develop improved detection mechanisms for self-replicating malware
- Analyze the attack's propagation patterns to understand ecosystem vulnerabilities
- Work with npm and other package registries to improve rapid response capabilities

The Shai-Hulud attack serves as a watershed moment in supply chain security, demonstrating that package manager ecosystems must evolve their security
models to address the threat of self-replicating malware.

<div style="text-align: center">⁂</div>

[^1]: https://nx.dev/blog/s1ngularity-postmortem

[^2]: https://www.wiz.io/blog/s1ngularity-supply-chain-attack

[^3]: https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/

[^4]: https://secure.software/npm/packages/rxnt-authentication/0.0.4

[^5]: https://www.securityweek.com/shai-hulud-supply-chain-attack-worm-used-to-steal-secrets-180-npm-packages-hit/

[^6]: https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages

[^7]: https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/

[^8]: https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials

[^9]: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/

[^10]: https://www.sonatype.com/blog/ongoing-npm-software-supply-chain-attack-exposes-new-risks

[^11]: https://www.trendmicro.com/en_ca/research/25/i/npm-supply-chain-attack.html

[^12]: https://threatprotect.qualys.com/2025/09/17/more-than-400-npm-packages-affected-by-the-ongoing-supply-chain-attack/

[^13]: https://www.getsafety.com/blog-posts/shai-hulud-npm-attack

[^14]: https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack

[^15]: https://www.endorlabs.com/learn/how-to-defend-against-npm-software-supply-chain-attacks
