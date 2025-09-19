import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import {promisify} from 'util';
import {CompromissionIndicator, PackageJson} from '../types';
import {LockfileAnalyzer} from './lockfile-analyzer';
import {Base64Decoder} from './base64-decoder';

const readFile = promisify(fs.readFile);
const access = promisify(fs.access);
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

export class IndicatorDetector {
    private lockfileAnalyzer: LockfileAnalyzer;
    private base64Decoder: Base64Decoder;
    private compromisedData: Record<string, unknown> = {};

    // Patterns loaded from shai-hulud-indicators.json
    private maliciousHashes = new Set<string>();
    private suspiciousFilePatterns: RegExp[] = [];
    
    // High confidence patterns (always trigger)
    private highConfidenceCryptoPatterns: RegExp[] = [];
    private specificExfiltrationPatterns: RegExp[] = [];
    private specificCryptoAddresses: RegExp[] = [];
    private specificMaliciousFiles: RegExp[] = [];
    
    // Contextual patterns (require additional validation)
    private contextualCryptoPatterns: RegExp[] = [];
    private contextualExfiltrationPatterns: RegExp[] = [];
    private contextualSystemCommands: RegExp[] = [];
    
    // Highly contextual patterns (require very strict validation)
    private highlyContextualPatterns: RegExp[] = [];
    private highlyContextualExfiltration: RegExp[] = [];
    
    // Legitimate contexts to reduce false positives
    private legitimateWeb3Patterns: Set<string> = new Set();
    private legitimateWeb3Frameworks: Set<string> = new Set();
    private legitimateJSLibrariesWithXHR: Set<string> = new Set();
    private legitimateSecurityTools: Set<string> = new Set();
    private githubWorkflowContexts: Set<string> = new Set();
    private webhookTestingContexts: Set<string> = new Set();
    private buildDirectories: Set<string> = new Set();
    private legitBundleContexts: Set<string> = new Set();
    private envExampleContexts: Set<string> = new Set();

    constructor() {
        this.lockfileAnalyzer = new LockfileAnalyzer();
        this.base64Decoder = new Base64Decoder();
        this.loadShaiHuludIndicatorsData().catch(() => {
            console.warn('Warning: Could not load Shai-Hulud indicators data, using empty set');
        });
    }

    async analyzeProject(projectPath: string, packageJsonPath: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];
        const projectDir = path.dirname(packageJsonPath);

        try {
            // Analyze package.json for Shai-Hulud patterns
            const packageJsonIndicators = await this.analyzePackageJson(packageJsonPath);
            indicators.push(...packageJsonIndicators);

            // Analyze lockfiles for compromised Shai-Hulud packages
            const lockfileIndicators = await this.lockfileAnalyzer.analyzeLockfiles(projectDir);
            indicators.push(...lockfileIndicators);

            // Look for suspicious files specific to Shai-Hulud
            const fileIndicators = await this.scanForSuspiciousFiles(projectDir);
            indicators.push(...fileIndicators);

            // Analyze npm scripts for Shai-Hulud patterns
            const scriptIndicators = await this.analyzeNpmScripts(packageJsonPath);
            indicators.push(...scriptIndicators);

            // Look for malicious GitHub Actions workflows from Shai-Hulud
            const workflowIndicators = await this.scanGitHubWorkflows(projectDir);
            indicators.push(...workflowIndicators);

            // Check suspicious environment variables
            const envIndicators = await this.checkEnvironmentVariables(projectDir);
            indicators.push(...envIndicators);

        } catch (error) {
            // Ignore access errors
        }

        return indicators;
    }

    /**
     * Method to get detailed statistics of Shai-Hulud indicators
     */
    getDetectionStatistics(indicators: CompromissionIndicator[]): {
        totalIndicators: number;
        byType: Record<string, number>;
        bySeverity: Record<string, number>;
        criticalFiles: string[];
    } {
        const stats = {
            totalIndicators: indicators.length,
            byType: {} as Record<string, number>,
            bySeverity: {} as Record<string, number>,
            criticalFiles: [] as string[]
        };

        for (const indicator of indicators) {
            // Count by type
            stats.byType[indicator.type] = (stats.byType[indicator.type] || 0) + 1;

            // Count by severity
            stats.bySeverity[indicator.severity] = (stats.bySeverity[indicator.severity] || 0) + 1;

            // Collect critical files
            if (indicator.severity === 'CRITICAL' && indicator.file && !stats.criticalFiles.includes(indicator.file)) {
                stats.criticalFiles.push(indicator.file);
            }
        }

        return stats;
    }

    /**
     * Method to analyze base64 data for Shai-Hulud indicators
     */
    analyzeBase64Data(base64Content: string): {
        isValidBase64: boolean;
        decodedLevels: number;
        containsSensitiveData: boolean;
        detectedPatterns: string[];
    } {
        const results = this.base64Decoder.decodeRecursively(base64Content);
        const sensitiveLevels = results.filter(r => r.containsSensitiveData);

        return {
            isValidBase64: results.length > 0,
            decodedLevels: results.length,
            containsSensitiveData: sensitiveLevels.length > 0,
            detectedPatterns: sensitiveLevels.flatMap(l => l.detectedPatterns)
        };
    }

    /**
     * Method to validate Shai-Hulud exfiltrated data structure
     */
    validateExfiltratedData(content: string): boolean {
        return this.base64Decoder.validateExfiltratedDataStructure(content);
    }

    private async loadShaiHuludIndicatorsData() {
        try {
            this.compromisedData = await import('../data/shai-hulud-indicators.json');

            // Load malicious hashes
            if (this.compromisedData.maliciousHashes) {
                for (const hash of Object.keys(this.compromisedData.maliciousHashes)) {
                    this.maliciousHashes.add(hash);
                }
            }

            // Load suspicious patterns with contextual classification
            if (this.compromisedData.suspiciousPatterns) {
                const patterns = this.compromisedData.suspiciousPatterns as Record<string, string[]>;

                // High confidence patterns (always trigger)
                this.highConfidenceCryptoPatterns = (patterns.highConfidenceCryptoStealer || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
                
                this.specificExfiltrationPatterns = (patterns.specificExfiltration || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
                
                this.specificCryptoAddresses = (patterns.specificCryptoAddresses || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

                this.specificMaliciousFiles = (patterns.specificMaliciousFiles || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

                // Contextual patterns (require validation)
                this.contextualCryptoPatterns = (patterns.contextualCryptoPatterns || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
                
                this.contextualExfiltrationPatterns = (patterns.contextualExfiltration || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
                
                this.contextualSystemCommands = (patterns.contextualSystemCommands || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

                // Highly contextual patterns (require very strict validation)
                this.highlyContextualPatterns = (patterns.highlyContextualPatterns || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
                
                this.highlyContextualExfiltration = (patterns.highlyContextualExfiltration || [])
                    .map((p: string) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

                // File patterns (shai-hulud specific always critical)
                this.suspiciousFilePatterns = [
                    /shai-hulud/i,
                    ...this.specificMaliciousFiles
                ];
            }

            // Load legitimate contexts
            if (this.compromisedData.legitimateContexts) {
                const legitContexts = this.compromisedData.legitimateContexts as Record<string, string[]>;
                
                (legitContexts.web3Patterns || []).forEach((p: string) => this.legitimateWeb3Patterns.add(p));
                (legitContexts.web3Frameworks || []).forEach((p: string) => this.legitimateWeb3Frameworks.add(p));
                (legitContexts.jsLibrariesWithXHR || []).forEach((p: string) => this.legitimateJSLibrariesWithXHR.add(p));
                (legitContexts.securityTools || []).forEach((p: string) => this.legitimateSecurityTools.add(p));
                (legitContexts.githubWorkflowContexts || []).forEach((p: string) => this.githubWorkflowContexts.add(p));
                (legitContexts.webhookTestingContexts || []).forEach((p: string) => this.webhookTestingContexts.add(p));
                (legitContexts.buildDirectories || []).forEach((p: string) => this.buildDirectories.add(p));
                (legitContexts.legitBundleContexts || []).forEach((p: string) => this.legitBundleContexts.add(p));
                (legitContexts.envExampleContexts || []).forEach((p: string) => this.envExampleContexts.add(p));
            }

        } catch (error) {
            console.warn('Warning: Could not load Shai-Hulud indicators data, using fallback patterns');
            // Fallback to hardcoded patterns with reduced false positives
            this.maliciousHashes.add('46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09');
            this.suspiciousFilePatterns = [/shai-hulud/i];
            this.highConfidenceCryptoPatterns = [/_0x112fa8/, /stealthProxyControl/, /runmask/, /checkethereumw/];
            this.specificExfiltrationPatterns = [/webhook\.site\/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/, /npmjs\.help/, /npnjs\.com/];
        }
    }

    private async analyzePackageJson(packageJsonPath: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];

        try {
            const content = await readFile(packageJsonPath, 'utf8');
            const packageJson: PackageJson = JSON.parse(content);

            // Check scripts for Shai-Hulud patterns with contextual analysis
            if (packageJson.scripts) {
                for (const [scriptName, scriptContent] of Object.entries(packageJson.scripts)) {
                    
                    // Check high confidence crypto-stealer patterns (always trigger)
                    for (const pattern of this.highConfidenceCryptoPatterns) {
                        if (pattern.test(scriptContent)) {
                            indicators.push({
                                type: 'SUSPICIOUS_SCRIPT',
                                severity: 'CRITICAL',
                                description: `Shai-Hulud crypto-stealer pattern detected in script: ${scriptName}`,
                                details: `Script: ${scriptContent}`,
                                file: packageJsonPath
                            });
                        }
                    }

                    // Check specific exfiltration patterns (always trigger)
                    for (const pattern of this.specificExfiltrationPatterns) {
                        if (pattern.test(scriptContent)) {
                            indicators.push({
                                type: 'SUSPICIOUS_SCRIPT',
                                severity: 'HIGH',
                                description: `Shai-Hulud exfiltration pattern detected in script: ${scriptName}`,
                                details: `Script: ${scriptContent}`,
                                file: packageJsonPath
                            });
                        }
                    }

                    // Check contextual patterns with validation
                    for (const pattern of this.contextualCryptoPatterns) {
                        if (pattern.test(scriptContent)) {
                            const patternString = pattern.source.replace(/\\\\/g, '');
                            
                            // Skip if it appears in legitimate Web3 context
                            if (this.isLegitimateWeb3Context(packageJsonPath, scriptContent, patternString)) {
                                continue;
                            }

                            indicators.push({
                                type: 'SUSPICIOUS_SCRIPT',
                                severity: 'MEDIUM',
                                description: `Potential crypto-related pattern in script: ${scriptName}`,
                                details: `Script: ${scriptContent} (requires validation)`,
                                file: packageJsonPath
                            });
                        }
                    }

                    // Check contextual exfiltration patterns
                    for (const pattern of this.contextualExfiltrationPatterns) {
                        if (pattern.test(scriptContent)) {
                            const patternString = pattern.source.replace(/\\\\/g, '');
                            
                            // Skip if it appears in legitimate security tool context
                            if (this.isLegitimateSecurityToolUsage(packageJsonPath, scriptContent, patternString)) {
                                continue;
                            }

                            indicators.push({
                                type: 'SUSPICIOUS_SCRIPT',
                                severity: 'MEDIUM',
                                description: `Potential suspicious tool usage in script: ${scriptName}`,
                                details: `Script: ${scriptContent} (requires validation)`,
                                file: packageJsonPath
                            });
                        }
                    }

                    // Check highly contextual patterns with very strict validation
                    for (const pattern of this.highlyContextualPatterns) {
                        if (pattern.test(scriptContent)) {
                            const patternString = pattern.source.replace(/\\\\/g, '');
                            
                            let isSuspicious = false;
                            if (patternString === 'XMLHttpRequest.prototype') {
                                isSuspicious = this.isHighlySuspiciousXHRUsage(packageJsonPath, scriptContent);
                            } else if (patternString === 'window.ethereum') {
                                isSuspicious = this.isHighlySuspiciousWeb3Usage(packageJsonPath, scriptContent);
                            }

                            if (isSuspicious) {
                                indicators.push({
                                    type: 'SUSPICIOUS_SCRIPT',
                                    severity: 'HIGH',
                                    description: `Highly suspicious ${patternString} usage in script: ${scriptName}`,
                                    details: `Script: ${scriptContent}`,
                                    file: packageJsonPath
                                });
                            }
                        }
                    }

                    // Check highly contextual exfiltration patterns
                    for (const pattern of this.highlyContextualExfiltration) {
                        if (pattern.test(scriptContent)) {
                            const patternString = pattern.source.replace(/\\\\/g, '');
                            
                            if (patternString === 'webhook.site') {
                                if (this.isHighlySuspiciousWebhookUsage(packageJsonPath, scriptContent)) {
                                    indicators.push({
                                        type: 'SUSPICIOUS_SCRIPT',
                                        severity: 'HIGH',
                                        description: `Highly suspicious webhook.site usage in script: ${scriptName}`,
                                        details: `Script: ${scriptContent}`,
                                        file: packageJsonPath
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Search for suspicious dependencies by Shai-Hulud patterns
            const allDeps = {
                ...packageJson.dependencies,
                ...packageJson.devDependencies
            };

            for (const [depName, version] of Object.entries(allDeps || {})) {
                // Check by suspicious file patterns
                if (this.suspiciousFilePatterns.some(pattern => pattern.test(depName))) {
                    indicators.push({
                        type: 'SUSPICIOUS_SCRIPT',
                        severity: 'MEDIUM',
                        description: `Suspicious Shai-Hulud dependency: ${depName}@${version}`,
                        details: 'Detected by Shai-Hulud specific pattern analysis',
                        file: packageJsonPath
                    });
                }
            }

        } catch (error) {
            // Ignore JSON parsing errors
        }

        return indicators;
    }

    private async scanForSuspiciousFiles(projectDir: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];

        try {
            await this.scanDirectoryForFiles(projectDir, indicators, 0);
        } catch (error) {
            // Ignore access errors
        }

        return indicators;
    }

    private async scanDirectoryForFiles(
        dirPath: string,
        indicators: CompromissionIndicator[],
        depth: number
    ): Promise<void> {
        if (depth > 3) {
            return;
        } // Limit depth

        try {
            const items = await readdir(dirPath);

            for (const item of items) {
                if (item === 'node_modules' || item.startsWith('.')) {
                    continue;
                }

                const itemPath = path.join(dirPath, item);
                const stats = await stat(itemPath);

                if (stats.isFile()) {
                    // Check suspicious Shai-Hulud filenames
                    for (const pattern of this.suspiciousFilePatterns) {
                        if (pattern.test(item)) {
                            const severity = item.includes('shai-hulud') ? 'CRITICAL' : 'HIGH';
                            indicators.push({
                                type: 'MALICIOUS_FILE',
                                severity,
                                description: `Suspicious Shai-Hulud file detected: ${item}`,
                                file: itemPath
                            });
                        }
                    }

                    // Check known Shai-Hulud file hashes with context validation
                    if (item === 'bundle.js' && stats.size > 3000000) { // > 3MB as documented
                        try {
                            const fileContent = await readFile(itemPath);
                            const hash = crypto.createHash('sha256').update(fileContent).digest('hex');

                            if (this.maliciousHashes.has(hash)) {
                                indicators.push({
                                    type: 'MALICIOUS_FILE',
                                    severity: 'CRITICAL',
                                    description: 'Malicious Shai-Hulud bundle.js file detected',
                                    details: `Hash SHA-256: ${hash}`,
                                    file: itemPath
                                });
                            } else {
                                // Check if this is a legitimate bundle to avoid false positive
                                const contentString = fileContent.toString('utf8', 0, Math.min(10000, fileContent.length));
                                if (!this.isLegitimateBundle(itemPath, contentString)) {
                                    // Only flag suspicious if not in legitimate build context
                                    indicators.push({
                                        type: 'MALICIOUS_FILE',
                                        severity: 'MEDIUM',
                                        description: 'Large bundle.js file detected (requires validation)',
                                        details: `Size: ${stats.size} bytes, Hash: ${hash}`,
                                        file: itemPath
                                    });
                                }
                            }
                        } catch (error) {
                            // Ignore read errors
                        }
                    }

                    // Analyze text file content for Shai-Hulud patterns with contextual analysis
                    if (this.isTextFile(item)) {
                        try {
                            const content = await readFile(itemPath, 'utf8');

                            // Analyze high confidence crypto-stealer patterns
                            for (const pattern of this.highConfidenceCryptoPatterns) {
                                if (pattern.test(content)) {
                                    indicators.push({
                                        type: 'MALICIOUS_FILE',
                                        severity: 'CRITICAL',
                                        description: 'Shai-Hulud crypto-stealer pattern detected in file',
                                        details: `Pattern found: ${pattern.source}`,
                                        file: itemPath
                                    });
                                }
                            }

                            // Check specific crypto addresses
                            for (const pattern of this.specificCryptoAddresses) {
                                if (pattern.test(content)) {
                                    indicators.push({
                                        type: 'MALICIOUS_FILE',
                                        severity: 'CRITICAL',
                                        description: 'Known Shai-Hulud crypto address detected in file',
                                        details: `Pattern found: ${pattern.source}`,
                                        file: itemPath
                                    });
                                }
                            }

                            // Check contextual crypto patterns with validation
                            for (const pattern of this.contextualCryptoPatterns) {
                                if (pattern.test(content)) {
                                    const patternString = pattern.source.replace(/\\\\/g, '');
                                    
                                    // Skip if in legitimate Web3 context
                                    if (this.isLegitimateWeb3Context(itemPath, content, patternString)) {
                                        continue;
                                    }

                                    indicators.push({
                                        type: 'MALICIOUS_FILE',
                                        severity: 'MEDIUM',
                                        description: 'Potential crypto-related pattern detected (requires validation)',
                                        details: `Pattern found: ${pattern.source}`,
                                        file: itemPath
                                    });
                                }
                            }

                            // Check contextual exfiltration patterns
                            for (const pattern of this.contextualExfiltrationPatterns) {
                                if (pattern.test(content)) {
                                    const patternString = pattern.source.replace(/\\\\/g, '');
                                    
                                    // Skip if in legitimate security tool context
                                    if (this.isLegitimateSecurityToolUsage(itemPath, content, patternString)) {
                                        continue;
                                    }

                                    indicators.push({
                                        type: 'MALICIOUS_FILE',
                                        severity: 'MEDIUM',
                                        description: 'Potential suspicious tool usage detected (requires validation)',
                                        details: `Pattern found: ${pattern.source}`,
                                        file: itemPath
                                    });
                                }
                            }

                            // Check highly contextual patterns with very strict validation
                            for (const pattern of this.highlyContextualPatterns) {
                                if (pattern.test(content)) {
                                    const patternString = pattern.source.replace(/\\\\/g, '');
                                    
                                    let isSuspicious = false;
                                    if (patternString === 'XMLHttpRequest.prototype') {
                                        isSuspicious = this.isHighlySuspiciousXHRUsage(itemPath, content);
                                    } else if (patternString === 'window.ethereum') {
                                        isSuspicious = this.isHighlySuspiciousWeb3Usage(itemPath, content);
                                    }

                                    if (isSuspicious) {
                                        indicators.push({
                                            type: 'MALICIOUS_FILE',
                                            severity: 'HIGH',
                                            description: `Highly suspicious ${patternString} usage detected`,
                                            details: `Pattern found: ${pattern.source}`,
                                            file: itemPath
                                        });
                                    }
                                }
                            }

                            // Check highly contextual exfiltration patterns
                            for (const pattern of this.highlyContextualExfiltration) {
                                if (pattern.test(content)) {
                                    const patternString = pattern.source.replace(/\\\\/g, '');
                                    
                                    if (patternString === 'webhook.site') {
                                        if (this.isHighlySuspiciousWebhookUsage(itemPath, content)) {
                                            indicators.push({
                                                type: 'MALICIOUS_FILE',
                                                severity: 'HIGH',
                                                description: 'Highly suspicious webhook.site usage detected',
                                                details: `Pattern found: ${pattern.source}`,
                                                file: itemPath
                                            });
                                        }
                                    }
                                }
                            }

                            // Base64 analysis for Shai-Hulud exfiltrated data
                            // Skip if this is a legitimate bundle in build directory
                            const isLegitBundle = this.isLegitimateBundle(itemPath, content);
                            if (!isLegitBundle) {
                                const base64Indicators = this.base64Decoder.analyzeFileForBase64(itemPath, content);
                                indicators.push(...base64Indicators);
                            }

                        } catch (error) {
                            // Ignore read errors
                        }
                    }
                } else if (stats.isDirectory()) {
                    await this.scanDirectoryForFiles(itemPath, indicators, depth + 1);
                }
            }
        } catch (error) {
            // Ignore access errors
        }
    }

    private async analyzeNpmScripts(packageJsonPath: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];

        try {
            const content = await readFile(packageJsonPath, 'utf8');
            const packageJson: PackageJson = JSON.parse(content);

            if (packageJson.scripts) {
                // Look for suspicious lifecycle scripts
                const suspiciousLifecycleScripts = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'];

                for (const script of suspiciousLifecycleScripts) {
                    if (packageJson.scripts[script]) {
                        const scriptContent = packageJson.scripts[script];

                        // Detect suspicious commands used by Shai-Hulud
                        if (scriptContent.includes('curl') ||
                            scriptContent.includes('wget') ||
                            scriptContent.includes('powershell') ||
                            scriptContent.includes('cmd.exe') ||
                            scriptContent.includes('node bundle.js')) { // Shai-Hulud specific script
                            indicators.push({
                                type: 'SUSPICIOUS_SCRIPT',
                                severity: 'HIGH',
                                description: `Suspicious Shai-Hulud lifecycle script: ${script}`,
                                details: `Command: ${scriptContent}`,
                                file: packageJsonPath
                            });
                        }
                    }
                }
            }
        } catch (error) {
            // Ignore errors
        }

        return indicators;
    }

    private async scanGitHubWorkflows(projectDir: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];
        const workflowsPath = path.join(projectDir, '.github', 'workflows');

        try {
            await access(workflowsPath);
            const workflows = await readdir(workflowsPath);

            for (const workflow of workflows) {
                // Check workflow name for Shai-Hulud patterns
                if (workflow.includes('shai-hulud')) {
                    indicators.push({
                        type: 'WORKFLOW_INJECTION',
                        severity: 'CRITICAL',
                        description: 'Malicious Shai-Hulud GitHub Actions workflow detected',
                        file: path.join(workflowsPath, workflow)
                    });
                }

                // Analyze workflow content for Shai-Hulud patterns
                try {
                    const workflowPath = path.join(workflowsPath, workflow);
                    const content = await readFile(workflowPath, 'utf8');

                    // First check if this is a legitimate security workflow
                    if (this.isLegitimateGitHubWorkflow(workflowPath, content)) {
                        continue; // Skip legitimate security workflows
                    }

                    // Only flag if it's NOT a legitimate workflow and contains suspicious patterns
                    if (content.includes('TruffleHog') || content.includes('webhook.site')) {
                        // Additional validation - check for Shai-Hulud specific indicators
                        const hasShaiHuludIndicators = [
                            'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
                            '_0x112fa8',
                            'stealthProxyControl',
                            'exfiltrate',
                            'steal'
                        ].some(indicator => content.includes(indicator));

                        if (hasShaiHuludIndicators) {
                            indicators.push({
                                type: 'WORKFLOW_INJECTION',
                                severity: 'HIGH',
                                description: 'Suspicious Shai-Hulud GitHub Actions workflow detected',
                                details: 'Contains references to TruffleHog or webhook.site with malicious indicators',
                                file: workflowPath
                            });
                        }
                    }
                } catch (error) {
                    // Ignore read errors
                }
            }
        } catch (error) {
            // .github/workflows doesn't exist or is not accessible
        }

        return indicators;
    }

    /**
     * Check if env file appears to be a legitimate example/template
     */
    private isLegitimateEnvFile(filePath: string, content: string): boolean {
        // Check if it's an example/template file
        const isExampleFile = Array.from(this.envExampleContexts).some(context => 
            filePath.includes(context)
        );

        if (isExampleFile) {
            return true;
        }

        // Check if values appear to be examples/placeholders
        const hasExampleValues = [
            'your_token_here',
            'your-token',
            'YOUR_TOKEN',
            'example_token',
            'placeholder',
            'secret_value',
            'your_secret',
            '<your-',
            'xxx',
            '***',
            'change_me',
            'replace_with'
        ].some(placeholder => content.toLowerCase().includes(placeholder.toLowerCase()));

        return hasExampleValues;
    }

    /**
     * Check for specific Shai-Hulud indicators in env context
     */
    private hasShaiHuludEnvIndicators(content: string): boolean {
        const shaiHuludEnvIndicators = [
            'webhook.site',
            'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
            'TruffleHog',
            '_0x112fa8',
            'stealthProxyControl',
            'exfiltrate',
            'steal',
            'crypto',
            'wallet'
        ];

        return shaiHuludEnvIndicators.some(indicator => 
            content.toLowerCase().includes(indicator.toLowerCase())
        );
    }

    private async checkEnvironmentVariables(projectDir: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];
        const envFiles = ['.env', '.env.local', '.env.production', '.env.development'];

        for (const envFile of envFiles) {
            try {
                const envPath = path.join(projectDir, envFile);
                await access(envPath);

                const content = await readFile(envPath, 'utf8');

                // Skip if it's a legitimate example/template file
                if (this.isLegitimateEnvFile(envPath, content)) {
                    continue;
                }

                // Look for exposed environment variables (Shai-Hulud target)
                const hasSensitiveTokens = content.includes('GITHUB_TOKEN') ||
                                          content.includes('NPM_TOKEN') ||
                                          content.includes('AWS_ACCESS_KEY');

                if (hasSensitiveTokens) {
                    // Only flag if there are additional Shai-Hulud indicators or suspicious patterns
                    const hasShaiHuludIndicators = this.hasShaiHuludEnvIndicators(content);
                    
                    if (hasShaiHuludIndicators) {
                        indicators.push({
                            type: 'ENVIRONMENT_VAR',
                            severity: 'HIGH',
                            description: 'Sensitive environment variables with Shai-Hulud indicators detected',
                            details: '.env file contains potentially compromised tokens',
                            file: envPath
                        });
                    } else {
                        // Lower severity for normal .env files with tokens (common in legitimate projects)
                        indicators.push({
                            type: 'ENVIRONMENT_VAR',
                            severity: 'LOW',
                            description: 'Environment file contains sensitive tokens (review recommended)',
                            details: '.env file contains tokens - verify they are secure',
                            file: envPath
                        });
                    }
                }
            } catch (error) {
                // .env file doesn't exist
            }
        }

        return indicators;
    }

    private isTextFile(filename: string): boolean {
        const textExtensions = ['.js', '.ts', '.jsx', '.tsx', '.json', '.yml', '.yaml', '.txt', '.md', '.sh', '.bat', '.ps1'];
        return textExtensions.some(ext => filename.endsWith(ext));
    }

    /**
     * Check if a file path is in a legitimate build directory
     */
    private isInBuildDirectory(filePath: string): boolean {
        const pathParts = filePath.split(path.sep);
        return pathParts.some(part => this.buildDirectories.has(part));
    }

    /**
     * Check if a file appears to be a legitimate bundle based on context
     */
    private isLegitimateBundle(filePath: string, content?: string): boolean {
        // Check if in build directory
        if (this.isInBuildDirectory(filePath)) {
            return true;
        }

        // Check if it's a browser extension bundle (common patterns)
        const extensionPatterns = [
            '/extension/',
            '/chrome/',
            '/firefox/',
            '/opera/',
            '/edge/',
            'contentScript.bundle.js',
            'background.bundle.js',
            'popup.bundle.js',
            'options.bundle.js',
            'content-script.bundle.js'
        ];

        if (extensionPatterns.some(pattern => filePath.includes(pattern))) {
            return true;
        }

        // Check if generated by legitimate bundler (if content provided)
        if (content) {
            const hasLegitBundlerMarker = Array.from(this.legitBundleContexts).some(tool => 
                content.includes(tool) || content.includes(`Generated by ${tool}`)
            );
            if (hasLegitBundlerMarker) {
                return true;
            }

            // Check for webpack/other bundler markers in the content
            const bundlerMarkers = [
                '__webpack_require__',
                'webpackBootstrap',
                'webpackJsonp',
                '/******/ (function(modules)',
                'define.amd',
                'System.register',
                'parcelRequire'
            ];

            if (bundlerMarkers.some(marker => content.includes(marker))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Analyze if crypto patterns appear in legitimate Web3 context
     */
    private isLegitimateWeb3Context(filePath: string, content: string, pattern: string): boolean {
        if (!this.legitimateWeb3Patterns.has(pattern)) {
            return false;
        }

        // Check for legitimate Web3 indicators
        const legitWeb3Indicators = [
            'MetaMask',
            'WalletConnect',
            'Web3Provider',
            'ethers',
            'web3.js',
            '@web3-react',
            'wagmi',
            'rainbow-kit'
        ];

        return legitWeb3Indicators.some(indicator => 
            content.includes(indicator) || filePath.includes(indicator)
        );
    }

    /**
     * Check if security tool usage appears legitimate
     */
    private isLegitimateSecurityToolUsage(filePath: string, content: string, pattern: string): boolean {
        if (!this.legitimateSecurityTools.has(pattern)) {
            return false;
        }

        // Check for legitimate security context (documentation, CI configs, security tests)
        const legitSecurityContexts = [
            'README',
            'SECURITY',
            'docs/',
            'scripts/',
            '.github/',
            '.gitlab/',
            'security/',
            'test/',
            'spec/',
            'cypress/',
            'jest.config'
        ];

        const isInLegitContext = legitSecurityContexts.some(context => 
            filePath.includes(context)
        );

        // Check for legitimate usage patterns
        const legitUsagePatterns = [
            'audit',
            'scan',
            'check',
            'security',
            'vulnerability',
            'how to use',
            'example',
            'documentation'
        ];

        const hasLegitUsage = legitUsagePatterns.some(usage => 
            content.toLowerCase().includes(usage)
        );

        return isInLegitContext || hasLegitUsage;
    }

    /**
     * Check if GitHub workflow usage of security tools is legitimate
     */
    private isLegitimateGitHubWorkflow(filePath: string, content: string): boolean {
        // Must be in .github/workflows directory
        if (!filePath.includes('.github/workflows/')) {
            return false;
        }

        // Check if workflow filename indicates security purpose
        const filename = path.basename(filePath, '.yml');
        const isSecurityWorkflow = Array.from(this.githubWorkflowContexts).some(context => 
            filename.toLowerCase().includes(context)
        );

        if (isSecurityWorkflow) {
            return true;
        }

        // Check if workflow content indicates legitimate CI/CD security scanning
        const legitWorkflowPatterns = [
            'uses: trufflesecurity/trufflehog',
            'uses: gitleaks/gitleaks-action',
            'uses: GitGuardian/ggshield-action',
            'uses: snyk/actions',
            'uses: github/codeql-action',
            'npm audit',
            'yarn audit',
            'security scan',
            'dependency check',
            'vulnerability scan',
            'SAST',
            'secrets scan'
        ];

        return legitWorkflowPatterns.some(pattern => 
            content.toLowerCase().includes(pattern.toLowerCase())
        );
    }

    /**
     * Very strict validation for XMLHttpRequest.prototype usage
     * Only triggers if there are strong Shai-Hulud indicators
     */
    private isHighlySuspiciousXHRUsage(filePath: string, content: string): boolean {
        // Must have multiple Shai-Hulud specific indicators
        const shaiHuludIndicators = [
            '_0x112fa8',
            'stealthProxyControl', 
            'runmask',
            'checkethereumw',
            'newdlocal',
            '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976'
        ];

        const foundIndicators = shaiHuludIndicators.filter(indicator => 
            content.includes(indicator)
        );

        // Require at least 2 Shai-Hulud indicators + XHR manipulation
        if (foundIndicators.length < 2) {
            return false;
        }

        // Check if it's in legitimate JS library context
        const hasLegitJSLibrary = Array.from(this.legitimateJSLibrariesWithXHR).some(lib => 
            content.includes(lib) || filePath.includes(lib)
        );

        return !hasLegitJSLibrary;
    }

    /**
     * Very strict validation for webhook.site usage
     * Only triggers for specific Shai-Hulud patterns or suspicious context
     */
    private isHighlySuspiciousWebhookUsage(filePath: string, content: string): boolean {
        // Always suspicious if it's the specific Shai-Hulud URL
        if (content.includes('webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7')) {
            return true;
        }

        // Check if it's in legitimate testing/documentation context
        const isInTestingContext = Array.from(this.webhookTestingContexts).some(context => 
            filePath.toLowerCase().includes(context) || 
            content.toLowerCase().includes(context)
        );

        if (isInTestingContext) {
            return false;
        }

        // Check for additional Shai-Hulud indicators
        const shaiHuludIndicators = [
            'TruffleHog',
            'base64',
            'exfiltrate',
            'steal',
            'token',
            'secret'
        ];

        const foundIndicators = shaiHuludIndicators.filter(indicator => 
            content.toLowerCase().includes(indicator.toLowerCase())
        );

        // Only suspicious if multiple indicators present
        return foundIndicators.length >= 2;
    }

    /**
     * Very strict validation for window.ethereum usage  
     * Only triggers if not in legitimate Web3 application context
     */
    private isHighlySuspiciousWeb3Usage(filePath: string, content: string): boolean {
        // Check for legitimate Web3 framework indicators
        const hasLegitWeb3Framework = Array.from(this.legitimateWeb3Frameworks).some(framework => 
            content.includes(framework) || filePath.includes(framework)
        );

        if (hasLegitWeb3Framework) {
            return false;
        }

        // Check for legitimate Web3 package.json dependencies
        if (filePath.includes('package.json')) {
            const web3Dependencies = [
                'ethers',
                'web3',
                '@web3-react',
                'wagmi',
                'rainbow-kit',
                'metamask'
            ];

            const hasWeb3Deps = web3Dependencies.some(dep => content.includes(dep));
            if (hasWeb3Deps) {
                return false;
            }
        }

        // Check for Shai-Hulud specific crypto stealer patterns
        const shaiHuludCryptoPatterns = [
            '_0x112fa8',
            'stealthProxyControl',
            'runmask', 
            'checkethereumw',
            '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976'
        ];

        const foundCryptoPatterns = shaiHuludCryptoPatterns.filter(pattern => 
            content.includes(pattern)
        );

        // Only suspicious if Shai-Hulud patterns present
        return foundCryptoPatterns.length > 0;
    }

    /**
     * Calculate confidence score for detection based on context
     */
    private calculateConfidenceScore(indicators: CompromissionIndicator[]): number {
        let highConfidenceCount = 0;
        const totalCount = indicators.length;

        for (const indicator of indicators) {
            if (indicator.severity === 'CRITICAL') {
                highConfidenceCount += 3;
            } else if (indicator.severity === 'HIGH') {
                highConfidenceCount += 2;
            } else if (indicator.severity === 'MEDIUM') {
                highConfidenceCount += 1;
            }
        }

        return totalCount > 0 ? highConfidenceCount / (totalCount * 2) : 0;
    }
}

