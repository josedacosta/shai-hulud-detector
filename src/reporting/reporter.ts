import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {exec} from 'child_process';
import {promisify} from 'util';
import {ProjectScan, ScanResult} from '../types';

const writeFile = promisify(fs.writeFile);
const execAsync = promisify(exec);
const readFile = promisify(fs.readFile);

export interface ReportDetails {
    bundleHashes: string[];
    maliciousWorkflows: string[];
    maliciousRepositories: string[];
    sensitiveEnvVars: string[];
    suspiciousProcesses: string[];
    additionalDetails: string[];
}

export class SecurityReporter {
    private workingDirectory: string;

    constructor(workingDirectory: string = process.cwd()) {
        this.workingDirectory = workingDirectory;
    }

    async generateReport(scanResult: ScanResult, scanDirectory: string): Promise<string | null> {
        if (scanResult.compromisedProjects.length === 0) {
            return null; // No report if no compromised projects
        }

        const timestamp = this.generateTimestamp();
        const filename = `shai-hulud-report-${timestamp}.md`;
        const filepath = path.join(this.workingDirectory, filename);

        // Collect detailed information
        const details = await this.collectDetailedInformation(scanResult.compromisedProjects);

        const report = await this.buildReport(scanResult, scanDirectory, details, timestamp);

        try {
            await writeFile(filepath, report, 'utf8');
            return filepath;
        } catch (error) {
            console.error('Error generating report:', error);
            return null;
        }
    }

    private async collectDetailedInformation(compromisedProjects: ProjectScan[]): Promise<ReportDetails> {
        const details: ReportDetails = {
            bundleHashes: [],
            maliciousWorkflows: [],
            maliciousRepositories: [],
            sensitiveEnvVars: [],
            suspiciousProcesses: [],
            additionalDetails: []
        };

        for (const project of compromisedProjects) {
            // Search for malicious bundle.js files
            const bundleHashes = await this.findBundleHashes(project.path);
            details.bundleHashes.push(...bundleHashes);

            // Detect malicious workflows
            const workflows = await this.detectMaliciousWorkflows(project.path);
            details.maliciousWorkflows.push(...workflows);

            // Search for malicious repositories
            const repos = await this.detectMaliciousRepositories(project.path);
            details.maliciousRepositories.push(...repos);

            // Analyze environment variables
            const envVars = await this.analyzeSensitiveEnvVars(project.path);
            details.sensitiveEnvVars.push(...envVars);
        }

        // Detect suspicious processes on the system
        details.suspiciousProcesses = await this.detectSuspiciousProcesses();

        return details;
    }

    private async findBundleHashes(projectPath: string): Promise<string[]> {
        const hashes: string[] = [];

        try {
            const bundlePath = path.join(projectPath, 'bundle.js');
            if (fs.existsSync(bundlePath)) {
                const stats = fs.statSync(bundlePath);
                if (stats.size > 3000000) { // > 3MB
                    const content = await readFile(bundlePath);
                    const hash = crypto.createHash('sha256').update(content).digest('hex');
                    hashes.push(`${bundlePath}: ${hash}`);
                }
            }

            // Recursively search for other bundle.js files
            const {stdout} = await execAsync(`find "${projectPath}" -name "bundle.js" -size +3M 2>/dev/null || true`);
            const files = stdout.trim().split('\n').filter(f => f);

            for (const file of files) {
                if (file !== bundlePath) {
                    try {
                        const content = await readFile(file);
                        const hash = crypto.createHash('sha256').update(content).digest('hex');
                        hashes.push(`${file}: ${hash}`);
                    } catch (error) {
                        // Ignore read errors
                    }
                }
            }
        } catch (error) {
            // Ignore errors
        }

        return hashes;
    }

    private async detectMaliciousWorkflows(projectPath: string): Promise<string[]> {
        const workflows: string[] = [];

        try {
            const workflowsPath = path.join(projectPath, '.github', 'workflows');
            if (fs.existsSync(workflowsPath)) {
                const files = fs.readdirSync(workflowsPath);

                for (const file of files) {
                    if (file.includes('shai-hulud') || file.includes('trufflehog')) {
                        workflows.push(`${projectPath}/.github/workflows/${file}`);
                    }

                    // Analyze workflow content
                    try {
                        const filePath = path.join(workflowsPath, file);
                        const content = await readFile(filePath, 'utf8');

                        if (content.includes('TruffleHog') ||
                            content.includes('webhook.site') ||
                            content.includes('shai-hulud')) {
                            workflows.push(`${projectPath}/.github/workflows/${file} (suspicious content)`);
                        }
                    } catch (error) {
                        // Ignore read errors
                    }
                }
            }
        } catch (error) {
            // Ignore errors
        }

        return workflows;
    }

    private async detectMaliciousRepositories(projectPath: string): Promise<string[]> {
        const repos: string[] = [];

        try {
            // Check if this is a git repository
            const gitPath = path.join(projectPath, '.git');
            if (fs.existsSync(gitPath)) {
                // Search for suspicious branches
                const {stdout: branches} = await execAsync(`cd "${projectPath}" && git branch -a 2>/dev/null || true`);

                if (branches.includes('shai-hulud')) {
                    repos.push(`${projectPath} (shai-hulud branch detected)`);
                }

                // Check remotes
                const {stdout: remotes} = await execAsync(`cd "${projectPath}" && git remote -v 2>/dev/null || true`);

                if (remotes.includes('shai-hulud') || remotes.includes('Shai-Hulud')) {
                    repos.push(`${projectPath} (suspicious remote detected)`);
                }
            }
        } catch (error) {
            // Ignore errors
        }

        return repos;
    }

    private async analyzeSensitiveEnvVars(projectPath: string): Promise<string[]> {
        const envVars: string[] = [];
        const envFiles = ['.env', '.env.local', '.env.production', '.env.development', '.env.staging'];

        for (const envFile of envFiles) {
            try {
                const envPath = path.join(projectPath, envFile);
                if (fs.existsSync(envPath)) {
                    const content = await readFile(envPath, 'utf8');
                    const lines = content.split('\n');

                    for (const line of lines) {
                        if (line.trim() && !line.startsWith('#')) {
                            const [key] = line.split('=');
                            if (this.isSensitiveVariable(key)) {
                                envVars.push(`${envPath}: ${key}=***MASKED***`);
                            }
                        }
                    }
                }
            } catch (error) {
                // Ignore errors
            }
        }

        return envVars;
    }

    private async detectSuspiciousProcesses(): Promise<string[]> {
        const processes: string[] = [];

        try {
            // Search for suspicious processes
            const suspiciousNames = ['trufflehog', 'shai-hulud', 'webhook', 'crypto-stealer'];

            for (const name of suspiciousNames) {
                try {
                    const {stdout} = await execAsync(`ps aux | grep -i "${name}" | grep -v grep || true`);
                    if (stdout.trim()) {
                        processes.push(`Suspicious process detected: ${name}`);
                        processes.push(stdout.trim());
                    }
                } catch (error) {
                    // Ignore errors
                }
            }

            // Check for suspicious network connections
            try {
                const {stdout} = await execAsync(`netstat -tulpn 2>/dev/null | grep -E "(webhook\\.site|npmjs\\.help|npnjs\\.com)" || true`);
                if (stdout.trim()) {
                    processes.push('Suspicious network connections:');
                    processes.push(stdout.trim());
                }
            } catch (error) {
                // Ignore errors (command may not exist on all systems)
            }
        } catch (error) {
            // Ignore general errors
        }

        return processes;
    }

    private isSensitiveVariable(key: string): boolean {
        const sensitivePatterns = [
            'TOKEN', 'KEY', 'SECRET', 'PASSWORD', 'PASS', 'PWD',
            'GITHUB', 'NPM', 'AWS', 'GCP', 'AZURE', 'GITLAB',
            'DATABASE', 'DB_', 'MONGO', 'REDIS', 'API_KEY'
        ];

        const upperKey = key.toUpperCase();
        return sensitivePatterns.some(pattern => upperKey.includes(pattern));
    }

    private async buildReport(
        scanResult: ScanResult,
        scanDirectory: string,
        details: ReportDetails,
        timestamp: string
    ): Promise<string> {
        const reportLines: string[] = [];

        // Markdown report header
        reportLines.push('# 🚨 SHAI-HULUD SECURITY REPORT');
        reportLines.push('## 🔍 COMPROMISE INDICATOR DETECTION');
        reportLines.push('');
        reportLines.push('---');
        reportLines.push('');

        // General information
        reportLines.push('## 📅 GENERAL INFORMATION');
        reportLines.push('');
        reportLines.push('| 🏷️ **Field** | 📄 **Value** |');
        reportLines.push('|---------------|----------------|');
        reportLines.push(`| **Date and time** | ${this.formatTimestamp(timestamp)} |`);
        reportLines.push(`| **Scanned directory** | \`${scanDirectory}\` |`);
        reportLines.push(`| **Operating system** | ${os.type()} ${os.release()} |`);
        reportLines.push(`| **Architecture** | ${os.arch()} |`);
        reportLines.push(`| **User** | \`${os.userInfo().username}\` |`);
        reportLines.push(`| **Working directory** | \`${this.workingDirectory}\` |`);
        reportLines.push('');

        // Results summary
        reportLines.push('## 📊 RESULTS SUMMARY');
        reportLines.push('');
        reportLines.push('| 📈 **Metric** | 🔢 **Count** | 📊 **Percentage** |');
        reportLines.push('|-----------------|---------------|--------------------|');
        reportLines.push(`| **Total scanned projects** | ${scanResult.totalProjects} | 100% |`);
        reportLines.push(`| ✅ **Clean projects** | ${scanResult.cleanProjects.length} | ${Math.round((scanResult.cleanProjects.length / scanResult.totalProjects) * 100)}% |`);
        reportLines.push(`| ⚠️ **Suspicious projects** | ${scanResult.suspiciousProjects.length} | ${Math.round((scanResult.suspiciousProjects.length / scanResult.totalProjects) * 100)}% |`);
        reportLines.push(`| 🚨 **COMPROMISED PROJECTS** | **${scanResult.compromisedProjects.length}** | **${Math.round((scanResult.compromisedProjects.length / scanResult.totalProjects) * 100)}%** |`);
        reportLines.push(`| ⏱️ **Scan duration** | ${scanResult.scanDuration}ms | - |`);
        reportLines.push('');

        // Visual alert if compromised
        if (scanResult.compromisedProjects.length > 0) {
            reportLines.push('> 🚨 **CRITICAL SECURITY ALERT**');
            reportLines.push('> ');
            reportLines.push('> Shai-Hulud compromise indicators have been detected!');
            reportLines.push('> Immediate action required to secure the system.');
            reportLines.push('');
        }

        // Compromised project details
        if (scanResult.compromisedProjects.length > 0) {
            reportLines.push('## 🚨 DETECTED COMPROMISED PROJECTS');
            reportLines.push('');

            scanResult.compromisedProjects.forEach((project, index) => {
                reportLines.push(`### 💀 Project ${index + 1}: \`${project.path}\``);
                reportLines.push('');
                reportLines.push('| 🏷️ **Property** | 📄 **Value** |');
                reportLines.push('|-------------------|----------------|');
                reportLines.push(`| **Path** | \`${project.path}\` |`);
                reportLines.push(`| **Package.json** | \`${project.packageJsonPath}\` |`);
                reportLines.push(`| **Status** | 🚨 **COMPROMISED** |`);
                reportLines.push(`| **Indicators** | **${project.indicators.length}** detected |`);
                reportLines.push('');

                reportLines.push('#### 🔍 Detected compromise indicators:');
                reportLines.push('');
                reportLines.push('| # | 🏷️ **Type** | ⚠️ **Severity** | 📝 **Description** | 📄 **File** |');
                reportLines.push('|---|-------------|------------------|-------------------|-----------------|');

                project.indicators.forEach((indicator, idx) => {
                    const severityIcon = this.getSeverityIcon(indicator.severity);
                    const fileName = indicator.file ? `\`${path.basename(indicator.file)}\`` : '-';
                    reportLines.push(`| ${idx + 1} | ${indicator.type} | ${severityIcon} ${indicator.severity} | ${indicator.description} | ${fileName} |`);
                });
                reportLines.push('');

                // Indicator details if available
                const indicatorsWithDetails = project.indicators.filter(i => i.details);
                if (indicatorsWithDetails.length > 0) {
                    reportLines.push('#### 📋 Technical details:');
                    reportLines.push('');
                    indicatorsWithDetails.forEach((indicator, _idx) => {
                        reportLines.push(`- **${indicator.type}**: ${indicator.details}`);
                    });
                    reportLines.push('');
                }
            });
        }

        // In-depth technical details
        reportLines.push('## 🔍 IN-DEPTH TECHNICAL DETAILS');
        reportLines.push('');

        if (details.bundleHashes.length > 0) {
            reportLines.push('### 📄 Malicious bundle.js files');
            reportLines.push('');
            details.bundleHashes.forEach(hash => {
                const [filepath, hashValue] = hash.split(': ');
                reportLines.push(`- **File**: \`${filepath}\``);
                reportLines.push(`  - **SHA-256 Hash**: \`${hashValue}\``);
            });
            reportLines.push('');
        }

        if (details.maliciousWorkflows.length > 0) {
            reportLines.push('### ⚙️ Malicious GitHub Actions workflows');
            reportLines.push('');
            details.maliciousWorkflows.forEach(workflow => {
                reportLines.push(`- \`${workflow}\``);
            });
            reportLines.push('');
        }

        if (details.maliciousRepositories.length > 0) {
            reportLines.push('### 📁 Suspicious repositories');
            reportLines.push('');
            details.maliciousRepositories.forEach(repo => {
                reportLines.push(`- \`${repo}\``);
            });
            reportLines.push('');
        }

        if (details.sensitiveEnvVars.length > 0) {
            reportLines.push('### 🔑 Sensitive environment variables');
            reportLines.push('');
            reportLines.push('| 📁 **File** | 🔑 **Variable** |');
            reportLines.push('|----------------|-----------------|');
            details.sensitiveEnvVars.forEach(envVar => {
                const [filepath, variable] = envVar.split(': ');
                reportLines.push(`| \`${filepath}\` | \`${variable}\` |`);
            });
            reportLines.push('');
        }

        if (details.suspiciousProcesses.length > 0) {
            reportLines.push('### 🔄 Suspicious processes');
            reportLines.push('');
            reportLines.push('```');
            details.suspiciousProcesses.forEach(process => {
                reportLines.push(process);
            });
            reportLines.push('```');
            reportLines.push('');
        }

        // Cleanup recommendations
        reportLines.push('## 🛠️ CLEANUP AND MITIGATION RECOMMENDATIONS');
        reportLines.push('');
        reportLines.push('### 🚨 1. IMMEDIATE ISOLATION');
        reportLines.push('');
        reportLines.push('- [ ] **Immediately disconnect the system from the network**');
        reportLines.push('- [ ] **Backup critical uncompromised data**');
        reportLines.push('- [ ] **Document the current state before any modifications**');
        reportLines.push('- [ ] **Take screenshots of detected indicators**');
        reportLines.push('');
        reportLines.push('### 🧹 2. PROJECT CLEANUP');
        reportLines.push('');
        reportLines.push('- [ ] **Completely remove identified compromised projects**');
        reportLines.push('- [ ] **Remove detected malicious bundle.js files**');
        reportLines.push('- [ ] **Remove malicious GitHub Actions workflows**');
        reportLines.push('- [ ] **Purge npm cache**: `npm cache clean --force`');
        reportLines.push('- [ ] **Remove node_modules and reinstall**: `rm -rf node_modules && npm ci`');
        reportLines.push('');
        reportLines.push('### 🔐 3. ACCESS REVOCATION');
        reportLines.push('');
        reportLines.push('- [ ] **Revoke all exposed NPM tokens**');
        reportLines.push('- [ ] **Revoke all exposed GitHub tokens**');
        reportLines.push('- [ ] **Revoke exposed AWS/GCP/Azure keys**');
        reportLines.push('- [ ] **Change all potentially compromised passwords**');
        reportLines.push('- [ ] **Enable 2FA authentication on all accounts**');
        reportLines.push('');
        reportLines.push('### 👁️ 4. MONITORING');
        reportLines.push('');
        reportLines.push('- [ ] **Monitor suspicious network activities**');
        reportLines.push('- [ ] **Check account access logs**');
        reportLines.push('- [ ] **Monitor cryptocurrency transactions**');
        reportLines.push('- [ ] **Audit recent repository access**');
        reportLines.push('');
        reportLines.push('### 🔄 5. RESTORATION');
        reportLines.push('');
        reportLines.push('- [ ] **Reinstall projects from safe sources**');
        reportLines.push('- [ ] **Use `npm ci` instead of `npm install`**');
        reportLines.push('- [ ] **Enable enhanced 2FA authentication**');
        reportLines.push('- [ ] **Implement continuous monitoring**');
        reportLines.push('- [ ] **Schedule regular scans with this detector**');

        // Documentation and references
        reportLines.push('## 📚 DOCUMENTATION AND REFERENCES');
        reportLines.push('');
        reportLines.push('### 🔗 Official Shai-Hulud documentation');
        reportLines.push('');
        reportLines.push('- [Sysdig: Novel Self-Replicating Worm](https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages)');
        reportLines.push('- [JFrog: New Compromised Packages Detected](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)');
        reportLines.push('- [Semgrep: Secret Scanning Tools to Steal Credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials)');
        reportLines.push('');
        reportLines.push('### 🛡️ NPM security guides');
        reportLines.push('');
        reportLines.push('- [NPM: Auditing Package Dependencies](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities/)');
        reportLines.push('- [OWASP: NPM Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html)');
        reportLines.push('- [GitHub: Securing Your Software Supply Chain](https://docs.github.com/en/code-security/supply-chain-security)');
        reportLines.push('');
        reportLines.push('### 🔧 Cleanup resources');
        reportLines.push('');
        reportLines.push('- [GitHub: Revoking Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation)');
        reportLines.push('- [NPM: Managing Access Tokens](https://docs.npmjs.com/about-access-tokens)');
        reportLines.push('- [AWS: Rotating Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey)');

        // Signature and end
        reportLines.push('---');
        reportLines.push('');
        reportLines.push('## 📝 REPORT INFORMATION');
        reportLines.push('');
        reportLines.push('| 🏷️ **Property** | 📄 **Value** |');
        reportLines.push('|------------------|----------------|');
        reportLines.push(`| **Generated by** | Shai-Hulud Detector v1.0.0 |`);
        reportLines.push(`| **File** | \`${this.getReportFilename(timestamp)}\` |`);
        reportLines.push(`| **Location** | \`${this.workingDirectory}\` |`);
        reportLines.push(`| **Size** | ${this.estimateReportSize(reportLines)} characters |`);
        reportLines.push(`| **Format** | Markdown (.md) |`);
        reportLines.push('');
        reportLines.push('> ⚠️ **WARNING**  ');
        reportLines.push('> This report contains sensitive security information.  ');
        reportLines.push('> Store it securely and share only with authorized personnel.');
        reportLines.push('');
        reportLines.push('---');
        reportLines.push('');
        reportLines.push('### ✅ REPORT GENERATED SUCCESSFULLY');
        reportLines.push('');
        reportLines.push('**This report was automatically generated following the detection of Shai-Hulud compromise indicators.**  ');
        reportLines.push('Immediately follow the cleanup recommendations to secure your system.');

        return reportLines.join('\n');
    }

    private generateTimestamp(): string {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');

        return `${year}${month}${day}-${hours}${minutes}${seconds}`;
    }

    private formatTimestamp(timestamp: string): string {
        const year = timestamp.substring(0, 4);
        const month = timestamp.substring(4, 6);
        const day = timestamp.substring(6, 8);
        const hours = timestamp.substring(9, 11);
        const minutes = timestamp.substring(11, 13);
        const seconds = timestamp.substring(13, 15);

        return `${day}/${month}/${year} at ${hours}:${minutes}:${seconds}`;
    }

    private getReportFilename(timestamp: string): string {
        return `shai-hulud-report-${timestamp}.md`;
    }

    private getSeverityIcon(severity: string): string {
        switch (severity) {
            case 'CRITICAL':
                return '💀';
            case 'HIGH':
                return '🔥';
            case 'MEDIUM':
                return '⚠️';
            case 'LOW':
                return '💡';
            default:
                return '❓';
        }
    }

    private estimateReportSize(lines: string[]): number {
        return lines.join('\n').length;
    }
}
