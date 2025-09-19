export interface CompromissionIndicator {
    type: 'MALICIOUS_FILE' | 'SUSPICIOUS_SCRIPT' | 'WORKFLOW_INJECTION' | 'ENVIRONMENT_VAR' | 'COMPROMISED_DEPENDENCY';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
    details?: string;
    file?: string;
    lineNumber?: number;
}

export interface ProjectScan {
    path: string;
    packageJsonPath: string;
    indicators: CompromissionIndicator[];
    status: 'CLEAN' | 'SUSPICIOUS' | 'COMPROMISED';
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    scanDuration?: number;
}

export type ProjectStatus = 'CLEAN' | 'SUSPICIOUS' | 'COMPROMISED';

export interface ScanResult {
    totalProjects: number;
    cleanProjects: ProjectScan[];
    suspiciousProjects: ProjectScan[];
    compromisedProjects: ProjectScan[];
    allProjects: ProjectScan[];
    scanDuration: number;
}

export interface DetectorOptions {
    scanDirectory: string;
    excludedDirs?: string[];
}

export interface PackageJson {
    name?: string;
    version?: string;
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;

    [key: string]: unknown;
}

