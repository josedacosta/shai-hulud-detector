import * as fs from 'fs';
import * as path from 'path';
import {promisify} from 'util';
import {CompromissionIndicator} from '../types';

const readFile = promisify(fs.readFile);
const access = promisify(fs.access);

export interface LockfileEntry {
    name: string;
    version: string;
    resolved?: string;
    integrity?: string;
}

export interface LockfileAnalysis {
    format: 'package-lock' | 'npm-shrinkwrap';
    dependencies: LockfileEntry[];
    totalPackages: number;
    compromisedPackages: LockfileEntry[];
}

export class LockfileAnalyzer {
    private compromisedData: Record<string, unknown> = {};
    private compromisedPackages: Record<string, string[]> = {};
    private compromisedNamespaces: Record<string, string[]> = {};

    constructor() {
        this.loadShaiHuludIndicatorsData();
    }

    async analyzeLockfiles(projectDir: string): Promise<CompromissionIndicator[]> {
        const indicators: CompromissionIndicator[] = [];

        // Analyze ONLY npm lockfiles (Shai-Hulud focus)
        const npmLockfiles = [
            'package-lock.json',
            'npm-shrinkwrap.json'
        ];

        for (const lockfile of npmLockfiles) {
            const lockfilePath = path.join(projectDir, lockfile);

            try {
                await access(lockfilePath);
                const analysis = await this.analyzeNpmLockfile(lockfilePath);

                if (analysis.compromisedPackages.length > 0) {
                    indicators.push({
                        type: 'COMPROMISED_DEPENDENCY',
                        severity: 'CRITICAL',
                        description: `${analysis.compromisedPackages.length} compromised Shai-Hulud packages detected in ${lockfile}`,
                        details: analysis.compromisedPackages.map(pkg => `${pkg.name}@${pkg.version}`).join(', '),
                        file: lockfilePath
                    });

                    // Add detailed indicator for each compromised Shai-Hulud package
                    for (const pkg of analysis.compromisedPackages) {
                        indicators.push({
                            type: 'COMPROMISED_DEPENDENCY',
                            severity: 'HIGH',
                            description: `Compromised Shai-Hulud package: ${pkg.name}@${pkg.version}`,
                            details: `Detected in ${lockfile} - September 2025 supply chain attack`,
                            file: lockfilePath
                        });
                    }
                }
            } catch (error) {
                // Lockfile doesn't exist or is not accessible
            }
        }

        return indicators;
    }

    private loadShaiHuludIndicatorsData() {
        try {
            const dataPath = path.join(__dirname, '..', 'data', 'shai-hulud-indicators.json');
            const content = fs.readFileSync(dataPath, 'utf8');
            this.compromisedData = JSON.parse(content);
            this.compromisedPackages = (this.compromisedData.packages as Record<string, string[]>) || {};
            this.compromisedNamespaces = (this.compromisedData.namespaces as Record<string, string[]>) || {};
        } catch (error) {
            console.warn('Warning: Could not load Shai-Hulud indicators data, using empty set');
            this.compromisedPackages = {};
            this.compromisedNamespaces = {};
        }
    }

    private async analyzeNpmLockfile(lockfilePath: string): Promise<LockfileAnalysis> {
        const format = lockfilePath.includes('shrinkwrap') ? 'npm-shrinkwrap' : 'package-lock';
        const content = await readFile(lockfilePath, 'utf8');
        const lockfile = JSON.parse(content);

        const dependencies: LockfileEntry[] = [];
        const compromisedPackages: LockfileEntry[] = [];

        // Analyze npm lockfile v1 format (dependencies)
        if (lockfile.dependencies) {
            this.extractNpmDependencies(lockfile.dependencies, dependencies, compromisedPackages);
        }

        // Analyze npm lockfile v2+ format (packages)
        if (lockfile.packages) {
            for (const [packagePath, packageInfo] of Object.entries(lockfile.packages)) {
                if (packagePath === '') {
                    continue;
                } // Skip root package

                const packageData = packageInfo as { name?: string; version?: string };
                const name = packageData.name || this.extractPackageNameFromPath(packagePath);
                const version = packageData.version;

                if (name && version) {
                    const entry: LockfileEntry = {name, version};
                    dependencies.push(entry);

                    if (this.isPackageCompromisedShaiHulud(name, version)) {
                        compromisedPackages.push(entry);
                    }
                }
            }
        }

        return {
            format,
            dependencies,
            totalPackages: dependencies.length,
            compromisedPackages
        };
    }

    private extractNpmDependencies(
        deps: Record<string, { version?: string; resolved?: string; integrity?: string; dependencies?: Record<string, unknown> }>,
        allDeps: LockfileEntry[],
        compromised: LockfileEntry[]
    ) {
        for (const [name, info] of Object.entries(deps)) {
            if (info.version) {
                const entry: LockfileEntry = {
                    name,
                    version: info.version,
                    resolved: info.resolved,
                    integrity: info.integrity
                };

                allDeps.push(entry);

                if (this.isPackageCompromisedShaiHulud(name, info.version)) {
                    compromised.push(entry);
                }
            }

            // Recursive for nested dependencies
            if (info.dependencies) {
                this.extractNpmDependencies(info.dependencies as Record<string, {
                    version?: string;
                    resolved?: string;
                    integrity?: string;
                    dependencies?: Record<string, unknown>
                }>, allDeps, compromised);
            }
        }
    }

    private extractPackageNameFromPath(packagePath: string): string {
        // Extract package name from a path like "node_modules/@scope/package"
        const parts = packagePath.split('/');
        if (parts[1]?.startsWith('@')) {
            return `${parts[1]}/${parts[2]}`;
        }
        return parts[1] || '';
    }

    private isPackageCompromisedShaiHulud(name: string, version: string): boolean {
        // Check against specific compromised Shai-Hulud packages
        if (this.compromisedPackages[name]) {
            const compromisedVersions = this.compromisedPackages[name];
            return compromisedVersions.includes(version);
        }

        // Check against compromised Shai-Hulud namespaces
        for (const [namespace, patterns] of Object.entries(this.compromisedNamespaces)) {
            if (name.startsWith(`${namespace}/`)) {
                // For now, all packages in compromised namespaces are considered suspicious
                return patterns.includes('*');
            }
        }

        return false;
    }
}
