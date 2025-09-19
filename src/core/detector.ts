import * as path from 'path';
import {ProjectScanner} from './scanner';
import {IndicatorDetector} from '../analysis/indicators';
import {CompromissionIndicator, DetectorOptions, ProjectScan, ScanResult} from '../types';
import {SecurityReporter} from '../reporting/reporter';
import chalk from 'chalk';
import ora from 'ora';

export class ShaiHuludDetector {
    private scanner: ProjectScanner;
    private indicatorDetector: IndicatorDetector;
    private reporter: SecurityReporter;
    private options: DetectorOptions;

    constructor(options: DetectorOptions) {
        this.options = options;
        this.scanner = new ProjectScanner(options.excludedDirs);
        this.indicatorDetector = new IndicatorDetector();
        this.reporter = new SecurityReporter();
    }

    async scan(): Promise<ScanResult> {
        const startTime = Date.now();

        // Step 1: Search for npm projects
        const searchSpinner = ora({
            text: chalk.cyan('🔍 Searching for npm projects...'),
            color: 'cyan',
            spinner: 'bouncingBar'
        }).start();

        const packageJsonFiles = await this.scanner.findPackageJsonFiles(
            this.options.scanDirectory,
            (currentDir: string) => {
                // Update spinner with current directory being scanned
                const displayDir = this.truncatePath(currentDir.replace(this.options.scanDirectory, ''), 50);
                searchSpinner.text = chalk.cyan(`🔍 Scanning: ${chalk.yellow(displayDir || '/')}`);
            }
        );

        searchSpinner.succeed(chalk.green(`✅ ${packageJsonFiles.length} npm projects found`));

        if (packageJsonFiles.length === 0) {
            const noProjectsSpinner = ora({
                text: chalk.yellow('⚠️ No npm projects found'),
                color: 'yellow'
            }).start();

            setTimeout(() => {
                noProjectsSpinner.warn(chalk.yellow('🤷 No npm projects detected in the specified directory'));
            }, 1000);

            return {
                totalProjects: 0,
                cleanProjects: [],
                suspiciousProjects: [],
                compromisedProjects: [],
                allProjects: [],
                scanDuration: Date.now() - startTime
            };
        }

        // Step 2: Detailed analysis with progress
        const analysisSpinner = ora({
            text: chalk.blue('🔬 Initializing security analysis...'),
            color: 'blue',
            spinner: 'dots12'
        }).start();

        const projectScans: ProjectScan[] = [];
        let compromisedFound = 0;
        let suspiciousFound = 0;

        for (let i = 0; i < packageJsonFiles.length; i++) {
            const packageJsonPath = packageJsonFiles[i];
            const projectPath = path.dirname(packageJsonPath);
            const projectName = path.basename(projectPath);

            // Update spinner with progress
            const progress = Math.round(((i + 1) / packageJsonFiles.length) * 100);
            analysisSpinner.text = chalk.blue(`🔬 Analysis: ${chalk.cyan(`${i + 1}/${packageJsonFiles.length}`)} (${progress}%) - ${chalk.yellow(this.truncatePath(projectName, 30))}`);

            try {
                const indicators = await this.indicatorDetector.analyzeProject(projectPath, packageJsonPath);
                const status = this.determineProjectStatus(indicators);

                // Count discoveries in real time
                if (status === 'COMPROMISED') {
                    compromisedFound++;
                    analysisSpinner.color = 'red';
                    analysisSpinner.text = chalk.red(`🚨 COMPROMISE DETECTED! ${chalk.yellow(projectName)} - Analysis: ${i + 1}/${packageJsonFiles.length}`);
                } else if (status === 'SUSPICIOUS') {
                    suspiciousFound++;
                    if (analysisSpinner.color !== 'red') {
                        analysisSpinner.color = 'yellow';
                        analysisSpinner.text = chalk.yellow(`⚠️ Suspicious project: ${chalk.yellow(projectName)} - Analysis: ${i + 1}/${packageJsonFiles.length}`);
                    }
                }

                projectScans.push({
                    path: projectPath,
                    packageJsonPath,
                    indicators,
                    status
                });
            } catch (error) {
                // Silently continue on analysis errors to avoid noise

                projectScans.push({
                    path: projectPath,
                    packageJsonPath,
                    indicators: [],
                    status: 'CLEAN'
                });
            }

            // Small pause for visual effect
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        // Finalize spinner based on results
        if (compromisedFound > 0) {
            analysisSpinner.fail(chalk.red(`💀 ANALYSIS COMPLETE - ${compromisedFound} compromised project(s) detected!`));
        } else if (suspiciousFound > 0) {
            analysisSpinner.warn(chalk.yellow(`⚠️ ANALYSIS COMPLETE - ${suspiciousFound} suspicious project(s) detected`));
        } else {
            analysisSpinner.succeed(chalk.green(`✅ ANALYSIS COMPLETE - All projects are clean`));
        }

        const endTime = Date.now();
        const scanDuration = endTime - startTime;

        // Sort projects by status
        const cleanProjects = projectScans.filter(p => p.status === 'CLEAN');
        const suspiciousProjects = projectScans.filter(p => p.status === 'SUSPICIOUS');
        const compromisedProjects = projectScans.filter(p => p.status === 'COMPROMISED');

        const scanResults: ScanResult = {
            totalProjects: projectScans.length,
            cleanProjects,
            suspiciousProjects,
            compromisedProjects,
            allProjects: projectScans,
            scanDuration
        };

        // Automatically generate a report if compromised projects are detected
        if (compromisedProjects.length > 0) {
            const reportSpinner = ora({
                text: chalk.yellow('📝 Generating security report...'),
                color: 'yellow',
                spinner: 'dots'
            }).start();

            try {
                const reportPath = await this.reporter.generateReport(scanResults, this.options.scanDirectory);

                if (reportPath) {
                    reportSpinner.succeed(chalk.green(`✅ Security report generated: ${chalk.cyan(path.basename(reportPath))}`));

                    // Display report information
                    console.log(chalk.yellow(`\n📄 Report location: ${chalk.cyan(reportPath)}`));
                    console.log(chalk.gray('   The report contains complete details on detected compromises'));
                    console.log(chalk.gray('   and cleanup recommendations.'));
                } else {
                    reportSpinner.warn(chalk.yellow('⚠️ Unable to generate security report'));
                }
            } catch (error) {
                reportSpinner.fail(chalk.red('❌ Error generating report'));
                console.error(chalk.gray(`Error details: ${error instanceof Error ? error.message : 'Unknown error'}`));
            }
        }

        return scanResults;
    }

    async quickScan(directory: string): Promise<boolean> {
        try {
            const packageJsonFiles = await this.scanner.scanDirectoryShallow(directory);

            for (const packageJsonPath of packageJsonFiles) {
                const projectPath = path.dirname(packageJsonPath);
                const indicators = await this.indicatorDetector.analyzeProject(projectPath, packageJsonPath);

                if (indicators.some(i => i.severity === 'CRITICAL' || i.severity === 'HIGH')) {
                    return true; // Compromise detected
                }
            }

            return false; // No compromise detected
        } catch (error) {
            return false; // In case of error, consider as clean to avoid false positives
        }
    }

    private determineProjectStatus(indicators: CompromissionIndicator[]): 'CLEAN' | 'SUSPICIOUS' | 'COMPROMISED' {
        if (indicators.length === 0) {
            return 'CLEAN';
        }

        // If a critical indicator is found, the project is compromised
        const hasCriticalIndicator = indicators.some(i => i.severity === 'CRITICAL');
        if (hasCriticalIndicator) {
            return 'COMPROMISED';
        }

        // If multiple high severity indicators, consider as compromised
        const highSeverityIndicators = indicators.filter(i => i.severity === 'HIGH');
        if (highSeverityIndicators.length >= 2) {
            return 'COMPROMISED';
        }

        // If a high severity indicator is found, the project is compromised
        if (highSeverityIndicators.length >= 1) {
            return 'COMPROMISED';
        }

        // Otherwise, the project is suspicious
        return 'SUSPICIOUS';
    }

    private truncatePath(path: string, maxLength: number): string {
        if (path.length <= maxLength) {
            return path;
        }
        return '...' + path.slice(-(maxLength - 3));
    }
}

