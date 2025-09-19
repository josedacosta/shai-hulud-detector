import chalk from 'chalk';
import boxen from 'boxen';
import figlet from 'figlet';
import gradient from 'gradient-string';
import Table from 'cli-table3';
import {ProjectScan, ScanResult} from '../../types';

export class UIFormatter {
    private static readonly ICONS = {
        SCAN: '🔍',
        SHIELD: '🛡️',
        WARNING: '⚠️',
        DANGER: '🚨',
        SUCCESS: '✅',
        FIRE: '🔥',
        SKULL: '💀',
        WORM: '🪱',
        DETECTIVE: '🕵️',
        COMPUTER: '💻',
        BUG: '🐛',
        LOCK: '🔒',
        KEY: '🗝️',
        EXPLOSION: '💥',
        HOURGLASS: '⏳',
        CHART: '📊',
        FOLDER: '📁',
        FILE: '📄',
        GEAR: '⚙️',
        MAGNIFYING: '🔎',
        TARGET: '🎯',
        ROBOT: '🤖'
    };

    private static readonly GRADIENTS = {
        fire: gradient(['#ff0000', '#ff6600', '#ffaa00']),
        ocean: gradient(['#0066cc', '#0099ff', '#66ccff']),
        sunset: gradient(['#ff6b6b', '#ffa500', '#ffff00']),
        matrix: gradient(['#00ff00', '#00cc00', '#009900']),
        purple: gradient(['#9b59b6', '#8e44ad', '#663399']),
        danger: gradient(['#e74c3c', '#c0392b', '#922b21'])
    };

    static showBanner(): void {
        console.clear();

        const terminalWidth = process.stdout.columns || 120;
        const maxWidth = Math.min(terminalWidth - 4, 120);

        const title = figlet.textSync('SHAI-HULUD', {
            font: 'ANSI Shadow',
            horizontalLayout: 'fitted',
            width: maxWidth
        });

        // Add top and left margin line by line
        const titleWithMargin = '\n' + title.split('\n').map(line => '  ' + line).join('\n');
        console.log(this.GRADIENTS.fire(titleWithMargin));

        const subtitle = figlet.textSync('DETECTOR', {
            font: 'Small',
            horizontalLayout: 'fitted',
            width: maxWidth
        });

        // Add left margin line by line
        const subtitleWithMargin = subtitle.split('\n').map(line => '  ' + line).join('\n');
        console.log(this.GRADIENTS.ocean(subtitleWithMargin));

        // Adjust content to avoid overflow
        const banner = boxen(
            `${this.ICONS.WORM} ${chalk.bold.red('NPM COMPROMISE INDICATOR DETECTOR')} ${this.ICONS.WORM}\n\n` +
            `${this.ICONS.DETECTIVE}  Specialized in Shai-Hulud attack detection\n` +
            `${this.ICONS.SHIELD}  Protection against supply chain attacks\n` +
            `${this.ICONS.TARGET}  Analysis of suspicious npm projects\n\n` +
            chalk.gray('Developed by josedacosta • Version 2.0.0'),
            {
                padding: 1,
                margin: 1,
                borderStyle: 'double',
                borderColor: 'red',
                backgroundColor: 'black',
                textAlignment: 'center'
            }
        );

        console.log(banner);
    }

    static showScanStart(directory: string): void {
        const terminalWidth = process.stdout.columns || 120;
        const boxWidth = Math.min(terminalWidth - 8, 60);
        const truncatedDir = this.truncatePath(directory, boxWidth - 20);

        const startBox = boxen(
            `${this.ICONS.SCAN}  ${chalk.bold.cyan('SCAN START')}\n\n` +
            `${this.ICONS.FOLDER}  Directory: ${chalk.yellow(truncatedDir)}\n` +
            `${this.ICONS.MAGNIFYING}  Searching for npm projects...`,
            {
                padding: 1,
                borderStyle: 'round',
                borderColor: 'cyan',
                title: '🚀 LAUNCH',
                titleAlignment: 'center',
                textAlignment: 'center'
            }
        );

        console.log('\n' + startBox);
    }

    static showProgress(current: number, total: number, projectPath: string): void {
        const percentage = Math.round((current / total) * 100);
        const terminalWidth = process.stdout.columns || 120;
        const availableWidth = terminalWidth - 50; // Reserve space for progress info
        const maxPathLength = Math.max(20, availableWidth - 30);
        const progressBar = this.createProgressBar(percentage);
        const truncatedPath = this.truncatePath(projectPath, maxPathLength);

        process.stdout.write(`\r${this.ICONS.GEAR}  Analysis: ${chalk.cyan(`${current}/${total}`)} ${progressBar} ${chalk.yellow(truncatedPath)}`);
    }

    static showResults(results: ScanResult): void {
        console.log('\n\n');

        // Results title with visual effect
        const resultsTitle = figlet.textSync('RESULTS', {
            font: 'Small',
            horizontalLayout: 'fitted'
        });

        console.log(this.GRADIENTS.matrix(resultsTitle));

        // Summary table
        this.showSummaryTable(results);

        // Detailed display by category
        if (results.compromisedProjects.length > 0) {
            this.showCompromisedProjects(results.compromisedProjects);
        }

        if (results.suspiciousProjects.length > 0) {
            this.showSuspiciousProjects(results.suspiciousProjects);
        }

        if (results.compromisedProjects.length === 0 && results.suspiciousProjects.length === 0) {
            this.showCleanResults();
        }

        // Footer with statistics
        this.showFooter(results);
    }

    static showError(message: string): void {
        const __terminalWidth = process.stdout.columns || 120;

        const errorBox = boxen(
            `${this.ICONS.EXPLOSION} ${chalk.bold.red('ERROR')} ${this.ICONS.EXPLOSION}\n\n` +
            chalk.red(message),
            {
                padding: 1,
                borderStyle: 'double',
                borderColor: 'red',
                backgroundColor: 'black',
                textAlignment: 'center'
            }
        );

        console.log('\n' + errorBox);
    }

    /**
     * Display base64 analysis results
     */
    static showBase64Analysis(analysis: {
        isValidBase64: boolean;
        decodedLevels: number;
        containsSensitiveData: boolean;
        detectedPatterns: string[];
    }): void {
        const __terminalWidth = process.stdout.columns || 120;

        if (!analysis.isValidBase64) {
            const warningBox = boxen(
                `${this.ICONS.WARNING} ${chalk.yellow('Invalid or undetected base64 data')}`,
                {
                    padding: 1,
                    borderStyle: 'round',
                    borderColor: 'yellow',
                    textAlignment: 'center'
                }
            );
            console.log(warningBox);
            return;
        }

        const title = analysis.containsSensitiveData
            ? chalk.red.bold('🚨 SENSITIVE DATA DETECTED')
            : chalk.green.bold('✅ Base64 analysis completed');

        let content = `${title}\n\n`;
        content += `${this.ICONS.CHART}  Decoding levels: ${chalk.cyan(analysis.decodedLevels)}\n`;
        content += `${this.ICONS.SHIELD}  Sensitive data: ${analysis.containsSensitiveData ? chalk.red('YES') : chalk.green('NO')}\n`;

        if (analysis.detectedPatterns.length > 0) {
            content += `\n${chalk.bold('Detected patterns:')}\n`;
            analysis.detectedPatterns.forEach((pattern, index) => {
                content += `${chalk.red(`  ${index + 1}. ${pattern}`)}\n`;
            });
        }

        const resultBox = boxen(
            content,
            {
                padding: 1,
                borderStyle: analysis.containsSensitiveData ? 'double' : 'single',
                borderColor: analysis.containsSensitiveData ? 'red' : 'green',
                title: '🔍 BASE64 ANALYSIS',
                titleAlignment: 'center'
            }
        );

        console.log('\n' + resultBox + '\n');
    }

    /**
     * Display detailed scan statistics
     */
    static showDetailedStats(stats: {
        totalIndicators: number;
        byType: Record<string, number>;
        bySeverity: Record<string, number>;
        criticalFiles: string[];
    }): void {
        if (stats.totalIndicators === 0) {
            return;
        }

        const __terminalWidth = process.stdout.columns || 120;

        let content = `${chalk.bold('📊 DETAILED STATISTICS')}\n\n`;
        content += `${this.ICONS.TARGET}  Total indicators: ${chalk.cyan(stats.totalIndicators)}\n\n`;

        // By type
        if (Object.keys(stats.byType).length > 0) {
            content += `${chalk.bold('By type:')}\n`;
            for (const [type, count] of Object.entries(stats.byType)) {
                const icon = this.getTypeIcon(type);
                content += `  ${icon} ${type}: ${chalk.cyan(count)}\n`;
            }
            content += '\n';
        }

        // By severity
        if (Object.keys(stats.bySeverity).length > 0) {
            content += `${chalk.bold('By severity:')}\n`;
            for (const [severity, count] of Object.entries(stats.bySeverity)) {
                const icon = this.getSeverityIcon(severity);
                const color = this.getSeverityColor(severity);
                content += `  ${icon} ${chalk[color](severity)}: ${chalk.cyan(count)}\n`;
            }
        }

        // Critical files
        if (stats.criticalFiles.length > 0) {
            content += `\n${chalk.red.bold('⚠️ Critical files:')}\n`;
            stats.criticalFiles.forEach((file, index) => {
                content += `  ${chalk.red(`${index + 1}. ${this.truncatePath(file, 70)}`)}\n`;
            });
        }

        const statsBox = boxen(
            content,
            {
                padding: 1,
                borderStyle: 'round',
                borderColor: 'blue',
                title: '📈 STATISTICS',
                titleAlignment: 'center'
            }
        );

        console.log('\n' + statsBox + '\n');
    }

    private static showSummaryTable(results: ScanResult): void {
        const __terminalWidth = process.stdout.columns || 120;

        // Table with widths adjusted for full names
        const col1Width = 24; // Category with full name
        const col2Width = 10; // Readable count
        const col3Width = 14; // Readable percentage
        const col4Width = 20; // Status with full name

        const table = new Table({
            head: [
                chalk.bold.white('📊 CATEGORY'),
                chalk.bold.white('📈 COUNT'),
                chalk.bold.white('📊 %'),
                chalk.bold.white('🎯 STATUS')
            ],
            style: {
                head: ['cyan'],
                border: ['grey']
            },
            colWidths: [col1Width, col2Width, col3Width, col4Width]
        });

        const total = results.totalProjects;
        const cleanPct = Math.round((results.cleanProjects.length / total) * 100);
        const suspiciousPct = Math.round((results.suspiciousProjects.length / total) * 100);
        const compromisedPct = Math.round((results.compromisedProjects.length / total) * 100);

        table.push(
            [
                `✓ Clean Projects`,
                chalk.green.bold(results.cleanProjects.length.toString()),
                chalk.green(`${cleanPct}%`),
                chalk.green.bold('✓ SECURE')
            ],
            [
                `⚠ Suspicious Projects`,
                chalk.yellow.bold(results.suspiciousProjects.length.toString()),
                chalk.yellow(`${suspiciousPct}%`),
                chalk.yellow.bold('⚠ WARNING')
            ],
            [
                `🚨 Compromised Projects`,
                chalk.red.bold(results.compromisedProjects.length.toString()),
                chalk.red(`${compromisedPct}%`),
                results.compromisedProjects.length > 0 ? chalk.red.bold('🚨 DANGER') : chalk.green.bold('✓ NONE')
            ]
        );

        // Calculate boxen width so it doesn't overflow
        const _boxWidth = Math.min(__terminalWidth - 2, 70);

        // Ensure content doesn't exceed available width
        const totalText = total > 999 ? `${total}` : chalk.cyan.bold(total);

        const summaryBox = boxen(
            `${this.ICONS.CHART}  ${chalk.bold.white('SCAN SUMMARY')}\n\n` +
            table.toString() +
            `\n\n${this.ICONS.FOLDER}  Total: ${totalText} npm projects`,
            {
                padding: 1,
                borderStyle: 'round',
                borderColor: 'white',
                title: '📋 REPORT',
                titleAlignment: 'center',
            }
        );

        console.log(summaryBox);
    }

    private static showCompromisedProjects(projects: ProjectScan[]): void {
        const __terminalWidth = process.stdout.columns || 120;
        const warningArt = `
██     ██  █████  ██████  ███    ██ ██ ███    ██  ██████
██     ██ ██   ██ ██   ██ ████   ██ ██ ████   ██ ██
██  █  ██ ███████ ██████  ██ ██  ██ ██ ██ ██  ██ ██   ███
██ ███ ██ ██   ██ ██   ██ ██  ██ ██ ██ ██  ██ ██ ██    ██
 ███ ███  ██   ██ ██   ██ ██   ████ ██ ██   ████  ██████
    `;

        // Add top and left margin line by line
        const warningTitleWithMargin = '\n' + warningArt.split('\n').map(line => '  ' + line).join('\n');
        const warningTitle = this.GRADIENTS.danger(warningTitleWithMargin);

        console.log(warningTitle);

        const compromisedBox = boxen(
            `${this.ICONS.SKULL} ${chalk.bold.red('COMPROMISED PROJECTS DETECTED')} ${this.ICONS.SKULL}\n` +
            chalk.red.bold('IMMEDIATE ACTION REQUIRED!'),
            {
                padding: 1,
                borderStyle: 'double',
                borderColor: 'red',
                backgroundColor: 'black',
                textAlignment: 'center'
            }
        );

        console.log(compromisedBox);

        projects.forEach((project, index) => {
            this.showProjectDetails(project, 'COMPROMISED', index + 1);
        });
    }

    private static showSuspiciousProjects(projects: ProjectScan[]): void {
        const __terminalWidth = process.stdout.columns || 120;

        const warningBox = boxen(
            `${this.ICONS.WARNING} ${chalk.bold.yellow('SUSPICIOUS PROJECTS DETECTED')} ${this.ICONS.WARNING}\n` +
            chalk.yellow('Investigation recommended'),
            {
                padding: 1,
                borderStyle: 'round',
                borderColor: 'yellow',
                textAlignment: 'center'
            }
        );

        console.log('\n' + warningBox);

        projects.forEach((project, index) => {
            this.showProjectDetails(project, 'SUSPICIOUS', index + 1);
        });
    }

    private static showProjectDetails(
        project: ProjectScan,
        type: 'COMPROMISED' | 'SUSPICIOUS',
        index: number
    ): void {
        const isCompromised = type === 'COMPROMISED';
        const icon = isCompromised ? this.ICONS.EXPLOSION : this.ICONS.WARNING;
        const color = isCompromised ? 'red' : 'yellow';
        const bgColor = isCompromised ? 'black' : undefined;

        const terminalWidth = process.stdout.columns || 120;

        // Optimized widths - FILE PATH 50% larger to see end of path
        const indicatorWidth = 18;   // Indicator type (compact)
        const severityWidth = 14;    // Severity (slightly larger for better readability)
        const descriptionWidth = 40; // Complete description
        const filePathWidth = 56;   // FILE PATH (adjusted to maintain total width)

        const table = new Table({
            head: [
                chalk.bold.white('🔍 INDICATOR TYPE'),
                chalk.bold.white('⚠️ SEVERITY'),
                chalk.bold.white('📝 DESCRIPTION'),
                chalk.bold.white('📁 FILE PATH')
            ],
            style: {
                head: [color],
                border: ['grey']
            },
            colWidths: [indicatorWidth, severityWidth, descriptionWidth, filePathWidth],
            wordWrap: true
        });

        project.indicators.forEach(indicator => {
            const severityIcon = this.getSeverityIcon(indicator.severity);
            const severityColor = this.getSeverityColor(indicator.severity);

            // Display file path with smart truncation preserving the end
            const filePath = indicator.file ? this.truncatePathSmart(indicator.file, filePathWidth - 2) : 'N/A';

            table.push([
                `${this.getTypeIcon(indicator.type)} ${indicator.type}`,
                chalk[severityColor](`${severityIcon} ${indicator.severity}`),
                indicator.description + (indicator.details ? `\n${chalk.gray(indicator.details)}` : ''),
                chalk.cyan(filePath)
            ]);
        });

        const projectBox = boxen(
            `${icon} ${chalk.bold[color](`PROJECT ${index}`)} ${icon}\n\n` +
            `${this.ICONS.FOLDER}  ${chalk.bold('Path:')} ${chalk.cyan(this.truncatePath(project.path, Math.max(50, terminalWidth - 30)))}\n` +
            `${this.ICONS.FILE}  ${chalk.bold('Package.json:')} ${chalk.gray(this.truncatePath(project.packageJsonPath, Math.max(50, terminalWidth - 30)))}\n\n` +
            table.toString(),
            {
                padding: 1,
                borderStyle: isCompromised ? 'double' : 'single',
                borderColor: color,
                backgroundColor: bgColor,
                title: isCompromised ? '💀 COMPROMISED' : '⚠️ SUSPICIOUS',
                titleAlignment: 'center'
            }
        );

        console.log('\n' + projectBox);
    }

    private static showCleanResults(): void {
        const __terminalWidth = process.stdout.columns || 120;
        const cleanTitle = this.GRADIENTS.matrix(`
 ██████ ██      ███████  █████  ███    ██
██      ██      ██      ██   ██ ████   ██
██      ██      █████   ███████ ██ ██  ██
██      ██      ██      ██   ██ ██  ██ ██
 ██████ ███████ ███████ ██   ██ ██   ████
    `);

        // Add left margin for CLEAN title
        const cleanTitleWithMargin = cleanTitle.split('\n').map(line => '  ' + line).join('\n');
        console.log('\n' + cleanTitleWithMargin);

        const _cleanBoxWidth = Math.min(__terminalWidth - 4, 55);

        const successBox = boxen(
            `${this.ICONS.SUCCESS} ${chalk.bold.green('CONGRATULATIONS!')} ${this.ICONS.SUCCESS}\n\n` +
            `${this.ICONS.SHIELD}  No Shai-Hulud compromise indicators detected\n` +
            `${this.ICONS.LOCK}  Your npm projects appear secure\n` +
            `${this.ICONS.ROBOT}  Continue monitoring regularly`,
            {
                padding: 2,
                borderStyle: 'double',
                borderColor: 'green',
                title: '🎉 CLEAN SYSTEM',
                titleAlignment: 'center',
                textAlignment: 'left',
            }
        );

        console.log('\n' + successBox);
    }

    private static showFooter(results: ScanResult): void {
        const __terminalWidth = process.stdout.columns || 120;
        const _maxFooterWidth = Math.min(__terminalWidth - 4, 70);

        const duration = results.scanDuration < 1000
            ? `${results.scanDuration}ms`
            : `${(results.scanDuration / 1000).toFixed(2)}s`;

        let footerContent = `${this.ICONS.HOURGLASS}  ${chalk.bold('Scan duration:')} ${chalk.cyan(duration)}\n` +
            `${this.ICONS.DETECTIVE}  ${chalk.bold('Scanner:')} Shai-Hulud Detector v2.0.0\n` +
            `${this.ICONS.GEAR}  ${chalk.bold('Status:')} Scan completed successfully\n`;

        // Add note about report if projects are compromised
        if (results.compromisedProjects.length > 0) {
            footerContent += `${this.ICONS.FILE}  ${chalk.bold('Report:')} Security report generated in current directory\n`;
        }

        footerContent += `\n${chalk.gray('💡  Recommendation: Run this scan regularly to maintain security')}`;

        if (results.compromisedProjects.length > 0) {
            footerContent += `\n${chalk.red('⚠️  IMPORTANT: Consult the security report for actions to take')}`;
        }

        const footerBox = boxen(
            footerContent,
            {
                padding: 1,
                borderStyle: 'round',
                borderColor: results.compromisedProjects.length > 0 ? 'red' : 'blue',
                title: '📝 INFORMATION',
                titleAlignment: 'center',
            }
        );

        console.log('\n' + footerBox + '\n');
    }

    private static createProgressBar(percentage: number, width: number = 30): string {
        const filled = Math.round((percentage / 100) * width);
        const empty = width - filled;

        const filledBar = '█'.repeat(filled);
        const emptyBar = '░'.repeat(empty);

        const coloredBar = percentage < 30 ? chalk.red(filledBar) :
            percentage < 70 ? chalk.yellow(filledBar) :
                chalk.green(filledBar);

        return `[${coloredBar}${chalk.gray(emptyBar)}] ${chalk.bold(percentage)}%`;
    }

    private static getSeverityIcon(severity: string): string {
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

    private static getSeverityColor(severity: string): 'red' | 'yellow' | 'blue' | 'gray' {
        switch (severity) {
            case 'CRITICAL':
                return 'red';
            case 'HIGH':
                return 'red';
            case 'MEDIUM':
                return 'yellow';
            case 'LOW':
                return 'blue';
            default:
                return 'gray';
        }
    }

    private static getTypeIcon(type: string): string {
        switch (type) {
            case 'MALICIOUS_FILE':
                return '📄';
            case 'SUSPICIOUS_SCRIPT':
                return '⚙️';
            case 'WORKFLOW_INJECTION':
                return '🔧';
            case 'ENVIRONMENT_VAR':
                return '🔑';
            case 'COMPROMISED_DEPENDENCY':
                return '📦';
            default:
                return '❓';
        }
    }

    private static truncatePath(path: string, maxLength: number): string {
        if (path.length <= maxLength) {
            return path;
        }
        return '...' + path.slice(-(maxLength - 3));
    }

    private static centerText(text: string, width: number): string {
        const lines = text.split('\n');
        return lines.map(line => {
            const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, ''); // Remove ANSI codes for length calculation
            const padding = Math.max(0, Math.floor((width - cleanLine.length) / 2));
            return ' '.repeat(padding) + line;
        }).join('\n');
    }

    /**
     * Intelligent path truncation that preserves end of path (filename + 2-3 directory levels)
     */
    private static truncatePathSmart(path: string, maxLength: number): string {
        if (path.length <= maxLength) {
            return path;
        }

        // Split path into parts
        const parts = path.split('/').filter(part => part.length > 0);

        // Always keep filename + at least 2 directory levels if possible
        const minPartsToKeep = Math.min(3, parts.length);
        const endParts = parts.slice(-minPartsToKeep);
        let result = endParts.join('/');

        // If still too long, just truncate from start with ...
        if (result.length > maxLength - 3) {
            return '...' + result.slice(-(maxLength - 3));
        }

        // Add more directory levels from the end while we have space
        for (let i = minPartsToKeep; i < parts.length; i++) {
            const newResult = parts.slice(-(i + 1)).join('/');
            if (newResult.length > maxLength - 3) {
                break;
            }
            result = newResult;
        }

        // Add ... prefix if we couldn't fit the full path
        if (result !== path) {
            result = '...' + result;
        }

        return result;
    }
}
