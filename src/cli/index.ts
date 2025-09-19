#!/usr/bin/env node

import {Command} from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import * as fs from 'fs';
import * as path from 'path';
import {ShaiHuludDetector} from '../core/detector';
import {UIFormatter} from './ui/formatter';

const program = new Command();

// Handle graceful shutdown on SIGINT (Ctrl+C)
process.on('SIGINT', () => {
    console.log(chalk.yellow('\n\n👋 Scan interrupted by user'));
    process.exit(0);
});

// Function to validate directory existence
function validateDirectory(dirPath: string): { isValid: boolean; errorMessage?: string; normalizedPath?: string } {
    try {
        // Normalize and resolve the path
        const normalizedPath = path.resolve(dirPath);

        // Check if path exists
        if (!fs.existsSync(normalizedPath)) {
            return {
                isValid: false,
                errorMessage: `Directory does not exist: ${chalk.yellow(dirPath)}`
            };
        }

        // Check if it's actually a directory
        const stats = fs.statSync(normalizedPath);
        if (!stats.isDirectory()) {
            return {
                isValid: false,
                errorMessage: `Path is not a directory: ${chalk.yellow(dirPath)}`
            };
        }

        // Check if directory is readable
        try {
            fs.accessSync(normalizedPath, fs.constants.R_OK);
        } catch (error) {
            return {
                isValid: false,
                errorMessage: `Directory is not readable: ${chalk.yellow(dirPath)}`
            };
        }

        return {
            isValid: true,
            normalizedPath
        };
    } catch (error) {
        return {
            isValid: false,
            errorMessage: `Invalid directory path: ${chalk.yellow(dirPath)}`
        };
    }
}

program
    .name('shai-hulud-detector')
    .description('Shai-Hulud compromise indicator detector for npm projects - Version 1.0.0')
    .version('1.1.0');

program
    .option('-d, --directory <path>', 'Directory to scan', '/')
    .option('-e, --exclude <dirs>', 'Directories to exclude from scan (comma-separated: dir1,dir2,dir3)', '')
    .option('--no-interactive', 'Non-interactive mode')
    .action(async (options) => {
        try {
            // Display beautiful welcome banner
            UIFormatter.showBanner();

            let scanDirectory = options.directory;

            if (options.interactive !== false) {
                const answers = await inquirer.prompt([
                    {
                        type: 'input',
                        name: 'directory',
                        message: `${chalk.cyan('🕵️  Which directory do you want to scan?')}`,
                        default: scanDirectory,
                        validate: (input: string) => {
                            if (!input || input.trim() === '') {
                                return chalk.red('❌ Please specify a valid directory');
                            }

                            const validation = validateDirectory(input.trim());
                            if (!validation.isValid) {
                                return chalk.red(`❌ ${validation.errorMessage}`);
                            }

                            return true;
                        }
                    },
                    {
                        type: 'confirm',
                        name: 'confirm',
                        message: `${chalk.green('🚀 Launch Shai-Hulud detection scan?')}`,
                        default: true
                    }
                ]);

                if (!answers.confirm) {
                    console.log(chalk.yellow('\n👋 Scan cancelled by user'));
                    process.exit(0);
                }

                scanDirectory = answers.directory;
            }

            // Validate directory existence for both interactive and non-interactive modes
            const directoryValidation = validateDirectory(scanDirectory);
            if (!directoryValidation.isValid) {
                UIFormatter.showError(`${directoryValidation.errorMessage}\n\nPlease provide a valid directory path.`);
                return; // Exit gracefully without error code
            }

            // Use the normalized path for scanning (guaranteed to exist at this point)
            scanDirectory = directoryValidation.normalizedPath as string;

            // Display scan start with style
            UIFormatter.showScanStart(scanDirectory);

            const spinner = ora({
                text: `${chalk.cyan('🔎 Initializing Shai-Hulud scanner...')}`,
                color: 'cyan',
                spinner: 'dots12'
            }).start();

            // Parse excluded directories
            const excludedDirs = options.exclude 
                ? options.exclude.split(',').map((dir: string) => dir.trim()).filter((dir: string) => dir.length > 0)
                : [];

            const detector = new ShaiHuludDetector({
                scanDirectory,
                excludedDirs
            });

            try {
                const results = await detector.scan();
                spinner.stop();

                // Display results
                UIFormatter.showResults(results);

                // Exit code based on results
                process.exit(results.compromisedProjects.length > 0 ? 1 : 0);
            } catch (error) {
                spinner.fail(`${chalk.red('💥 Error during scan')}`);
                UIFormatter.showError(error instanceof Error ? error.message : 'Unknown error');
                process.exit(1);
            }
        } catch (error) {
            UIFormatter.showError(error instanceof Error ? error.message : 'Unknown error');
            process.exit(1);
        }
    });

// Command to analyze external base64 data
program
    .command('decode-base64')
    .description('Analyze external base64 data for Shai-Hulud indicators')
    .option('-d, --data <base64>', 'Base64 data to analyze')
    .option('-f, --file <path>', 'File containing base64 data')
    .action(async (options) => {
        try {
            const {IndicatorDetector} = await import('../analysis/indicators');
            const detector = new IndicatorDetector();

            let base64Content = '';

            if (options.file) {
                const fs = await import('fs/promises');
                base64Content = await fs.readFile(options.file, 'utf8');
            } else if (options.data) {
                base64Content = options.data;
            } else {
                console.log(chalk.red('❌ Specify data with --data or a file with --file'));
                process.exit(1);
            }

            console.log(chalk.cyan('🔍 Analyzing base64 data...\n'));

            const analysis = detector.analyzeBase64Data(base64Content.trim());

            UIFormatter.showBase64Analysis(analysis);

        } catch (error) {
            UIFormatter.showError(error instanceof Error ? error.message : 'Unknown error');
            process.exit(1);
        }
    });

program.parse();

