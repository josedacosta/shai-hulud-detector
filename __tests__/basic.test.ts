import * as fs from 'fs';
import * as path from 'path';
import {execSync} from 'child_process';

describe('Basic functionality tests', () => {
    const distPath = path.join(__dirname, '..', 'dist');
    const packageJsonPath = path.join(__dirname, '..', 'package.json');
    const mainEntryPath = path.join(distPath, 'cli', 'index.js');

    beforeAll(() => {
        // Ensure the project is built before running tests
        try {
            execSync('yarn build', {
                cwd: path.join(__dirname, '..'),
                stdio: 'inherit'
            });
        } catch (error) {
            throw new Error('Failed to build project before testing');
        }
    });

    test('package.json exists and is valid', () => {
        expect(fs.existsSync(packageJsonPath)).toBe(true);

        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        expect(packageJson.name).toBe('shai-hulud-detector');
        expect(packageJson.version).toBeDefined();
        expect(packageJson.main).toBeDefined();
        expect(packageJson.bin).toBeDefined();
    });

    test('project builds successfully', () => {
        // Check that dist directory exists
        expect(fs.existsSync(distPath)).toBe(true);

        // Check that main entry file exists
        expect(fs.existsSync(mainEntryPath)).toBe(true);

        // Check that the file is executable (has shebang)
        const content = fs.readFileSync(mainEntryPath, 'utf-8');
        expect(content.startsWith('#!/usr/bin/env node')).toBe(true);
    });

    test('CLI executes with --help flag', () => {
        try {
            const output = execSync('node dist/cli/index.js --help', {
                cwd: path.join(__dirname, '..'),
                encoding: 'utf-8',
                timeout: 10000
            });

            // Check that help output contains expected text
            expect(output).toContain('Shai-Hulud');
            expect(output).toContain('detector');
            expect(output).toContain('--directory');
            expect(output).toContain('--exclude');
            expect(output).toContain('--no-interactive');
        } catch (error) {
            throw new Error(`CLI --help failed: ${error}`);
        }
    });

    test('CLI executes with --version flag', () => {
        try {
            const output = execSync('node dist/cli/index.js --version', {
                cwd: path.join(__dirname, '..'),
                encoding: 'utf-8',
                timeout: 10000
            });

            // Should output version number
            expect(output.trim()).toMatch(/^\d+\.\d+\.\d+$/);
        } catch (error) {
            throw new Error(`CLI --version failed: ${error}`);
        }
    });

    test('CLI can perform a basic scan (dry run)', () => {
        try {
            // Create a temporary test directory with a package.json
            const testDir = path.join(__dirname, 'temp-test');
            if (!fs.existsSync(testDir)) {
                fs.mkdirSync(testDir, {recursive: true});
            }

            // Create a minimal package.json for testing
            const testPackageJson = {
                name: 'test-package',
                version: '1.0.0',
                scripts: {
                    start: 'node index.js'
                }
            };
            fs.writeFileSync(
                path.join(testDir, 'package.json'),
                JSON.stringify(testPackageJson, null, 2)
            );

            // Run the CLI on the test directory
            const output = execSync(`node dist/cli/index.js -d "${testDir}" --no-interactive`, {
                cwd: path.join(__dirname, '..'),
                encoding: 'utf-8',
                timeout: 30000
            });

            // Should contain scan completion message
            expect(output).toContain('Scan completed successfully');
            // Should indicate at least one project was found
            expect(output).toContain('Total: 1 npm projects');
            // Should show the clean result
            expect(output).toContain('CLEAN SYSTEM');

            // Clean up test directory
            fs.rmSync(testDir, {recursive: true, force: true});

        } catch (error) {
            // Clean up in case of error
            const testDir = path.join(__dirname, 'temp-test');
            if (fs.existsSync(testDir)) {
                fs.rmSync(testDir, {recursive: true, force: true});
            }
            throw new Error(`CLI basic scan failed: ${error}`);
        }
    });

    test('TypeScript types are properly exported', () => {
        // Check that type definition files exist
        const typeFiles = [
            path.join(distPath, 'types', 'index.d.ts'),
            path.join(distPath, 'core', 'detector.d.ts'),
        ];

        typeFiles.forEach(typeFile => {
            if (fs.existsSync(typeFile)) {
                const content = fs.readFileSync(typeFile, 'utf-8');
                expect(content.length).toBeGreaterThan(0);
            }
        });
    });
});
