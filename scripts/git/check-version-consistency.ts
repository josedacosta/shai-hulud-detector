#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';

interface VersionLocation {
    file: string;
    pattern: RegExp;
    required: boolean;
    description: string;
}

/**
 * Configuration of files to check and their patterns
 */
const VERSION_LOCATIONS: VersionLocation[] = [
    {
        file: 'package.json',
        pattern: /"version":\s*"([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)"/,
        required: true,
        description: 'Package version',
    },
    {
        file: 'CHANGELOG.md',
        pattern: /## \[([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)] - \d{4}-\d{2}-\d{2}/,
        required: true,
        description: 'Latest changelog entry',
    },
    {
        file: 'src/cli/index.ts',
        pattern: /\.version\('([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)'\)/,
        required: true,
        description: 'CLI version in src/cli/index.ts',
    },
];

/**
 * Extracts version from a file using a pattern
 */
function extractVersion(filePath: string, pattern: RegExp): string | null {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const match = pattern.exec(content);
        return match ? match[1] : null;
    } catch {
        return null;
    }
}

/**
 * Checks version consistency
 */
function checkVersionConsistency(): void {
    const projectRoot = path.resolve(__dirname, '../..');
    const versions = new Map<string, string>();
    const errors: string[] = [];

    console.log('🔍 Checking version consistency...\n');

    // Extract all versions
    for (const location of VERSION_LOCATIONS) {
        const filePath = path.join(projectRoot, location.file);
        const version = extractVersion(filePath, location.pattern);

        if (version === null && location.required) {
            errors.push(`❌ Version not found in ${location.file} (${location.description})`);
        } else if (version) {
            versions.set(location.file, version);
            console.log(`✓ ${location.file}: ${version} (${location.description})`);
        } else if (!location.required) {
            console.log(`⚠️  ${location.file}: not found (optional - ${location.description})`);
        }
    }

    // Check consistency
    if (versions.size > 0) {
        const uniqueVersions = [...new Set(versions.values())];

        if (uniqueVersions.length > 1) {
            console.log('\n⚠️  Inconsistency detected!');
            console.log('Versions found:');
            for (const [file, version] of versions) {
                console.log(`  - ${file}: ${version}`);
            }
            errors.push(`Versions are not synchronized: ${uniqueVersions.join(', ')}`);
        } else {
            console.log(`\n✅ All versions are consistent: ${uniqueVersions[0]}`);
        }
    }

    // Display errors and exit with appropriate code
    if (errors.length > 0) {
        console.error('\n❌ Errors found:');
        errors.forEach((error) => console.error(`  - ${error}`));
        process.exit(1);
    }

    console.log('\n✅ Check successful! All versions are consistent.');
    process.exit(0);
}

// Execute the check
checkVersionConsistency();
