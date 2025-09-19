import * as fs from 'fs';
import * as path from 'path';
import {promisify} from 'util';

const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);
const access = promisify(fs.access);

export class ProjectScanner {
    private excludedDirs: Set<string>;

    constructor(additionalExcludedDirs: string[] = []) {
        // Default excluded directories
        this.excludedDirs = new Set([
            'node_modules',
            '.git',
            '.svn',
            '.hg',
            'dist',
            'build',
            'coverage',
            '.nyc_output',
            'tmp',
            'temp',
            '.cache',
            '.next',
            '.nuxt',
            'out',
            '.vscode',
            '.idea',
            'logs'
        ]);

        // Add user-specified excluded directories
        additionalExcludedDirs.forEach(dir => {
            this.excludedDirs.add(dir);
        });
    }

    private isExcluded(itemPath: string, itemName: string): boolean {
        // Check if directory name is in excluded list
        if (this.excludedDirs.has(itemName)) {
            return true;
        }

        // Check if full path (normalized) is in excluded list
        const normalizedItemPath = path.resolve(itemPath);
        for (const excludedDir of this.excludedDirs) {
            // Handle absolute paths
            if (excludedDir.startsWith('/') || excludedDir.includes('\\')) {
                const normalizedExcludedPath = path.resolve(excludedDir);
                if (normalizedItemPath === normalizedExcludedPath) {
                    return true;
                }
                // Also check if the item path starts with the excluded path (for subdirectories)
                if (normalizedItemPath.startsWith(normalizedExcludedPath + path.sep)) {
                    return true;
                }
            }
        }

        return false;
    }

    async findPackageJsonFiles(rootPath: string, onProgress?: (currentDir: string) => void): Promise<string[]> {
        const packageJsonFiles: string[] = [];
        await this.scanDirectory(rootPath, packageJsonFiles, 0, onProgress);
        return packageJsonFiles;
    }

    async scanDirectoryShallow(dirPath: string): Promise<string[]> {
        const packageJsonFiles: string[] = [];

        try {
            await access(dirPath, fs.constants.R_OK);
            const items = await readdir(dirPath);

            for (const item of items) {
                const itemPath = path.join(dirPath, item);

                try {
                    const stats = await stat(itemPath);

                    if (stats.isFile() && item === 'package.json') {
                        packageJsonFiles.push(itemPath);
                    } else if (stats.isDirectory() && !this.isExcluded(itemPath, item) && !item.startsWith('.')) {
                        const subItems = await readdir(itemPath);
                        if (subItems.includes('package.json')) {
                            packageJsonFiles.push(path.join(itemPath, 'package.json'));
                        }
                    }
                } catch (error) {
                    continue;
                }
            }
        } catch (error) {
            return packageJsonFiles;
        }

        return packageJsonFiles;
    }

    private async scanDirectory(dirPath: string, packageJsonFiles: string[], depth = 0, onProgress?: (currentDir: string) => void): Promise<void> {
        if (depth > 10) {
            return;
        } // Depth limit to avoid infinite loops

        // Report progress if callback provided
        if (onProgress) {
            onProgress(dirPath);
        }

        try {
            await access(dirPath, fs.constants.R_OK);
            const items = await readdir(dirPath);

            for (const item of items) {
                const itemPath = path.join(dirPath, item);

                try {
                    const stats = await stat(itemPath);

                    if (stats.isFile() && item === 'package.json') {
                        packageJsonFiles.push(itemPath);
                    } else if (stats.isDirectory() && !this.isExcluded(itemPath, item) && !item.startsWith('.')) {
                        await this.scanDirectory(itemPath, packageJsonFiles, depth + 1, onProgress);
                    }
                } catch (error) {
                    // Ignore file/folder access errors
                    continue;
                }
            }
        } catch (error) {
            // Ignore directory access errors
            return;
        }
    }
}
