import {CompromissionIndicator} from '../types';

export interface DecodedData {
    level: number;
    content: string;
    isValid: boolean;
    containsSensitiveData: boolean;
    detectedPatterns: string[];
}

export class Base64Decoder {
    private static readonly MAX_DECODE_ITERATIONS = 5;
    private static readonly MIN_CONTENT_LENGTH = 10;

    // SPECIFIC Shai-Hulud patterns for detecting sensitive data
    private shaiHuludPatterns = [
        /TruffleHog/gi,                                                   // Tool used by Shai-Hulud
        /webhook\.site\/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/gi,          // Specific Shai-Hulud endpoint
        /webhook\.site/gi,                                                // Shai-Hulud exfiltration domain
        /0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976/gi,                  // Attacker's Ethereum address
        /checkethereumw|runmask|stealthProxyControl/gi,                   // Shai-Hulud malware functions
        /npmjs\.help|npnjs\.com/gi,                                       // Malicious Shai-Hulud domains
        /shai-hulud/gi,                                                   // Attack name
        /bundle\.js|node-gyp\.dll/gi                                      // Malicious Shai-Hulud files
    ];

    /**
     * Recursively decodes base64 content up to 5 levels
     * Specialized for detecting Shai-Hulud exfiltrated data
     */
    decodeRecursively(content: string): DecodedData[] {
        const results: DecodedData[] = [];
        let currentContent = content.trim();

        for (let level = 0; level < Base64Decoder.MAX_DECODE_ITERATIONS; level++) {
            if (!this.isBase64(currentContent)) {
                break;
            }

            try {
                const decoded = Buffer.from(currentContent, 'base64').toString('utf8');

                if (decoded.length < Base64Decoder.MIN_CONTENT_LENGTH || decoded === currentContent) {
                    break;
                }

                const analysis = this.analyzeContentForShaiHulud(decoded);

                results.push({
                    level: level + 1,
                    content: this.sanitizeShaiHuludContent(decoded),
                    isValid: true,
                    containsSensitiveData: analysis.containsSensitiveData,
                    detectedPatterns: analysis.patterns
                });

                currentContent = decoded;

                // If Shai-Hulud patterns found, continue decoding
                if (!analysis.containsSensitiveData && !this.isBase64(decoded)) {
                    break;
                }

            } catch (error) {
                // Decode error, stop here
                break;
            }
        }

        return results;
    }

    /**
     * Analyzes a suspicious file for base64 encoded content with Shai-Hulud patterns
     */
    analyzeFileForBase64(filePath: string, content: string): CompromissionIndicator[] {
        const indicators: CompromissionIndicator[] = [];

        // Search for base64 blocks in content
        const base64Patterns = [
            /[A-Za-z0-9+\/]{100,}={0,2}/g, // General base64
            /"data":\s*"([A-Za-z0-9+\/=]{50,})"/g, // JSON with base64 data
            /data:([^;]+);base64,([A-Za-z0-9+\/=]+)/g // Data URLs
        ];

        for (const pattern of base64Patterns) {
            let match;
            while ((match = pattern.exec(content)) !== null) {
                const base64Content = match[1] || match[2] || match[0];

                if (base64Content.length > 100) { // Ignore small blocks
                    const decodedResults = this.decodeRecursively(base64Content);

                    if (decodedResults.length > 0) {
                        const shaiHuludLevels = decodedResults.filter(r => r.containsSensitiveData);

                        if (shaiHuludLevels.length > 0) {
                            indicators.push({
                                type: 'MALICIOUS_FILE',
                                severity: 'CRITICAL',
                                description: `Shai-Hulud base64 encoded data detected (${shaiHuludLevels.length} levels)`,
                                details: `Shai-Hulud patterns detected: ${shaiHuludLevels.flatMap(l => l.detectedPatterns).join(', ')}`,
                                file: filePath
                            });
                        } else if (decodedResults.length > 2) {
                            // More than 2 suspicious encoding levels (technique used by Shai-Hulud)
                            indicators.push({
                                type: 'MALICIOUS_FILE',
                                severity: 'HIGH',
                                description: `Suspicious Shai-Hulud multi-level base64 encoding (${decodedResults.length} levels)`,
                                details: 'Obfuscation technique used by Shai-Hulud attack',
                                file: filePath
                            });
                        }
                    }
                }
            }
        }

        return indicators;
    }

    /**
     * Validates typical Shai-Hulud exfiltrated data structure
     */
    validateExfiltratedDataStructure(content: string): boolean {
        try {
            const parsed = JSON.parse(content);

            // Typical Shai-Hulud data structure (based on attack documentation)
            const shaiHuludFields = ['system', 'env', 'tokens', 'repos', 'npm_config'];
            const foundFields = shaiHuludFields.filter(field => Object.prototype.hasOwnProperty.call(parsed, field));

            return foundFields.length >= 2; // At least 2 expected Shai-Hulud fields
        } catch {
            // Not JSON, search for Shai-Hulud structural patterns
            const shaiHuludStructuralPatterns = [
                /system:\s*\{/,
                /env:\s*\[/,
                /tokens:\s*\{/,
                /repos:\s*\[/,
                /TruffleHog.*scan/,
                /webhook\.site.*post/
            ];

            const matchingPatterns = shaiHuludStructuralPatterns.filter(pattern => pattern.test(content));
            return matchingPatterns.length >= 2;
        }
    }

    /**
     * Checks if a string is valid base64
     */
    private isBase64(str: string): boolean {
        if (!str || str.length < 4 || str.length % 4 !== 0) {
            return false;
        }

        const base64Regex = /^[A-Za-z0-9+\/]*={0,2}$/;
        return base64Regex.test(str);
    }

    /**
     * Analyzes decoded content for specific Shai-Hulud patterns
     */
    private analyzeContentForShaiHulud(content: string): { containsSensitiveData: boolean; patterns: string[] } {
        const detectedPatterns: string[] = [];
        let containsSensitiveData = false;

        for (const pattern of this.shaiHuludPatterns) {
            const matches = content.match(pattern);
            if (matches) {
                containsSensitiveData = true;
                detectedPatterns.push(...matches.slice(0, 3)); // Limit to 3 matches per pattern
            }
        }

        return {
            containsSensitiveData,
            patterns: detectedPatterns
        };
    }

    /**
     * Sanitizes content by masking sensitive data while preserving Shai-Hulud patterns for analysis
     */
    private sanitizeShaiHuludContent(content: string): string {
        let sanitized = content;

        // Mask specific Shai-Hulud crypto addresses
        sanitized = sanitized
            .replace(/0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976/gi, '0x[SHAI_HULUD_ETH_ADDRESS]')
            .replace(/webhook\.site\/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/gi, 'webhook.site/[SHAI_HULUD_ENDPOINT]');

        // Limit length for display
        if (sanitized.length > 500) {
            sanitized = sanitized.substring(0, 500) + '... [TRUNCATED]';
        }

        return sanitized;
    }
}
