# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-09-19

### 🚀 Enhanced Features

- Improved detection algorithms and performance optimizations
- Better CLI user experience with enhanced formatting
- Updated security indicators and threat patterns

## [1.0.0] - 2025-09-19

### 🎉 Initial Release

First stable version of the Shai-Hulud detector for npm project security.

### Added

#### CLI and User Interface

- **Complete command-line interface** with Commander.js
- **Interactive mode** with directory selection via inquirer
- **Non-interactive mode** for automation and scripts
- **Rich output** with colors, tables and progress indicators
- **Output format support**: formatted console and JSON
- **Visual indicators**: spinners, progress bars, ASCII banners

#### Security Detection Engine

- **Shai-Hulud indicator detection** based on the documented September 2025 attack
- **Multi-level analysis**: files, npm scripts, environment variables
- **Threat classification**: CLEAN, SUSPICIOUS, COMPROMISED
- **Severity levels**: LOW, MEDIUM, HIGH, CRITICAL

#### Detected Compromise Indicators

- **Malicious files**:
    - `bundle.js` > 3MB with known SHA-256 hashes
    - `shai-hulud-workflow.yml` in GitHub Actions
    - `node-gyp.dll` with malicious signatures
    - Files containing "shai-hulud" in their name
- **Suspicious npm scripts**:
    - Crypto-stealer patterns
    - Specific Ethereum addresses (0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976)
    - Malicious global variables
    - TruffleHog references
- **System compromise**:
    - Malicious GitHub workflows
    - Suspicious environment variables
    - Connections to webhook.site

#### Project Scanner

- **Recursive discovery** of package.json files
- **Intelligent exclusion** of directories (node_modules, .git, dist, etc.)
- **Depth limitation** to prevent infinite recursion
- **Permission handling** with graceful degradation
- **Multi-platform support** (Windows, macOS, Linux)

#### Report Generation

- **Detailed security reports** in Markdown format
- **Automatic timestamping**: `shai-hulud-report-YYYYMMDD-HHMMSS.md`
- **Complete information**: findings, remediation steps, system analysis
- **Metadata**: tool version, scan time, statistics

#### Technical Architecture

- **Complete TypeScript** with strict type checking
- **Modular architecture** with separation of concerns:
    - `detector.ts`: Main orchestration
    - `scanner.ts`: Project discovery
    - `indicators.ts`: Detection logic
    - `reporter.ts`: Report generation
    - `ui.ts`: Interface formatting
- **Robust error handling** with clear user messages
- **Complete logging** for debugging and audit

#### Development Tools

- **Build scripts** with TypeScript
- **ESLint linting** with TypeScript configuration
- **Jest tests** for validation
- **Development scripts** with ts-node
- **CLI binary configuration** for global installation

#### Security and Best Practices

- **Read-only operations** - never modifies scanned files
- **Input validation** with error handling
- **Process isolation** without arbitrary code execution
- **Automatic cleanup** of temporary resources
- **Secure path handling** with validation

### System Configuration

- **Node.js minimum**: 16.0.0
- **Package manager**: Yarn (recommended)
- **Platform**: Windows, macOS, Linux
- **Dependencies**: Commander, Inquirer, Chalk, Ora, CLI-Table3, Boxen

### Documentation

- **Complete README** with usage examples
- **Installation and configuration guide**
- **API documentation** and CLI options
- **Contribution guide** for developers
- **Legal disclaimer** and security warnings
