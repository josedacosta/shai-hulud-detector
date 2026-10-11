# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Shai-Hulud Detector is a CLI security tool for detecting compromise indicators of the Shai-Hulud attack in npm projects. It's a TypeScript-based
security scanner that analyzes package.json files and their associated projects for specific malware indicators documented in the September 2025 npm
supply chain attack.

## Package Manager

**ALWAYS use YARN** for all operations in this project:

- `yarn install` - Install dependencies
- `yarn build` - Compile TypeScript to JavaScript
- `yarn start` - Run the compiled application
- `yarn dev` - Run development mode with ts-node
- `yarn test` - Run Jest tests
- `yarn lint` - Run ESLint checks
- `yarn typecheck` - Run TypeScript type checking

## Essential Development Commands

### Build and Run

```bash
yarn build        # Compile TypeScript (required before running)
yarn start        # Run the CLI tool after building
yarn dev          # Development mode (uses ts-node)
```

### Quality Assurance

```bash
yarn lint         # ESLint validation
yarn typecheck    # TypeScript type checking
yarn test         # Jest test suite
```

### CLI Usage Examples

```bash
# Interactive mode (default)
yarn start

# Scan specific directory
yarn start -d /path/to/scan

# Exclude specific directories from scan
yarn start -d /path/to/scan -e "my-project,temp-folder,backup"

# Verbose output with JSON format
yarn start -d /home/projects -v --json

# Non-interactive mode
yarn start -d /home/projects --no-interactive
```

## Architecture Overview

### Core Components

- **`src/index.ts`**: CLI entry point using Commander.js, handles argument parsing and interactive prompts
- **`src/detector.ts`**: Main ShaiHuludDetector class orchestrating the entire scanning process
- **`src/scanner.ts`**: ProjectScanner class for finding package.json files recursively
- **`src/indicators.ts`**: CompromissionIndicatorChecker containing all Shai-Hulud detection logic
- **`src/reporter.ts`**: SecurityReporter for generating detailed security reports
- **`src/ui.ts`**: UIFormatter providing rich CLI formatting with colors, tables, and progress indicators
- **`src/types.ts`**: TypeScript interfaces for type safety

### Key Architectural Patterns

**Detection Pipeline**: Scanner → Detector → Indicator Analysis → Reporting

- Scanner finds npm projects by locating package.json files
- Detector orchestrates analysis of each project
- Indicator checker analyzes for specific Shai-Hulud compromise patterns
- Reporter generates detailed security reports when threats are found

**Security-First Design**:

- Comprehensive indicator detection based on real attack analysis
- Multiple severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Project status classification (CLEAN, SUSPICIOUS, COMPROMISED)

**CLI User Experience**:

- Rich interactive prompts using inquirer
- Colorized output with chalk
- Progress indicators with ora spinners
- Formatted tables and boxes for results display

## Shai-Hulud Detection Logic

The tool detects specific indicators documented from the September 2025 attack:

### Malicious Files

- `bundle.js` files > 3MB with known SHA-256 hashes
- `shai-hulud-workflow.yml` GitHub Actions workflows
- `node-gyp.dll` malicious DLL files
- Files containing "shai-hulud" in their names

### Suspicious Scripts

- npm scripts with crypto-stealer patterns
- References to specific Ethereum addresses (0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976)
- Global variables: `stealthProxyControl`, `runmask`, `checkethereumw`
- TruffleHog secret scanning tool references

### System Compromise

- Malicious GitHub workflows and repositories
- Suspicious environment variables
- Network connections to webhook.site

## TypeScript Configuration

- **Target**: ES2020 with CommonJS modules
- **Output**: `./dist` directory
- **Source**: `./src` with source maps enabled
- **Strict mode**: Enabled for type safety
- **Declaration files**: Generated for potential library usage

## Code Style and Linting

- ESLint with TypeScript parser
- Extends recommended configurations
- Key rules: no unused vars (error), explicit any (warn)
- Node.js environment configuration

## Testing Strategy

- Jest testing framework configured
- Test files excluded from TypeScript compilation
- Use `yarn test` to run the test suite

## Security Considerations

This is a defensive security tool:

- **Read-only operations** - Never modifies scanned files
- **Permission-aware** - Gracefully handles access denied scenarios
- **Depth-limited scanning** - Prevents infinite recursion
- **Comprehensive logging** - Detailed reporting for security analysis

## Report Generation

When compromise indicators are detected, the tool generates timestamped reports:

- **Format**: `shai-hulud-report-YYYYMMDD-HHMMSS.md`
- **Location**: Current working directory
- **Content**: Detailed findings, remediation steps, system analysis

## CLI Binary

The project is configured as an npm CLI tool:

- **Binary name**: `shai-hulud-detector`
- **Shebang**: `#!/usr/bin/env node`
- **Entry point**: `./dist/index.js`
- **Minimum Node.js**: 16.0.0

## File Exclusions

The scanner intelligently excludes common directories to improve performance:

- `node_modules`, `.git`, `dist`, `build`
- IDE folders (`.vscode`, `.idea`)
- Cache directories (`.cache`, `.next`, `.nuxt`)
- Log and temporary directories

## Dependencies

### Production Dependencies

- **commander**: CLI argument parsing
- **inquirer**: Interactive prompts
- **chalk**: Terminal coloring
- **ora**: Loading spinners
- **cli-table3**: Formatted tables
- **boxen**: Terminal boxes
- **figlet**: ASCII art banners
- **cli-progress**: Progress bars

### Development Dependencies

- **TypeScript** toolchain with ts-node
- **ESLint** with TypeScript support
- **Jest** testing framework
- **@types/** packages for type definitions

## Development Notes

- The project structure follows a modular approach with clear separation of concerns
- All user-facing text is in French as per the project's target audience
- Rich CLI experience with extensive use of colors, emojis, and formatting
- Comprehensive error handling with graceful degradation
- Performance-optimized scanning with depth limits and directory exclusions

## Git & Version Control

### Branching Model: GitHub Flow

- **Base**: `main` branch - always deployable
- **Workflow**: Create short-lived branch from `main` → Push regularly → Open PR early (draft if needed) → Code review → CI green → Merge → Delete
  branch
- **Deploy frequently**: Risky features use feature flags

### Branch Naming Convention

**Patterns**:

- `feat/<scope>-<short-description>`
- `fix/<scope>-<short-description>`
- `chore/<scope>-<short-description>`
- `docs/<scope>-<short-description>`
- `refactor/<scope>-<short-description>`
- `test/<scope>-<short-description>`

**Optional**: Prefix with issue ID → `1234-fix-login-timeout` or `feat/auth-oauth-device-flow-#812`

**Rules**:

- Lowercase only
- Use hyphens `-`
- No accents or spaces
- 50-72 characters max

### Commit Message Standards: Conventional Commits

**Format**: `<type>(<scope>): <summary>`

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`, `build`, `perf`

**Examples**:

- `feat(auth): support OAuth device flow`
- `fix(api): retry on 429 (Fixes #812)`
- `feat!: drop Node 16 (BREAKING CHANGE)`

**Rules**:

- Summary: 50 chars max, imperative mood
- Body: Optional, explain why/how, 72 chars per line
- Footer: Link issues (`Fixes #123`), breaking changes (`BREAKING CHANGE:`)
- **NO Claude Code references** - Never add Claude Code references in commits
- **Keep messages clean** - Only actual commit content
- **Author**: Always use josedacosta <contact@josedacosta.info>

### Git Configuration Required

```bash
git config user.name "josedacosta"
git config user.email "contact@josedacosta.info"
```

### Pull Request Standards

- **Small PRs**: ≤300 lines modified when possible
- **Clear description**: Context → Solution → Tests → Risks/rollbacks
- **Link issues**: Use "Fixes #ID" or "Closes #ID"
- **Include visuals**: Screenshots/GIFs when relevant
- **Use PR template**: See `.github/PULL_REQUEST_TEMPLATE.md`
- **Review quickly**: Respond to feedback promptly
- **Merge strategy**: Squash & merge recommended

### Protected Branch Rules (main)

**Required**:

- Pull request before merging
- At least 1 approval
- Status checks must pass (CI/lint/test/build)
- Branches up to date before merging
- Linear history (no merge commits)
- CODEOWNERS review when applicable

**Optional**:

- Signed commits
- Restrict direct pushes

### Versioning & Releases

- **SemVer**: `vMAJOR.MINOR.PATCH`
- **Tags**: Tag each release
- **CHANGELOG**: Follow Keep a Changelog format
- **Release automation**: Consider semantic-release or release-please

#### Release Process - CRITICAL: Always Do Both

**IMPORTANT**: When creating a release, you MUST always create both:

1. **Git Tag**: `git tag -a vX.X.X -m "Release message"`
2. **GitHub Release**: `gh release create vX.X.X --title "Release vX.X.X" --notes "Release notes"`

**Complete Release Workflow**:

```bash
# 1. Ensure versions are synchronized
yarn run ts-node scripts/version/check-version-consistency.ts

# 2. Verify project quality
yarn verify

# 3. Create git tag
git tag -a vX.X.X -m "Release vX.X.X"

# 4. Push commits and tags
git push && git push --tags

# 5. Create GitHub Release (MANDATORY)
gh release create vX.X.X --title "Release vX.X.X" --notes "Release notes" --generate-notes
```

**Why Both Are Required**:
- **Git Tag** = Version marker in Git history
- **GitHub Release** = Public release page with notes, downloads, and GitHub visibility

Never create just a tag without the corresponding GitHub release!
