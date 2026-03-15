# Contributing to CipherBlock

Thanks for your interest in contributing! Here's how to get started.

## Development Environment

### Prerequisites

- Node.js 18+
- npm

### Setup

```bash
git clone https://github.com/your-org/logseq-cipherblock.git
cd logseq-cipherblock
npm install
```

### Build

```bash
npm run build
```

### Run Tests

```bash
npm run test
```

Tests use [Vitest](https://vitest.dev/) as the test runner and [fast-check](https://fast-check.dev/) for property-based tests.

### Watch Mode

```bash
npm run dev          # rebuild on file changes
npm run test:watch   # re-run tests on file changes
```

## Coding Standards

- **TypeScript strict mode** — all code must pass `tsc --noEmit` with strict checks enabled
- **Tests required** — new functionality must include Vitest unit tests; core logic should also have fast-check property-based tests
- **Modular architecture** — keep concerns separated (key management, crypto, UI, Logseq API integration)
- **Typed interfaces** — all module boundaries use TypeScript interfaces defined in `src/interfaces.ts`

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`
2. **Implement** your changes with tests
3. **Verify** all tests pass: `npm run test`
4. **Lint/type-check** your code: `npx tsc --noEmit`
5. **Submit** a pull request against `main` with a clear description of the change

### PR Checklist

- [ ] Tests added or updated for the change
- [ ] All existing tests pass
- [ ] TypeScript compiles without errors
- [ ] Documentation updated if applicable
