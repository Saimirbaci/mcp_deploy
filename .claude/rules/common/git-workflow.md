# Git Workflow

## Branch Naming
- Use descriptive lowercase names with hyphens: `feature/ssh-key-handling`, `fix/ip-whitelist-error`
- Prefix with type: `feature/`, `fix/`, `refactor/`, `docs/`

## Commit Messages
- Use imperative mood: "Add IP whitelist validation" not "Added..."
- First line: max 72 characters, describe what changed
- Body: explain why (motivation, problem solved) when not obvious
- Reference issues/tickets when applicable

## Process
1. Create feature branch from `master`
2. Write code following coding style rules
3. Run `cargo clippy --fix` and `cargo fmt` before committing
4. Ensure tests pass: `cargo test`
5. Commit with clear message describing intent
6. Open PR for review; describe changes and any security considerations

## Before Merging
- All CI checks pass (if enabled)
- No clippy warnings or formatting issues
- Tests cover new functionality
- Documentation updated if CLI or config format changed

## Security-Sensitive Changes
- Any changes to SSH key handling, credential storage, or IP validation require extra scrutiny
- Document security implications in PR description
- Ensure no private keys are logged or exposed in error messages