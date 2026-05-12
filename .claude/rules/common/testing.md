# Testing

## Running Tests
```bash
cargo test          # Run all unit and integration tests
cargo clippy        # Check for common mistakes and style issues
```

## Test Requirements
- All tests must pass before committing (CI if enabled)
- Add tests for new functionality, especially edge cases
- Use descriptive test names that explain the scenario being tested
- Mock external dependencies (SSH, file I/O) appropriately

## Test Organization
- Unit tests: co-located in same file, in `#[cfg(test)]` module
- Integration tests: in `tests/` directory
- Place tests near the code they test (prefer internal over external modules)

## Test Naming Convention
Use descriptive names: `test_ssh_connection_fails_with_invalid_key` rather than `test_1`

## Coverage Considerations
- Focus on correctness of IP whitelisting logic
- Verify error messages don't expose sensitive data (key paths, actual IPs)
- Test configuration loading and validation
- Test both success and failure paths for SSH execution