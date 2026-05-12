# Coding Style

## General Principles
- Write clear, self-documenting code with descriptive names
- Prefer explicit over implicit; avoid clever one-liners that obscure intent
- Keep functions small and focused on a single responsibility
- Handle errors explicitly with meaningful error messages
- Add inline comments only when intent or non-obvious behavior needs clarification

## Project Conventions
- 4-space indentation for Rust code
- Snake case for variables, functions, and modules (`snake_case`)
- Pascal case for types and enums (`PascalCase`)
- Prefix private fields with underscore in structs (`_field_name`)
- Use `Result` types for fallible operations; avoid `unwrap()` in production code
- Group imports by external, internal, local (`std`, crate, super, self)
- Maximum line length: 100 characters
- Keep trait bounds on separate lines when they exceed line length

## Error Handling
- Always use `anyhow::Result<T>` or custom error types for public APIs
- Propagate errors with `?` operator; avoid `unwrap()` and `expect()` except in tests
- Create descriptive error messages that include context (file paths, IPs, etc.)
- Wrap errors at boundaries to provide meaningful context for the user

## Documentation
- Document public APIs with doc comments (`///`)
- Include usage examples in complex public functions
- Document security implications where relevant (SSH handling, IP validation)
- Keep README updated when CLI interface changes