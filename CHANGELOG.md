# Changelog

## v1.3 (2025-09-18)

### Changed
- **Performance Refactoring:** The server has been fundamentally refactored to use `bloodyAD` as a direct Python library instead of spawning a new subprocess for each command.
  - This eliminates significant overhead, resulting in much faster command execution, especially for rapid or sequential operations.
  - Reduces overall CPU and memory usage of the server.
