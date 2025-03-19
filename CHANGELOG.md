# Change Log

All notable changes to the "Yamify" extension will be documented in this file.

## [1.1.0] - 2025-03-19

- **Added**: Exact formatting preservation in default non-encrypted mode using YAML literal style (`|`) to maintain original code structure without unwanted line splitting.
- **Added**: `preserveNewlines` option to escape newlines (`\n`), tabs (`\t`), and carriage returns (`\r`) into a concise 3-4 line output in YAML/JSON when enabled.
- **Added**: Single-line output for encrypted mode, with optional newline escaping when `preserveNewlines` is enabled.
- **Improved**: Import logic to restore exact original formatting across all modes by correctly handling escaped characters only when present.
- **Fixed**: YAML output in non-encrypted mode to prevent unnecessary line splitting, ensuring code blocks remain intact as in the source files.

## [1.0.0] - 2025-03-17

- Initial release of Yamify extension with basic codebase export/import functionality.
- Support for exporting full codebase or settings to YAML/JSON.
- Basic encryption support for secure code export.
- Import capabilities for codebases and VS Code settings/extensions.
- Activity bar integration with commands for export/import operations.