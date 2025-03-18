# Yamify - Codebase and Settings Export/Import Tool for VS Code

Yamify is a powerful Visual Studio Code extension designed to streamline the process of exporting and importing codebases and settings with secure encryption. Whether you're migrating to a new machine, sharing your development environment with a team, or backing up your workspace, Yamify makes it easy to handle everything in a few clicks.

## Features

- **Export Full Codebase**: Export your entire codebase, including all files and dependencies, in either YAML or JSON format.
- **Encrypted Export**: Securely export your codebase with AES-256 encryption, ensuring your sensitive data remains protected.
- **Export Settings Only**: Export your VS Code settings, keybindings, snippets, and installed extensions.
- **Import Codebase**: Import a previously exported codebase, with support for encrypted files.
- **Import Settings**: Import settings, keybindings, snippets, and extensions into your VS Code environment.
- **Dependency Management**: Automatically detect and manage dependencies for various programming languages (Node.js, Python, Go, Ruby, etc.).
- **Workspace Configuration**: Export and import workspace-specific configurations like tasks and launch settings.
- **Tree View Interface**: Easily access all features through a convenient tree view in the VS Code sidebar.
- **Customizable Output**: Choose between YAML or JSON formats for your exports, and configure output modes (full code or modules with overlay).

## Why Use Yamify?

- **Seamless Migration**: Easily move your development environment between machines without losing any configuration.
- **Team Collaboration**: Share your development environment with your team, ensuring everyone is on the same page.
- **Backup and Restore**: Create backups of your codebase and settings, and restore them with ease.
- **Secure Sharing**: Encrypt your codebase for secure sharing, ensuring that only authorized users can access it.
- **Dependency Management**: Automatically detect and manage dependencies, making it easier to set up new environments.

## Installation

1. Open Visual Studio Code.
2. Go to the Extensions view by clicking on the Extensions icon in the Activity Bar on the side of the window or by pressing `Ctrl+Shift+X`.
3. Search for "Yamify".
4. Click the Install button.

## Usage

### Exporting Codebase

1. Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P` on macOS).
2. Type `Yamify: Convert to YAML` and select it.
3. Choose your desired output mode (full code or modules with overlay) and format (YAML or JSON).
4. If you choose the encrypted mode, enter a secure key.
5. The codebase will be exported to a file in your workspace root.

### Exporting Settings

1. Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P` on macOS).
2. Type `Yamify: Export Settings Only` and select it.
3. Choose your desired format (YAML or JSON).
4. The settings will be exported to a file of your choice.

### Importing Codebase

1. Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P` on macOS).
2. Type `Yamify: Import from YAML` and select it.
3. Select the file you wish to import.
4. If the file is encrypted, enter the key used during export.
5. The codebase will be imported into your workspace.

### Importing Settings

1. Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P` on macOS).
2. Type `Yamify: Import from YAML` and select it.
3. Select the file you wish to import.
4. Choose whether to import settings, extensions, or both.
5. The settings will be imported into your VS Code environment.

## Configuration

Yamify can be configured through the VS Code settings:

1. Open the Settings view (`Ctrl+,` or `Cmd+,` on macOS).
2. Search for "Yamify".
3. Adjust the settings as needed, such as default output format and mode.

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) for more information on how to get started.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have any questions, please [open an issue](https://github.com/rkeshri04/Yamify-VSCodeExtension/issues) on GitHub.

---

**Yamify** - Simplify your development environment management with ease and security.