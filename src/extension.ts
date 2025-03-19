import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import * as crypto from 'crypto';
import * as yaml from 'js-yaml';
import * as cp from 'child_process';

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const readdirAsync = promisify(fs.readdir);
const mkdirAsync = promisify(fs.mkdir);
const existsAsync = promisify(fs.exists);

interface PackageJson {
    dependencies?: { [key: string]: string };
    [key: string]: any;
}

function extractImports(content: string, extension: string): string[] {
    const imports: string[] = [];
    const lines = content.split('\n');
    switch (extension.toLowerCase()) {
        case '.js': case '.ts': case '.jsx': case '.tsx':
            lines.forEach(line => {
                if (line.match(/import.*from\s*['"].*['"]/)) imports.push(line.trim());
                else if (line.match(/require\(['"].*['"]\)/)) imports.push(line.trim());
            });
            break;
        case '.py':
            lines.forEach(line => {
                if (line.match(/^\s*(import\s+[\w.]+|from\s+[\w.]+\s+import)/)) imports.push(line.trim());
            });
            break;
        case '.java':
            lines.forEach(line => {
                if (line.match(/^\s*import\s+[\w.]+(\.\*|\w+);/)) imports.push(line.trim());
            });
            break;
        case '.cpp': case '.c': case '.h': case '.hpp':
            lines.forEach(line => {
                if (line.match(/^\s*#include\s+["<][^">]+[">]/)) imports.push(line.trim());
            });
            break;
        case '.rb':
            lines.forEach(line => {
                if (line.match(/^\s*require\s+['"].*['"]/)) imports.push(line.trim());
            });
            break;
        case '.go':
            let inImportBlock = false;
            lines.forEach(line => {
                if (line.match(/^\s*import\s*\(/)) inImportBlock = true;
                else if (line.match(/^\s*\)/) && inImportBlock) inImportBlock = false;
                else if ((inImportBlock || line.match(/^\s*import\s+["']/)) && line.match(/["'].*["']/)) imports.push(line.trim());
            });
            break;
        case '.rs':
            lines.forEach(line => {
                if (line.match(/^\s*use\s+[\w:]+(\s*::\s*\w+)*;/)) imports.push(line.trim());
            });
            break;
        case '.php':
            lines.forEach(line => {
                if (line.match(/^\s*use\s+[\w\\]+(\s+as\s+\w+)?;/) || line.match(/^\s*(require|include)(_once)?\s+['"].*['"]/)) imports.push(line.trim());
            });
            break;
        case '.cs':
            lines.forEach(line => {
                if (line.match(/^\s*using\s+[\w.]+;/)) imports.push(line.trim());
            });
            break;
        case '.html':
            lines.forEach(line => {
                if (line.match(/<script\s+.*src=['"].*['"]>/)) imports.push(line.trim());
                else if (line.match(/<link\s+.*href=['"].*['"].*rel=['"]stylesheet['"]>/)) imports.push(line.trim());
            });
            break;
        case '.css':
            lines.forEach(line => {
                if (line.match(/^\s*@import\s+['"].*['"];/)) imports.push(line.trim());
            });
            break;
        default:
            lines.forEach(line => {
                if (line.match(/^\s*(import|require|use|include|#include)\s+['"<]?[\w./:-]+['">]?/)) imports.push(line.trim());
            });
            break;
    }
    return imports;
}

export function activate(context: vscode.ExtensionContext) {
    console.log('Yamify extension activated');
    if (!context.globalState.get('yamifyWelcomeShown')) {
        vscode.window.showInformationMessage('Welcome to Yamify! Exact code formatting preserved');
        context.globalState.update('yamifyWelcomeShown', true);
    }

    let exportDisposable = vscode.commands.registerCommand('yamify.convertToYaml', async () => {
        console.log('Exporting codebase');
        const config = vscode.workspace.getConfiguration('yamify');
        const exportMode = config.get<string>('exportMode', 'Non-Encrypted Format');
        const outputFormat = config.get<string>('outputFormat', 'yaml');
        const preserveNewlines = config.get<boolean>('preserveNewlines', false);
        const workspaceFolders = vscode.workspace.workspaceFolders;
        let outputPath: string;

        try {
            if (!workspaceFolders) {
                vscode.window.showErrorMessage('No workspace open');
                return;
            }
            const rootPath = workspaceFolders[0].uri.fsPath;
            outputPath = path.join(rootPath, `codebase.${outputFormat}`);

            if (exportMode === 'Non-Encrypted Format') {
                await convertFullCode(rootPath, outputPath, outputFormat, preserveNewlines);
            } else if (exportMode === 'Encrypted Format') {
                const key = await vscode.window.showInputBox({
                    prompt: 'Enter encryption key (min 8 chars, remember this)',
                    password: true,
                    validateInput: (value) => value.length < 8 ? 'Key must be 8+ chars' : null
                });
                if (!key) return;
                await convertModulesAndOverlay(rootPath, outputPath, outputFormat, key, preserveNewlines);
            }

            vscode.window.showInformationMessage(`Exported to ${outputPath}`);
            const doc = await vscode.workspace.openTextDocument(outputPath);
            await vscode.window.showTextDocument(doc);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Export failed: ${error.message}`);
        }
    });

    let exportSettingsOnlyDisposable = vscode.commands.registerCommand('yamify.exportSettingsOnly', async () => {
        console.log('Exporting settings');
        const config = vscode.workspace.getConfiguration('yamify');
        const outputFormat = config.get<string>('outputFormat', 'yaml');

        try {
            const fileUri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`vscode-settings.${outputFormat}`),
                filters: { 'Configuration': [outputFormat] }
            });
            if (!fileUri) return;

            await exportSettingsToFile(fileUri.fsPath, outputFormat);
            vscode.window.showInformationMessage(`Settings exported to ${fileUri.fsPath}`);
            const doc = await vscode.workspace.openTextDocument(fileUri.fsPath);
            await vscode.window.showTextDocument(doc);
        } catch (error: any) {
            vscode.window.showErrorMessage(`Settings export failed: ${error.message}`);
        }
    });

    let importDisposable = vscode.commands.registerCommand('yamify.importFromYaml', async () => {
        console.log('Importing file');
        const fileUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            filters: { 'Configuration': ['yaml', 'yml', 'json'] }
        });
        if (!fileUri || !fileUri[0]) return;

        try {
            const content = await readFileAsync(fileUri[0].fsPath, 'utf8');
            const data = fileUri[0].fsPath.endsWith('.json') ? JSON.parse(content) : yaml.load(content);

            if (!data.metadata || data.metadata.generator !== 'yamify') {
                vscode.window.showErrorMessage('Invalid Yamify file');
                return;
            }

            const workspaceFolders = vscode.workspace.workspaceFolders;
            const rootPath = workspaceFolders?.[0].uri.fsPath;
            let key: string | undefined;

            if (data.metadata.signature) {
                if (data.metadata.mode === 'Encrypted Format') {
                    while (true) {
                        key = await vscode.window.showInputBox({
                            prompt: 'Enter decryption key',
                            password: true
                        });
                        if (!key) return;
                        if (verifySignature(data, content, key) && verifyKey(data, key)) break;
                        const retry = await vscode.window.showErrorMessage('Wrong key or file corrupted', 'Try Again');
                        if (retry !== 'Try Again') return;
                    }
                } else {
                    if (!verifySignature(data, content, '')) {
                        vscode.window.showErrorMessage('File verification failed');
                        return;
                    }
                }
            }

            if (data.files) {
                if (!rootPath) {
                    vscode.window.showErrorMessage('Open a workspace to import');
                    return;
                }
                const options = await vscode.window.showQuickPick(
                    [{ label: 'Codebase Only', value: 'codebase' }],
                    { placeHolder: 'Select import type' }
                );
                if (!options) return;

                await importCodebase(data.files, rootPath, data.metadata.mode === 'Encrypted Format' ? key : undefined);
                if (data.requirements) await handleRequirements(data.requirements, rootPath);
            } else if (data.settings) {
                const options = await vscode.window.showQuickPick(
                    [
                        { label: 'Settings Only', value: 'settings' },
                        { label: 'Extensions Only', value: 'extensions' }
                    ],
                    { placeHolder: 'Select settings import type' }
                );
                if (!options) return;

                if (options.value === 'settings') {
                    await importSettings(data.settings);
                } else if (options.value === 'extensions' && data.settings.extensions) {
                    await installExtensions(data.settings.extensions);
                }
            }

            vscode.window.showInformationMessage('Import completed');
        } catch (error: any) {
            vscode.window.showErrorMessage(`Import failed: ${error.message}`);
        }
    });

    const treeDataProvider = new YamifyTreeProvider();
    console.log('Setting up activity bar');
    vscode.window.createTreeView('yamifyActivityView', { treeDataProvider });
    console.log('Activity bar ready');

    context.subscriptions.push(exportDisposable, exportSettingsOnlyDisposable, importDisposable);
    console.log('Commands registered');
}

async function convertFullCode(rootPath: string, outputPath: string, format: string, preserveNewlines: boolean) {
    const files = await getWorkspaceFiles();
    const requirements = await collectRequirements(files);
    const output: { 
        metadata: { 
            created: string; 
            fileCount: number; 
            mode: string; 
            generator: string;
            signature: string;
        }; 
        files: { [key: string]: string }; 
        requirements?: any 
    } = { 
        metadata: { 
            created: new Date().toISOString(), 
            fileCount: files.length, 
            mode: 'Non-Encrypted Format',
            generator: 'yamify',
            signature: ''
        }, 
        files: {} 
    };

    for (const file of files) {
        const relativePath = path.relative(rootPath, file.fsPath);
        const content = await readFileAsync(file.fsPath, 'utf8');
        // In default mode, preserve exact content as a single string; in preserveNewlines, escape and minimize
        output.files[relativePath] = preserveNewlines 
            ? content.replace(/\n/g, '\\n').replace(/\t/g, '\\t').replace(/\r/g, '\\r')
            : content;
    }

    if (Object.keys(requirements).length > 0) {
        output.requirements = requirements;
    }

    const contentWithoutSignature = JSON.stringify({ ...output, metadata: { ...output.metadata, signature: undefined } });
    output.metadata.signature = crypto.createHash('sha256').update(contentWithoutSignature).digest('hex');

    const finalContent = format === 'yaml'
        ? yaml.dump(output, { 
            lineWidth: preserveNewlines ? 80 : -1, // Limit to ~3-4 lines when preserving newlines
            noRefs: true,
            styles: { '!!str': preserveNewlines ? 'plain' : 'literal' } // Use literal style for exact preservation
        })
        : JSON.stringify(output, null, preserveNewlines ? 0 : 2);

    await writeFileAsync(outputPath, finalContent);
}

async function convertModulesAndOverlay(rootPath: string, outputPath: string, format: string, key: string, preserveNewlines: boolean) {
    const files = await getWorkspaceFiles();
    const requirements = await collectRequirements(files);
    const output: { 
        metadata: { 
            created: string; 
            fileCount: number; 
            mode: string; 
            generator: string;
            keySignature: string;
            signature: string;
        }; 
        files: { [key: string]: any }; 
        requirements?: any 
    } = { 
        metadata: { 
            created: new Date().toISOString(), 
            fileCount: files.length, 
            mode: 'Encrypted Format',
            generator: 'yamify',
            keySignature: crypto.createHmac('sha256', key).update('yamify-verification').digest('hex'),
            signature: ''
        }, 
        files: {} 
    };

    for (const file of files) {
        const relativePath = path.relative(rootPath, file.fsPath);
        const content = await readFileAsync(file.fsPath, 'utf8');
        const processedContent = preserveNewlines
            ? content.replace(/\n/g, '\\n').replace(/\t/g, '\\t').replace(/\r/g, '\\r')
            : content.replace(/\n/g, '').replace(/\t/g, '').replace(/\r/g, ''); // Single line for encryption
        const encryptedContent = encryptContent(processedContent, key);
        const imports = extractImports(content, path.extname(file.fsPath));
        output.files[relativePath] = { content: encryptedContent, imports };
    }

    if (Object.keys(requirements).length > 0) {
        output.requirements = requirements;
    }

    const contentWithoutSignature = JSON.stringify({ ...output, metadata: { ...output.metadata, signature: undefined } });
    output.metadata.signature = crypto.createHmac('sha256', key).update(contentWithoutSignature).digest('hex');

    const finalContent = format === 'yaml'
        ? yaml.dump(output, { lineWidth: 80, noRefs: true, styles: { '!!str': 'plain' } }) // Single-line for encrypted
        : JSON.stringify(output, null, 0);

    await writeFileAsync(outputPath, finalContent);
}

function encryptContent(content: string, key: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', crypto.createHash('sha256').update(key).digest(), iv);
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptContent(encrypted: string, key: string): string {
    const [ivHex, encryptedHex] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update(key).digest(), iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function verifyKey(data: any, key: string): boolean {
    const expectedKeySignature = crypto.createHmac('sha256', key).update('yamify-verification').digest('hex');
    return data.metadata.keySignature === expectedKeySignature;
}

function verifySignature(data: any, content: string, key: string): boolean {
    const contentWithoutSignature = JSON.stringify({ ...data, metadata: { ...data.metadata, signature: undefined } });
    const expectedSignature = data.metadata.mode === 'Encrypted Format'
        ? crypto.createHmac('sha256', key).update(contentWithoutSignature).digest('hex')
        : crypto.createHash('sha256').update(contentWithoutSignature).digest('hex');
    return data.metadata.signature === expectedSignature;
}

async function exportSettingsToFile(outputPath: string, format: string) {
    const settingsData = await getCompleteSettings();
    const output = { 
        metadata: { 
            created: new Date().toISOString(), 
            generator: 'yamify',
            signature: ''
        }, 
        settings: settingsData 
    };
    const contentWithoutSignature = JSON.stringify({ ...output, metadata: { ...output.metadata, signature: undefined } });
    output.metadata.signature = crypto.createHash('sha256').update(contentWithoutSignature).digest('hex');
    const finalContent = format === 'yaml'
        ? yaml.dump(output, { lineWidth: -1, noRefs: true })
        : JSON.stringify(output, null, 2);
    await writeFileAsync(outputPath, finalContent);
}

async function getWorkspaceFiles(): Promise<vscode.Uri[]> {
    const includePatterns = [
        '**/*.ts', '**/*.js', '**/*.py', '**/*.java', '**/*.cpp', '**/*.c', '**/*.rb', '**/*.go',
        '**/*.rs', '**/*.php', '**/*.cs', '**/*.html', '**/*.css', '**/*.jsx', '**/*.tsx'
    ];
    const excludePatterns = [
        '**/node_modules/**', '**/dist/**', '**/build/**', '**/out/**', '**/target/**', '**/bin/**',
        '**/obj/**', '**/lib/**', '**/output/**', '**/release/**', '**/debug/**', '**/.git/**',
        '**/.svn/**', '**/.hg/**', '**/.vs/**', '**/.vscode/**', '**/.idea/**', '**/.fleet/**',
        '**/.eclipse/**', '**/.settings/**', '**/.project/**', '**/.classpath/**', '**/.metadata/**',
        '**/.cache/**', '**/__pycache__/**', '**/.pytest_cache/**', '**/.mypy_cache/**', '**/.nyc_output/**',
        '**/coverage/**', '**/vendor/**', '**/venv/**', '**/.env/**', '**/env/**', '**/packages/**',
        '**/bower_components/**', '**/jspm_packages/**', '**/compiled/**', '**/generated/**', '**/autogen/**',
        '**/auto-generated/**', '**/*.min.js', '**/*.min.css', '**/logs/**', '**/tmp/**', '**/temp/**',
        '**/.next/**', '**/docs/**', '**/documentation/**'
    ];
    return await vscode.workspace.findFiles(`{${includePatterns.join(',')}}`, `{${excludePatterns.join(',')}}`);
}

async function getCompleteSettings(): Promise<any> {
    const settings: any = {};
    const configDir = process.env.APPDATA
        ? path.join(process.env.APPDATA, 'Code', 'User')
        : path.join(process.env.HOME || '~', '.config', 'Code', 'User');
    const settingsPath = path.join(configDir, 'settings.json');
    if (fs.existsSync(settingsPath)) settings.settings = JSON.parse(await readFileAsync(settingsPath, 'utf8'));
    const keybindingsPath = path.join(configDir, 'keybindings.json');
    if (fs.existsSync(keybindingsPath)) settings.keybindings = JSON.parse(await readFileAsync(keybindingsPath, 'utf8'));
    const snippetsDir = path.join(configDir, 'snippets');
    if (fs.existsSync(snippetsDir)) {
        const snippetFiles = await readdirAsync(snippetsDir);
        settings.snippets = {};
        for (const file of snippetFiles) {
            if (file.endsWith('.json')) {
                settings.snippets[file] = JSON.parse(await readFileAsync(path.join(snippetsDir, file), 'utf8'));
            }
        }
    }
    if (vscode.workspace.workspaceFolders) {
        const workspaceFolder = vscode.workspace.workspaceFolders[0];
        const vscodeFolder = path.join(workspaceFolder.uri.fsPath, '.vscode');
        if (fs.existsSync(vscodeFolder)) {
            settings.workspace = {};
            const tasksPath = path.join(vscodeFolder, 'tasks.json');
            if (fs.existsSync(tasksPath)) settings.workspace.tasks = JSON.parse(await readFileAsync(tasksPath, 'utf8'));
            const launchPath = path.join(vscodeFolder, 'launch.json');
            if (fs.existsSync(launchPath)) settings.workspace.launch = JSON.parse(await readFileAsync(launchPath, 'utf8'));
        }
    }
    settings.extensions = await getInstalledExtensions();
    return settings;
}

async function getInstalledExtensions(): Promise<string[]> {
    return new Promise((resolve) => {
        const command = process.platform === 'win32' ? 'code.cmd --list-extensions' : 'code --list-extensions';
        cp.exec(command, (error, stdout) => {
            if (error) {
                const extensions = vscode.extensions.all
                    .filter(ext => !ext.packageJSON.isBuiltin)
                    .map(ext => `${ext.packageJSON.publisher}.${ext.packageJSON.name}`);
                resolve(extensions);
                return;
            }
            resolve(stdout.trim().split('\n'));
        });
    });
}

async function installExtensions(extensions: string[]): Promise<void> {
    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Installing extensions',
        cancellable: true
    }, async (progress, token) => {
        const total = extensions.length;
        let installed = 0;
        for (const ext of extensions) {
            if (token.isCancellationRequested) break;
            try {
                if (!vscode.extensions.getExtension(ext)) {
                    const command = process.platform === 'win32'
                        ? `code.cmd --install-extension ${ext}`
                        : `code --install-extension ${ext}`;
                    await new Promise<void>((resolve) => {
                        cp.exec(command, (error) => {
                            if (error) vscode.window.showWarningMessage(`Failed to install ${ext}`);
                            resolve();
                        });
                    });
                }
                installed++;
                progress.report({ message: `${installed}/${total}: ${ext}`, increment: (1 / total) * 100 });
            } catch (error) {
                vscode.window.showWarningMessage(`Extension ${ext} install failed`);
            }
        }
    });
}

async function importSettings(settingsData: any) {
    const configDir = process.env.APPDATA
        ? path.join(process.env.APPDATA, 'Code', 'User')
        : path.join(process.env.HOME || '~', '.config', 'Code', 'User');
    if (!await existsAsync(configDir)) await mkdirAsync(configDir, { recursive: true });
    if (settingsData.settings) {
        await writeFileAsync(path.join(configDir, 'settings.json'), JSON.stringify(settingsData.settings, null, 2));
    }
    if (settingsData.keybindings) {
        await writeFileAsync(path.join(configDir, 'keybindings.json'), JSON.stringify(settingsData.keybindings, null, 2));
    }
    if (settingsData.snippets) {
        const snippetsDir = path.join(configDir, 'snippets');
        if (!await existsAsync(snippetsDir)) await mkdirAsync(snippetsDir, { recursive: true });
        for (const [fileName, content] of Object.entries(settingsData.snippets)) {
            await writeFileAsync(path.join(snippetsDir, fileName), JSON.stringify(content as any, null, 2));
        }
    }
    if (settingsData.workspace && vscode.workspace.workspaceFolders) {
        const workspaceFolder = vscode.workspace.workspaceFolders[0];
        const vscodeFolder = path.join(workspaceFolder.uri.fsPath, '.vscode');
        if (!await existsAsync(vscodeFolder)) await mkdirAsync(vscodeFolder, { recursive: true });
        if (settingsData.workspace.tasks) {
            await writeFileAsync(path.join(vscodeFolder, 'tasks.json'), JSON.stringify(settingsData.workspace.tasks, null, 2));
        }
        if (settingsData.workspace.launch) {
            await writeFileAsync(path.join(vscodeFolder, 'launch.json'), JSON.stringify(settingsData.workspace.launch, null, 2));
        }
    }
    const reload = await vscode.window.showInformationMessage('Settings imported. Reload?', 'Reload', 'Later');
    if (reload === 'Reload') vscode.commands.executeCommand('workbench.action.reloadWindow');
}

async function importCodebase(files: { [key: string]: any }, rootPath: string, key?: string) {
    for (const [relativePath, fileData] of Object.entries(files)) {
        const fullPath = path.join(rootPath, relativePath);
        const dir = path.dirname(fullPath);
        if (!await existsAsync(dir)) await mkdirAsync(dir, { recursive: true });
        let content: string;
        if (typeof fileData === 'string') {
            content = fileData.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r');
        } else if (key && fileData.content) {
            content = decryptContent(fileData.content, key).replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r');
        } else {
            continue;
        }
        await writeFileAsync(fullPath, content);
    }
    vscode.window.showInformationMessage(`Codebase imported to ${rootPath}`);
}

async function collectRequirements(files: vscode.Uri[]): Promise<any> {
    const requirements: any = {};
    for (const file of files) {
        const content = await readFileAsync(file.fsPath, 'utf8');
        const ext = path.extname(file.fsPath).toLowerCase();
        const imports = extractImports(content, ext);
        switch (ext) {
            case '.js': case '.ts': case '.jsx': case '.tsx':
                requirements.npm = requirements.npm || [];
                imports.forEach((imp: string) => {
                    const match = imp.match(/from\s+['"]([^'"]+)['"]/);
                    if (match && !match[1].startsWith('.') && !match[1].startsWith('/')) requirements.npm.push(match[1]);
                });
                break;
            case '.py':
                requirements.pip = requirements.pip || [];
                imports.forEach((imp: string) => {
                    const match = imp.match(/^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/);
                    if (match) {
                        const module = match[1] || match[2];
                        if (module && !module.includes('.')) requirements.pip.push(module);
                    }
                });
                break;
            case '.go':
                requirements.go = requirements.go || [];
                imports.forEach((imp: string) => {
                    const match = imp.match(/["']([^"']+)["']/);
                    if (match) requirements.go.push(match[1]);
                });
                break;
            case '.rb':
                requirements.gem = requirements.gem || [];
                imports.forEach((imp: string) => {
                    const match = imp.match(/['"]([^'"]+)['"]/);
                    if (match) requirements.gem.push(match[1]);
                });
                break;
        }
    }
    for (const key in requirements) {
        requirements[key] = [...new Set(requirements[key])];
    }
    return requirements;
}

async function handleRequirements(requirements: any, rootPath: string) {
    let instructions = 'Required dependencies:\n';
    if (requirements.npm) {
        instructions += `\nNPM (run in ${rootPath}):\nnpm install ${requirements.npm.join(' ')}\n`;
        const packageJsonPath = path.join(rootPath, 'package.json');
        let packageJson: PackageJson = {};
        if (await existsAsync(packageJsonPath)) packageJson = JSON.parse(await readFileAsync(packageJsonPath, 'utf8'));
        packageJson.dependencies = packageJson.dependencies || {};
        requirements.npm.forEach((dep: string) => packageJson.dependencies![dep] = 'latest');
        await writeFileAsync(packageJsonPath, JSON.stringify(packageJson, null, 2));
    }
    if (requirements.pip) instructions += `\nPython:\npip install ${requirements.pip.join(' ')}\n`;
    if (requirements.go) instructions += `\nGo (run in ${rootPath}):\n${requirements.go.map((mod: string) => `go get ${mod}`).join('\n')}\n`;
    if (requirements.gem) instructions += `\nRuby:\ngem install ${requirements.gem.join(' ')}\n`;
    if (instructions !== 'Required dependencies:\n') {
        await vscode.window.showInformationMessage(instructions, 'Copy')
            .then(choice => { if (choice === 'Copy') vscode.env.clipboard.writeText(instructions); });
    }
}

class YamifyTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null> = new vscode.EventEmitter<vscode.TreeItem | undefined | null>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null> = this._onDidChangeTreeData.event;

    refresh(): void { this._onDidChangeTreeData.fire(null); }
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem { return element; }

    getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
        if (element) return Promise.resolve([]);
        const fullConvertItem = new vscode.TreeItem('Export Codebase', vscode.TreeItemCollapsibleState.None);
        fullConvertItem.command = { command: 'yamify.convertToYaml', title: 'Export Codebase' };
        fullConvertItem.tooltip = 'Export with exact formatting';
        fullConvertItem.iconPath = new vscode.ThemeIcon('archive');

        const exportSettingsItem = new vscode.TreeItem('Export Settings', vscode.TreeItemCollapsibleState.None);
        exportSettingsItem.command = { command: 'yamify.exportSettingsOnly', title: 'Export Settings' };
        exportSettingsItem.tooltip = 'Export VS Code settings';
        exportSettingsItem.iconPath = new vscode.ThemeIcon('settings-gear');

        const importItem = new vscode.TreeItem('Import Code/Settings', vscode.TreeItemCollapsibleState.None);
        importItem.command = { command: 'yamify.importFromYaml', title: 'Import' };
        importItem.tooltip = 'Import with original formatting';
        importItem.iconPath = new vscode.ThemeIcon('cloud-download');

        const changeSettingsItem = new vscode.TreeItem('Settings', vscode.TreeItemCollapsibleState.None);
        changeSettingsItem.command = { command: 'workbench.action.openSettings', title: 'Open Settings', arguments: ['yamify'] };
        changeSettingsItem.tooltip = 'Configure Yamify options';
        changeSettingsItem.iconPath = new vscode.ThemeIcon('gear');

        const githubItem = new vscode.TreeItem('GitHub', vscode.TreeItemCollapsibleState.None);
        githubItem.command = { command: 'vscode.open', title: 'Visit GitHub', arguments: [vscode.Uri.parse('https://github.com/rkeshri04/Yamify-VSCodeExtension')] };
        githubItem.tooltip = 'View Yamify repo';
        githubItem.iconPath = new vscode.ThemeIcon('github');

        return Promise.resolve([fullConvertItem, exportSettingsItem, importItem, changeSettingsItem, githubItem]);
    }
}

export function deactivate() {}