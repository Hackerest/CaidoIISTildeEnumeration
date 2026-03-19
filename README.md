# IIS Tilde Enumeration for Caido

IIS Tilde Enumeration is a [Caido](https://caido.io/) plugin for detecting and enumerating IIS 8.3 shortnames using differential tilde probes.

Maintained by [Hackerest](https://hackerest.com/).

## Overview

This plugin is built for security testing workflows where you want to:

- detect whether an IIS target is vulnerable to 8.3 shortname disclosure
- run shortname bruteforce directly from Caido
- inspect scan progress while jobs are running
- stop long-running scans without restarting the plugin
- create findings from confirmed evidence

The implementation is inspired by the following research and tooling:

- [PortSwigger IIS Tilde Enumeration Scanner](https://github.com/PortSwigger/iis-tilde-enumeration-scanner)
- [sw33tLie/sns](https://github.com/sw33tLie/sns)

## Features

- Differential detection of IIS shortname exposure
- Optional shortname enumeration after detection
- Concurrent scan execution
- Live progress updates and partial results in the UI
- Early stop for running scans
- Integration with Caido findings

## Install

## From the Caido Plugin Repository

If this plugin is available in the Caido community repository:

1. Open Caido.
2. Go to the plugin manager.
3. Search for `IIS Tilde Enumeration`.
4. Install the plugin and reload it if Caido prompts you to.

## From a Local Package

If you want to install a build produced from this repository:

1. Build the plugin:

```bash
pnpm install
pnpm build
```

2. In Caido, open the plugin manager.
3. Choose the manual or local install option.
4. Select [dist/plugin_package.zip](/home/luca/Progetti/caido-iis-tilde-enumeration/dist/plugin_package.zip).

## Development

## Requirements

- Node.js 20
- pnpm 9
- a local Caido installation

## Run in Development Mode

Install dependencies:

```bash
pnpm install
```

Start the development watcher:

```bash
pnpm watch
```

Then install the plugin in Caido from the development package URL:

`http://localhost:3000/plugin_package.zip`

Keep `pnpm watch` running while developing. Reload the plugin page in Caido after making changes.

## Useful Commands

```bash
pnpm typecheck
pnpm lint:fix
pnpm lint:check
pnpm build
```

## Linting and Formatting

This repository is configured to automatically fix lint and style issues:

- on save in VS Code through [.vscode/settings.json](/home/luca/Progetti/caido-iis-tilde-enumeration/.vscode/settings.json)
- on commit through [.githooks/pre-commit](/home/luca/Progetti/caido-iis-tilde-enumeration/.githooks/pre-commit)
- before push through [.githooks/pre-push](/home/luca/Progetti/caido-iis-tilde-enumeration/.githooks/pre-push)

To ensure the local Git hooks are active:

```bash
pnpm hooks:install
```

The ESLint configuration also rejects `null` as a TypeScript type and expects `undefined` instead.

## Project Structure

- [packages/backend/src/index.ts](/home/luca/Progetti/caido-iis-tilde-enumeration/packages/backend/src/index.ts): scan engine and Caido backend API
- [packages/frontend/src/views/App.vue](/home/luca/Progetti/caido-iis-tilde-enumeration/packages/frontend/src/views/App.vue): plugin UI
- [caido.config.ts](/home/luca/Progetti/caido-iis-tilde-enumeration/caido.config.ts): plugin metadata and build configuration

## Future Development

- Add a background detection module that passively checks targets for IIS 8.3 shortname exposure without launching full enumeration, and automatically creates a finding when the issue is identified.

## Contributing

Contributions are welcome from researchers, plugin developers, and testers.

## Reporting Issues

Please open an issue when you find:

- detection false positives or false negatives
- bruteforce results that differ from expected IIS behavior
- UI or background job issues in Caido
- packaging, signing, or release problems

When creating an issue, include:

- Caido version
- plugin version
- target behavior you expected
- actual behavior you observed
- relevant logs, screenshots, or reproduction steps

## Submitting Pull Requests

1. Fork the repository and create a topic branch.
2. Make focused changes with clear commit messages.
3. Run the local checks before opening the PR:

```bash
pnpm lint:check
pnpm typecheck
pnpm build
```

4. Open a pull request with a concise explanation of:

- what changed
- why the change is needed
- how it was tested

Small, targeted pull requests are preferred over large unrelated changes.

## Security Notes

This plugin is intended for authorized security testing only. You are responsible for ensuring that your use complies with applicable laws, contracts, and scope restrictions.

## Maintainer

Maintained by [Hackerest](https://hackerest.com/).
