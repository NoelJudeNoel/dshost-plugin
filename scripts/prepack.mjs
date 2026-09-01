// Prepack build for the dsh-remote plugin package.
//
// The plugin and the standalone agent share one engine (src/agent/core.js).
// npm packages cannot reference files outside the package directory, so this
// script materializes self-contained copies inside the package at pack time:
//   lib/core.js     <- src/agent/core.js     (import rewritten to ./protocol.js)
//   lib/protocol.js <- src/common/protocol.js
// Run automatically via `npm pack` / `npm publish` (package.json "prepack").
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(here, '..');
const repoRoot = path.resolve(pkgRoot, '..', '..');

// Source resolution is layout-aware so one script serves both checkouts:
//  · GitHub standalone repo (dshost-plugin): repo root == package root, with
//    agent/core.js and common/protocol.js beside the package.
//  · dshost monorepo (/root/dshost): sources live under src/.
const coreSrc = fs.existsSync(path.join(pkgRoot, 'agent', 'core.js'))
  ? path.join(pkgRoot, 'agent', 'core.js')
  : path.join(repoRoot, 'src', 'agent', 'core.js');
const protocolSrc = fs.existsSync(path.join(pkgRoot, 'common', 'protocol.js'))
  ? path.join(pkgRoot, 'common', 'protocol.js')
  : path.join(repoRoot, 'src', 'common', 'protocol.js');
const coreDest = path.join(pkgRoot, 'lib', 'core.js');
const protocolDest = path.join(pkgRoot, 'lib', 'protocol.js');

let core = fs.readFileSync(coreSrc, 'utf8');
// Keep the import inside the package after copying.
core = core.replace("from '../common/protocol.js'", "from './protocol.js'");
fs.writeFileSync(coreDest, core);
fs.copyFileSync(protocolSrc, protocolDest);
console.log('[prepack] wrote lib/core.js and lib/protocol.js');
