import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

// Adapted from source-pinned release-identity.mjs; see dependencies/SOURCES.md.
const SCHEMA = 'cnb-release-identity/v1';
const SERVICE = /^[a-z][a-z0-9-]{0,62}$/u;
const GIT_SHA = /^(?:[0-9a-f]{40}|unknown)$/u;
const BUILD_ID = /^(?:cnb-[a-z0-9][a-z0-9-]{2,127}|development)$/u;

export function renderReleaseIdentity({ service, gitSha, buildId }) {
  if (typeof service !== 'string' || !SERVICE.test(service)) throw new Error('invalid release identity service');
  if (!GIT_SHA.test(gitSha)) throw new Error('invalid release identity Git SHA');
  if (!BUILD_ID.test(buildId)) throw new Error('invalid release identity build ID');
  if ((gitSha === 'unknown') !== (buildId === 'development')) {
    throw new Error('development release identity must use both placeholders');
  }
  return JSON.stringify({ build_id: buildId, git_sha: gitSha, schema: SCHEMA, service }) + '\n';
}

export async function writeReleaseIdentity({ service, gitSha, buildId, output }) {
  const rendered = renderReleaseIdentity({ service, gitSha, buildId });
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, rendered, { encoding: 'utf8', mode: 0o644 });
}

function parseArguments(arguments_) {
  const names = new Set(['service', 'git-sha', 'build-id', 'output']);
  const values = {};

  for (const argument of arguments_) {
    if (!argument.startsWith('--')) throw new Error('invalid release identity option');
    const separator = argument.indexOf('=');
    if (separator === -1) throw new Error('invalid release identity option');
    const name = argument.slice(2, separator);
    const value = argument.slice(separator + 1);
    if (
      !names.has(name) ||
      Object.hasOwn(values, name) ||
      value.length === 0 ||
      value.startsWith('-') ||
      /[\r\n]/u.test(value)
    ) {
      throw new Error('invalid release identity option');
    }
    values[name] = value;
  }

  if ([...names].some((name) => !Object.hasOwn(values, name))) {
    throw new Error('missing release identity option');
  }
  return values;
}

async function main(arguments_) {
  const values = parseArguments(arguments_);
  await writeReleaseIdentity({
    service: values.service,
    gitSha: values['git-sha'],
    buildId: values['build-id'],
    output: values.output,
  });
}

function isMain() {
  try {return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);} catch {return false;}
}
if (isMain()) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
