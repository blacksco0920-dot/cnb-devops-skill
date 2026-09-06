// Adapted from the source-pinned release-request.mjs; see dependencies/SOURCES.md.
const GIT_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const BUILD_ID_PATTERN = /^cnb-[a-z0-9][a-z0-9-]{2,127}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const NAME_PATTERN = /^[a-z][a-z0-9-]{0,62}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const REQUEST_KEYS = ['schema','project','environment','controller','git_sha','controller_commit','build_id','images'];
export const RELEASE_REQUEST_MAX_BYTES = 16 * 1024;
function fail(message) { throw new Error(message); }
function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) fail(`invalid ${label} keys`);
}
function requirePattern(name, value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) fail(`invalid release request ${name}`);
  return value;
}
export function validateConfig(config) {
  if (config?.schema !== 'cnb-devops-ci/v1' || config.environment !== 'test') fail('unsupported CI configuration or environment; production is not implemented');
  requirePattern('project', config.project, NAME_PATTERN);
  requirePattern('controller', config.controller_id, /^[a-z][a-z0-9-]{0,95}$/u);
  if (!config.services || typeof config.services !== 'object' || Array.isArray(config.services) || !Object.keys(config.services).length) fail('services are required');
  for (const [name, service] of Object.entries(config.services)) {
    requirePattern('service', name, NAME_PATTERN);
    requirePattern('image repository', service?.image_repository, /^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?\/[a-z0-9._/-]+$/u);
  }
  for (const key of ['controller_program_sha256','controller_compose_sha256','policy_sha256']) requirePattern(key,config[key],SHA256_PATTERN);
  expectedProbes(config);
  return config;
}
export function expectedProbes(config) {
  if (!Array.isArray(config.probes) || config.probes.length === 0) fail('expected probes are required');
  for (const probe of config.probes) {
    let url;
    try {url = new URL(probe.url);} catch {fail('invalid expected probe');}
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || /[\r\n\0]/u.test(probe.url)) fail('invalid expected probe');
  }
  return [...new Set(config.probes.map(probe=>probe.url))].sort();
}
export function validateReleaseRequest(model, config) {
  validateConfig(config);
  exactKeys(model, REQUEST_KEYS, 'release request');
  if (model.schema !== 'cnb-release-request/v1' || model.project !== config.project || model.environment !== config.environment || model.controller !== config.controller_id) fail('release request policy mismatch');
  requirePattern('Git SHA', model.git_sha, GIT_SHA_PATTERN);
  requirePattern('controller commit', model.controller_commit, GIT_SHA_PATTERN);
  if (model.controller_commit !== model.git_sha) fail('controller commit must equal application commit');
  requirePattern('build ID', model.build_id, BUILD_ID_PATTERN);
  exactKeys(model.images, Object.keys(config.services), 'release images');
  for (const [service, spec] of Object.entries(config.services)) {
    const image = model.images[service];
    const prefix = `${spec.image_repository}@sha256:`;
    if (typeof image !== 'string' || !image.startsWith(prefix) || !SHA256_PATTERN.test(image.slice(prefix.length))) fail(`invalid immutable image for ${service}`);
  }
  return model;
}
function canonicalJson(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonicalJson(value[key])).join(',')+'}';
  if (Array.isArray(value)) return '['+value.map(canonicalJson).join(',')+']';
  return JSON.stringify(value);
}
export function renderReleaseRequest(values, config) {
  const model = validateReleaseRequest(values, config);
  const json = canonicalJson(model);
  const encoded = Buffer.from(json, 'utf8').toString('base64url');
  if (!BASE64URL_PATTERN.test(encoded) || Buffer.byteLength(encoded, 'ascii') > RELEASE_REQUEST_MAX_BYTES || Buffer.from(encoded, 'base64url').toString('utf8') !== json) fail('invalid release request encoding');
  return encoded;
}
export function parseReleaseRequest(encoded, config) {
  if (typeof encoded !== 'string' || !BASE64URL_PATTERN.test(encoded) || Buffer.byteLength(encoded, 'ascii') > RELEASE_REQUEST_MAX_BYTES || Buffer.from(encoded,'base64url').toString('base64url') !== encoded) fail('invalid release request encoding');
  let model;
  try {model = JSON.parse(Buffer.from(encoded,'base64url').toString('utf8'));} catch {fail('invalid release request JSON');}
  // Canonical object round-trip also rejects duplicate JSON keys and invalid UTF-8.
  if (Buffer.from(canonicalJson(model),'utf8').toString('base64url') !== encoded) fail('release request is not exact JSON');
  return validateReleaseRequest(model,config);
}
const RECEIPT_KEYS=['schema','status','project','environment','controller','git_sha','controller_commit','build_id','images','controller_program_sha256','controller_compose_sha256','policy_sha256','database_backup_sha256','container_count','probe_count','probes'];
export function validateReleaseReceipt(receipt, request, config, binding) {
  validateReleaseRequest(request,config);
  exactKeys(receipt,RECEIPT_KEYS,'release receipt');
  if (receipt.schema !== 'cnb-deploy-result/v1' || receipt.status !== 'passed') fail('release receipt is not passed');
  for (const key of ['project','environment','controller','git_sha','controller_commit','build_id']) if(receipt[key]!==request[key]) fail(`receipt ${key} mismatch`);
  exactKeys(receipt.images,Object.keys(request.images),'receipt images');
  for (const [name,image] of Object.entries(request.images)) if(receipt.images[name]!==image) fail('receipt image mismatch');
  for (const [key,bindingKey] of [['controller_program_sha256','program_sha256'],['controller_compose_sha256','compose_sha256'],['policy_sha256','policy_sha256']]) {
    requirePattern(key,receipt[key],SHA256_PATTERN);
    if(receipt[key]!==binding?.[bindingKey]) fail(`receipt ${key} mismatch`);
  }
  requirePattern('backup hash',receipt.database_backup_sha256,SHA256_PATTERN);
  const probes=expectedProbes(config);
  if(receipt.container_count!==Object.keys(config.services).length || receipt.probe_count!==probes.length || JSON.stringify(receipt.probes)!==JSON.stringify(probes)) fail('receipt coverage mismatch');
  return receipt;
}
