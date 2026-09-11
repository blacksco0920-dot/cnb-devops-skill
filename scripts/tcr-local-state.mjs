// Private local transaction files for configure-tcr. No cloud operations live here.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';
export const fail = code => { throw new Error(code); };
export const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : object(value)
  ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
export const sha = value => createHash('sha256').update(value).digest('hex');
export function safeDirectory(input, privateDir = false) {
  if (typeof input !== 'string' || !path.isAbsolute(input) || path.normalize(input) !== input) fail('TCR_PATH_UNSAFE');
  try {
    for (let current = input;; current = path.dirname(current)) {
      const st = fs.lstatSync(current), sticky = current !== input && st.uid === 0 && (st.mode & 0o1000);
      if (!st.isDirectory() || st.isSymbolicLink() || ![0, process.getuid()].includes(st.uid) || ((st.mode & 0o022) && !sticky) ||
          (current === input && privateDir && (st.uid !== process.getuid() || (st.mode & 0o777) !== 0o700))) fail('TCR_PATH_UNSAFE');
      if (current === path.dirname(current)) return input;
    }
  } catch (error) { if (/^TCR_/.test(error.message)) throw error; fail('TCR_PATH_UNSAFE'); }
}
export function readJson(file, { optional = false, secret = true } = {}) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.normalize(file) !== file) fail('TCR_PATH_UNSAFE');
  safeDirectory(path.dirname(file));
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== process.getuid() || (st.mode & 0o022) ||
        (secret && (st.mode & 0o777) !== 0o600) || st.size > 1024 * 1024) fail('TCR_INPUT_UNSAFE');
    const raw = fs.readFileSync(fd, 'utf8');
    let value;
    try { value = parseStrictJson(raw, { maxBytes: 1024 * 1024 }); } catch { fail('TCR_SPEC_INVALID'); }
    return value;
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    if (/^TCR_/.test(error.message)) throw error;
    fail('TCR_INPUT_UNSAFE');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
function syncDirectory(dir) {
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
export function writeJson(file, value, replace = false) {
  safeDirectory(path.dirname(file), true);
  const temp = `${file}.${randomBytes(12).toString('hex')}.tmp`;
  let fd;
  try {
    if (replace) readJson(file);
    fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, `${canonical(value)}\n`); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    if (replace) fs.renameSync(temp, file);
    else { fs.linkSync(temp, file); fs.unlinkSync(temp); }
    syncDirectory(path.dirname(file));
  } catch (error) { if (/^TCR_/.test(error.message)) throw error; fail('TCR_STATE_WRITE_FAILED'); }
  finally { if (fd !== undefined) fs.closeSync(fd); try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') fail('TCR_STATE_WRITE_FAILED'); } }
}
export function openState(directory, specDigest) {
  safeDirectory(directory, true);
  const lock = path.join(directory, '.lock');
  try { fs.mkdirSync(lock, { mode: 0o700 }); } catch { fail('TCR_STATE_LOCKED'); }
  try {
    const filename = path.join(directory, 'state.json');
    const saved = readJson(filename, { optional: true });
    if (saved && (!object(saved) || saved.schema !== 'cnb-tcr-state/v1' || saved.spec_sha256 !== specDigest || !object(saved.operations) ||
        Object.keys(saved).sort().join(',') !== 'operations,schema,spec_sha256')) fail('TCR_STATE_CONFLICT');
    const state = saved || { schema: 'cnb-tcr-state/v1', spec_sha256: specDigest, operations: {} };
    let exists = !!saved;
    return { state, save() { writeJson(filename, state, exists); exists = true; }, close() { fs.rmdirSync(lock); } };
  } catch (error) { fs.rmdirSync(lock); throw error; }
}
