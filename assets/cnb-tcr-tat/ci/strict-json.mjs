// JSON.parse 负责语法；再次扫描键名，避免重复键在解析时被静默覆盖。
export function parseStrictJson(text, { maxBytes = 65536 } = {}) {
  const fail = () => { throw new Error('STRICT_JSON_REJECTED'); };
  if (typeof text !== 'string' || !Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
      maxBytes > 16 * 1024 * 1024 || Buffer.byteLength(text, 'utf8') > maxBytes) fail();
  let result;
  try { result = JSON.parse(text); } catch { fail(); }
  let index = 0;
  let nodes = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[index] || '\0')) index++; };
  const string = () => {
    const match = /^"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(index));
    if (!match) fail();
    index += match[0].length;
    const value = JSON.parse(match[0]);
    for (const character of value) {
      const point = character.codePointAt(0);
      if (point >= 0xd800 && point <= 0xdfff) fail();
    }
    return value;
  };
  const scan = (depth) => {
    if (depth > 64 || ++nodes > 100000) fail();
    whitespace();
    const next = text[index];
    if (next === '"') { string(); return; }
    if (next === '{' || next === '[') {
      index++;
      const object = next === '{';
      const closing = object ? '}' : ']';
      const seen = new Set();
      whitespace();
      if (text[index] === closing) { index++; return; }
      while (true) {
        whitespace();
        if (object) {
          const key = string();
          if (seen.has(key)) fail();
          seen.add(key);
          whitespace();
          if (text[index++] !== ':') fail();
        }
        scan(depth + 1);
        whitespace();
        if (text[index] === closing) { index++; return; }
        if (text[index++] !== ',') fail();
      }
    }
    const primitive = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(index));
    if (!primitive) fail();
    index += primitive[0].length;
    if (/^[-0-9]/.test(primitive[0])) {
      const number = Number(primitive[0]);
      if (!Number.isFinite(number) || (Number.isInteger(number) && !Number.isSafeInteger(number))) fail();
    }
  };
  try { scan(0); whitespace(); if (index !== text.length) fail(); } catch { fail(); }
  return result;
}
