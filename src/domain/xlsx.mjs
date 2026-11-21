// Minimal XLSX reader for inventory imports: first worksheet → array of row objects keyed by the header row.
// Safety: decompressed size is capped (zip-bomb protection), only the shared-strings and first-sheet parts are read,
// formulas are never evaluated (cached values only), and no external relationships are followed.
import { unzipSync, strFromU8 } from 'fflate';
import { ParseError } from './parsers.mjs';

const MAX_UNCOMPRESSED = 50 * 1024 * 1024;
const MAX_ROWS = 50000;
const decode = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&amp;/g, '&');
const colIndex = (ref) => { let n = 0; for (const ch of ref.replace(/\d+/g, '')) n = n * 26 + (ch.charCodeAt(0) - 64); return n - 1; };

export function readXlsxRows(buf) {
  let total = 0;
  let files;
  try {
    files = unzipSync(new Uint8Array(buf), {
      filter: (f) => {
        if (!/^xl\/(sharedStrings\.xml|worksheets\/sheet1\.xml|workbook\.xml)$/.test(f.name)) return false;
        total += f.originalSize; if (total > MAX_UNCOMPRESSED) throw new ParseError('XLSX expands beyond 50 MB; rejected.');
        return true;
      },
    });
  } catch (e) { if (e instanceof ParseError) throw e; throw new ParseError('Not a valid XLSX (zip) file.'); }
  const sheet = files['xl/worksheets/sheet1.xml'];
  if (!sheet) throw new ParseError('XLSX has no first worksheet.');
  const shared = files['xl/sharedStrings.xml'] ? [...strFromU8(files['xl/sharedStrings.xml']).matchAll(/<si>([\s\S]*?)<\/si>/g)].map(m => decode([...m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join(''))) : [];
  const rows = [];
  for (const rm of strFromU8(sheet).matchAll(/<row[^>]*>([\s\S]*?)<\/row>/g)) {
    const cells = [];
    for (const cm of rm[1].matchAll(/<c ([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const attrs = cm[1]; const inner = cm[2] || '';
      const ref = /r="([A-Z]+\d+)"/.exec(attrs)?.[1]; const type = /t="(\w+)"/.exec(attrs)?.[1];
      let v = /<v>([\s\S]*?)<\/v>/.exec(inner)?.[1];
      if (type === 's' && v != null) v = shared[Number(v)];
      else if (type === 'inlineStr') v = [...inner.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join('');
      else if (type === 'b') v = v === '1' ? 'true' : 'false';
      cells[ref ? colIndex(ref) : cells.length] = v == null ? '' : decode(String(v));
    }
    rows.push(cells);
    if (rows.length > MAX_ROWS + 1) throw new ParseError('Too many rows (max 50,000).');
  }
  if (!rows.length) return [];
  const header = rows[0].map(h => String(h || '').trim().toLowerCase());
  return rows.slice(1).filter(r => r.some(c => c !== undefined && c !== '')).map(r => Object.fromEntries(header.map((h, i) => [h, (r[i] ?? '').trim()]).filter(([h]) => h)));
}
