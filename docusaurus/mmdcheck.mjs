// Parse every mermaid diagram in the docs, so a syntax error is caught here rather than
// as a blank box in a reader's browser. Docusaurus renders mermaid client-side, so
// `docusaurus build` cannot fail on a bad diagram.
//
// mermaid's flowchart path sanitises labels through DOMPurify, which needs a DOM. Rather
// than pulling in jsdom for a syntax check, stub the two hooks DOMPurify's mermaid
// integration installs. Sanitisation is irrelevant to whether the grammar accepts the
// input, which is all this asks.
import fs from 'node:fs';
import DOMPurify from 'dompurify';

if (typeof DOMPurify.addHook !== 'function') {
  DOMPurify.addHook = () => {};
}
if (typeof DOMPurify.sanitize !== 'function') {
  DOMPurify.sanitize = (s) => s;
}

const mermaid = (await import('mermaid')).default;

let blocks = 0;
let bad = 0;
for (const file of process.argv.slice(2)) {
  const text = fs.readFileSync(file, 'utf8');
  const fence = /```mermaid\n([\s\S]*?)```/g;
  let match;
  let index = 0;
  while ((match = fence.exec(text))) {
    index += 1;
    blocks += 1;
    try {
      await mermaid.parse(match[1]);
    } catch (err) {
      bad += 1;
      const first = String(err?.message ?? err).split('\n')[0];
      console.log(`FAIL ${file} block ${index}: ${first}`);
    }
  }
}
console.log(`${blocks} diagrams parsed, ${bad} failed`);
process.exit(bad ? 1 : 0);
