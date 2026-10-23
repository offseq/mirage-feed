import { writeFileSync } from "node:fs";
import sharp from "sharp";
import { FAVICON } from "../src/icon";

const out = (name: string) => new URL(`../assets/${name}`, import.meta.url);
const png = (svg: string, size?: number) =>
  sharp(Buffer.from(svg)).resize(size).png({ palette: true, colours: 32, compressionLevel: 9 }).toBuffer();

const OG = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="Menlo, DejaVu Sans Mono, monospace">
<rect width="1200" height="630" fill="#f9f7f2"/>
<g font-size="26" fill="#464e58"><text x="72" y="92" font-weight="700" fill="#161d27">MIRAGE-FEED(7)</text><text x="1128" y="92" text-anchor="end">OffSeq Mirage</text></g>
<rect x="520" y="66" width="160" height="36" fill="#000"/><text x="600" y="92" font-size="24" font-weight="700" fill="#fff" text-anchor="middle">TLP:CLEAR</text>
<line x1="72" y1="124" x2="1128" y2="124" stroke="#d1cdc5" stroke-width="2"/>
<text x="72" y="200" font-size="26" font-weight="700" fill="#161d27">NAME</text>
<text x="140" y="262" font-size="54" font-weight="700" fill="#161d27">mirage-feed</text>
<g font-size="30" fill="#161d27"><text x="140" y="320">daily attacker indicators from the</text><text x="140" y="362">OffSeq Mirage honeypot fleet</text></g>
<rect x="140" y="410" width="988" height="70" fill="#f0ede6"/><rect x="140" y="410" width="4" height="70" fill="#005971"/>
<text x="168" y="456" font-size="24" fill="#161d27"><tspan fill="#464e58">$&#160;</tspan>curl -fsSL feeds.offseq.com/mirage-feed/latest/ipv4-7d.txt</text>
<line x1="72" y1="550" x2="1128" y2="550" stroke="#d1cdc5" stroke-width="2"/>
<g font-size="24" fill="#464e58"><text x="72" y="590">feeds.offseq.com</text><text x="1128" y="590" text-anchor="end">CC BY 4.0</text></g>
</svg>`;

function ico(image: Buffer, size: number): Buffer {
  const head = Buffer.alloc(22);
  head.writeUInt16LE(1, 2);
  head.writeUInt16LE(1, 4);
  head.writeUInt8(size, 6);
  head.writeUInt8(size, 7);
  head.writeUInt16LE(1, 10);
  head.writeUInt16LE(32, 12);
  head.writeUInt32LE(image.length, 14);
  head.writeUInt32LE(22, 18);
  return Buffer.concat([head, image]);
}

writeFileSync(out("og.png"), await png(OG));
writeFileSync(out("apple-touch-icon.png"), await png(FAVICON, 180));
writeFileSync(out("favicon.ico"), ico(await png(FAVICON, 32), 32));
