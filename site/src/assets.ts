import { APP_JS } from "./app";
import { FAVICON } from "./icon";
import plex400 from "../fonts/ibm-plex-mono-latin-400-normal.woff2";
import plex600 from "../fonts/ibm-plex-mono-latin-600-normal.woff2";
import favicon from "../assets/favicon.ico";
import touchIcon from "../assets/apple-touch-icon.png";
export { default as OG_FALLBACK } from "../assets/og.png";

function fnv1a(data: ArrayBuffer | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  let h = 0x811c9dc5;
  for (const b of bytes) h = Math.imul(h ^ b, 0x01000193);
  return (h >>> 0).toString(16).padStart(8, "0");
}

export const APP_PATH = `/app.${fnv1a(APP_JS)}.js`;
export const FONT_400 = `/fonts/plex-mono-400.${fnv1a(plex400)}.woff2`;
export const FONT_600 = `/fonts/plex-mono-600.${fnv1a(plex600)}.woff2`;

export interface Asset {
  body: BodyInit;
  type: string;
  immutable?: boolean;
}

export const ASSETS: Record<string, Asset> = {
  [APP_PATH]: { body: APP_JS, type: "text/javascript; charset=utf-8", immutable: true },
  [FONT_400]: { body: plex400, type: "font/woff2", immutable: true },
  [FONT_600]: { body: plex600, type: "font/woff2", immutable: true },
  "/favicon.svg": { body: FAVICON, type: "image/svg+xml" },
  "/favicon.ico": { body: favicon, type: "image/x-icon" },
  "/apple-touch-icon.png": { body: touchIcon, type: "image/png" },
};
