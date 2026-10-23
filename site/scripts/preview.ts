import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { APP_JS } from "../src/app";
import { APP_PATH, FONT_400, FONT_600 } from "../src/assets";
import { datasetLd, renderHome } from "../src/home";
import { layout } from "../src/html";

const read = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8"));
const feed = read("feed.json");
const html = layout({
  title: "Mirage Feed: daily honeypot threat intelligence",
  description: "Preview rendered from fixtures.",
  path: "/",
  body: renderHome(feed, read("stats.json"), Date.parse(feed.generated)),
  shadow: false,
  day: feed.day,
  head: datasetLd(feed),
})
  .replaceAll(FONT_400, "../fonts/ibm-plex-mono-latin-400-normal.woff2")
  .replaceAll(FONT_600, "../fonts/ibm-plex-mono-latin-600-normal.woff2")
  .replace(`src="${APP_PATH}"`, 'src="app.js"');

const out = new URL("../preview/", import.meta.url);
mkdirSync(out, { recursive: true });
writeFileSync(new URL("index.html", out), html);
writeFileSync(new URL("app.js", out), APP_JS);
console.log(`preview/index.html ${html.length} bytes`);
