import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    {
      name: "woff2-as-arraybuffer",
      enforce: "pre",
      load(id) {
        if (!id.endsWith(".woff2")) return null;
        const b64 = readFileSync(id).toString("base64");
        return `export default Uint8Array.from(atob("${b64}"), (c) => c.charCodeAt(0)).buffer;`;
      },
    },
  ],
  test: { include: ["test/**/*.test.ts"] },
});
