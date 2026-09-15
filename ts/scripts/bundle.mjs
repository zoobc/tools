// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
// Bundle the library (not the CLI) into ../js/zbc.js: one dependency-free file that defines the
// global `ZBC` for a <script> tag and also works as a CommonJS module. Run from ts/: npm run bundle
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const version = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
await build({
  entryPoints: [join(here, "..", "src", "index.ts")],
  bundle: true,
  format: "iife",
  globalName: "ZBC",
  target: ["es2020"],
  platform: "browser",
  outfile: join(here, "..", "..", "js", "zbc.js"),
  legalComments: "none",
  banner: { js: `// SPDX-License-Identifier: MIT\n// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci\n// ZooBC tools ${version}, built from ts/ by scripts/bundle.mjs. Defines the global ZBC. Do not edit.` },
  footer: { js: `if (typeof module !== "undefined" && module.exports) module.exports = ZBC;` },
});
console.log("wrote js/zbc.js");
