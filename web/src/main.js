// Entry point (bundled by tools/build_web.mjs; served unbundled by the mock server with --dev).
import { boot } from './app.js';

boot().catch((e) => {
  console.error(e);
});
