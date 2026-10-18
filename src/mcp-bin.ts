import { startHttpServer } from "./http.js";
import { serve } from "./index.js";

(process.argv.includes("--http") ? startHttpServer() : serve()).catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
