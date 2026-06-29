import { serve } from "./index.js";

serve().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
