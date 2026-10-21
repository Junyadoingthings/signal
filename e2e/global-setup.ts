import { execFileSync } from "node:child_process";
import { join } from "node:path";

/** Generate the same synthetic logs `make seed` uses. */
export default function globalSetup(): void {
  execFileSync("python3", ["../tools/seed/generate.py", "--out", join(import.meta.dirname, ".data")], {
    stdio: "inherit",
  });
}
