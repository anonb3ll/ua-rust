// Install actual tarballs outside the workspace so source links cannot hide defects.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const candidates = resolve(process.argv[2] ?? join(root, "dist/candidates"));
const manifest = JSON.parse(readFileSync(join(candidates, "manifest.json"), "utf8"));
assert.equal(manifest.packages.length, 3, "all SDK packages must be present");
const tarballs = manifest.packages.map((pkg) => {
  const path = join(candidates, pkg.filename);
  assert.equal(createHash("sha256").update(readFileSync(path)).digest("hex"), pkg.sha256, `checksum: ${pkg.name}`);
  return path;
});
const consumer = mkdtempSync(join(tmpdir(), "ua-sdk-consumer-"));
try {
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs], {
    cwd: consumer, stdio: "inherit",
  });
  for (const pkg of manifest.packages) {
    const directory = join(consumer, "node_modules", pkg.name);
    assert.equal(lstatSync(directory).isSymbolicLink(), false, `source link: ${pkg.name}`);
    const installed = JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));
    assert.equal(installed.version, pkg.version);
    assert.equal(installed.private, true);
    for (const spec of Object.values(installed.dependencies ?? {})) {
      assert.equal(spec.startsWith("file:"), false, `local dependency in ${pkg.name}`);
    }
  }
  writeFileSync(join(consumer, "smoke.mjs"), `
    import assert from 'node:assert/strict';
    import { Task } from '@unified-agent/protocol';
    import { UnifiedAgentClient } from '@unified-agent/client';
    import { ApprovalClient } from '@unified-agent/approval-client';
    assert.equal(typeof UnifiedAgentClient, 'function');
    assert.equal(typeof ApprovalClient, 'function');
    assert.equal(Task.parse({id: 1, title: 'candidate', status: 'open',
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z'}).id, 1);
  `);
  execFileSync(process.execPath, ["smoke.mjs"], { cwd: consumer, stdio: "inherit" });
  writeFileSync(join(consumer, "smoke.ts"), `
    import type { TaskType } from '@unified-agent/protocol';
    import { UnifiedAgentClient } from '@unified-agent/client';
    import { ApprovalClient } from '@unified-agent/approval-client';
    const task: TaskType = {id: 1, title: 'candidate', status: 'open', priority: 'med', project: 'unified-agent',
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z'};
    void [task, UnifiedAgentClient, ApprovalClient];
  `);
  execFileSync(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--noEmit",
    "--strict", "--skipLibCheck", "--module", "NodeNext", "--target", "ES2022", "smoke.ts"], {
    cwd: consumer, stdio: "inherit",
  });
  console.log("Candidate checksums, installation, runtime imports and consumer types passed");
} finally {
  rmSync(consumer, { recursive: true, force: true });
}
