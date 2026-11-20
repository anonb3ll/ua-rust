// Stage installable candidates without changing workspace manifests or publishing.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(process.argv[2] ?? join(root, "dist/candidates"));
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const packages = readJson(join(root, "package.json")).workspaces.map((path) => ({
  path: join(root, path),
  manifest: readJson(join(root, path, "package.json")),
}));
const versions = new Map(packages.map(({ manifest }) => [manifest.name, manifest.version]));
const staging = mkdtempSync(join(tmpdir(), "ua-sdk-pack-"));
const provenance = {
  sourceSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
  sourceDirty: Boolean(execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim()),
  packages: [],
};

mkdirSync(output, { recursive: true });
try {
  for (const [index, pkg] of packages.entries()) {
    const directory = join(staging, String(index));
    mkdirSync(directory);
    const manifest = structuredClone(pkg.manifest);
    // file:../protocol works in the source workspace, but breaks outside it.
    // Consumers install every candidate tarball together, satisfying these pins.
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      for (const name of Object.keys(manifest[field] ?? {})) {
        if (versions.has(name)) manifest[field][name] = versions.get(name);
      }
    }
    delete manifest.devDependencies;
    delete manifest.scripts;
    for (const path of manifest.files) {
      cpSync(join(pkg.path, path), join(directory, path), { recursive: true });
    }
    writeFileSync(join(directory, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
    // `npm pack --json` prints an array of results on older npm and an object
    // keyed by package name on newer npm; accept both.
    const packedJson = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", output], {
      cwd: directory, encoding: "utf8",
    }));
    const [packed] = Array.isArray(packedJson) ? packedJson : Object.values(packedJson);
    if (!packed?.filename) throw new Error(`npm pack returned no filename for ${manifest.name}`);
    provenance.packages.push({
      name: manifest.name,
      version: manifest.version,
      filename: packed.filename,
      sha256: createHash("sha256").update(readFileSync(join(output, packed.filename))).digest("hex"),
    });
  }
  writeFileSync(join(output, "manifest.json"), JSON.stringify(provenance, null, 2) + "\n");
  console.log(`Packed ${packages.length} private candidates in ${output}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
