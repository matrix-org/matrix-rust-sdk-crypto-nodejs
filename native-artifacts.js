const { createHash } = require("crypto");
const { createReadStream } = require("fs");
const { lstat, readFile, readdir, rm, writeFile } = require("fs/promises");
const path = require("path");
const { version } = require("./package.json");

const filenames = [
    "darwin-arm64",
    "darwin-x64",
    "linux-arm-gnueabihf",
    "linux-arm64-gnu",
    "linux-arm64-musl",
    "linux-ia32-gnu",
    "linux-riscv64-gnu",
    "linux-s390x-gnu",
    "linux-x64-gnu",
    "linux-x64-musl",
    "win32-arm64-msvc",
    "win32-ia32-msvc",
    "win32-x64-msvc",
].map((target) => `matrix-sdk-crypto.${target}.node`);
const manifestPath = path.join(__dirname, "native-artifacts.json");

function validateInventory(names) {
    if (names.length !== filenames.length || names.some((name) => !filenames.includes(name))) {
        throw new Error("Native artifact inventory must contain exactly the supported filenames");
    }
}

async function readManifest() {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (manifest?.version !== version) {
        throw new Error(`Native artifact manifest must match package version ${version}`);
    }
    if (!manifest.artifacts || typeof manifest.artifacts !== "object" || Array.isArray(manifest.artifacts)) {
        throw new Error("Invalid native artifact manifest");
    }
    validateInventory(Object.keys(manifest.artifacts));
    for (const [name, entry] of Object.entries(manifest.artifacts)) {
        if (
            !entry ||
            typeof entry.sha256 !== "string" ||
            !/^[a-f0-9]{64}$/.test(entry.sha256) ||
            !Number.isSafeInteger(entry.size) ||
            entry.size <= 0
        ) {
            throw new Error(`Invalid SHA-256 or size in native artifact manifest for ${name}`);
        }
    }
    return manifest.artifacts;
}

async function fingerprint(file) {
    if (!(await lstat(file)).isFile()) {
        throw new Error(`Native artifact must be a regular file: ${file}`);
    }
    const hash = createHash("sha256");
    let size = 0;
    for await (const chunk of createReadStream(file)) {
        hash.update(chunk);
        size += chunk.length;
    }
    return { sha256: hash.digest("hex"), size };
}

async function verifyArtifact(file, expected) {
    try {
        const actual = await fingerprint(file);
        return actual.size === expected.size && actual.sha256 === expected.sha256;
    } catch (error) {
        if (error.code === "ENOENT") return false;
        throw error;
    }
}

async function generate(directory, tag) {
    // A failed regeneration must not leave an older manifest available for packing.
    await rm(manifestPath, { force: true });
    if (!directory || tag !== `v${version}`) {
        throw new Error(`Usage: node native-artifacts.js generate <release-assets-directory> v${version}`);
    }
    validateInventory(await readdir(directory));
    const artifacts = {};
    for (const name of filenames) {
        artifacts[name] = await fingerprint(path.join(directory, name));
        if (!artifacts[name].size) throw new Error(`Empty native artifact: ${name}`);
    }
    await writeFile(manifestPath, JSON.stringify({ version, artifacts }, null, 4) + "\n");
}

if (require.main === module) {
    const [command, directory, tag] = process.argv.slice(2);
    const run = async () => {
        if (command === "generate") return generate(directory, tag);
        if (command === "check") return readManifest();
        throw new Error("Expected native-artifacts.js generate or check");
    };
    run().catch((error) => {
        console.error("Native artifact manifest failed:", error);
        process.exitCode = 1;
    });
}

module.exports = { filenames, readManifest, verifyArtifact };
