const fs = require("fs/promises");
const path = require("path");
const { root, filenames, name, bytes, digest, fixture, run } = require("./native-artifacts-helpers");
const { packageManager } = require("../package.json");

// pnpm test supplies its actual JS entry, avoiding Windows .cmd shims and shell quoting.
const pnpmEntry = process.env.npm_execpath;

beforeAll(async () => {
    if (!pnpmEntry || !/^pnpm\.(?:c?js|mjs)$/i.test(path.basename(pnpmEntry))) {
        throw new Error("Run these tests with pnpm test using the Node.js distribution of pnpm");
    }
    const result = await run(root, process.execPath, [pnpmEntry, "--version"]);
    expect(result.code).toBe(0);
    expect(`pnpm@${result.stdout.trim()}`).toBe(packageManager);
});

let pkg;
let assets;
let releaseBytes;

beforeEach(async () => {
    pkg = await fixture();
    assets = path.join(pkg.directory, "release-artifacts");
    await fs.mkdir(assets);
    releaseBytes = {};
    for (const file of filenames) {
        releaseBytes[file] = Buffer.from(`Inert release bytes for ${file}\n`);
        await fs.writeFile(path.join(assets, file), releaseBytes[file]);
    }
});

afterEach(async () => {
    if (pkg) await fs.rm(pkg.directory, { recursive: true, force: true });
});

function generate(tag = `v${pkg.version}`) {
    return run(pkg.directory, process.execPath, ["native-artifacts.js", "generate", assets, tag]);
}

function pack() {
    return run(pkg.directory, process.execPath, [pnpmEntry, "pack", "--out", "package.tgz"]);
}

test("generates exactly all release digests, not the packaging job's local binary", async () => {
    await fs.writeFile(path.join(pkg.directory, name), bytes);
    expect(await generate()).toMatchObject({ code: 0, signal: null });
    const manifest = JSON.parse(await fs.readFile(path.join(pkg.directory, "native-artifacts.json"), "utf8"));
    expect(manifest.version).toBe(pkg.version);
    expect(Object.keys(manifest.artifacts).sort()).toEqual([...filenames].sort());
    for (const file of filenames) {
        expect(manifest.artifacts[file]).toEqual({
            sha256: await digest(releaseBytes[file]),
            size: releaseBytes[file].length,
        });
    }
    expect(manifest.artifacts[name].sha256).not.toBe(await digest(bytes));
});

test.each([
    ["missing asset", () => fs.rm(path.join(assets, name))],
    [
        "wrong target",
        async () => {
            await fs.rename(path.join(assets, name), path.join(assets, "matrix-sdk-crypto.freebsd-x64.node"));
        },
    ],
    ["extra native asset", () => fs.writeFile(path.join(assets, "extra.node"), bytes)],
    [
        "duplicate in a subdirectory",
        async () => {
            await fs.mkdir(path.join(assets, "duplicate"));
            await fs.writeFile(path.join(assets, "duplicate", name), bytes);
        },
    ],
    ["empty asset", () => fs.writeFile(path.join(assets, name), "")],
    [
        "directory instead of asset",
        async () => {
            await fs.rm(path.join(assets, name));
            await fs.mkdir(path.join(assets, name));
        },
    ],
])("rejects %s and removes an older manifest", async (_label, change) => {
    await change();
    const result = await generate();
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("Native artifact manifest failed");
    await expect(fs.access(path.join(pkg.directory, "native-artifacts.json"))).rejects.toMatchObject({
        code: "ENOENT",
    });
});

// File symlinks need privileges or Developer Mode on Windows; the directory case runs everywhere.
(process.platform === "win32" ? test.skip : test)("rejects a file symlink instead of an asset", async () => {
    await fs.rm(path.join(assets, name));
    await fs.symlink(path.join(assets, filenames[0]), path.join(assets, name));
    const result = await generate();
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("Native artifact must be a regular file");
    await expect(fs.access(path.join(pkg.directory, "native-artifacts.json"))).rejects.toMatchObject({
        code: "ENOENT",
    });
});

test("rejects a tag that does not match the package version", async () => {
    const result = await generate("v0.0.0-wrong");
    expect(result.code).toBe(1);
    expect(result.stderr).toContain(`v${pkg.version}`);
    await expect(fs.access(path.join(pkg.directory, "native-artifacts.json"))).rejects.toMatchObject({
        code: "ENOENT",
    });
});

test.each([
    ["missing", () => fs.rm(path.join(pkg.directory, "native-artifacts.json"))],
    ["malformed", () => fs.writeFile(path.join(pkg.directory, "native-artifacts.json"), "{")],
    [
        "wrong version",
        () => {
            pkg.manifest.version = "0.0.0-wrong";
        },
    ],
    [
        "missing digest",
        () => {
            delete pkg.manifest.artifacts[name].sha256;
        },
    ],
    [
        "malformed digest",
        () => {
            pkg.manifest.artifacts[name].sha256 = "invalid";
        },
    ],
    [
        "non-string digest",
        () => {
            pkg.manifest.artifacts[name].sha256 = [pkg.manifest.artifacts[name].sha256];
        },
    ],
    [
        "missing target",
        () => {
            delete pkg.manifest.artifacts[name];
        },
    ],
    [
        "extra target",
        () => {
            pkg.manifest.artifacts["extra.node"] = pkg.manifest.artifacts[name];
        },
    ],
    [
        "invalid size",
        () => {
            pkg.manifest.artifacts[name].size = 0;
        },
    ],
])("prepack rejects %s manifest", async (label, change) => {
    await change();
    if (!["missing", "malformed"].includes(label)) {
        await fs.writeFile(path.join(pkg.directory, "native-artifacts.json"), JSON.stringify(pkg.manifest));
    }
    const result = await pack();
    expect(result.code).toBe(1);
    expect(result.stdout + result.stderr).toContain("Native artifact manifest failed");
    await expect(fs.access(path.join(pkg.directory, "package.tgz"))).rejects.toMatchObject({ code: "ENOENT" });
});

test("packed npm package includes runtime and manifest, excluding build and download artifacts", async () => {
    // Copy the source tree into the disposable package; generated bindings are inert stand-ins.
    for (const entry of await fs.readdir(root)) {
        if ([".git", "node_modules", "target"].includes(entry) || entry.endsWith(".node")) continue;
        await fs.cp(path.join(root, entry), path.join(pkg.directory, entry), { recursive: true });
    }
    await fs.writeFile(path.join(pkg.directory, "index.js"), "// Inert generated binding stand-in.\n");
    await fs.writeFile(path.join(pkg.directory, "index.d.ts"), "// Inert generated types stand-in.\n");
    await fs.writeFile(path.join(pkg.directory, name), bytes);
    await fs.writeFile(path.join(pkg.directory, name + ".version"), pkg.version);
    await fs.mkdir(path.join(pkg.directory, ".native-artifact-stale"));
    await fs.writeFile(path.join(pkg.directory, ".native-artifact-stale", "partial"), bytes);
    expect((await generate()).code).toBe(0);
    const manifestText = await fs.readFile(path.join(pkg.directory, "native-artifacts.json"), "utf8");
    const result = await pack();
    expect(result).toMatchObject({ code: 0, signal: null });
    const unpacked = path.join(pkg.directory, "unpacked");
    await fs.mkdir(unpacked);
    const extract = await run(pkg.directory, "tar", ["-xzf", "package.tgz", "-C", unpacked]);
    expect(extract.code).toBe(0);
    const packed = path.join(unpacked, "package");
    const files = (await fs.readdir(packed, { recursive: true })).map((file) => file.replaceAll(path.sep, "/"));
    expect(files).toEqual(
        expect.arrayContaining([
            "package.json",
            "index.js",
            "index.d.ts",
            "download-lib.js",
            "native-artifacts.js",
            "native-artifacts.json",
        ]),
    );
    expect(
        files.filter((file) =>
            /\.node(?:\.version)?$|\.native-artifact-|^(release-artifacts|src|tests|target|xtask|\.github|\.cargo)(\/|$)/.test(
                file,
            ),
        ),
    ).toEqual([]);
    expect(await fs.readFile(path.join(packed, "native-artifacts.json"), "utf8")).toBe(manifestText);
    expect((await run(packed, process.execPath, ["native-artifacts.js", "check"])).code).toBe(0);
});
