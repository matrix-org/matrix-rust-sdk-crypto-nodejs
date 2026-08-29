const { webcrypto } = require("crypto");
const { spawn } = require("child_process");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");

const root = path.resolve(__dirname, "..");
// Independent release inventory and inert bytes; never load a native fixture.
const targets = [
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
];
const filenames = targets.map((target) => `matrix-sdk-crypto.${target}.node`);
const name = "matrix-sdk-crypto.win32-x64-msvc.node";
const bytes = Buffer.from("Inert native artifact fixture, never dlopen.\n");

async function digest(data) {
    return Buffer.from(await webcrypto.subtle.digest("SHA-256", data)).toString("hex");
}

async function fixture() {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "matrix-native-artifacts-"));
    try {
        for (const file of ["package.json", "download-lib.js", "native-artifacts.js", ".npmignore", ".gitignore"]) {
            await fs.copyFile(path.join(root, file), path.join(directory, file));
        }
        await fs.symlink(path.join(root, "node_modules"), path.join(directory, "node_modules"), "junction");
        const packageText = await fs.readFile(path.join(directory, "package.json"), "utf8");
        const { version } = JSON.parse(packageText);
        const artifacts = {};
        for (const file of filenames) artifacts[file] = { sha256: await digest(bytes), size: bytes.length };
        const manifest = { version, artifacts };
        await fs.writeFile(path.join(directory, "native-artifacts.json"), JSON.stringify(manifest));
        return { directory, version, packageText, manifest };
    } catch (error) {
        await fs.rm(directory, { recursive: true, force: true });
        throw error;
    }
}

function run(directory, command, args, overrides = {}) {
    const env = { ...process.env };
    for (const key of [
        "https_proxy",
        "HTTPS_PROXY",
        "http_proxy",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "npm_config_target_platform",
        "npm_config_target_arch",
        "npm_config_platform",
        "npm_config_arch",
        "MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL",
    ])
        delete env[key];
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            cwd: directory,
            env: { ...env, ...overrides },
            stdio: ["ignore", "pipe", "pipe"],
            detached: process.platform !== "win32",
        });
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        const deadline = setTimeout(() => {
            timedOut = true;
            if (process.platform === "win32") child.kill("SIGKILL");
            else process.kill(-child.pid, "SIGKILL");
        }, 8000);
        child.stdout.on("data", (data) => (stdout += data));
        child.stderr.on("data", (data) => (stderr += data));
        child.once("error", (error) => {
            clearTimeout(deadline);
            reject(error);
        });
        child.once("close", (code, signal) => {
            clearTimeout(deadline);
            if (timedOut) return reject(new Error(`Child exceeded deadline: ${command}\n${stdout}\n${stderr}`));
            resolve({ code, signal, stdout, stderr });
        });
    });
}

module.exports = { root, filenames, name, bytes, digest, fixture, run };
