const fs = require("fs/promises");
const http = require("http");
const path = require("path");
const { bytes, name, fixture, run } = require("./native-artifacts-helpers");

let pkg;
let server;
let sockets;
let requests;
let respond;
let baseUrl;

beforeEach(async () => {
    pkg = await fixture();
    sockets = new Set();
    requests = [];
    respond = (_req, res) => res.end(bytes);
    server = http.createServer((req, res) => {
        requests.push(req.url);
        respond(req, res);
    });
    server.on("connection", (socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}/mirror`;
    await fs.mkdir(path.join(pkg.directory, ".native-artifact-unrelated"));
    await fs.writeFile(path.join(pkg.directory, ".native-artifact-unrelated", "keep"), "unrelated");
});

afterEach(async () => {
    if (server) {
        const closed = new Promise((resolve) => server.close(resolve));
        for (const socket of sockets) socket.destroy();
        await closed;
    }
    if (pkg) await fs.rm(pkg.directory, { recursive: true, force: true });
});

function install(overrides = {}) {
    return run(pkg.directory, process.execPath, ["download-lib.js"], {
        npm_config_target_platform: "win32",
        npm_config_target_arch: "x64",
        MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL: baseUrl,
        ...overrides,
    });
}

async function assertOutcome(result, success, artifactName = name) {
    expect(result.signal).toBeNull();
    expect({ code: result.code, stderr: result.stderr }).toEqual({
        code: success ? 0 : 1,
        stderr: success ? "" : expect.any(String),
    });
    if (success) {
        expect(await fs.readFile(path.join(pkg.directory, artifactName))).toEqual(bytes);
    } else {
        await expect(fs.access(path.join(pkg.directory, artifactName))).rejects.toMatchObject({ code: "ENOENT" });
        expect(result.stdout + result.stderr).not.toContain("Download Completed");
        expect(result.stderr).toContain("Download Failed");
    }
    expect(await fs.readFile(path.join(pkg.directory, "package.json"), "utf8")).toBe(pkg.packageText);
    expect(await fs.readFile(path.join(pkg.directory, ".native-artifact-unrelated", "keep"), "utf8")).toBe("unrelated");
    const files = await fs.readdir(pkg.directory);
    expect(files.filter((file) => file.startsWith(".native-artifact-"))).toEqual([".native-artifact-unrelated"]);
    expect(files.filter((file) => file.endsWith(".version"))).toEqual([]);
    expect(files.filter((file) => file.endsWith(".node"))).toEqual(success ? [artifactName] : []);
}

function truncated(req, body, declaredSize) {
    req.socket.end(
        Buffer.concat([
            Buffer.from(`HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ${declaredSize}\r\n\r\n`),
            body,
        ]),
    );
}

test.each([
    ["known length", (_req, res) => res.end(bytes)],
    [
        "chunked",
        (_req, res) => {
            res.write(bytes.subarray(0, 7));
            res.end(bytes.subarray(7));
        },
    ],
    [
        "unknown length",
        (req) => req.socket.end(Buffer.concat([Buffer.from("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"), bytes])),
    ],
])("installs verified %s response", async (_label, handler) => {
    respond = handler;
    const result = await install();
    await assertOutcome(result, true);
    expect(result.stdout.match(/Download Completed/g)).toHaveLength(1);
    expect(requests).toEqual([`/mirror/v${pkg.version}/${name}`]);
});

test.each([
    ["same-length tampering", (_req, res) => res.end(Buffer.alloc(bytes.length, "x"))],
    ["honest short body", (_req, res) => res.end(bytes.subarray(0, 7))],
    ["interrupted body", (req) => truncated(req, bytes.subarray(0, 7), bytes.length)],
    ["mismatched Content-Length despite correct bytes", (req) => truncated(req, bytes, bytes.length + 10)],
    [
        "extra bytes after Content-Length",
        (req) => truncated(req, Buffer.concat([bytes, Buffer.from("extra")]), bytes.length),
    ],
    [
        "unterminated chunked body despite correct bytes",
        (req) =>
            req.socket.end(
                Buffer.concat([
                    Buffer.from(
                        `HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n${bytes.length.toString(16)}\r\n`,
                    ),
                    bytes,
                    Buffer.from("\r\n"),
                ]),
            ),
    ],
])("rejects %s", async (_label, handler) => {
    respond = handler;
    await assertOutcome(await install(), false);
    expect(requests).toHaveLength(1);
});

test.each(["0.0.0-stale", "current", undefined])("repairs invalid cached bytes with marker %s", async (marker) => {
    await fs.writeFile(path.join(pkg.directory, name), Buffer.alloc(bytes.length, "x"));
    if (marker)
        await fs.writeFile(path.join(pkg.directory, name + ".version"), marker === "current" ? pkg.version : marker);
    await assertOutcome(await install(), true);
    expect(requests).toHaveLength(1);
});

test.each(["current", undefined])("verifies valid cache without network with marker %s", async (marker) => {
    await fs.writeFile(path.join(pkg.directory, name), bytes);
    if (marker) await fs.writeFile(path.join(pkg.directory, name + ".version"), pkg.version);
    respond = (_req, res) => {
        res.writeHead(503);
        res.end();
    };
    const result = await install();
    await assertOutcome(result, true);
    expect(result.stdout).toContain("File already in place");
    expect(result.stdout).not.toContain("Download Completed");
    expect(requests).toEqual([]);
});

test("removes invalid cache when repair fails", async () => {
    await fs.writeFile(path.join(pkg.directory, name), Buffer.alloc(bytes.length, "x"));
    await fs.writeFile(path.join(pkg.directory, name + ".version"), pkg.version);
    respond = (_req, res) => {
        res.writeHead(503);
        res.end();
    };
    await assertOutcome(await install(), false);
});

test("reports the original HTTP 503 cause", async () => {
    respond = (_req, res) => {
        res.writeHead(503);
        res.end("unavailable");
    };
    const result = await install();
    await assertOutcome(result, false);
    expect(result.stderr).toContain("Response status was 503");
    expect(result.stderr).not.toContain("ReferenceError");
});

test("ignores redirect and Content-Disposition filenames", async () => {
    respond = (req, res) => {
        if (req.url === `/mirror/v${pkg.version}/${name}`) {
            res.writeHead(302, { Location: "/renamed/package.json" });
            res.end();
        } else {
            res.writeHead(200, { "Content-Disposition": 'attachment; filename="package.json"' });
            res.end(bytes);
        }
    };
    await assertOutcome(await install(), true);
    expect(requests).toEqual([`/mirror/v${pkg.version}/${name}`, "/renamed/package.json"]);
});

test("bounds redirect loops", async () => {
    respond = (_req, res) => {
        res.writeHead(302, { Location: "/loop" });
        res.end();
    };
    const result = await install();
    await assertOutcome(result, false);
    expect(result.stderr).toContain("Too many redirects");
    expect(requests).toHaveLength(11);
});

test.each([
    ["target overrides take precedence", { npm_config_platform: "darwin", npm_config_arch: "arm64" }, name],
    [
        "legacy npm overrides",
        {
            npm_config_target_platform: "",
            npm_config_target_arch: "",
            npm_config_platform: "darwin",
            npm_config_arch: "arm64",
        },
        "matrix-sdk-crypto.darwin-arm64.node",
    ],
    [
        "Linux arm ABI",
        { npm_config_target_platform: "linux", npm_config_target_arch: "arm" },
        "matrix-sdk-crypto.linux-arm-gnueabihf.node",
    ],
])("preserves %s", async (_label, overrides, artifactName) => {
    await assertOutcome(await install(overrides), true, artifactName);
    expect(requests).toEqual([`/mirror/v${pkg.version}/${artifactName}`]);
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
            pkg.manifest.artifacts[name].sha256 = "not-a-digest";
        },
    ],
    [
        "non-string digest",
        () => {
            pkg.manifest.artifacts[name].sha256 = [pkg.manifest.artifacts[name].sha256];
        },
    ],
    [
        "wrong size",
        () => {
            pkg.manifest.artifacts[name].size = -1;
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
            pkg.manifest.artifacts["unknown.node"] = pkg.manifest.artifacts[name];
        },
    ],
])("rejects %s manifest before network", async (label, change) => {
    await change();
    if (!["missing", "malformed"].includes(label)) {
        await fs.writeFile(path.join(pkg.directory, "native-artifacts.json"), JSON.stringify(pkg.manifest));
    }
    await assertOutcome(await install(), false);
    expect(requests).toEqual([]);
});

test.each([
    ["darwin", "x64", "darwin-x64"],
    ["win32", "ia32", "win32-ia32-msvc"],
    ["win32", "arm64", "win32-arm64-msvc"],
    ["linux", "ia32", "linux-ia32-gnu"],
    ["linux", "s390x", "linux-s390x-gnu"],
    ["linux", "riscv64", "linux-riscv64-gnu"],
    ["linux", "x64", `linux-x64-${process.report.getReport().header.glibcVersionRuntime ? "gnu" : "musl"}`],
    ["linux", "arm64", `linux-arm64-${process.report.getReport().header.glibcVersionRuntime ? "gnu" : "musl"}`],
])("selects the supported %s %s artifact", async (platform, arch, target) => {
    const artifactName = `matrix-sdk-crypto.${target}.node`;
    await assertOutcome(
        await install({ npm_config_target_platform: platform, npm_config_target_arch: arch }),
        true,
        artifactName,
    );
    expect(requests).toEqual([`/mirror/v${pkg.version}/${artifactName}`]);
});

test.each(["https_proxy", "HTTPS_PROXY"])("preserves HTTPS redirects through %s", async (proxyVariable) => {
    const https = require("https");
    const net = require("net");
    // Public localhost test identity; trust is scoped to the installer child, never the system.
    const certificatePath = path.join(__dirname, "fixtures", "localhost.crt");
    const secureRequests = [];
    const secure = https.createServer(
        {
            key: await fs.readFile(path.join(__dirname, "fixtures", "localhost.key")),
            cert: await fs.readFile(certificatePath),
        },
        (req, res) => {
            secureRequests.push(req.url);
            if (req.url === "/first") {
                res.writeHead(307, { Location: "relative/package.json" });
                res.end();
            } else {
                res.writeHead(200, { "Content-Disposition": 'attachment; filename="package.json"' });
                res.write(bytes.subarray(0, 7));
                res.end(bytes.subarray(7));
            }
        },
    );
    const connections = new Set();
    secure.on("connection", (socket) => {
        connections.add(socket);
        socket.on("close", () => connections.delete(socket));
    });
    try {
        await new Promise((resolve) => secure.listen(0, "127.0.0.1", resolve));
        const authority = `localhost:${secure.address().port}`;
        const tunnels = [];
        server.on("connect", (req, socket, head) => {
            tunnels.push(req.url);
            // Never proxy arbitrary destinations, even if the tested installer is broken.
            if (req.url !== authority) return socket.destroy();
            const upstream = net.connect(secure.address().port, "127.0.0.1", () => {
                socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
                upstream.write(head);
                upstream.pipe(socket);
                socket.pipe(upstream);
            });
            connections.add(upstream);
            upstream.on("close", () => connections.delete(upstream));
            upstream.on("error", () => socket.destroy());
            socket.on("error", () => upstream.destroy());
            socket.on("close", () => upstream.destroy());
        });
        respond = (_req, res) => {
            res.writeHead(302, { Location: `https://${authority}/first` });
            res.end();
        };
        const result = await install({
            NODE_EXTRA_CA_CERTS: certificatePath,
            // Windows folds environment names; test lowercase precedence only on other platforms.
            ...(process.platform !== "win32" ? { HTTPS_PROXY: "http://127.0.0.1:1" } : {}),
            [proxyVariable]: `http://127.0.0.1:${server.address().port}`,
        });
        await assertOutcome(result, true);
        expect(secureRequests).toEqual(["/first", "/relative/package.json"]);
        expect(tunnels.length).toBeGreaterThanOrEqual(1);
        expect(tunnels.every((destination) => destination === authority)).toBe(true);
    } finally {
        const closed = new Promise((resolve) => secure.close(resolve));
        for (const socket of connections) socket.destroy();
        await closed;
    }
});
