const { spawnSync } = require("child_process");
const path = require("path");
const { version } = require("../package.json");

// Executed in a child process so the entrypoint uses real stderr and process.exit.
function installerChild() {
    const scenario = process.argv[1];
    const bindings = {
        "fs": {
            statSync() {
                throw Object.assign(new Error("Missing native library"), { code: "ENOENT" });
            },
            writeFileSync(filename, contents) {
                if (scenario === "write") {
                    throw Object.assign(new Error("synthetic EACCES"), { code: "EACCES" });
                }
                console.log("VERSION_WRITE", JSON.stringify([filename, contents]));
            },
        },
        "path": require("path"),
        "https-proxy-agent": {},
        "node-downloader-helper": {
            DownloaderHelper: class extends require("events").EventEmitter {
                async start() {
                    if (scenario === "download") {
                        const error = Object.assign(new Error("synthetic ECONNRESET"), { code: "ECONNRESET" });
                        this.emit("error", error);
                        throw error;
                    }
                    this.emit("end");
                }
            },
        },
        "./package.json": require("./package.json"),
    };
    const filename = require("path").join(process.cwd(), "download-lib.js");
    require("vm").runInNewContext(
        require("fs").readFileSync(filename, "utf8"),
        {
            require: (id) => bindings[id],
            __dirname: process.cwd(),
            console,
            process: {
                env: { npm_config_target_platform: "darwin", npm_config_target_arch: "x64" },
                exit: process.exit,
            },
        },
        { filename },
    );
}

function runInstaller(scenario) {
    const result = spawnSync(
        process.execPath,
        ["--unhandled-rejections=strict", "-e", `(${installerChild.toString()})()`, scenario],
        { cwd: path.join(__dirname, ".."), encoding: "utf8" },
    );
    expect(result.error).toBeUndefined();
    expect(result.signal).toBeNull();
    return result;
}

describe("download-lib.js", () => {
    test.each([
        ["download", "ECONNRESET"],
        ["write", "EACCES"],
    ])("reports the original %s error and exits unsuccessfully", (scenario, code) => {
        const result = runInstaller(scenario);

        expect(result.status).toBe(1);
        expect(result.stderr).not.toContain("ReferenceError");
        expect(result.stderr).toContain(`Error: synthetic ${code}`);
        expect(result.stdout).not.toContain("VERSION_WRITE");
    });

    test("writes the version marker and exits successfully after downloading", () => {
        const result = runInstaller("success");
        const versionFile = path.join(__dirname, "..", "matrix-sdk-crypto.darwin-x64.node.version");

        expect(result.status).toBe(0);
        expect(result.stderr).toBe("");
        expect(result.stdout.split("\n").filter((line) => line.startsWith("VERSION_WRITE "))).toEqual([
            `VERSION_WRITE ${JSON.stringify([versionFile, version])}`,
        ]);
    });
});
