const { createWriteStream } = require("fs");
const { mkdtemp, rename, rm } = require("fs/promises");
const http = require("http");
const https = require("https");
const path = require("path");
const { pipeline } = require("stream/promises");
const { HttpsProxyAgent } = require("https-proxy-agent");
const { filenames, readManifest, verifyArtifact } = require("./native-artifacts");
const { version } = require("./package.json");

async function download(url, destination) {
    const proxy = process.env.https_proxy ?? process.env.HTTPS_PROXY;
    const agent = proxy ? new HttpsProxyAgent(proxy) : undefined;
    try {
        for (let redirects = 0; redirects <= 10; redirects++) {
            const protocol = new URL(url).protocol;
            if (protocol !== "https:" && protocol !== "http:") {
                throw new Error(`Unsupported download protocol: ${protocol}`);
            }
            const transport = protocol === "https:" ? https : http;
            let requestError;
            let requestClosed;
            const response = await new Promise((resolve, reject) => {
                const request = transport.get(url, { agent: protocol === "https:" ? agent : undefined }, resolve);
                requestClosed = new Promise((resolve) => request.once("close", resolve));
                request.on("error", (error) => {
                    requestError = error;
                    reject(error);
                });
            });
            if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
                response.destroy();
                url = new URL(response.headers.location, url).href;
                continue;
            }
            if (response.statusCode < 200 || response.statusCode >= 300) {
                response.destroy();
                throw new Error(`Response status was ${response.statusCode}`);
            }
            // pipeline rejects truncated responses, including chunked bodies without a final chunk.
            // The destination is ours; Content-Disposition and redirect filenames never choose it.
            await pipeline(response, createWriteStream(destination, { flags: "wx" }));
            // HTTP parser errors can arrive on the request after its response was delivered.
            await requestClosed;
            if (requestError) throw requestError;
            if (!response.complete) throw new Error("Incomplete native artifact response");
            return;
        }
        throw new Error("Too many redirects");
    } finally {
        agent?.destroy();
    }
}

async function downloadLib() {
    const artifacts = await readManifest();
    // Keep npm's target overrides ahead of the host platform and architecture.
    const platform = process.env.npm_config_target_platform || process.env.npm_config_platform || process.platform;
    const arch = process.env.npm_config_target_arch || process.env.npm_config_arch || process.arch;
    let target = `${platform}-${arch}`;
    if (platform === "win32") target += "-msvc";
    if (platform === "linux") {
        const musl = ["x64", "arm64"].includes(arch) && !process.report.getReport().header.glibcVersionRuntime;
        target += arch === "arm" ? "-gnueabihf" : musl ? "-musl" : "-gnu";
    }
    const name = `matrix-sdk-crypto.${target}.node`;
    if (!filenames.includes(name)) throw new Error(`Unsupported OS or architecture: ${platform}, ${arch}`);

    const finalPath = path.join(__dirname, name);
    await rm(finalPath + ".version", { force: true });
    if (await verifyArtifact(finalPath, artifacts[name])) {
        console.debug("File already in place, not downloading");
        return;
    }
    await rm(finalPath, { force: true });
    const staging = await mkdtemp(path.join(__dirname, ".native-artifact-"));
    try {
        const baseUrl =
            process.env.MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL ||
            "https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/releases/download";
        console.info(`Downloading lib ${name}`);
        const stagedPath = path.join(staging, name);
        await download(`${baseUrl.replace(/\/$/, "")}/v${version}/${name}`, stagedPath);
        if (!(await verifyArtifact(stagedPath, artifacts[name]))) {
            throw new Error(`Native artifact integrity check failed for ${name}: SHA-256 or size mismatch`);
        }
        await rename(stagedPath, finalPath);
    } finally {
        await rm(staging, { recursive: true, force: true });
    }
    console.info("Download Completed");
}

downloadLib().catch((error) => {
    console.error("Download Failed:", error);
    process.exitCode = 1;
});
