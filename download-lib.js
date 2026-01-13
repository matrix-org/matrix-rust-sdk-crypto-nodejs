const { statSync, writeFileSync, readFileSync } = require('fs');
const path = require('path');
const { HttpsProxyAgent } = require("https-proxy-agent");
const { DownloaderHelper } = require("node-downloader-helper");
const { version } = require("./package.json");

// Get the platform and architecture based on environment variables,
// falling back to the current platform and architecture
const platform = process.env.npm_config_target_platform || process.env.npm_config_platform || process.platform;
const arch = process.env.npm_config_target_arch || process.env.npm_config_arch || process.arch;

const DOWNLOADS_BASE_URL = "https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/releases/download";
const CURRENT_VERSION = `v${version}`;

const byteHelper = function (value) {
    if (value === 0) {
        return "0 b";
    }
    const units = ["b", "kB", "MB", "GB", "TB"];
    const number = Math.floor(Math.log(value) / Math.log(1024));
    return (value / Math.pow(1024, Math.floor(number))).toFixed(1) + " " + units[number];
};

async function download_lib(libname) {
    const VERSION_FILE = path.join(__dirname, libname + ".version");
    try {
        statSync(path.join(__dirname, libname));
        const downloadedVersion = readFileSync(VERSION_FILE, 'utf-8');
        if (downloadedVersion === version) {
            console.debug("File already in place, not downloading");
        }
        return;
    } catch (ex) {
        if (ex.code === 'ENOENT') {
            // Missing file, continue;
        } else {
            console.error(ex);
            process.exit(1);
        }
    }

    let startTime = new Date();

    const url = `${DOWNLOADS_BASE_URL}/${CURRENT_VERSION}/${libname}`;
    console.info(`Downloading lib ${libname} from ${url}`);
    const dl = new DownloaderHelper(url, __dirname, {
        override: true,
    });

    const proxy = process.env.https_proxy ?? process.env.HTTPS_PROXY;
    if (proxy) {
        const proxyAgent = new HttpsProxyAgent(proxy);
        dl.updateOptions({
            httpsRequestOptions: { agent: proxyAgent },
        });
    }

    dl.on("end", () => console.info("Download Completed"));
    dl.on("error", (err) => console.info("Download Failed", err));
    dl.on("progress", (stats) => {
        const progress = stats.progress.toFixed(1);
        const speed = byteHelper(stats.speed);
        const downloaded = byteHelper(stats.downloaded);
        const total = byteHelper(stats.total);

        // print every one second (`progress.throttled` can be used instead)
        const currentTime = new Date();
        const elaspsedTime = currentTime - startTime;
        if (elaspsedTime > 1000) {
            startTime = currentTime;
            console.info(`${speed}/s - ${progress}% [${downloaded}/${total}]`);
        }
    });
    try {
        await dl.start();
        writeFileSync(path.join(__dirname, libname + ".version"), version);
    } catch (ex) {
        console.error(err);
        process.exit(1);
    }
}

function isMusl() {
    const { glibcVersionRuntime } = process.report.getReport().header;
    return !glibcVersionRuntime;
}

switch (platform) {
    case "win32":
        switch (arch) {
            case "x64":
                download_lib("matrix-sdk-crypto.win32-x64-msvc.node");
                break;
            case "ia32":
                download_lib("matrix-sdk-crypto.win32-ia32-msvc.node");
                break;
            case "arm64":
                download_lib("matrix-sdk-crypto.win32-arm64-msvc.node");
                break;
            default:
                throw new Error(`Unsupported architecture on Windows: ${arch}`);
        }
        break;
    case "darwin":
        switch (arch) {
            case "x64":
                download_lib("matrix-sdk-crypto.darwin-x64.node");
                break;
            case "arm64":
                download_lib("matrix-sdk-crypto.darwin-arm64.node");
                break;
            default:
                throw new Error(`Unsupported architecture on macOS: ${arch}`);
        }
        break;
    case "linux":
        switch (arch) {
            case "x64":
                if (isMusl()) {
                    download_lib("matrix-sdk-crypto.linux-x64-musl.node");
                } else {
                    download_lib("matrix-sdk-crypto.linux-x64-gnu.node");
                }
                break;
            case "arm64":
                if (isMusl()) {
                    throw new Error("Linux for arm64 musl isn't support at the moment");
                } else {
                    download_lib("matrix-sdk-crypto.linux-arm64-gnu.node");
                }
                break;
            case "arm":
                download_lib("matrix-sdk-crypto.linux-arm-gnueabihf.node");
                break;
            case "s390x":
                download_lib("matrix-sdk-crypto.linux-s390x-gnu.node");
                break;
            default:
                throw new Error(`Unsupported architecture on Linux: ${arch}`);
        }
        break;
    default:
        throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`);
}
