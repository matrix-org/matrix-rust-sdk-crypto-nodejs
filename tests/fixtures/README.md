# Native installer test fixtures

Run the installer and package tests with the Node.js distribution of the pnpm
version pinned in `package.json`:

```sh
pnpm test --runInBand tests/download-lib.test.js tests/native-artifacts.test.js --watchman=false
```

`pnpm test` supplies `npm_execpath`, its actual JavaScript entry. The package tests
verify that entry's version and invoke it through `process.execPath` for packing,
without a shell, PATH lookup, or Windows command shim. Direct Jest invocation and
the standalone pnpm executable are not supported by this test invocation contract.
The packed-inventory test also requires `tar` on PATH to extract the tarball.

`localhost.crt` and `localhost.key` are a deliberately public, test-only TLS
identity, never credentials for a real service. The server binds only to loopback.
Only the installer child trusts this certificate, through `NODE_EXTRA_CA_CERTS`;
TLS certificate verification stays enabled and no system trust store is modified.
The fixtures are excluded from the npm package with the rest of `tests/`.

Running the tests does not require OpenSSL. To regenerate the certificate before
it expires in August 2046, run the following from this directory on a machine with
OpenSSL, then review both resulting files. The configuration file supplies the
extensions without requiring the `-addext` option:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 -config localhost.cnf -keyout localhost.key -out localhost.crt
```

The directory-as-artifact rejection test runs on every platform. The separate
file-symlink rejection test is skipped on Windows because creating that fixture
requires Developer Mode or elevated privileges. Proxy success tests run with one
working variable on Windows; lowercase-over-uppercase precedence is checked only
where environment names are case-sensitive.
