# Vendored third-party code

Everything here is pinned and checked in, so the server never downloads code at
runtime and the browser never loads anything from another site.

## age.js

The browser-side age decryptor used by the Vault page. It decrypts your
records on your own device; your private key never reaches the server.

| | |
|---|---|
| Package | `age-encryption` 0.3.1 (typage, by Filippo Valsorda, author of age) |
| Source | https://github.com/FiloSottile/typage |
| Bundled dependencies | @noble/ciphers 2.4.0, @noble/curves 2.4.0 and 2.0.1, @noble/hashes 2.4.0 and 2.0.1, @noble/post-quantum 0.5.4, @scure/base 2.4.0 |
| Built with | esbuild 0.25.10, not minified so it can be read |
| SHA-256 | `45822ca38a76da01ee27acc3768e267c75e76575fa8ca474494e32967351cebc` |
| License | BSD-3-Clause (typage); MIT (noble, scure) |

Rebuild (should produce the same hash):

```sh
cd "$(mktemp -d)" && npm init -y >/dev/null
npm install --save-exact age-encryption@0.3.1 esbuild@0.25.10
npx esbuild --bundle --format=esm --target=es2022 --legal-comments=inline \
    --outfile=age.js age-encryption
sha256sum age.js
```

## Fonts (../fonts)

IBM Plex Sans and JetBrains Mono, latin subset, weights 400/500/600, from
`@fontsource/ibm-plex-sans` 5.2.6 and `@fontsource/jetbrains-mono` 5.2.6.
Both are under the SIL Open Font License 1.1 (see the OFL-*.txt files).
