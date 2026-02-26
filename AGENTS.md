# AGENTS.md

Privacy Pass TypeScript implementation. Compliant with:

-   [RFC 9576](https://datatracker.ietf.org/doc/html/rfc9576) — Privacy Pass Architecture (roles, deployment models, security considerations)
-   [RFC 9578](https://datatracker.ietf.org/doc/html/rfc9578) — Privacy Pass Issuance Protocol
-   [draft-hendrickson-privacypass-public-metadata](https://datatracker.ietf.org/doc/draft-hendrickson-privacypass-public-metadata/) — Public Metadata (Partially Blind RSA)
-   [draft-ietf-privacypass-batched-tokens](https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/) — Batched Tokens

Reference implementations to cross-check behavior when debugging protocol issues.

1. [pat-go](https://github.com/cloudflare/pat-go) (Cloudflare's Go implementation),
2. [privacypass](https://github.com/raphaelrobert/privacypass) (Raphael Robert's Rust implementation).

## Token Types

| Type                         | Module           | Crypto              |
| ---------------------------- | ---------------- | ------------------- |
| Public-Verifiable            | `publicVerif`    | Blind RSA           |
| Public-Verifiable + Metadata | `publicVerif`    | Partially Blind RSA |
| Private-Verifiable           | `privateVerif`   | VOPRF (P-384)       |
| Batched (generic)            | `genericBatched` | Any of above        |

## Structure

```
src/
  index.ts              # exports, TOKEN_TYPES registry
  pub_verif_token.ts    # Blind RSA / Partially Blind RSA
  priv_verif_token.ts   # VOPRF
  generic_batched_token.ts
  issuance.ts           # fetch helpers, MediaType enum
  auth_scheme/          # WWW-Authenticate / Authorization parsing (RFC 9110)
test/
  *.test.ts             # vitest tests
  test_data/            # JSON test vectors (Go, Rust implementations)
examples/               # usage examples — run with `npm run examples`
```

## Requirements

-   **Node.js ≥20**
-   **npm** (not pnpm/yarn)
-   **ESM-only** — uses `"type": "module"`, all imports need `.js` extensions

## Commands

```bash
npm ci            # install dependencies
npm run build     # tsc -b (required before test/bench/examples)
npm run test      # vitest
npm run lint      # eslint
npm run format    # prettier
npm run examples  # run examples (builds first)
npm run bench     # run benchmarks (builds first)
```

See [README.md](README.md) for full usage.

## Code Patterns

### Serialization

All wire types implement `serialize(): Uint8Array` and `static deserialize(bytes: Uint8Array): T`.

```typescript
class TokenRequest {
    serialize(): Uint8Array {
        /* ... */
    }
    static deserialize(tokenType: TokenTypeEntry, bytes: Uint8Array): TokenRequest {
        /* ... */
    }
}
```


### Role Classes

Per [RFC 9576](https://datatracker.ietf.org/doc/html/rfc9576) (Privacy Pass Architecture), each token type exposes three roles:

-   `Client` — creates token requests, finalizes tokens
-   `Issuer` — signs blinded requests
-   `Origin` — creates challenges, verifies tokens

### Type Imports/Exports

ESLint enforces `consistent-type-imports` and `consistent-type-exports`:

```typescript
// use `import type` for type-only imports
import type { TokenChallenge } from './auth_scheme/private_token.js';

// use `export type` for type-only exports
export type { TokenReq, TokenRes };
```

### Unused Variables

Prefix with underscore to satisfy `noUnusedLocals`/`noUnusedParameters`:

```typescript
function example(_unusedParam: string): void {
    /* ... */
}
```

## Testing

### Test Vectors

Vectors live in `test/test_data/` as JSON. Sources:

-   Go: RFC 9578 reference implementation
-   Rust: [raphaelrobert/privacypass](https://github.com/raphaelrobert/privacypass)

### Adding Test Vectors

1. Generate vectors from another implementation (see [Interop Wiki](https://github.com/raphaelrobert/privacypass/wiki/Interop))
2. Place JSON in `test/test_data/` with naming convention: `{token_type}_{source}.json`
3. Import in relevant `*.test.ts` and add to test array

Example from `pub_verif_token.test.ts`:

```typescript
import vectorsGo from './test_data/pub_verif_rfc9578.go.json';
import vectorsRust from './test_data/pub_verif_rfc9578.rust.json';
const vectors = [...vectorsGo, ...vectorsRust];

describe.each(vectors)('PublicVerifiable-Vector-%#', (v: Vectors) => {
    /* ... */
});
```

### Test Helpers

-   `testSerialize(Type, instance)` — roundtrip serialize/deserialize
-   `testSerializeType(tokenType, Type, instance)` — same, with token type param
-   `hexToUint8`, `uint8ToHex` — hex conversion utilities

## Platform Constraints

**Partially Blind RSA verification does not work in browsers.** WebCrypto implementations reject the large public exponents required by the protocol. See [Chromium bug](https://issues.chromium.org/issues/340178598), [Firefox bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1896444).

Workaround: verify tokens server-side only.

## Extensions

Token requests can carry extensions per [draft-hendrickson-privacypass-public-metadata](https://datatracker.ietf.org/doc/draft-hendrickson-privacypass-public-metadata/). See `Extensions` class in `src/auth_scheme/private_token.ts`. This is draft-stage; API may change.

## IETF Compliance

This library tracks IETF specifications. When drafts advance (new versions or RFC publication), update the implementation accordingly. Check the [IETF Privacy Pass WG](https://datatracker.ietf.org/wg/privacypass/documents/) for current document status.

## Dependencies

-   [@cloudflare/blindrsa-ts](https://github.com/cloudflare/blindrsa-ts) — Blind RSA, Partially Blind RSA
-   [@cloudflare/voprf-ts](https://github.com/cloudflare/voprf-ts) — VOPRF
