// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import type { TokenTypeEntry } from './auth_scheme/private_token.js';

export const VOPRF_TOKEN_TYPE = {
    value: 0x0001,
    name: 'VOPRF (P-384, SHA-384)',
    Nk: 48,
    Nid: 32,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
} as const satisfies Readonly<TokenTypeEntry>;

export const BLIND_RSA_TOKEN_TYPE = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
} as const satisfies Readonly<TokenTypeEntry>;

export const PARTIALLY_BLIND_RSA_TOKEN_TYPE = {
    value: 0xda7a,
    name: 'Partially Blind RSA (2048-bit)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: true,
    privateMetadata: false,
} as const satisfies Readonly<TokenTypeEntry>;

export const TOKEN_TYPES = {
    // Token Type Blind RSA (2048-bit)
    BLIND_RSA: BLIND_RSA_TOKEN_TYPE,
    // Token Type Partially Blind RSA (2048-bit)
    PARTIALLY_BLIND_RSA: PARTIALLY_BLIND_RSA_TOKEN_TYPE,
    // Token Type VOPRF (P-384, SHA-384)
    VOPRF: VOPRF_TOKEN_TYPE,
} as const;

export type TokenTypeRegistry = Record<string, TokenTypeEntry>;

export function tokenEntryToSerializedLength(tokenType: TokenTypeEntry): number {
    // TokenRequest structure: 2-byte token_type + 1-byte truncated_token_key_id + blinded_msg
    const headerLen = 3; // token_type (2) + truncated_token_key_id (1)
    switch (tokenType.value) {
        case TOKEN_TYPES.VOPRF.value:
            return headerLen + 49;
        case TOKEN_TYPES.BLIND_RSA.value:
            return headerLen + TOKEN_TYPES.BLIND_RSA.Nk;
        case TOKEN_TYPES.PARTIALLY_BLIND_RSA.value:
            return headerLen + TOKEN_TYPES.PARTIALLY_BLIND_RSA.Nk;
        default:
            throw new Error(`unrecognized or non-supported token type: ${tokenType.value}`);
    }
}

export function tokenRequestToTokenTypeEntry(
    bytes: Uint8Array,
    registry: TokenTypeRegistry = TOKEN_TYPES,
): TokenTypeEntry {
    // All token requests have a 2-byte value at the beginning of the token describing TokenTypeEntry.
    const input = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const type = input.getUint16(0);
    const tokenType = Object.values(registry).find((t) => t.value === type);

    if (tokenType === undefined) {
        throw new Error(`unrecognized or non-supported token type: ${type}`);
    }

    return tokenType;
}
