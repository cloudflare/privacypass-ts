// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64url } from 'rfc4648';
import { WWWAuthenticateHeader, type TokenTypeEntry } from './auth_scheme/private_token.js';
import {
    Client as PublicVerifClient,
    BLIND_RSA,
    PARTIALLY_BLIND_RSA,
    BlindRSAMode,
} from './pub_verif_token.js';
import { Client as PrivateVerifClient, VOPRF } from './priv_verif_token.js';
import { fetchToken, type PrivacyPassClient } from './issuance.js';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';

export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * from './auth_scheme/private_token.js';
export * from './issuance.js';
export * as arbitraryBatched from './arbitrary_batched_token.js';
export * as privateVerif from './priv_verif_token.js';
export * as publicVerif from './pub_verif_token.js';

// Privacy Pass Token Type Registry
// Supported:
//  - Token Type VOPRF (P-384, SHA-384)
//  - Token Type Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-registry-updates
export const TOKEN_TYPES = {
    // Token Type Blind RSA (2048-bit)
    BLIND_RSA,
    // Token Type Partially Blind RSA (2048-bit)
    PARTIALLY_BLIND_RSA,
    // Token Type VOPRF (P-384, SHA-384)
    VOPRF,
} as const;

// The Privacy Pass HTTP Authentication Scheme
//
// Ref. https://datatracker.ietf.org/doc/draft-ietf-privacypass-auth-scheme/
//
// +--------+                               +--------+
// | Origin |                               | Client |
// +---+----+                               +---+----+
//     |                                        |
//     +-- WWW-Authenticate: TokenChallenge --->|
//     |                                        |
//     |                            (Run issuance protocol)
//     |                                        |
//     |<------ Authorization: Token -----------+
//     |                                        |
//

// header_to_token parses a WWAuthenticate header received from
// the Origin, and runs the issuance protocol, which returns an
// Authorization header ready to be redeemed by the Origin.
export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = WWWAuthenticateHeader.parse(header);
    if (privateTokens.length === 0) {
        return null;
    }

    // On the presence of multiple challenges, it takes the first one.
    const pt = privateTokens[0];

    let client: PrivacyPassClient;
    switch (pt.challenge.tokenType) {
        case TOKEN_TYPES.VOPRF.value:
            client = new PrivateVerifClient();
            break;
        case TOKEN_TYPES.BLIND_RSA.value:
            client = new PublicVerifClient(BlindRSAMode.PSS);
            break;
        default:
            console.log(
                `unrecognized or non-supported token type in the challenge: ${pt.challenge.tokenType}`,
            );
            return null;
    }

    const te = new TextEncoder();
    const authHeader = await fetchToken(client, pt);
    const encodedToken = base64url.stringify(te.encode(authHeader.toString()));
    return encodedToken;
}

export function tokenRequestToTokenTypeEntry(bytes: Uint8Array): TokenTypeEntry {
    // All token requests have a 2-byte value at the beginning of the token describing TokenTypeEntry.
    const input = new DataView(bytes.buffer);

    const type = input.getUint16(0);
    const tokenType = Object.values(TOKEN_TYPES).find((t) => t.value === type);

    if (tokenType === undefined) {
        throw new Error(`unrecognized or non-supported token type: ${type}`);
    }

    return tokenType;
}
