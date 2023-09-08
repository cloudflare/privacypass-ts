// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64url } from 'rfc4648';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
import { BLIND_RSA } from './pub_verif_token.js';
import { VOPRF } from './priv_verif_token.js';
import { type TokenTypeEntry, WWWAuthenticateHeader } from './auth_scheme/private_token.js';
import { issuanceProtocolPriv, issuanceProtocolPub } from './issuance.js';

export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * from './auth_scheme/private_token.js';
export * from './pub_verif_token.js';
export * from './priv_verif_token.js';
export * from './issuance.js';

// Privacy Pass Token Type Registry
// Updates:
//  - Token Type Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-12#name-token-type-registry-updates
export const TOKEN_TYPES: Record<string, Readonly<TokenTypeEntry>> = {
    // Token Type Blind RSA (2048-bit)
    BLIND_RSA,
    // Token Type VOPRF (P-384, SHA-384)
    VOPRF,
} as const;

export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = WWWAuthenticateHeader.parse(header);
    if (privateTokens.length === 0) {
        return null;
    }

    // Takes the first one.
    const pt = privateTokens[0];
    const tokenType = pt.challenge.tokenType;
    const te = new TextEncoder();
    switch (tokenType) {
        case TOKEN_TYPES.VOPRF.value: {
            const token = await issuanceProtocolPriv(pt);
            const encodedToken = base64url.stringify(te.encode(token.toString()));
            return encodedToken;
        }

        case TOKEN_TYPES.BLIND_RSA.value: {
            const token = await issuanceProtocolPub(pt);
            const encodedToken = base64url.stringify(te.encode(token.toString()));
            return encodedToken;
        }

        default:
            console.log(`unrecognized or non-supported type of challenge: ${tokenType}`);
    }
    return null;
}
