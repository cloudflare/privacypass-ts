// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64url } from 'rfc4648';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
import { BLIND_RSA } from './pub_verif_token.js';
import { VOPRF } from './priv_verif_token.js';
import { AuthorizationHeader, WWWAuthenticateHeader } from './auth_scheme/private_token.js';
import { issuanceProtocolPriv, issuanceProtocolPub } from './issuance.js';

export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * from './auth_scheme/private_token.js';
export * from './pub_verif_token.js';
export * from './priv_verif_token.js';
export * from './issuance.js';

// Privacy Pass Token Type Registry
// Supported:
//  - Token Type VOPRF (P-384, SHA-384)
//  - Token Type Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-registry-updates
export const TOKEN_TYPES = {
    // Token Type Blind RSA (2048-bit)
    BLIND_RSA,
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
//     |      | WWW-Authenticate:         |     |
//     +----- |    PrivateToken challenge | --->|
//     |                                        |
//     |                            (Run issuance protocol)
//     |                                        |
//     |      | Authorization:            |     |
//     |<---- |    PrivateToken token     | ----+
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
    let authHeader: AuthorizationHeader;
    switch (pt.challenge.tokenType) {
        case TOKEN_TYPES.VOPRF.value:
            authHeader = await issuanceProtocolPriv(pt);
            break;
        case TOKEN_TYPES.BLIND_RSA.value:
            authHeader = await issuanceProtocolPub(pt);
            break;
        default:
            console.log(
                `unrecognized or non-supported token type in the challenge: ${pt.challenge.tokenType}`,
            );
            return null;
    }

    const te = new TextEncoder();
    const encodedToken = base64url.stringify(te.encode(authHeader.toString()));
    return encodedToken;
}
