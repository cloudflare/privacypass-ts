// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TOKEN_TYPES } from './pubVerifToken.js';
import { PrivateToken, Token } from './httpAuthScheme.js';
import { base64url } from 'rfc4648';

import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * from './pubVerifToken.js';
export * from './httpAuthScheme.js';
export * from './issuance.js';

export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = PrivateToken.parse(header);
    if (privateTokens.length === 0) {
        return null;
    }

    // Takes the first one.
    const pt = privateTokens[0];
    const tokenType = pt.challenge.tokenType;
    switch (tokenType) {
        case TOKEN_TYPES.BLIND_RSA.value: {
            const token = await Token.fetch(pt);
            const encodedToken = base64url.stringify(token.serialize());
            return encodedToken;
        }

        default:
            console.log(`unrecognized or non-supported type of challenge: ${tokenType}`);
    }
    return null;
}
