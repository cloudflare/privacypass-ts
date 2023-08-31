// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TokenType as PubTokenType, fetchPublicVerifToken } from './pubVerifToken.js';
import { PrivateToken } from './httpAuthScheme.js';
import { base64url } from 'rfc4648';

import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
export const util = { convertEncToRSASSAPSS, convertRSASSAPSSToEnc };
export * as pubVerfiToken from './pubVerifToken.js';
export * as httpAuthScheme from './httpAuthScheme.js';
export * as issuance from './issuance.js';

export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = PrivateToken.parseMultiple(header);
    if (privateTokens.length === 0) {
        return null;
    }

    // Takes the first one.
    const pt = privateTokens[0];
    const tokenType = pt.challenge.tokenType;
    switch (tokenType) {
        case PubTokenType.value: {
            const token = await fetchPublicVerifToken(pt);
            const encodedToken = base64url.stringify(token.serialize());
            return encodedToken;
        }

        default:
            console.log(`unrecognized or non-supported type of challenge: ${tokenType}`);
    }
    return null;
}
