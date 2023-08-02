// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TokenType as PubTokenType, fetchPublicVerifToken } from './pubVerifToken.js';
import { parsePrivateTokens, TokenChallenge } from './httpAuthScheme.js';
import { base64url } from 'rfc4648';

export async function header_to_token(header: string): Promise<string | null> {
    const privateTokens = parsePrivateTokens(header);
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

export { TokenChallenge };
