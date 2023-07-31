import { TokenType as PubTokenType, fetchPublicVerifToken } from './pubVerifToken.js';
import { parseWWWAuthHeader } from './httpAuthScheme.js';
import { base64url } from 'rfc4648';

export async function header_to_token(requestId: string, header: string): Promise<string | null> {
    const tokenDetails = parseWWWAuthHeader(header);
    if (tokenDetails.length === 0) {
        return null;
    }

    console.log('new token details for: ', requestId);
    const td = tokenDetails[0];
    switch (td.type) {
        case PubTokenType.value: {
            console.log(`type of challenge: ${td.type} is supported`);
            const token = await fetchPublicVerifToken(td);
            const encodedToken = base64url.stringify(token.serialize());
            return encodedToken;
        }

        default:
            console.log(`unrecognized or non-supported type of challenge: ${td.type}`);
    }
    return null;
}

export interface TokenTypeEntry {
    name: string;
    value: number;
    Nk: number;
    Nid: number;
}
