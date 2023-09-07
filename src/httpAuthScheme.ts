// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// The Privacy Pass HTTP Authentication Scheme
//
// Ref. https://datatracker.ietf.org/doc/draft-ietf-privacypass-auth-scheme/
//
// +--------+                              +--------+
// | Origin |                              | Client |
// +---+----+                              +---+----+
//     |                                       |
//     +-- WWW-Authenticate: PrivateToken ---->|
//     |                                       |
//     |                            (Run issuance protocol)
//     |                                       |
//     |<------ Authorization: Token ----------+
//     |                                       |
//
// Figure 1: Challenge-response redemption protocol flow.

import { base64url } from 'rfc4648';

import {
    parseWWWAuthenticate,
    parseWWWAuthenticateWithNonCompliantTokens,
    toStringWWWAuthenticate,
} from './rfc9110.js';
import { Token, TokenTypeEntry, TokenChallenge } from './tokenBase.js';

const AUTH_SCHEME_NAME = 'PrivateToken';

export class WWWAuthenticateHeader {
    constructor(
        public challenge: TokenChallenge,
        public tokenKey: Uint8Array,
        public maxAge?: number, // an optional parameter that consists of the number of seconds for which the challenge will be accepted by the origin.
    ) {}

    private static parseSingle(data: string): WWWAuthenticateHeader {
        // Consumes data:
        //   challenge="abc...", token-key="123..."

        const attributes = data.split(',');
        let challenge = undefined;
        let challengeSerialized = undefined;
        let tokenKey = undefined;
        let maxAge = undefined;

        for (const attr of attributes) {
            const idx = attr.indexOf('=');
            let attrKey = attr.substring(0, idx);
            let attrValue = attr.substring(idx + 1);
            attrValue = attrValue.replaceAll('"', '');
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();

            switch (attrKey) {
                case 'challenge':
                    challengeSerialized = base64url.parse(attrValue);
                    challenge = TokenChallenge.deserialize(challengeSerialized);
                    break;
                case 'token-key':
                    tokenKey = base64url.parse(attrValue);
                    break;
                case 'max-age':
                    maxAge = parseInt(attrValue);
                    break;
            }
        }

        // Check for mandatory fields.
        if (
            challenge === undefined ||
            challengeSerialized === undefined ||
            tokenKey === undefined
        ) {
            throw new Error('cannot parse PrivateToken');
        }

        return new WWWAuthenticateHeader(challenge, tokenKey, maxAge);
    }

    private static parseInternal(
        header: string,
        parseWWWAuthenticate: (header: string) => string[],
    ): WWWAuthenticateHeader[] {
        // Consumes data:
        //   PrivateToken challenge="abc...", token-key="123...",
        //   PrivateToken challenge="def...", token-key="234..."
        const challenges = parseWWWAuthenticate(header);

        const listTokens = new Array<WWWAuthenticateHeader>();

        for (const challenge of challenges) {
            if (!challenge.startsWith(`${AUTH_SCHEME_NAME} `)) {
                continue;
            }
            const chl = challenge.slice(`${AUTH_SCHEME_NAME} `.length);
            const privToken = WWWAuthenticateHeader.parseSingle(chl);
            listTokens.push(privToken);
        }

        return listTokens;
    }

    static parse(header: string): WWWAuthenticateHeader[] {
        const tokens = this.parseInternal(header, parseWWWAuthenticate);
        // if compliant tokens are found, return them
        if (tokens.length !== 0) {
            return tokens;
        }
        // otherwise, parse the challenge again including non compliant tokens
        return this.parseInternal(header, parseWWWAuthenticateWithNonCompliantTokens);
    }

    toString(quotedString = false): string {
        const authParams: Record<string, string | number> = {
            challenge: base64url.stringify(this.challenge.serialize()),
            'token-key': base64url.stringify(this.tokenKey),
        };
        if (this.maxAge) {
            authParams['max-age'] = this.maxAge;
        }
        return toStringWWWAuthenticate(AUTH_SCHEME_NAME, authParams, quotedString);
    }
}

export class AuthorizationHeader {
    constructor(public token: Token) {}

    private static parseSingle(tokenTypeEntry: TokenTypeEntry, data: string): AuthorizationHeader {
        // Consumes data:
        //   token="abc..."

        const attributes = data.split(',');
        let ppToken: Token | undefined = undefined;

        for (const attr of attributes) {
            const idx = attr.indexOf('=');
            let attrKey = attr.substring(0, idx);
            let attrValue = attr.substring(idx + 1);
            attrValue = attrValue.replaceAll('"', '');
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();

            if (attrKey === 'token') {
                const tokenEnc = base64url.parse(attrValue);
                ppToken = Token.deserialize(tokenTypeEntry, tokenEnc);
            }
        }

        // Check for mandatory fields.
        if (ppToken === undefined) {
            throw new Error('cannot parse token');
        }

        return new AuthorizationHeader(ppToken);
    }

    private static parseInternal(
        tokenTypeEntry: TokenTypeEntry,
        header: string,
        parseWWWAuthenticate: (header: string) => string[],
    ): AuthorizationHeader[] {
        // Consumes data:
        //   PrivateToken token="abc...",
        //   PrivateToken token=def...
        const challenges = parseWWWAuthenticate(header);

        const listTokens = new Array<AuthorizationHeader>();

        for (const challenge of challenges) {
            if (!challenge.startsWith(`${AUTH_SCHEME_NAME} `)) {
                continue;
            }
            const chl = challenge.slice(`${AUTH_SCHEME_NAME} `.length);
            const privToken = AuthorizationHeader.parseSingle(tokenTypeEntry, chl);
            listTokens.push(privToken);
        }

        return listTokens;
    }

    static parse(tokenTypeEntry: TokenTypeEntry, header: string): AuthorizationHeader[] {
        const tokens = this.parseInternal(tokenTypeEntry, header, parseWWWAuthenticate);
        // if compliant tokens are found, return them
        if (tokens.length !== 0) {
            return tokens;
        }
        // otherwise, parse the challenge again including non compliant tokens
        return this.parseInternal(
            tokenTypeEntry,
            header,
            parseWWWAuthenticateWithNonCompliantTokens,
        );
    }

    toString(quotedString = false): string {
        const token = base64url.stringify(this.token.serialize());
        return toStringWWWAuthenticate(AUTH_SCHEME_NAME, { token }, quotedString);
    }
}
