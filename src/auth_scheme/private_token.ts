// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

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
// Figure 1: Challenge and redemption protocol flow

import { base64url } from 'rfc4648';

import {
    parseWWWAuthenticate,
    parseWWWAuthenticateWithNonCompliantTokens,
    toStringWWWAuthenticate,
} from './rfc9110.js';
import { joinAll } from '../util.js';

export const AUTH_SCHEME_NAME = 'PrivateToken';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-type-registry
export interface TokenTypeEntry {
    value: number;
    name: string;
    publicVerifiable: boolean;
    publicMetadata: boolean;
    privateMetadata: boolean;
    Nk: number;
    Nid: number;
}

export class TokenChallenge {
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-challenge
    //
    // struct {
    //     uint16_t token_type;
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    // } TokenChallenge;

    static readonly REDEMPTION_CONTEXT_LENGTH = [0, 32];

    constructor(
        public readonly tokenType: number,
        public readonly issuerName: string,
        public readonly redemptionContext: Uint8Array,
        public readonly originInfo?: string[],
    ) {
        const MAX_UINT16 = (1 << 16) - 1;
        if (issuerName.length > MAX_UINT16) {
            throw new Error('invalid issuer name size');
        }

        if (originInfo) {
            const allOriginInfo = originInfo.join(',');
            if (allOriginInfo.length > MAX_UINT16) {
                throw new Error('invalid origin info size');
            }
        }

        if (!TokenChallenge.REDEMPTION_CONTEXT_LENGTH.includes(redemptionContext.length)) {
            throw new Error('invalid redemptionContext size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenChallenge {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        let len = input.getUint16(offset);
        offset += 2;
        const issuerNameBytes = input.buffer.slice(offset, offset + len);
        offset += len;

        const td = new TextDecoder();
        const issuerName = td.decode(issuerNameBytes);

        len = input.getUint8(offset);
        offset += 1;
        const redemptionContext = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = input.getUint16(offset);
        offset += 2;

        let originInfo = undefined;
        if (len > 0) {
            const allOriginInfoBytes = input.buffer.slice(offset, offset + len);
            const allOriginInfo = td.decode(allOriginInfoBytes);
            originInfo = allOriginInfo.split(',');
        }

        return new TokenChallenge(type, issuerName, redemptionContext, originInfo);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        const te = new TextEncoder();
        const issuerNameBytes = te.encode(this.issuerName);

        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, issuerNameBytes.length);
        output.push(b);

        b = issuerNameBytes.buffer;
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.redemptionContext.length);
        output.push(b);

        b = this.redemptionContext.buffer;
        output.push(b);

        b = new ArrayBuffer(2);

        let allOriginInfoBytes = new Uint8Array(0);
        if (this.originInfo) {
            const allOriginInfo = this.originInfo.join(',');
            allOriginInfoBytes = te.encode(allOriginInfo);
        }

        new DataView(b).setUint16(0, allOriginInfoBytes.length);
        output.push(b);

        b = allOriginInfoBytes.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class AuthenticatorInput {
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-verification
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    // } AuthenticatorInput;

    static readonly NONCE_LENGTH = 32;
    static readonly CHALLENGE_LENGTH = 32;

    constructor(
        tokenTypeEntry: TokenTypeEntry,
        public readonly tokenType: number,
        public readonly nonce: Uint8Array,
        public readonly challengeDigest: Uint8Array,
        public readonly tokenKeyId: Uint8Array,
    ) {
        if (tokenType !== tokenTypeEntry.value) {
            throw new Error('mismatch of token type');
        }

        if (nonce.length !== AuthenticatorInput.NONCE_LENGTH) {
            throw new Error('invalid nonce size');
        }

        if (challengeDigest.length !== AuthenticatorInput.CHALLENGE_LENGTH) {
            throw new Error('invalid challenge size');
        }

        if (tokenKeyId.length !== tokenTypeEntry.Nid) {
            throw new Error('invalid tokenKeyId size');
        }

        this.tokenType = tokenTypeEntry.value;
    }

    static deserialize(
        tokenTypeEntry: TokenTypeEntry,
        bytes: Uint8Array,
        ops: { bytesRead: number },
    ): AuthenticatorInput {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        let len = AuthenticatorInput.NONCE_LENGTH;
        const nonce = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = AuthenticatorInput.CHALLENGE_LENGTH;
        const challengeDigest = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = tokenTypeEntry.Nid;
        const tokenKeyId = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        ops.bytesRead = offset;

        return new AuthenticatorInput(tokenTypeEntry, type, nonce, challengeDigest, tokenKeyId);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = this.nonce.buffer;
        output.push(b);

        b = this.challengeDigest.buffer;
        output.push(b);

        b = this.tokenKeyId.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class Token {
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-structure
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    //     uint8_t authenticator[Nk];
    // } Token;

    constructor(
        tokenTypeEntry: TokenTypeEntry,
        public authInput: AuthenticatorInput,
        public authenticator: Uint8Array,
    ) {
        if (authenticator.length !== tokenTypeEntry.Nk) {
            throw new Error('invalid authenticator size');
        }
    }

    static deserialize(tokenTypeEntry: TokenTypeEntry, bytes: Uint8Array): Token {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const ops = { bytesRead: 0 };
        const payload = AuthenticatorInput.deserialize(tokenTypeEntry, bytes, ops);
        offset += ops.bytesRead;

        const len = tokenTypeEntry.Nk;
        const authenticator = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new Token(tokenTypeEntry, payload, authenticator);
    }

    serialize(): Uint8Array {
        return new Uint8Array(
            joinAll([this.authInput.serialize().buffer, this.authenticator.buffer]),
        );
    }
}

// WWWAuthenticateHeader handles the parsing of the WWW-Authenticate header
// under the PrivateToken scheme.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-sending-token-challenges
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

// AuthorizationHeader handles the parsing of the Authorization header
// under the PrivateToken scheme.
//
// See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-sending-tokens
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
