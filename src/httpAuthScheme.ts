// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { base64url } from 'rfc4648';
import { joinAll } from './util.js';
import { parseWWWAuthenticate } from './rfc9110.js';
import { getIssuerUrl } from './issuance.js';
import { Client, TokenResponse } from './pubVerifToken.js';

export interface TokenTypeEntry {
    name: string;
    value: number;
    Nk: number;
    Nid: number;
    publicVerifiable: boolean;
    publicMetadata: boolean;
    privateMetadata: boolean;
}

export class TokenChallenge {
    // This class represents the following structure:
    //
    // struct {
    //     uint16_t token_type;
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    // } TokenChallenge;

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

        if (!(redemptionContext.length == 0 || redemptionContext.length == 32)) {
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

export class PrivateToken {
    challengeSerialized: Uint8Array; // contains a serialized version of the TokenChallenge value.
    constructor(
        public challenge: TokenChallenge,
        public tokenKey: Uint8Array,
        public maxAge?: number, // an optional parameter that consists of the number of seconds for which the challenge will be accepted by the origin.
    ) {
        this.challengeSerialized = challenge.serialize();
    }

    static parse(data: string): PrivateToken {
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

        // Check for mandotory fields.
        if (
            challenge === undefined ||
            challengeSerialized === undefined ||
            tokenKey === undefined
        ) {
            throw new Error('cannot parse PrivateToken');
        }

        const pt = new PrivateToken(challenge, tokenKey, maxAge);
        pt.challengeSerialized = challengeSerialized;

        return pt;
    }

    static parseMultiple(header: string): PrivateToken[] {
        // Consumes data:
        //   PrivateToken challenge="abc...", token-key="123...",
        //   PrivateToken challenge="def...", token-key="234..."
        const challenges = parseWWWAuthenticate(header);

        const listTokens = new Array<PrivateToken>();

        for (const challenge of challenges) {
            if (!challenge.startsWith('PrivateToken ')) {
                continue;
            }
            const chl = challenge.slice('PrivateToken '.length);
            const privToken = PrivateToken.parse(chl);
            listTokens.push(privToken);
        }

        return listTokens;
    }

    static async create(
        tokenType: TokenTypeEntry,
        issuer: {
            name: string;
            publicKey: CryptoKey;
        },
        redemptionContext = new Uint8Array(0),
        originInfo?: string[],
        maxAge?: number,
    ): Promise<PrivateToken> {
        const tokenChallenge = new TokenChallenge(
            tokenType.value,
            issuer.name,
            redemptionContext,
            originInfo,
        );
        const publicKeySpki = new Uint8Array(
            await crypto.subtle.exportKey('spki', issuer.publicKey),
        );

        return new PrivateToken(tokenChallenge, publicKeySpki, maxAge);
    }

    toString(quotedString = false): string {
        // WWW-Authenticate does not impose authentication parameters escape with a double quote
        // For more details, refer to RFC9110 Section 11.2 https://www.rfc-editor.org/rfc/rfc9110#section-11.2
        const quote = quotedString ? '"' : '';
        // eslint-disable-next-line func-style
        const authParamToString = (param: string, value: string | number): string =>
            `${param}=${quote}${value}${quote}`;
        const chl = base64url.stringify(this.challenge.serialize());
        const key = base64url.stringify(this.tokenKey);
        const authParams: Record<string, string | number> = {
            challenge: chl,
            'token-key': key,
        };
        if (this.maxAge) {
            authParams['max-age'] = this.maxAge;
        }
        const params = Object.entries(authParams)
            .map(([param, value]) => authParamToString(param, value))
            .join(', ');
        return `PrivateToken ${params}`;
    }
}

export class TokenPayload {
    static readonly NONCE_LENGTH = 32;
    static readonly CHALLENGE_LENGTH = 32;
    tokenType: number;
    constructor(
        tokenTypeEntry: TokenTypeEntry,
        public nonce: Uint8Array,
        public challengeDigest: Uint8Array,
        public tokenKeyId: Uint8Array,
    ) {
        if (nonce.length !== TokenPayload.NONCE_LENGTH) {
            throw new Error('invalid nonce size');
        }

        if (challengeDigest.length !== TokenPayload.CHALLENGE_LENGTH) {
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
    ): TokenPayload {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== tokenTypeEntry.value) {
            throw new Error('mismatch of token type');
        }

        let len = TokenPayload.NONCE_LENGTH;
        const nonce = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = TokenPayload.CHALLENGE_LENGTH;
        const challengeDigest = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = tokenTypeEntry.Nid;
        const tokenKeyId = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        ops.bytesRead = offset;

        return new TokenPayload(tokenTypeEntry, nonce, challengeDigest, tokenKeyId);
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
    // This class represents the Token structure (composed by a TokenPayload and an authenticator).
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
        public payload: TokenPayload,
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
        const payload = TokenPayload.deserialize(tokenTypeEntry, bytes, ops);
        offset += ops.bytesRead;

        const len = tokenTypeEntry.Nk;
        const authenticator = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new Token(tokenTypeEntry, payload, authenticator);
    }

    static async fetch(pt: PrivateToken): Promise<Token> {
        const issuerUrl = await getIssuerUrl(pt.challenge.issuerName);
        const client = new Client();
        const tokReq = await client.createTokenRequest(pt);
        const tokRes = await tokReq.send(issuerUrl, TokenResponse);
        const token = await client.finalize(tokRes);
        return token;
    }

    serialize(): Uint8Array {
        return new Uint8Array(
            joinAll([this.payload.serialize().buffer, this.authenticator.buffer]),
        );
    }

    verify(publicKey: CryptoKey): Promise<boolean> {
        return crypto.subtle.verify(
            { name: 'RSA-PSS', saltLength: 48 },
            publicKey,
            this.authenticator,
            this.payload.serialize(),
        );
    }
}
