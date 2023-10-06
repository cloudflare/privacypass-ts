// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { BlindRSA, SUITES } from '@cloudflare/blindrsa-ts';

import { convertRSASSAPSSToEnc, joinAll } from './util.js';
import {
    AuthenticatorInput,
    Token,
    TokenChallenge,
    type TokenTypeEntry,
} from './auth_scheme/private_token.js';

// Token Type Entry Update:
//  - Token Type Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-blind-rsa-2048-b',
// TODO: Add support for both modes:
// notes: "The RSABSSA-SHA384-PSS-Deterministic and RSABSSA-SHA384-PSSZERO-Deterministic variants are supported"
// notes: 'Only the RSABSSA-SHA384-PSS-Deterministic is supported',
export const BLIND_RSA: Readonly<TokenTypeEntry> = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
} as const;

export function keyGen(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: Uint8Array.from([1, 0, 1]),
            hash: 'SHA-384',
        } as RsaHashedKeyGenParams,
        true,
        ['sign', 'verify'],
    );
}

function getCryptoKey(publicKey: Uint8Array): Promise<CryptoKey> {
    // Converts a RSA-PSS key into a RSA Encryption key.
    // Required because WebCrypto do not support importing keys with `RSASSA-PSS` OID,
    // See https://github.com/w3c/webcrypto/pull/325
    const spkiEncoded = convertRSASSAPSSToEnc(publicKey);

    return crypto.subtle.importKey(
        'spki',
        spkiEncoded,
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );
}

export async function getPublicKeyBytes(publicKey: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
}

async function getTokenKeyID(publicKey: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
}

export class TokenRequest {
    // struct {
    //     uint16_t token_type = 0x0002; /* Type Blind RSA (2048-bit) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Nk];
    // } TokenRequest;

    tokenType: number;
    constructor(
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {
        if (blindedMsg.length !== BLIND_RSA.Nk) {
            throw new Error('invalid blinded message size');
        }

        this.tokenType = BLIND_RSA.value;
    }

    static deserialize(bytes: Uint8Array): TokenRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== BLIND_RSA.value) {
            throw new Error('mismatch of token type');
        }

        const tokenKeyId = input.getUint8(offset);
        offset += 1;

        const len = BLIND_RSA.Nk;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new TokenRequest(tokenKeyId, blindedMsg);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.tokenKeyId);
        output.push(b);

        b = this.blindedMsg.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class TokenResponse {
    constructor(public blindSig: Uint8Array) {
        if (blindSig.length !== BLIND_RSA.Nk) {
            throw new Error('blind signature has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenResponse {
        return new TokenResponse(bytes.slice(0, BLIND_RSA.Nk));
    }

    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

export function verifyToken(token: Token, publicKeyIssuer: CryptoKey): Promise<boolean> {
    return crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 48 },
        publicKeyIssuer,
        token.authenticator,
        token.authInput.serialize(),
    );
}

export class Issuer {
    static readonly TYPE = BLIND_RSA;

    private blindRSAIssuer: BlindRSA;

    constructor(
        public name: string,
        private privateKey: CryptoKey,
        public publicKey: CryptoKey,
    ) {
        this.blindRSAIssuer = SUITES.SHA384.PSS.Deterministic();
    }

    async issue(tokReq: TokenRequest): Promise<TokenResponse> {
        const blindSig = await this.blindRSAIssuer.blindSign(this.privateKey, tokReq.blindedMsg);
        return new TokenResponse(blindSig);
    }
}

export class Client {
    static readonly TYPE = BLIND_RSA;

    private finData?: {
        pkIssuer: CryptoKey;
        tokenInput: Uint8Array;
        authInput: AuthenticatorInput;
        inv: Uint8Array;
    };

    async createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<TokenRequest> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#section-6.1
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', tokChl.serialize()));

        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        const authInput = new AuthenticatorInput(
            Client.TYPE,
            Client.TYPE.value,
            nonce,
            context,
            tokenKeyId,
        );
        const tokenInput = authInput.serialize();

        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        const pkIssuer = await getCryptoKey(issuerPublicKey);

        const { blindedMsg, inv } = await blindRSA.blind(pkIssuer, tokenInput);
        // "truncated_token_key_id" is the least significant byte of the
        // token_key_id in network byte order (in other words, the
        // last 8 bits of token_key_id).
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const tokenRequest = new TokenRequest(truncatedTokenKeyId, blindedMsg);

        this.finData = { tokenInput, authInput, inv, pkIssuer };

        return tokenRequest;
    }

    async finalize(tokRes: TokenResponse): Promise<Token> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-12#section-6.3
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }

        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        const authenticator = await blindRSA.finalize(
            this.finData.pkIssuer,
            this.finData.tokenInput,
            tokRes.blindSig,
            this.finData.inv,
        );
        const token = new Token(Client.TYPE, this.finData.authInput, authenticator);

        this.finData = undefined;

        return token;
    }
}
