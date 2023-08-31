// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { SUITES } from '@cloudflare/blindrsa-ts';

import { TokenTypeEntry, PrivateToken, TokenPayload, Token } from './httpAuthScheme.js';
import { convertRSASSAPSSToEnc, joinAll } from './util.js';
import { TokenResponseProtocol, TokenRequestProtocol, MediaType } from './issuance.js';

const BLIND_RSA: TokenTypeEntry = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
} as const;

export const TOKEN_TYPES = {
    BLIND_RSA,
} as const;

export class TokenRequest implements TokenRequestProtocol {
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

    // Send TokenRequest to Issuer (fetch w/POST).
    async send<T extends TokenResponseProtocol>(
        issuerUrl: string,
        tokRes: { new (_: Uint8Array): T },
        headers?: Headers,
    ): Promise<T> {
        headers ??= new Headers();
        headers.append('Content-Type', MediaType.PRIVATE_TOKEN_REQUEST);
        headers.append('Accept', MediaType.PRIVATE_TOKEN_RESPONSE);
        const issuerResponse = await fetch(issuerUrl, {
            method: 'POST',
            headers,
            body: this.serialize().buffer,
        });

        if (issuerResponse.status !== 200) {
            const body = await issuerResponse.text();
            throw new Error(
                `tokenRequest failed with code:${issuerResponse.status} response:${body}`,
            );
        }

        const contentType = issuerResponse.headers.get('Content-Type');

        if (!contentType || contentType.toLowerCase() !== MediaType.PRIVATE_TOKEN_RESPONSE) {
            throw new Error(`tokenRequest: missing ${MediaType.PRIVATE_TOKEN_RESPONSE} header`);
        }

        //  Receive a TokenResponse,
        const resp = new Uint8Array(await issuerResponse.arrayBuffer());
        return new tokRes(resp);
    }
}

export class TokenResponse implements TokenResponseProtocol {
    constructor(public blindSig: Uint8Array) {
        if (blindSig.length !== BLIND_RSA.Nk) {
            throw new Error('invalid blind signature size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenResponse {
        return new TokenResponse(bytes.slice(0, BLIND_RSA.Nk));
    }

    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

export class Issuer {
    static readonly TYPE = BLIND_RSA;

    constructor(
        public name: string,
        private privateKey: CryptoKey,
        public publicKey: CryptoKey,
    ) {}

    async issue(tokReq: TokenRequest): Promise<TokenResponse> {
        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        return new TokenResponse(await blindRSA.blindSign(this.privateKey, tokReq.blindedMsg));
    }
}

export class Client {
    static readonly TYPE = BLIND_RSA;
    private finData?: {
        publicKeyIssuer: CryptoKey;
        tokenInput: Uint8Array;
        tokenPayload: TokenPayload;
        tokenRequest: TokenRequest;
        inv: Uint8Array;
    };

    async createTokenRequest(privToken: PrivateToken): Promise<TokenRequest> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#section-6.1
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(
            await crypto.subtle.digest('SHA-256', privToken.challengeSerialized),
        );
        const keyId = new Uint8Array(await crypto.subtle.digest('SHA-256', privToken.tokenKey));
        const tokenPayload = new TokenPayload(Client.TYPE, nonce, context, keyId);
        const tokenInput = tokenPayload.serialize();

        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        const spkiEncoded = convertRSASSAPSSToEnc(privToken.tokenKey);
        const publicKeyIssuer = await crypto.subtle.importKey(
            'spki',
            spkiEncoded,
            { name: 'RSA-PSS', hash: 'SHA-384' },
            true,
            ['verify'],
        );

        const { blindedMsg, inv } = await blindRSA.blind(publicKeyIssuer, tokenInput);
        const tokenKeyId = keyId[keyId.length - 1];
        const tokenRequest = new TokenRequest(tokenKeyId, blindedMsg);
        this.finData = { tokenInput, tokenPayload, inv, tokenRequest, publicKeyIssuer };

        return tokenRequest;
    }

    async finalize(t: TokenResponse): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet.');
        }

        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        const authenticator = await blindRSA.finalize(
            this.finData.publicKeyIssuer,
            this.finData.tokenInput,
            t.blindSig,
            this.finData.inv,
        );
        const token = new Token(Client.TYPE, this.finData.tokenPayload, authenticator);
        this.finData = undefined;

        return token;
    }
}
