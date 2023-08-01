// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { SUITES } from '@cloudflare/blindrsa-ts';
import { Buffer } from 'buffer';

import { TokenTypeEntry, PrivateToken, TokenPayload, Token } from './httpAuthScheme.js';
import { convertPSSToEnc } from './util.js';
import {
    sendTokenRequest,
    getIssuerUrl,
    TokenResponseProtocol,
    TokenRequestProtocol,
} from './issuance.js';

export const TokenType: TokenTypeEntry = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
} as const;

export class TokenRequest implements TokenRequestProtocol {
    constructor(
        public tokenType: number,
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.tokenKeyId);
        output.push(b);

        b = Buffer.from(this.blindedMsg);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

export class TokenResponse implements TokenResponseProtocol {
    constructor(public blindSig: Uint8Array) {}
    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

export class Issuer {
    static readonly TYPE = TokenType;
    static async issue(privateKey: CryptoKey, tokReq: TokenRequest): Promise<TokenResponse> {
        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        return new TokenResponse(await blindRSA.blindSign(privateKey, tokReq.blindedMsg));
    }
}

export class Client {
    static readonly TYPE = TokenType;
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
        const tokenPayload = new TokenPayload(Client.TYPE.value, nonce, context, keyId);
        const tokenInput = tokenPayload.serialize();

        const blindRSA = SUITES.SHA384.PSS.Deterministic();
        const spkiEncoded = convertPSSToEnc(privToken.tokenKey);
        const publicKeyIssuer = await crypto.subtle.importKey(
            'spki',
            spkiEncoded,
            { name: 'RSA-PSS', hash: 'SHA-384' },
            true,
            ['verify'],
        );

        const { blindedMsg, inv } = await blindRSA.blind(publicKeyIssuer, tokenInput);
        const tokenKeyId = keyId[keyId.length - 1];
        const tokenRequest = new TokenRequest(Client.TYPE.value, tokenKeyId, blindedMsg);
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
        const token = new Token(this.finData.tokenPayload, authenticator);
        this.finData = undefined;

        return token;
    }
}

export async function fetchPublicVerifToken(pt: PrivateToken): Promise<Token> {
    const issuerUrl = await getIssuerUrl(pt.challenge.issuerName);
    const client = new Client();
    const tokReq = await client.createTokenRequest(pt);
    const tokRes = await sendTokenRequest(issuerUrl, tokReq, TokenResponse);
    const token = await client.finalize(tokRes);
    return token;
}
