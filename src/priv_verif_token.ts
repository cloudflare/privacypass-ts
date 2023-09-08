// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import {
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    Oprf,
    VOPRFClient,
    VOPRFServer,
    generateKeyPair,
    type DLEQParams,
    type HashID,
} from '@cloudflare/voprf-ts';

import { joinAll } from './util.js';
import { AuthenticatorInput, Token, TokenChallenge } from './auth_scheme/private_token.js';

const VOPRF_SUITE = Oprf.Suite.P384_SHA384;
const VOPRF_GROUP = Oprf.getGroup(VOPRF_SUITE);
const Ne = VOPRF_GROUP.eltSize();
const Ns = VOPRF_GROUP.scalarSize();
const Nk = Oprf.getOprfSize(VOPRF_SUITE);

// Token Type Entry Update:
//  - Token Type VOPRF (P-384, SHA-384)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-12#name-token-type-registry-updates
export const VOPRF /*: Readonly<TokenTypeEntry> */ = {
    value: 0x0001,
    name: 'VOPRF (P-384, SHA-384)',
    Nk: Nk,
    Nid: 32,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
    reference:
        'https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-voprf-p-384-sha-',
} as const;

export function keyGen2(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return generateKeyPair(VOPRF_SUITE);
}

async function getTokenKeyID(publicKey: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
}

export class TokenRequest2 {
    // struct {
    //     uint16_t token_type = 0x0001; /* Type VOPRF(P-384, SHA-384) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Ne];
    //   } TokenRequest;

    tokenType: number;
    constructor(
        public tokenKeyId: number,
        public blindedMsg: Uint8Array,
    ) {
        if (blindedMsg.length !== Ne) {
            throw new Error('invalid blinded message size');
        }

        this.tokenType = VOPRF.value;
    }

    static deserialize(bytes: Uint8Array): TokenRequest2 {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== VOPRF.value) {
            throw new Error('mismatch of token type');
        }

        const tokenKeyId = input.getUint8(offset);
        offset += 1;

        const len = Ne;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new TokenRequest2(tokenKeyId, blindedMsg);
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

export class TokenResponse2 {
    // struct {
    //     uint8_t evaluate_msg[Ne];
    //     uint8_t evaluate_proof[Ns+Ns];
    //  } TokenResponse;

    constructor(public evaluation: Evaluation) {
        if (evaluation.evaluated.length !== 1) {
            throw new Error('evaluation is of a non-single element');
        }
        const evaluate_msg = evaluation.evaluated[0].serialize();
        if (evaluate_msg.length !== Ne) {
            throw new Error('evaluate_msg has invalid size');
        }

        if (typeof evaluation.proof === 'undefined') {
            throw new Error('evaluation has no DLEQ proof');
        }
        const evaluate_proof = evaluation.proof.serialize();
        if (evaluate_proof.length !== 2 * Ns) {
            throw new Error('evaluate_proof has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenResponse2 {
        const params: DLEQParams = {
            gg: VOPRF_GROUP,
            hashID: Oprf.getHash(VOPRF_SUITE) as HashID,
            hash: Oprf.Crypto.hash,
            dst: '',
        };
        const evaluation = Evaluation.deserialize(params, bytes);

        return new TokenResponse2(evaluation);
    }

    serialize(): Uint8Array {
        return this.evaluation.serialize();
    }
}

export class Issuer2 {
    static readonly TYPE = VOPRF;

    private vServer: VOPRFServer;

    constructor(
        public name: string,
        private privateKey: Uint8Array,
        public publicKey: Uint8Array,
    ) {
        this.vServer = new VOPRFServer(VOPRF_SUITE, this.privateKey);
    }

    async issue(tokReq: TokenRequest2): Promise<TokenResponse2> {
        const blindedElt = VOPRF_GROUP.desElt(tokReq.blindedMsg);
        const evalReq = new EvaluationRequest([blindedElt]);
        const evaluation = await this.vServer.blindEvaluate(evalReq);
        return new TokenResponse2(evaluation);
    }

    verify(token: Token): Promise<boolean> {
        const authInput = token.authInput.serialize();
        return this.vServer.verifyFinalize(authInput, token.authenticator);
    }
}

export class Client2 {
    static readonly TYPE = VOPRF;

    private finData?: {
        vClient: VOPRFClient;
        authInput: AuthenticatorInput;
        finData: FinalizeData;
    };

    async createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<TokenRequest2> {
        // https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#section-6.1
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const context = new Uint8Array(await crypto.subtle.digest('SHA-256', tokChl.serialize()));

        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        const authInput = new AuthenticatorInput(
            Client2.TYPE,
            Client2.TYPE.value,
            nonce,
            context,
            tokenKeyId,
        );
        const tokenInput = authInput.serialize();

        const vClient = new VOPRFClient(VOPRF_SUITE, issuerPublicKey);
        const [finData, evalReq] = await vClient.blind([tokenInput]);
        const trucatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];

        if (evalReq.blinded.length !== 1) {
            throw new Error('created a non-single blinded element');
        }
        const tokenRequest = new TokenRequest2(trucatedTokenKeyId, evalReq.blinded[0].serialize());

        this.finData = { vClient, authInput, finData };

        return tokenRequest;
    }

    async finalize(tokRes: TokenResponse2): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }

        const [authenticator] = await this.finData.vClient.finalize(
            this.finData.finData,
            tokRes.evaluation,
        );
        const token = new Token(Client2.TYPE, this.finData.authInput, authenticator);

        this.finData = undefined;

        return token;
    }
}
