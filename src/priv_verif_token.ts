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
    type Group,
    type SuiteID,
    type HashID,
    DLEQProof,
} from '@cloudflare/voprf-ts';

import { joinAll } from './util.js';
import {
    AuthenticatorInput,
    Token,
    TokenChallenge,
    type TokenTypeEntry,
} from './auth_scheme/private_token.js';

export interface VOPRFExtraParams {
    suite: SuiteID;
    group: Group;
    Ne: number;
    Ns: number;
    Nk: number;
    hash: HashID;
    dleqParams: DLEQParams;
}

const VOPRF_SUITE = Oprf.Suite.P384_SHA384;
const VOPRF_GROUP = Oprf.getGroup(VOPRF_SUITE);
const VOPRF_HASH = Oprf.getHash(VOPRF_SUITE) as HashID;
const VOPRF_EXTRA_PARAMS: VOPRFExtraParams = {
    suite: VOPRF_SUITE,
    group: VOPRF_GROUP,
    Ne: VOPRF_GROUP.eltSize(),
    Ns: VOPRF_GROUP.scalarSize(),
    Nk: Oprf.getOprfSize(VOPRF_SUITE),
    hash: VOPRF_HASH,
    dleqParams: {
        gg: VOPRF_GROUP,
        hashID: VOPRF_HASH,
        hash: Oprf.Crypto.hash,
        dst: '',
    },
} as const;

// Token Type Entry Update:
//  - Token Type VOPRF (P-384, SHA-384)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-voprf-p-384-sha-
export const VOPRF: Readonly<TokenTypeEntry> & VOPRFExtraParams = {
    value: 0x0001,
    name: 'VOPRF (P-384, SHA-384)',
    Nid: 32,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
    ...VOPRF_EXTRA_PARAMS,
} as const;

export function keyGen2(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return generateKeyPair(VOPRF.suite);
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
        public readonly truncatedTokenKeyId: number,
        public readonly blindedMsg: Uint8Array,
    ) {
        if (blindedMsg.length !== VOPRF.Ne) {
            throw new Error('blinded message has invalide size');
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

        const truncatedTokenKeyId = input.getUint8(offset);
        offset += 1;

        const len = VOPRF.Ne;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new TokenRequest2(truncatedTokenKeyId, blindedMsg);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.truncatedTokenKeyId);
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

    constructor(
        public readonly evaluateMsg: Uint8Array,
        public readonly evaluateProof: Uint8Array,
    ) {
        if (evaluateMsg.length !== VOPRF.Ne) {
            throw new Error('evaluate_msg has invalid size');
        }
        if (evaluateProof.length !== 2 * VOPRF.Ns) {
            throw new Error('evaluate_proof has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenResponse2 {
        let offset = 0;
        let len = VOPRF.Ne;
        const evaluateMsg = new Uint8Array(bytes.slice(offset, offset + len));
        offset += len;

        len = 2 * VOPRF.Ns;
        const evaluateProof = new Uint8Array(bytes.slice(offset, offset + len));

        return new TokenResponse2(evaluateMsg, evaluateProof);
    }

    serialize(): Uint8Array {
        return new Uint8Array(joinAll([this.evaluateMsg, this.evaluateProof]));
    }
}

export function verifyToken2(token: Token, privateKeyIssuer: Uint8Array): Promise<boolean> {
    const vServer = new VOPRFServer(VOPRF.suite, privateKeyIssuer);
    const authInput = token.authInput.serialize();
    return vServer.verifyFinalize(authInput, token.authenticator);
}

export class Issuer2 {
    private vServer: VOPRFServer;

    constructor(
        public name: string,
        private privateKey: Uint8Array,
        public publicKey: Uint8Array,
    ) {
        this.vServer = new VOPRFServer(VOPRF.suite, this.privateKey);
    }

    async issue(tokReq: TokenRequest2): Promise<TokenResponse2> {
        const blindedElt = VOPRF.group.desElt(tokReq.blindedMsg);
        const evalReq = new EvaluationRequest([blindedElt]);
        const evaluation = await this.vServer.blindEvaluate(evalReq);

        if (evaluation.evaluated.length !== 1) {
            throw new Error('evaluation is of a non-single element');
        }
        const evaluateMsg = evaluation.evaluated[0].serialize();

        if (typeof evaluation.proof === 'undefined') {
            throw new Error('evaluation has no DLEQ proof');
        }
        const evaluateProof = evaluation.proof.serialize();

        return new TokenResponse2(evaluateMsg, evaluateProof);
    }

    verify(token: Token): Promise<boolean> {
        const authInput = token.authInput.serialize();
        return this.vServer.verifyFinalize(authInput, token.authenticator);
    }
}

export class Client2 {
    private finData?: {
        vClient: VOPRFClient;
        authInput: AuthenticatorInput;
        finData: FinalizeData;
    };

    async createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<TokenRequest2> {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const challengeDigest = new Uint8Array(
            await crypto.subtle.digest('SHA-256', tokChl.serialize()),
        );

        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        const authInput = new AuthenticatorInput(
            VOPRF,
            VOPRF.value,
            nonce,
            challengeDigest,
            tokenKeyId,
        );
        const tokenInput = authInput.serialize();

        const vClient = new VOPRFClient(VOPRF.suite, issuerPublicKey);
        const [finData, evalReq] = await vClient.blind([tokenInput]);
        if (evalReq.blinded.length !== 1) {
            throw new Error('created a non-single blinded element');
        }
        const blindedMsg = evalReq.blinded[0].serialize();

        // "truncated_token_key_id" is the least significant byte of the
        // token_key_id in network byte order (in other words, the
        // last 8 bits of token_key_id).
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const tokenRequest = new TokenRequest2(truncatedTokenKeyId, blindedMsg);

        this.finData = { vClient, authInput, finData };

        return tokenRequest;
    }

    async finalize(tokRes: TokenResponse2): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }

        const proof = DLEQProof.deserialize(VOPRF.dleqParams, tokRes.evaluateProof);
        const evaluateMsg = VOPRF.group.desElt(tokRes.evaluateMsg);
        const evaluation = new Evaluation(Oprf.Mode.VOPRF, [evaluateMsg], proof);
        const [authenticator] = await this.finData.vClient.finalize(
            this.finData.finData,
            evaluation,
        );
        const token = new Token(VOPRF, this.finData.authInput, authenticator);

        this.finData = undefined;

        return token;
    }
}
