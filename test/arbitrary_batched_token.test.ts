// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/* eslint-disable security/detect-object-injection */

import { VOPRFClient } from '@cloudflare/voprf-ts';
import { jest } from '@jest/globals';

import {
    BatchedTokenRequest,
    BatchedTokenResponse,
    Issuer,
    TokenRequest,
} from '../src/arbitrary_batched_token';
import {
    type Token,
    TokenChallenge,
    TOKEN_TYPES,
    privateVerif,
    publicVerif,
} from '../src/index.js';
const { Client: Type1Client } = privateVerif;
const { BlindRSAMode, Client: Type2Client } = publicVerif;

import { keysFromVector as type2KeysFromVector } from './pub_verif_token.js';
import { hexToUint8, testSerialize, uint8ToHex } from './util.js';

// https://github.com/cloudflare/pat-go/blob/main/tokens/batched/batched-issuance-test-vectors.json
import vectors from './test_data/arbitrary_batched_tokens_v4.json';

type Vectors = (typeof vectors)[number];

describe.each(vectors)('ArbitraryBatched-Vector-%#', (v: Vectors) => {
    const params = [[], [{ supportsRSARAW: true }]];

    test.each(params)('ArbitraryBatched-Vector-%#-Issuer-Params-%#', async (...params) => {
        const tokenRequests = new Array<TokenRequest>(v.issuance.length);
        const issuers = new Array<privateVerif.Issuer | publicVerif.Issuer>(v.issuance.length);
        const clients = new Array<privateVerif.Client | publicVerif.Client>(v.issuance.length);
        for (let i = 0; i < v.issuance.length; i += 1) {
            const issuance = v.issuance[i];
            const type = Number.parseInt(issuance.type);

            const nonce = hexToUint8(issuance.nonce);
            const blind = hexToUint8(issuance.blind);
            const challengeSerialized = hexToUint8(issuance.token_challenge);
            const tokChl = TokenChallenge.deserialize(challengeSerialized);
            switch (type) {
                case TOKEN_TYPES.VOPRF.value: {
                    const privateKey = hexToUint8(issuance.skS);
                    const publicKey = hexToUint8(issuance.pkS);

                    // Mock for randomized operations.
                    jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(nonce);
                    jest.spyOn(VOPRFClient.prototype, 'randomBlinder').mockReturnValueOnce(
                        Promise.resolve(TOKEN_TYPES.VOPRF.group.desScalar(blind)),
                    );

                    const client = new Type1Client();
                    clients[i] = client;
                    const tokReq = await client.createTokenRequest(tokChl, publicKey);
                    tokenRequests[i] = new TokenRequest(tokReq);

                    const issuer = new privateVerif.Issuer(
                        'issuer.example.com',
                        privateKey,
                        publicKey,
                    );
                    issuers[i] = issuer;
                    break;
                }
                case TOKEN_TYPES.BLIND_RSA.value: {
                    if (issuance.salt === undefined) {
                        throw new Error('invalid test vector');
                    }
                    const salt = hexToUint8(issuance.salt);
                    const mode =
                        salt.length == (BlindRSAMode.PSS as number)
                            ? BlindRSAMode.PSS
                            : BlindRSAMode.PSSZero;

                    jest.spyOn(crypto, 'getRandomValues')
                        .mockReturnValueOnce(nonce)
                        .mockReturnValueOnce(salt)
                        .mockReturnValueOnce(blind);

                    const client = new Type2Client(mode);
                    clients[i] = client;
                    const [{ privateKey, publicKey }, publicKeyEnc] =
                        await type2KeysFromVector(issuance);
                    const tokReq = await client.createTokenRequest(tokChl, publicKeyEnc);
                    tokenRequests[i] = new TokenRequest(tokReq);

                    const issuer = new publicVerif.Issuer(
                        mode,
                        'issuer.example.com',
                        privateKey,
                        publicKey,
                        ...params,
                    );
                    issuers[i] = issuer;
                    break;
                }
                default:
                    throw new Error('unsupported key type');
            }
        }
        const tokReq = new BatchedTokenRequest(tokenRequests);

        const tokReqSer = tokReq.serialize();
        expect(uint8ToHex(tokReqSer)).toBe(v.token_request);

        const issuer = new Issuer(...issuers);

        const tokRes = await issuer.issue(tokReq);
        testSerialize(BatchedTokenResponse, tokRes);

        for (let i = 0; i < v.issuance.length; i += 1) {
            const issuance = v.issuance[i];
            const res = tokRes.tokenResponses[i];
            const type = Number.parseInt(issuance.type);

            let token: Token;
            switch (type) {
                case TOKEN_TYPES.VOPRF.value: {
                    const client = clients[i] as privateVerif.Client;
                    const rawTokenResponse = res.tokenResponse;
                    if (rawTokenResponse === null) {
                        throw new Error('should not be null');
                    }
                    const tokenResponse = privateVerif.TokenResponse.deserialize(rawTokenResponse);
                    token = await client.finalize(tokenResponse);
                    break;
                }
                case TOKEN_TYPES.BLIND_RSA.value: {
                    const client = clients[i] as publicVerif.Client;
                    const rawTokenResponse = res.tokenResponse;
                    if (rawTokenResponse === null) {
                        throw new Error('should not be null');
                    }
                    const tokenResponse = publicVerif.TokenResponse.deserialize(rawTokenResponse);
                    token = await client.finalize(tokenResponse);
                    break;
                }
                default:
                    throw new Error('unsupported key type');
            }
            const tokenSer = token.serialize();
            expect(uint8ToHex(tokenSer)).toBe(issuance.token);
        }
    });
});
