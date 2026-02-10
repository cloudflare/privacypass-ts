// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

/* eslint-disable security/detect-object-injection */

import { VOPRFClient } from '@cloudflare/voprf-ts';
import { describe, expect, test, vi } from 'vitest';

import {
    BatchedTokenRequest,
    GenericBatchTokenResponse,
    Issuer,
    TokenRequest,
} from '../src/generic_batched_token';
import {
    type Token,
    TokenChallenge,
    TOKEN_TYPES,
    privateVerif,
    publicVerif,
} from '../src/index.js';

import { keysFromVector as type2KeysFromVector } from './pub_verif_token.js';
import { hexToUint8, uint8ToHex } from './util.js';

// https://github.com/cloudflare/pat-go/blob/main/tokens/batched/batched-issuance-test-vectors.json
import vectorsGo from './test_data/generic_batched_tokens_v6_go.json';
// https://raw.githubusercontent.com/raphaelrobert/privacypass/0600835c039c4b89f2137be3f5b1ecbeffe05417/tests/kat_vectors/generic_rs.json
import vectorsRust from './test_data/generic_batched_tokens_v6_rs.json';

const vectors = [...vectorsGo, ...vectorsRust];
console.log('NUMBEROFVECTORS', vectors.length);
type Vectors = (typeof vectors)[number];

const SUPPORTED_TYPES = [TOKEN_TYPES.VOPRF.value, TOKEN_TYPES.BLIND_RSA.value].map((t) =>
    t.toString().padStart(4, '0'),
);

const token_type = (i: unknown): string => {
    if (typeof i !== 'object' || i === null) {
        throw new Error('unsupported');
    }
    if ('type' in i && typeof i.type === 'string') {
        return i.type;
    } else if ('token_type' in i && typeof i.token_type === 'string') {
        return i.token_type;
    } else {
        throw new Error('unsupported');
    }
};

describe.each(vectors)('GenericBatched-Vector-%#', (v: Vectors) => {
    const params = [[], [{ supportsRSARAW: true }]];

    test.each(params)('GenericBatched-Vector-%#-Issuer-Params-%#', async (...params) => {
        // if the test vector contains an unsupported type, skip the test
        console.log(v.issuance.map(token_type));
        expect(v.issuance.every((i) => SUPPORTED_TYPES.includes(token_type(i)))).toBe(true);
        const tokenRequests = new Array<TokenRequest>(v.issuance.length);
        const issuers = new Array<privateVerif.Issuer | publicVerif.Issuer>(v.issuance.length);
        const clients = new Array<privateVerif.Client | publicVerif.Client>(v.issuance.length);
        for (let i = 0; i < v.issuance.length; i += 1) {
            const issuance = v.issuance[i];
            const type = Number.parseInt(token_type(issuance));

            const nonce = hexToUint8(issuance.nonce);
            const blind = hexToUint8(issuance.blind);
            const challengeSerialized = hexToUint8(issuance.token_challenge);
            const tokChl = TokenChallenge.deserialize(challengeSerialized);
            switch (type) {
                case TOKEN_TYPES.VOPRF.value: {
                    const privateKey = hexToUint8(issuance.skS);
                    const publicKey = hexToUint8(issuance.pkS);

                    // Mock for randomized operations.
                    vi.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(nonce);
                    vi.spyOn(VOPRFClient.prototype, 'randomBlinder').mockReturnValueOnce(
                        Promise.resolve(TOKEN_TYPES.VOPRF.group.desScalar(blind)),
                    );

                    const client = new privateVerif.Client();
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
                    if (issuance.salt === undefined || issuance.salt === null) {
                        throw new Error('invalid test vector');
                    }
                    const salt = hexToUint8(issuance.salt);
                    const mode =
                        salt.length == (publicVerif.BlindRSAMode.PSS as number)
                            ? publicVerif.BlindRSAMode.PSS
                            : publicVerif.BlindRSAMode.PSSZero;

                    vi.spyOn(crypto, 'getRandomValues')
                        .mockReturnValueOnce(nonce)
                        .mockReturnValueOnce(salt)
                        .mockReturnValueOnce(blind);

                    const client = new publicVerif.Client(mode);
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
        const bytes = tokRes.serialize();
        const got = GenericBatchTokenResponse.deserialize(bytes);
        expect(got).toStrictEqual(tokRes);

        for (let i = 0; i < v.issuance.length; i += 1) {
            const issuance = v.issuance[i];
            const res = tokRes.tokenResponses[i];
            const type = Number.parseInt(token_type(issuance));

            let token: Token;
            switch (type) {
                case TOKEN_TYPES.VOPRF.value: {
                    const client = clients[i] as privateVerif.Client;
                    const tokenResponse = res.tokenResponse as privateVerif.TokenResponse | null;
                    if (tokenResponse === null) {
                        throw new Error('should not be null');
                    }
                    token = await client.finalize(tokenResponse);
                    break;
                }
                case TOKEN_TYPES.BLIND_RSA.value: {
                    const client = clients[i] as publicVerif.Client;
                    const tokenResponse = res.tokenResponse;
                    if (tokenResponse === null) {
                        throw new Error('should not be null');
                    }
                    // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
                    token = await client.finalize(tokenResponse as publicVerif.TokenResponse);
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

describe('generic batched unit tests', () => {
    test('client should support initialisation with zero TokenRequest', () => {
        const newClient = () => new BatchedTokenRequest([]);
        expect(newClient).not.toThrow();
    });
});
