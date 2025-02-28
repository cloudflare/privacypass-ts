// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';
import { VOPRFClient } from '@cloudflare/voprf-ts';

import {
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    AuthorizationHeader,
    batchedPrivateVerif,
} from '../src/index.js';
const { Client, Issuer, BatchedTokenRequest, BatchedTokenResponse, VOPRF_RISTRETTO } =
    batchedPrivateVerif;

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-batched-tokens-04
import vectors from './test_data/batched_priv_verif_v4.json';

type Vectors = (typeof vectors)[number];

test.each(vectors)('BatchedPrivateVerifiable-Vector-%#', async (v: Vectors) => {
    const privateKey = hexToUint8(v.skS);
    const publicKey = hexToUint8(v.pkS);
    const nonces = v.nonces.map((nonce) => hexToUint8(nonce));
    const blinds = v.blinds.map((blind) => hexToUint8(blind));
    const challengeSerialized = hexToUint8(v.token_challenge);
    const tokChl = TokenChallenge.deserialize(challengeSerialized);

    // Mock for randomized operations.
    for (let i = 0; i < nonces.length; i += 1) {
        jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(nonces[i]);
        jest.spyOn(VOPRFClient.prototype, 'randomBlinder').mockReturnValueOnce(
            Promise.resolve(TOKEN_TYPES.VOPRF_RISTRETTO.group.desScalar(blinds[i])),
        );
    }

    const client = new Client();
    const tokReq = await client.createTokenRequests(tokChl, publicKey, nonces.length);
    testSerialize(BatchedTokenRequest, tokReq);

    const tokReqSer = tokReq.serialize();
    expect(uint8ToHex(tokReqSer)).toBe(v.token_request);
    // expect(tokenRequestToTokenTypeEntry(tokReqSer)).toBe(TOKEN_TYPES.VOPRF);

    const issuer = new Issuer('issuer.example.com', privateKey, publicKey);
    const tokRes = await issuer.issue(tokReq);
    testSerialize(BatchedTokenResponse, tokRes);

    const tokResSer = tokRes.serialize();

    // TODO: Incomplete test vectors in specification.
    // A tokenResponse is composed of an element and a randomized proof.
    // Checking only the element, and that the proof verifies.
    // but not exactly the proof bytes.
    //
    //     expect(uint8ToHex(tokResSer)).toBe(v.token_response);
    const proofElement = tokResSer.slice(0, VOPRF_RISTRETTO.Ne);
    const vectorProofElement = hexToUint8(v.token_response).slice(0, VOPRF_RISTRETTO.Ne);
    expect(proofElement).toStrictEqual(vectorProofElement);

    const tokens = await client.finalize(tokRes);

    for (let i = 0; i < tokens.length; i += 1) {
        const token = tokens[i];
        testSerializeType(TOKEN_TYPES.VOPRF_RISTRETTO, Token, token);

        expect(await issuer.verify(token)).toBe(true);

        const tokenSer = token.serialize();
        expect(uint8ToHex(tokenSer)).toBe(v.tokens[i]);

        const header = new AuthorizationHeader(token).toString();
        const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.VOPRF_RISTRETTO, header);
        const parsedToken = parsedTokens[0];
        expect(parsedTokens).toHaveLength(1);
        expect(parsedToken.token.authInput.challengeDigest).toEqual(
            token.authInput.challengeDigest,
        );
        expect(parsedToken.token.authInput.nonce).toEqual(token.authInput.nonce);
        expect(parsedToken.token.authInput.tokenKeyId).toEqual(token.authInput.tokenKeyId);
        expect(parsedToken.token.authInput.tokenType).toBe(token.authInput.tokenType);
        expect(parsedToken.token.authenticator).toEqual(token.authenticator);
    }
});
