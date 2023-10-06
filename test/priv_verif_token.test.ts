// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';
import { VOPRFClient } from '@cloudflare/voprf-ts';

import {
    Client2,
    Issuer2,
    TokenRequest2,
    TokenResponse2,
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    AuthorizationHeader,
    VOPRF,
} from '../src/index.js';

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#name-test-vectors
import vectors from './test_data/priv_verif_v11.json';

type Vectors = (typeof vectors)[number];

test.each(vectors)('PrivateVerifiable-Vector-%#', async (v: Vectors) => {
    const privateKey = hexToUint8(v.skS);
    const publicKey = hexToUint8(v.pkS);
    const nonce = hexToUint8(v.nonce);
    const blind = hexToUint8(v.blind);
    const challengeSerialized = hexToUint8(v.token_challenge);
    const tokChl = TokenChallenge.deserialize(challengeSerialized);

    // Mock for randomized operations.
    jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(nonce);
    jest.spyOn(VOPRFClient.prototype, 'randomBlinder').mockReturnValueOnce(
        Promise.resolve(TOKEN_TYPES.VOPRF.group.desScalar(blind)),
    );

    const client = new Client2();
    const tokReq = await client.createTokenRequest(tokChl, publicKey);
    testSerialize(TokenRequest2, tokReq);

    const tokReqSer = tokReq.serialize();
    expect(uint8ToHex(tokReqSer)).toBe(v.token_request);

    const issuer = new Issuer2('issuer.example.com', privateKey, publicKey);
    const tokRes = await issuer.issue(tokReq);
    testSerialize(TokenResponse2, tokRes);

    const tokResSer = tokRes.serialize();
    // TODO: Update reference test vectors.
    // A tokenResponse is an element and a randomized proof.
    //    expect(uint8ToHex(tokResSer)).toBe(v.token_response);
    // Checking only the element:
    expect(tokResSer.slice(0, VOPRF.Ne)).toStrictEqual(
        hexToUint8(v.token_response).slice(0, VOPRF.Ne),
    );

    const token = await client.finalize(tokRes);
    testSerializeType(TOKEN_TYPES.VOPRF, Token, token);

    const tokenSer = token.serialize();
    expect(uint8ToHex(tokenSer)).toBe(v.token);

    expect(await issuer.verify(token)).toBe(true);

    const header = new AuthorizationHeader(token).toString();
    const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.VOPRF, header);
    const parsedToken = parsedTokens[0];
    expect(parsedTokens).toHaveLength(1);
    expect(parsedToken.token.authInput.challengeDigest).toEqual(token.authInput.challengeDigest);
    expect(parsedToken.token.authInput.nonce).toEqual(token.authInput.nonce);
    expect(parsedToken.token.authInput.tokenKeyId).toEqual(token.authInput.tokenKeyId);
    expect(parsedToken.token.authInput.tokenType).toBe(token.authInput.tokenType);
    expect(parsedToken.token.authenticator).toEqual(token.authenticator);
});
