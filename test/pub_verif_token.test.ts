// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';

import {
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    AuthorizationHeader,
    publicVerif,
    tokenRequestToTokenTypeEntry,
} from '../src/index.js';
const { Client, Issuer, Origin, TokenRequest, TokenResponse, BlindRSAMode } = publicVerif;

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-test-vectors
import vectors from './test_data/pub_verif_v16.json';
import { keysFromVector, type Vectors } from './pub_verif_token.js';

describe.each(vectors)('PublicVerifiable-Vector-%#', (v: Vectors) => {
    const params = [[], [{ supportsRSARAW: true }]];

    test.each(params)('PublicVerifiable-Vector-%#-Issuer-Params-%#', async (...params) => {
        const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
        expect(privateKey).toBeDefined();
        expect(publicKey).toBeDefined();

        const salt = hexToUint8(v.salt);
        const mode =
            salt.length == (BlindRSAMode.PSS as number) ? BlindRSAMode.PSS : BlindRSAMode.PSSZero;
        const nonce = hexToUint8(v.nonce);
        const blind = hexToUint8(v.blind);
        const challengeSerialized = hexToUint8(v.token_challenge);
        const tokChl = TokenChallenge.deserialize(challengeSerialized);

        // Mock for randomized operations.
        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(nonce)
            .mockReturnValueOnce(salt)
            .mockReturnValueOnce(blind);

        const client = new Client(mode);
        const tokReq = await client.createTokenRequest(tokChl, publicKeyEnc);
        testSerializeType(TOKEN_TYPES.BLIND_RSA, TokenRequest, tokReq);

        const tokReqSer = tokReq.serialize();
        expect(uint8ToHex(tokReqSer)).toBe(v.token_request);
        expect(tokenRequestToTokenTypeEntry(tokReqSer)).toBe(TOKEN_TYPES.BLIND_RSA);

        const issuer = new Issuer(mode, 'issuer.example.com', privateKey, publicKey, ...params);
        const tokRes = await issuer.issue(tokReq);
        testSerialize(TokenResponse, tokRes);

        const tokResSer = tokRes.serialize();
        expect(uint8ToHex(tokResSer)).toBe(v.token_response);

        const token = await client.finalize(tokRes);
        testSerializeType(TOKEN_TYPES.BLIND_RSA, Token, token);

        const tokenSer = token.serialize();
        expect(uint8ToHex(tokenSer)).toBe(v.token);

        expect(await new Origin(mode).verify(token, issuer.publicKey)).toBe(true);

        const header = new AuthorizationHeader(token).toString();
        const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.BLIND_RSA, header);
        const parsedToken = parsedTokens[0];
        expect(parsedTokens).toHaveLength(1);
        expect(parsedToken.token.authInput.challengeDigest).toEqual(
            token.authInput.challengeDigest,
        );
        expect(parsedToken.token.authInput.nonce).toEqual(token.authInput.nonce);
        expect(parsedToken.token.authInput.tokenKeyId).toEqual(token.authInput.tokenKeyId);
        expect(parsedToken.token.authInput.tokenType).toBe(token.authInput.tokenType);
        expect(parsedToken.token.authenticator).toEqual(token.authenticator);
    });
});
