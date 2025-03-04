// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { jest } from '@jest/globals';

import {
    Token,
    TokenChallenge,
    TOKEN_TYPES,
    AuthorizationHeader,
    publicVerif,
    Extensions,
} from '../src/index.js';
const {
    ClientWithMetadata,
    ExtendedTokenRequest,
    IssuerWithMetadata,
    OriginWithMetadata,
    TokenResponse,
    PartiallyBlindRSAMode,
} = publicVerif;

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// Ad-hoc vectors, to be merged with the draft
import vectors from './test_data/pub_verif_with_metadata_v3.json';
type Vectors = (typeof vectors)[number];

import { keysFromVector } from './pub_verif_token.js';

describe.each(vectors)('PublicVerifiableMetadata-Vector-%#', (v: Vectors) => {
    const params = [[], [{ supportsRSARAW: true }]];

    test.each(params)('PublicVerifiableMetadata-Vector-%#-Issuer-Params-%#', async (...params) => {
        const [{ privateKey, publicKey }, publicKeyEnc] = await keysFromVector(v);
        expect(privateKey).toBeDefined();
        expect(publicKey).toBeDefined();

        const salt = hexToUint8(v.salt);
        const mode =
            salt.length == (PartiallyBlindRSAMode.PSS as number)
                ? PartiallyBlindRSAMode.PSS
                : PartiallyBlindRSAMode.PSSZero;
        const nonce = hexToUint8(v.nonce);
        const blind = hexToUint8(v.blind);
        const challengeSerialized = hexToUint8(v.token_challenge);
        const tokChl = TokenChallenge.deserialize(challengeSerialized);
        const extensionsSerialized = hexToUint8(v.extensions);
        const extensions = Extensions.deserialize(extensionsSerialized);

        // Mock for randomized operations.
        jest.spyOn(crypto, 'getRandomValues')
            .mockReturnValueOnce(nonce)
            .mockReturnValueOnce(salt)
            .mockReturnValueOnce(blind);

        const client = new ClientWithMetadata(mode, extensions);
        const tokReq = await client.createTokenRequest(tokChl, publicKeyEnc);
        testSerialize(ExtendedTokenRequest, tokReq);

        const tokReqSer = tokReq.serialize();
        expect(uint8ToHex(tokReqSer)).toBe(v.token_request);
        const issuer = new IssuerWithMetadata(
            mode,
            'issuer.example.com',
            privateKey,
            publicKey,
            ...params,
        );
        const tokRes = await issuer.issue(tokReq);
        testSerialize(TokenResponse, tokRes);

        const tokResSer = tokRes.serialize();
        expect(uint8ToHex(tokResSer)).toBe(v.token_response);

        const token = await client.finalize(tokRes);
        testSerializeType(TOKEN_TYPES.PARTIALLY_BLIND_RSA, Token, token);

        const tokenSer = token.serialize();
        expect(uint8ToHex(tokenSer)).toBe(v.token);

        expect(await new OriginWithMetadata(mode, extensions).verify(token, issuer.publicKey)).toBe(
            true,
        );

        const header = new AuthorizationHeader(token).toString();
        const parsedTokens = AuthorizationHeader.parse(TOKEN_TYPES.PARTIALLY_BLIND_RSA, header);
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
