// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { VOPRFClient } from '@cloudflare/voprf-ts';
import { expect, test, vi } from 'vitest';

import {
    TokenChallenge,
    TOKEN_TYPES,
    Token,
    AuthorizationHeader,
    privateVerif,
    tokenRequestToTokenTypeEntry,
} from '../src/index.js';
const { Client, Issuer, TokenRequest, TokenResponse, VOPRF } = privateVerif;

import { hexToUint8, testSerialize, testSerializeType, uint8ToHex } from './util.js';

// https://www.rfc-editor.org/rfc/rfc9578.html#name-issuance-protocol-1-voprfp-
import vectorsGo from './test_data/priv_verif_rfc9578.go.json';
// https://raw.githubusercontent.com/raphaelrobert/privacypass/refs/heads/main/tests/kat_vectors/private_p384_rs.json
import vectorsRust from './test_data/priv_verif_rfc9578.rust.json';

const vectors = [...vectorsGo, ...vectorsRust];

type Vectors = (typeof vectors)[number];

test.each(vectors)('PrivateVerifiable-Vector-%#', async (v: Vectors) => {
    const privateKey = hexToUint8(v.skS);
    const publicKey = hexToUint8(v.pkS);
    const nonce = hexToUint8(v.nonce);
    const blind = hexToUint8(v.blind);
    const challengeSerialized = hexToUint8(v.token_challenge);
    const tokChl = TokenChallenge.deserialize(challengeSerialized);

    // Mock for randomized operations.
    vi.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(nonce);
    vi.spyOn(VOPRFClient.prototype, 'randomBlinder').mockReturnValueOnce(
        Promise.resolve(TOKEN_TYPES.VOPRF.group.desScalar(blind)),
    );

    const client = new Client();
    const tokReq = await client.createTokenRequest(tokChl, publicKey);
    testSerialize(TokenRequest, tokReq);

    const tokReqSer = tokReq.serialize();
    expect(uint8ToHex(tokReqSer)).toBe(v.token_request);
    expect(tokenRequestToTokenTypeEntry(tokReqSer)).toBe(TOKEN_TYPES.VOPRF);

    const issuer = new Issuer('issuer.example.com', privateKey, publicKey);
    const tokRes = await issuer.issue(tokReq);
    testSerialize(TokenResponse, tokRes);

    const tokResSer = tokRes.serialize();

    // TODO: Incomplete test vectors in specification.
    // A tokenResponse is composed of an element and a randomized proof.
    // Checking only the element, and that the proof verifies.
    // but not exactly the proof bytes.
    //
    //     expect(uint8ToHex(tokResSer)).toBe(v.token_response);
    const proofElement = tokResSer.slice(0, VOPRF.Ne);
    const vectorProofElement = hexToUint8(v.token_response).slice(0, VOPRF.Ne);
    expect(proofElement).toStrictEqual(vectorProofElement);

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
