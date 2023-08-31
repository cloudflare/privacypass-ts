// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { Client, Issuer, PrivateToken, TOKEN_TYPES } from '../src/index.js';

function genRSAKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: Uint8Array.from([1, 0, 1]),
            hash: 'SHA-384',
        } as RsaHashedKeyGenParams,
        true,
        ['sign', 'verify'],
    );
}

export async function publicVerifiableTokens(): Promise<void> {
    // Protocol Setup
    //
    // [ Everybody ] decided to use Public Verifiable Tokens.

    // [ Issuer ] creates a key pair.
    const keys = await genRSAKeyPair();
    const issuer = new Issuer('issuer.com', keys.privateKey, keys.publicKey);

    // [ Client ] creates a state.
    const client = new Client();

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = ['origin.example.com', 'origin2.example.com'];
    const tokChl = await PrivateToken.create(
        TOKEN_TYPES.BLIND_RSA,
        issuer,
        redemptionContext,
        originInfo,
    );
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReq = await client.createTokenRequest(tokChl);
    //     |                     +--------- TokenRequest ------->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    const token = await client.finalize(tokRes);
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    const isValid = await /*origin*/ token.verify(issuer.publicKey);
    console.log(`Valid Public-Verifiable token? ${isValid}`);
}
