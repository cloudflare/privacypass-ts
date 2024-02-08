// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { TOKEN_TYPES, TokenChallenge, publicVerif } from '../src/index.js';
type BlindRSAMode = publicVerif.BlindRSAMode;
const { BlindRSAMode, Client, Issuer, getPublicKeyBytes, keyGen, verifyToken } = publicVerif;

async function rsaVariant(mode: BlindRSAMode): Promise<void> {
    // Protocol Setup
    //
    // [ Everybody ] agree to use Public Verifiable Tokens.
    const tokenType = TOKEN_TYPES.BLIND_RSA.value;

    // [ Issuer ] creates a key pair.
    const keys = await keyGen(mode, {
        modulusLength: 2048,
        publicExponent: Uint8Array.from([1, 0, 1]),
    });
    const issuer = new Issuer(mode, 'issuer.com', keys.privateKey, keys.publicKey);
    const pkIssuer = await getPublicKeyBytes(issuer.publicKey);

    // [ Client ] creates a state.
    const client = new Client(mode);

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = ['origin.example.com', 'origin2.example.com'];
    const tokChl = new TokenChallenge(tokenType, issuer.name, redemptionContext, originInfo);
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReq = await client.createTokenRequest(tokChl, pkIssuer);
    //     |                     +--------- TokenRequest ------->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    const token = await client.finalize(tokRes);
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    const isValid = await /*Origin*/ verifyToken(mode, token, issuer.publicKey);

    console.log('Public-Verifiable tokens');
    console.log(`    Suite: ${TOKEN_TYPES.BLIND_RSA.suite[mode as BlindRSAMode]()}`);
    console.log(`    Valid token: ${isValid}`);
}

export async function publicVerifiableTokens() {
    await rsaVariant(BlindRSAMode.PSS);
    await rsaVariant(BlindRSAMode.PSSZero);
}
