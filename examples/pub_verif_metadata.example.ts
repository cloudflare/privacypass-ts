// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import { generatePrimeSync } from 'node:crypto';

import { Extension, Extensions, TOKEN_TYPES, publicVerif } from '../src/index.js';
type PartiallyBlindRSAMode = publicVerif.PartiallyBlindRSAMode;
const {
    PartiallyBlindRSAMode,
    ClientWithMetadata,
    IssuerWithMetadata,
    OriginWithMetadata,
    getPublicKeyBytes,
} = publicVerif;

async function setup(mode: PartiallyBlindRSAMode, extensions: Extensions) {
    // [ Issuer ] creates a key pair.
    const keys = await IssuerWithMetadata.generateKey(
        mode,
        {
            modulusLength: 2048,
            publicExponent: Uint8Array.from([1, 0, 1]),
        },
        (length: number) => generatePrimeSync(length, { safe: true, bigint: true }),
    );
    const issuer = new IssuerWithMetadata(mode, 'issuer.com', keys.privateKey, keys.publicKey);
    const pkIssuer = await getPublicKeyBytes(issuer.publicKey);

    // [ Client ] creates a state.
    const client = new ClientWithMetadata(mode, extensions);

    // [ Origin ] creates a state.
    const origin = new OriginWithMetadata(mode, extensions, [
        'origin.example.com',
        'origin2.example.com',
    ]);

    return { issuer, client, origin, pkIssuer };
}

const TEST_EXTENSION_TYPE = 0xacdc;
function createTestExtension(info = new Uint8Array([TEST_EXTENSION_TYPE])) {
    return new Extension(TEST_EXTENSION_TYPE, info);
}

async function rsaVariant(mode: PartiallyBlindRSAMode): Promise<void> {
    // Protocol Setup
    //
    // [ Everybody ] agree to use Public Verifiable Tokens with Metadata.
    const extensions = new Extensions([createTestExtension(new Uint8Array([1, 2, 3]))]);
    const { issuer, client, origin, pkIssuer } = await setup(mode, extensions);

    // Online Protocol
    //
    // +--------+            +--------+         +----------+ +--------+
    // | Origin |            | Client |         | Attester | | Issuer |
    // +---+----+            +---+----+         +----+-----+ +---+----+
    //     |                     |                   |           |
    //     |<----- Request ------+                   |           |
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const tokChl = origin.createTokenChallenge(issuer.name, redemptionContext);
    //     +-- TokenChallenge -->|                   |           |
    //     |                     |<== Attestation ==>|           |
    //     |                     |                   |           |
    const tokReq = await client.createTokenRequest(tokChl, pkIssuer);
    //     |                     +----- ExtendedTokenRequest --->|
    //     |                     |                   |           |
    const tokRes = await issuer.issue(tokReq);
    //     |                     |<-------- TokenResponse -------+
    //     |                     |                   |           |
    const token = await client.finalize(tokRes);
    //     |<-- Request+Token ---+                   |           |
    //     |                     |                   |           |
    const isValid = await origin.verify(token, issuer.publicKey);

    console.log('Public-Verifiable With Metadata tokens');
    console.log(
        `    Suite: ${TOKEN_TYPES.PARTIALLY_BLIND_RSA.suite[mode as PartiallyBlindRSAMode]()}`,
    );
    console.log(`    Valid token: ${isValid}`);
}

export async function publicVerifiableWithMetadataTokens() {
    await rsaVariant(PartiallyBlindRSAMode.PSS);
    await rsaVariant(PartiallyBlindRSAMode.PSSZero);
}
