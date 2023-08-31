// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

export const PRIVATE_TOKEN_ISSUER_DIRECTORY = '/.well-known/private-token-issuer-directory';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#section-8.3
export enum MediaType {
    PRIVATE_TOKEN_ISSUER_DIRECTORY = 'application/private-token-issuer-directory',
    PRIVATE_TOKEN_REQUEST = 'application/private-token-request',
    PRIVATE_TOKEN_RESPONSE = 'application/private-token-response',
}

// Issuer 'token-keys' object description'
//
// See Table 2 of https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#name-configuration
export interface TokenKey {
    'token-type': number;
    'token-key': string;
    'not-before'?: number;
}

// Issuer directory object description
//
// See Table 1 of https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-11#name-configuration
export interface IssuerConfig {
    'issuer-request-uri': string;
    'token-keys': Array<TokenKey>;
}

// Fetch defaut issuer configuration.
export async function getIssuerUrl(issuerName: string): Promise<string> {
    const baseURL = `https://${issuerName}`;
    const configURI = `${baseURL}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`;
    const res = await fetch(configURI);
    if (res.status !== 200) {
        throw new Error(`issuerConfig: no configuration was found at ${configURI}`);
    }

    const response: IssuerConfig = await res.json();
    const uri = response['issuer-request-uri'];
    try {
        // assess is valid URL
        new URL(uri);
        return uri;
    } catch (_) {
        return `${baseURL}${uri}`;
    }
}

export interface TokenRequestProtocol {
    serialize(): Uint8Array;
}

export interface TokenResponseProtocol {}
