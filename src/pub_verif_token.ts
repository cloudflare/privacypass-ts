// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import {
    type BlindRSA,
    type PartiallyBlindRSA,
    type BlindRSAPlatformParams,
    RSABSSA,
    RSAPBSSA,
} from '@cloudflare/blindrsa-ts';

import { convertRSASSAPSSToEnc, joinAll } from './util.js';
import {
    AuthenticatorInput,
    Extensions,
    Token,
    TokenChallenge,
    type TokenTypeEntry,
} from './auth_scheme/private_token.js';

export enum BlindRSAMode {
    PSSZero = 0, // Corresponds to RSASSA.SHA384.PSSZero.Deterministic
    PSS = 48, // Corresponds to RSASSA.SHA384.PSS.Deterministic
}

export import PartiallyBlindRSAMode = BlindRSAMode;
import type { PartiallyBlindRSAPlatformParams } from '@cloudflare/blindrsa-ts/lib/src/partially_blindrsa.js';

export interface BlindRSAExtraParams {
    suite: Record<BlindRSAMode, (params?: BlindRSAPlatformParams) => BlindRSA>;
    rsaParams: RsaHashedImportParams;
}

export interface PartiallyBlindRSAExtraParams {
    suite: Record<PartiallyBlindRSAMode, (params?: BlindRSAPlatformParams) => PartiallyBlindRSA>;
    rsaParams: RsaHashedImportParams;
}

const BLINDRSA_EXTRA_PARAMS: BlindRSAExtraParams = {
    suite: {
        [BlindRSAMode.PSSZero]: RSABSSA.SHA384.PSSZero.Deterministic,
        [BlindRSAMode.PSS]: RSABSSA.SHA384.PSS.Deterministic,
    },
    rsaParams: {
        name: 'RSA-PSS',
        hash: 'SHA-384',
    },
} as const;

const PARTIALLY_BLINDRSA_EXTRA_PARAMS: PartiallyBlindRSAExtraParams = {
    suite: {
        [PartiallyBlindRSAMode.PSSZero]: RSAPBSSA.SHA384.PSSZero.Deterministic,
        [PartiallyBlindRSAMode.PSS]: RSAPBSSA.SHA384.PSS.Deterministic,
    },
    rsaParams: {
        name: 'RSA-PSS',
        hash: 'SHA-384',
    },
} as const;

// Token Type Entry Update:
//  - Token Type Blind RSA (2048-bit)
//  - Token Type Partially Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-blind-rsa-2048-b',
// https://datatracker.ietf.org/doc/html/draft-hendrickson-privacypass-public-metadata-03#section-8.2
export const BLIND_RSA: Readonly<TokenTypeEntry> & BlindRSAExtraParams = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
    ...BLINDRSA_EXTRA_PARAMS,
} as const;
type BlindRSAType = typeof BLIND_RSA;

export const PARTIALLY_BLIND_RSA: Readonly<TokenTypeEntry> & PartiallyBlindRSAExtraParams = {
    value: 0xda7a,
    name: 'Partially Blind RSA (2048-bit)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: true,
    privateMetadata: false,
    ...PARTIALLY_BLINDRSA_EXTRA_PARAMS,
} as const;
type PartiallyBlindRSAType = typeof PARTIALLY_BLIND_RSA;

function getCryptoKey(publicKey: Uint8Array): Promise<CryptoKey> {
    // Converts a RSA-PSS key into a RSA Encryption key.
    // Required because WebCrypto do not support importing keys with `RSASSA-PSS` OID,
    // See https://github.com/w3c/webcrypto/pull/325
    const spkiEncoded = convertRSASSAPSSToEnc(publicKey);

    return crypto.subtle.importKey('spki', spkiEncoded, BLIND_RSA.rsaParams, true, ['verify']);
}

export async function getPublicKeyBytes(publicKey: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
}

async function getTokenKeyID(publicKey: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
}

export class TokenRequest {
    // struct {
    //     uint16_t token_type = 0x0002 | 0xda7a; /* Type Blind RSA (2048-bit) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Nk];
    // } TokenRequest;

    tokenType: number;
    constructor(
        public readonly truncatedTokenKeyId: number,
        public readonly blindedMsg: Uint8Array,
        tokenType: TokenTypeEntry,
    ) {
        if (blindedMsg.length !== tokenType.Nk) {
            throw new Error('invalid blinded message size');
        }

        this.tokenType = tokenType.value;
    }

    static deserialize(tokenType: TokenTypeEntry, bytes: Uint8Array): TokenRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        if (type !== tokenType.value) {
            throw new Error('mismatch of token type');
        }

        const tokenKeyId = input.getUint8(offset);
        offset += 1;

        const len = tokenType.Nk;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new TokenRequest(tokenKeyId, blindedMsg, tokenType);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.truncatedTokenKeyId);
        output.push(b);

        b = this.blindedMsg.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class ExtendedTokenRequest {
    // struct {
    //     TokenRequest request;
    //     Extensions extensions;
    // } ExtendedTokenRequest;

    constructor(
        public readonly request: TokenRequest,
        public readonly extensions: Extensions,
    ) {}

    static deserialize(bytes: Uint8Array): ExtendedTokenRequest {
        const request = TokenRequest.deserialize(PARTIALLY_BLIND_RSA, bytes);
        const extensions = Extensions.deserialize(bytes.slice(3 + PARTIALLY_BLIND_RSA.Nk));
        return new ExtendedTokenRequest(request, extensions);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        const request = this.request.serialize();
        output.push(request.buffer);

        const extensions = this.extensions.serialize();
        output.push(extensions.buffer);

        return new Uint8Array(joinAll(output));
    }
}

export class TokenResponse {
    // struct {
    //     uint8_t blind_sig[Nk];
    // } TokenResponse;

    constructor(public readonly blindSig: Uint8Array) {
        if (blindSig.length !== BLIND_RSA.Nk) {
            throw new Error('blind signature has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenResponse {
        return new TokenResponse(bytes.slice(0, BLIND_RSA.Nk));
    }

    serialize(): Uint8Array {
        return new Uint8Array(this.blindSig);
    }
}

abstract class PubliclyVerifiableIssuer {
    private suite: (extensions?: Extensions) => Pick<BlindRSA, 'blindSign' | 'verify'>;

    constructor(
        public readonly mode: BlindRSAMode,
        public readonly name: string,
        private readonly privateKey: CryptoKey,
        public readonly publicKey: CryptoKey,
        public readonly params?: BlindRSAPlatformParams | PartiallyBlindRSAPlatformParams,
    ) {
        this.suite = (extensions?: Extensions) => {
            if (extensions === undefined) {
                return BLIND_RSA.suite[this.mode](this.params);
            } else {
                const suite = PARTIALLY_BLIND_RSA.suite[this.mode](this.params);
                const serializedExtensions = extensions.serialize();
                return {
                    blindSign: (privateKey: CryptoKey, blindMsg: Uint8Array) =>
                        suite.blindSign(privateKey, blindMsg, serializedExtensions),
                    verify: (publicKey: CryptoKey, signature: Uint8Array, message: Uint8Array) =>
                        suite.verify(publicKey, signature, message, serializedExtensions),
                };
            }
        };
    }

    protected async _issue(tokReq: TokenRequest, extensions?: Extensions): Promise<TokenResponse> {
        const blindSig = await this.suite(extensions).blindSign(this.privateKey, tokReq.blindedMsg);
        return new TokenResponse(blindSig);
    }

    verify(token: Token): Promise<boolean> {
        return this.suite().verify(
            this.publicKey,
            token.authenticator,
            token.authInput.serialize(),
        );
    }
}

export class Issuer extends PubliclyVerifiableIssuer {
    async issue(tokReq: TokenRequest): Promise<TokenResponse> {
        return super._issue(tokReq);
    }

    static generateKey(
        mode: BlindRSAMode,
        algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>,
    ): Promise<CryptoKeyPair> {
        const suite = BLIND_RSA.suite[mode as unknown as BlindRSAMode]();
        return suite.generateKey(algorithm);
    }
}

export class IssuerWithMetadata extends PubliclyVerifiableIssuer {
    async issue(tokReq: ExtendedTokenRequest): Promise<TokenResponse> {
        return super._issue(tokReq.request, tokReq.extensions);
    }

    static generateKey(
        mode: PartiallyBlindRSAMode,
        algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>,
        generateSafePrimeSync?: (length: number) => bigint,
    ): Promise<CryptoKeyPair> {
        const suite = PARTIALLY_BLIND_RSA.suite[mode as unknown as PartiallyBlindRSAMode]();
        return suite.generateKey(algorithm, generateSafePrimeSync);
    }
}

abstract class PubliclyVerifiableClient {
    private finData?: {
        pkIssuer: CryptoKey;
        tokenInput: Uint8Array;
        authInput: AuthenticatorInput;
        inv: Uint8Array;
    };

    // given extensions are known when the constructor is called, extensions can be abstracted to provide the same signature as BlindRSA
    private suite: Pick<BlindRSA, 'blind' | 'finalize'>;
    private tokenType: BlindRSAType | PartiallyBlindRSAType;

    constructor(
        public readonly mode: BlindRSAMode,
        public readonly extensions?: Extensions,
    ) {
        if (this.extensions === undefined) {
            this.tokenType = BLIND_RSA;
            this.suite = BLIND_RSA.suite[this.mode]();
        } else {
            this.tokenType = PARTIALLY_BLIND_RSA;
            const suite = PARTIALLY_BLIND_RSA.suite[this.mode]();
            const extensions = this.extensions.serialize();
            this.suite = {
                blind: (publicKey: CryptoKey, msg: Uint8Array) =>
                    suite.blind(publicKey, msg, extensions),
                finalize: (
                    publicKey: CryptoKey,
                    msg: Uint8Array,
                    blindSig: Uint8Array,
                    inv: Uint8Array,
                ) => suite.finalize(publicKey, msg, extensions, blindSig, inv),
            };
        }
    }

    protected async _createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<TokenRequest> {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const challengeDigest = new Uint8Array(
            await crypto.subtle.digest('SHA-256', tokChl.serialize()),
        );

        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        const authInput = new AuthenticatorInput(
            this.tokenType,
            this.tokenType.value,
            nonce,
            challengeDigest,
            tokenKeyId,
        );
        const tokenInput = authInput.serialize();

        const pkIssuer = await getCryptoKey(issuerPublicKey);
        const { blindedMsg, inv } = await this.suite.blind(pkIssuer, tokenInput);
        // "truncated_token_key_id" is the least significant byte of the
        // token_key_id in network byte order (in other words, the
        // last 8 bits of token_key_id).
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const tokenRequest = new TokenRequest(truncatedTokenKeyId, blindedMsg, this.tokenType);

        this.finData = { tokenInput, authInput, inv, pkIssuer };

        return tokenRequest;
    }

    deserializeTokenResponse(bytes: Uint8Array): TokenResponse {
        return TokenResponse.deserialize(bytes);
    }

    async finalize(tokRes: TokenResponse): Promise<Token> {
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }

        const authenticator = await this.suite.finalize(
            this.finData.pkIssuer,
            this.finData.tokenInput,
            tokRes.blindSig,
            this.finData.inv,
        );
        const token = new Token(this.tokenType, this.finData.authInput, authenticator);

        this.finData = undefined;

        return token;
    }
}

export class Client extends PubliclyVerifiableClient {
    async createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<TokenRequest> {
        return super._createTokenRequest(tokChl, issuerPublicKey);
    }
}

export class ClientWithMetadata extends PubliclyVerifiableClient {
    async createTokenRequest(
        tokChl: TokenChallenge,
        issuerPublicKey: Uint8Array,
    ): Promise<ExtendedTokenRequest> {
        const tokenRequest = await super._createTokenRequest(tokChl, issuerPublicKey);
        if (!this.extensions) {
            throw new Error('no extensions available');
        }
        return new ExtendedTokenRequest(tokenRequest, this.extensions);
    }
}

abstract class PubliclyVerifiableOrigin {
    private tokenType: BlindRSAType | PartiallyBlindRSAType;
    private suite: Pick<BlindRSA, 'verify'>;

    constructor(
        public readonly mode: BlindRSAMode,
        public readonly originInfo?: string[],
        public readonly extensions?: Extensions,
    ) {
        if (this.extensions === undefined) {
            this.suite = BLIND_RSA.suite[this.mode]();
            this.tokenType = BLIND_RSA;
        } else {
            const suite = PARTIALLY_BLIND_RSA.suite[this.mode]();
            const extensions = this.extensions.serialize();
            this.suite = {
                verify: (publicKey: CryptoKey, signature: Uint8Array, message: Uint8Array) =>
                    suite.verify(publicKey, signature, message, extensions),
            };
            this.tokenType = PARTIALLY_BLIND_RSA;
        }
    }

    async verify(token: Token, publicKeyIssuer: CryptoKey): Promise<boolean> {
        return this.suite.verify(publicKeyIssuer, token.authenticator, token.authInput.serialize());
    }

    createTokenChallenge(issuerName: string, redemptionContext: Uint8Array): TokenChallenge {
        return new TokenChallenge(
            this.tokenType.value,
            issuerName,
            redemptionContext,
            this.originInfo,
        );
    }
}

export class Origin extends PubliclyVerifiableOrigin {}

export class OriginWithMetadata extends PubliclyVerifiableOrigin {
    constructor(mode: PartiallyBlindRSAMode, extensions: Extensions, originInfo?: string[]) {
        super(mode, originInfo, extensions);
    }
}
