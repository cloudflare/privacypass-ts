// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import * as varint from 'quicvarint';

import type { privateVerif, publicVerif } from './index.js';
import {
    type Token,
    TOKEN_TYPES,
    tokenEntryToSerializedLength,
    tokenRequestToTokenTypeEntry,
} from './index.js';
import {
    Issuer as Type1Issuer,
    TokenRequest as Type1TokenRequest,
    TokenResponse as Type1TokenResponse,
} from './priv_verif_token.js';
import {
    TokenResponse as Type2TokenResponse,
    Issuer as Type2Issuer,
    TokenRequest as Type2TokenRequest,
} from './pub_verif_token.js';
import { joinAll } from './util.js';

const TokenStatus = {
    ABSENT: 0x00,
    PRESENT: 0x01,
} as const;

type TokenStatus = (typeof TokenStatus)[keyof typeof TokenStatus];

export class TokenRequest {
    // struct {
    //     uint16_t token_type;
    //     select (token_type) {
    //         case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Ne];
    //         case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Nk];
    //     }
    // } TokenRequest;
    constructor(public readonly tokenRequest: Type1TokenRequest | Type2TokenRequest) {}

    static deserialize(bytes: Uint8Array): TokenRequest {
        const tokenTypeEntry = tokenRequestToTokenTypeEntry(bytes);

        switch (tokenTypeEntry.value) {
            case TOKEN_TYPES.VOPRF.value:
                return new TokenRequest(Type1TokenRequest.deserialize(bytes));
            case TOKEN_TYPES.BLIND_RSA.value:
                return new TokenRequest(Type2TokenRequest.deserialize(tokenTypeEntry, bytes));
            default:
                throw new Error('Token Type not supported');
        }
    }

    serialize(): Uint8Array {
        return this.tokenRequest.serialize();
    }

    get tokenType(): number {
        return this.tokenRequest.tokenType;
    }

    get truncatedTokenKeyId(): number {
        return this.tokenRequest.truncatedTokenKeyId;
    }

    get blindMsg(): Uint8Array {
        return this.tokenRequest.blindedMsg;
    }
}

export class BatchedTokenRequest {
    // struct {
    //     TokenRequest token_requests<V>;
    // } BatchTokenRequest

    constructor(public readonly tokenRequests: TokenRequest[]) {}

    static deserialize(bytes: Uint8Array): BatchedTokenRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const { value: length, usize } = varint.read(input, offset);
        offset += usize;

        if (length + offset !== bytes.length) {
            throw new Error('provided bytes does not match its encoded length');
        }

        const batchedTokenRequests: TokenRequest[] = [];

        while (offset < bytes.length) {
            const tokenTypeEntry = tokenRequestToTokenTypeEntry(bytes);
            const len = tokenEntryToSerializedLength(tokenTypeEntry);
            const b = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;

            batchedTokenRequests.push(TokenRequest.deserialize(b));
        }

        return new BatchedTokenRequest(batchedTokenRequests);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let length = 0;
        for (const tokenRequest of this.tokenRequests) {
            const tokenRequestSerialized = tokenRequest.serialize();
            output.push(tokenRequestSerialized.buffer);
            length += tokenRequestSerialized.length;
        }

        const b = varint.encode(length);
        return new Uint8Array(joinAll([b, ...output]));
    }

    [Symbol.iterator](): Iterator<TokenRequest> {
        let index = 0;
        const data = this.tokenRequests;

        return {
            next(): IteratorResult<TokenRequest> {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                } else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}

export class OptionalTokenResponse {
    // struct {
    //     uint8 present;
    //     select (present) {
    //         case 0: ; /* empty */
    //         case 1:
    //             uint16 token_type;
    //             GenericTokenResponse generic_token_response; /* Defined by token_type */
    //     }
    // } OptionalTokenResponse;
    constructor(
        public readonly tokenType: 1 | 2,
        public readonly tokenResponse:
            | null
            | publicVerif.TokenResponse
            | privateVerif.TokenResponse,
    ) {}

    static deserialize(bytes: Uint8Array): OptionalTokenResponse {
        if (bytes.length === 0) {
            throw new Error('OptionalTokenResponse MUST be of length strictly greater than 0');
        }
        switch (bytes[0]) {
            case TokenStatus.ABSENT:
                // For absent responses, we still need a token type but it doesn't matter
                // We use 1 as a placeholder since the response is null
                return new OptionalTokenResponse(1, null);
            case TokenStatus.PRESENT: {
                if (bytes.length < 3) {
                    throw new Error('OptionalTokenResponse PRESENT requires at least 3 bytes');
                }
                // Parse token_type from bytes[1:3] big-endian
                const tokenType = (bytes[1] << 8) | bytes[2];
                if (
                    tokenType !== TOKEN_TYPES.VOPRF.value &&
                    tokenType !== TOKEN_TYPES.BLIND_RSA.value
                ) {
                    throw new Error(`unsupported token type: ${tokenType}`);
                }
                const responseBytes = bytes.slice(3);
                const response =
                    tokenType === TOKEN_TYPES.VOPRF.value
                        ? Type1TokenResponse.deserialize(responseBytes)
                        : Type2TokenResponse.deserialize(responseBytes);
                return new OptionalTokenResponse(tokenType as 1 | 2, response);
            }
            default:
                throw new Error('OptionalTokenResponse MUST start with either 0x00 or 0x01');
        }
    }

    serialize(): Uint8Array {
        if (this.tokenResponse === null) {
            return new Uint8Array([TokenStatus.ABSENT]);
        }
        const serialized = this.tokenResponse.serialize();
        // Format: [present:1][token_type:2 big-endian][response_data]
        const result = new Uint8Array(1 + 2 + serialized.length);
        result[0] = TokenStatus.PRESENT;
        result[1] = (this.tokenType >> 8) & 0xff;
        result[2] = this.tokenType & 0xff;
        result.set(serialized, 3);
        return result;
    }

    /** Returns the serialized length of this response */
    length(): number {
        if (this.tokenResponse === null) {
            return 1; // just the ABSENT byte
        }
        return 1 + 2 + this.tokenResponse.length(); // present + token_type + response
    }
}

export class GenericBatchTokenResponse {
    // struct {
    //   OptionalTokenResponse optional_token_responses<V>;
    // } GenericBatchTokenResponse
    constructor(public readonly tokenResponses: OptionalTokenResponse[]) {}

    static deserialize(bytes: Uint8Array): GenericBatchTokenResponse {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const { value: length, usize } = varint.read(input, offset);
        offset += usize;

        if (length + offset !== bytes.length) {
            throw new Error('provided bytes does not match its encoded length');
        }

        const batchedTokenResponses: OptionalTokenResponse[] = [];

        while (offset < bytes.length) {
            const otr = OptionalTokenResponse.deserialize(bytes.slice(offset));
            offset += otr.length();
            batchedTokenResponses.push(otr);
        }

        return new GenericBatchTokenResponse(batchedTokenResponses);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let length = 0;
        for (const tokenResponse of this.tokenResponses) {
            const tokenResponseSerialized = tokenResponse.serialize();

            output.push(tokenResponseSerialized);
            length += tokenResponseSerialized.length;
        }

        const b = varint.encode(length);
        return new Uint8Array(joinAll([b, ...output]));
    }

    [Symbol.iterator](): Iterator<OptionalTokenResponse> {
        let index = 0;
        const data = this.tokenResponses;

        return {
            next(): IteratorResult<OptionalTokenResponse> {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                } else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}

export class Issuer {
    private readonly issuers: { 1: Type1Issuer[]; 2: Type2Issuer[] };

    constructor(...issuers: (Type1Issuer | Type2Issuer)[]) {
        this.issuers = { 1: [], 2: [] };

        for (const issuer of issuers) {
            if (issuer instanceof Type1Issuer) {
                this.issuers[1].push(issuer);
            } else if (issuer instanceof Type2Issuer) {
                this.issuers[2].push(issuer);
            }
        }
    }

    private async issuer(
        tokenType: number,
        truncatedTokenKeyId: number,
    ): Promise<Type1Issuer | Type2Issuer> {
        if (![TOKEN_TYPES.VOPRF.value, TOKEN_TYPES.BLIND_RSA.value].includes(tokenType)) {
            throw new Error('unsupported token type');
        }
        const issuers = this.issuers[tokenType as 1 | 2];
        for (const issuer of issuers) {
            // "truncated_token_key_id" is the least significant byte of the
            // token_key_id in network byte order (in other words, the
            // last 8 bits of token_key_id).
            const tokenKeyId = await issuer.tokenKeyID();
            const truncated = tokenKeyId[tokenKeyId.length - 1];
            if (truncated == truncatedTokenKeyId) {
                return issuer;
            }
        }
        throw new Error('no issuer found provided the truncated token key id');
    }

    async issue(tokenRequests: BatchedTokenRequest): Promise<GenericBatchTokenResponse> {
        const tokenResponses: OptionalTokenResponse[] = [];
        for (const tokenRequest of tokenRequests) {
            const tokenType = tokenRequest.tokenType as 1 | 2;
            try {
                const issuer = await this.issuer(tokenType, tokenRequest.truncatedTokenKeyId);
                const response = await issuer.issue(tokenRequest.tokenRequest);
                tokenResponses.push(new OptionalTokenResponse(tokenType, response));
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
            } catch (e) {
                console.log(e);
                tokenResponses.push(new OptionalTokenResponse(tokenType, null));
            }
        }

        return new GenericBatchTokenResponse(tokenResponses);
    }

    tokenKeyIDs(tokenType: 1 | 2): Promise<Uint8Array[]> {
        // eslint-disable-next-line security/detect-object-injection
        return Promise.all(this.issuers[tokenType].map((issuer) => issuer.tokenKeyID()));
    }

    async verify(token: Token): Promise<boolean> {
        const { tokenType, tokenKeyId } = token.authInput;
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const issuer = await this.issuer(tokenType, truncatedTokenKeyId);
        return issuer.verify(token);
    }

    [Symbol.iterator](): Iterator<Type1Issuer | Type2Issuer> {
        let index = 0;
        const data = [...this.issuers[1], ...this.issuers[2]];

        return {
            next(): IteratorResult<Type1Issuer | Type2Issuer> {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                } else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}

export class Client {
    createTokenRequest(tokenRequests: TokenRequest[]): BatchedTokenRequest {
        return new BatchedTokenRequest(tokenRequests);
    }

    deserializeTokenResponse(bytes: Uint8Array): GenericBatchTokenResponse {
        return GenericBatchTokenResponse.deserialize(bytes);
    }
}
