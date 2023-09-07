// Entries of the Privacy Pass Token Type Registry

import { joinAll } from './util.js';

// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-12#name-token-type-registry
export interface TokenTypeEntry {
    value: number;
    name: string;
    publicVerifiable: boolean;
    publicMetadata: boolean;
    privateMetadata: boolean;
    Nk: number;
    Nid: number;
}

export class TokenChallenge {
    // This class represents the following structure:
    //
    // struct {
    //     uint16_t token_type;
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    // } TokenChallenge;

    constructor(
        public readonly tokenType: number,
        public readonly issuerName: string,
        public readonly redemptionContext: Uint8Array,
        public readonly originInfo?: string[],
    ) {
        const MAX_UINT16 = (1 << 16) - 1;
        if (issuerName.length > MAX_UINT16) {
            throw new Error('invalid issuer name size');
        }

        if (originInfo) {
            const allOriginInfo = originInfo.join(',');
            if (allOriginInfo.length > MAX_UINT16) {
                throw new Error('invalid origin info size');
            }
        }

        if (!(redemptionContext.length == 0 || redemptionContext.length == 32)) {
            throw new Error('invalid redemptionContext size');
        }
    }

    static deserialize(bytes: Uint8Array): TokenChallenge {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        let len = input.getUint16(offset);
        offset += 2;
        const issuerNameBytes = input.buffer.slice(offset, offset + len);
        offset += len;

        const td = new TextDecoder();
        const issuerName = td.decode(issuerNameBytes);

        len = input.getUint8(offset);
        offset += 1;
        const redemptionContext = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = input.getUint16(offset);
        offset += 2;

        let originInfo = undefined;
        if (len > 0) {
            const allOriginInfoBytes = input.buffer.slice(offset, offset + len);
            const allOriginInfo = td.decode(allOriginInfoBytes);
            originInfo = allOriginInfo.split(',');
        }

        return new TokenChallenge(type, issuerName, redemptionContext, originInfo);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        const te = new TextEncoder();
        const issuerNameBytes = te.encode(this.issuerName);

        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, issuerNameBytes.length);
        output.push(b);

        b = issuerNameBytes.buffer;
        output.push(b);

        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.redemptionContext.length);
        output.push(b);

        b = this.redemptionContext.buffer;
        output.push(b);

        b = new ArrayBuffer(2);

        let allOriginInfoBytes = new Uint8Array(0);
        if (this.originInfo) {
            const allOriginInfo = this.originInfo.join(',');
            allOriginInfoBytes = te.encode(allOriginInfo);
        }

        new DataView(b).setUint16(0, allOriginInfoBytes.length);
        output.push(b);

        b = allOriginInfoBytes.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class TokenPayload {
    // This class represents the following structure:
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    // } TokenPayload;

    static readonly NONCE_LENGTH = 32;
    static readonly CHALLENGE_LENGTH = 32;
    constructor(
        tokenTypeEntry: TokenTypeEntry,
        public readonly tokenType: number,
        public readonly nonce: Uint8Array,
        public readonly challengeDigest: Uint8Array,
        public readonly tokenKeyId: Uint8Array,
    ) {
        if (tokenType !== tokenTypeEntry.value) {
            throw new Error('mismatch of token type');
        }

        if (nonce.length !== TokenPayload.NONCE_LENGTH) {
            throw new Error('invalid nonce size');
        }

        if (challengeDigest.length !== TokenPayload.CHALLENGE_LENGTH) {
            throw new Error('invalid challenge size');
        }

        if (tokenKeyId.length !== tokenTypeEntry.Nid) {
            throw new Error('invalid tokenKeyId size');
        }

        this.tokenType = tokenTypeEntry.value;
    }

    static deserialize(
        tokenTypeEntry: TokenTypeEntry,
        bytes: Uint8Array,
        ops: { bytesRead: number },
    ): TokenPayload {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const type = input.getUint16(offset);
        offset += 2;

        let len = TokenPayload.NONCE_LENGTH;
        const nonce = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = TokenPayload.CHALLENGE_LENGTH;
        const challengeDigest = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        len = tokenTypeEntry.Nid;
        const tokenKeyId = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        ops.bytesRead = offset;

        return new TokenPayload(tokenTypeEntry, type, nonce, challengeDigest, tokenKeyId);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);

        b = this.nonce.buffer;
        output.push(b);

        b = this.challengeDigest.buffer;
        output.push(b);

        b = this.tokenKeyId.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}

export class Token {
    // This class represents the following structure:
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    //     uint8_t authenticator[Nk];
    // } Token;

    constructor(
        tokenTypeEntry: TokenTypeEntry,
        public tokenPayload: TokenPayload,
        public authenticator: Uint8Array,
    ) {
        if (authenticator.length !== tokenTypeEntry.Nk) {
            throw new Error('invalid authenticator size');
        }
    }

    static deserialize(tokenTypeEntry: TokenTypeEntry, bytes: Uint8Array): Token {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const ops = { bytesRead: 0 };
        const payload = TokenPayload.deserialize(tokenTypeEntry, bytes, ops);
        offset += ops.bytesRead;

        const len = tokenTypeEntry.Nk;
        const authenticator = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;

        return new Token(tokenTypeEntry, payload, authenticator);
    }

    serialize(): Uint8Array {
        return new Uint8Array(
            joinAll([this.tokenPayload.serialize().buffer, this.authenticator.buffer]),
        );
    }
}
