import { Buffer } from 'buffer';
import { base64url } from 'rfc4648';

export interface TokenTypeEntry {
    name: string;
    value: number;
    Nk: number;
    Nid: number;
    publicVerifiable: boolean;
    publicMetadata: boolean;
    privateMetadata: boolean;
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
        public tokenType: number,
        public issuerName: string,
        public redemptionContext: Uint8Array,
        public originInfo: string[],
    ) {}

    static parse(bytes: Uint8Array): TokenChallenge {
        let offset = 0;
        const input = Buffer.from(bytes);

        const type = input.readUint16BE(offset);
        offset += 2;

        let len = input.readUint16BE(offset);
        offset += 2;
        const issuerName = input.subarray(offset, offset + len).toString();
        offset += len;

        len = input.readUInt8(offset);
        offset += 1;
        const redemptionContext = new Uint8Array(input.subarray(offset, offset + len));
        offset += len;

        len = input.readUint16BE(offset);
        offset += 2;
        const allOriginInfo = input.subarray(offset, offset + len).toString();
        const originInfo = allOriginInfo.split(',');

        return new TokenChallenge(type, issuerName, redemptionContext, originInfo);
    }

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        const te = new TextEncoder();
        const issuerNameBytes = te.encode(this.issuerName);

        b = Buffer.alloc(2);
        b.writeUint16BE(issuerNameBytes.length);
        output.push(b);

        b = Buffer.from(issuerNameBytes);
        output.push(b);

        b = Buffer.alloc(1);
        b.writeUint8(this.redemptionContext.length);
        output.push(b);

        b = Buffer.from(this.redemptionContext);
        output.push(b);

        const allOriginInfo = this.originInfo.join(',');
        const allOriginInfoBytes = te.encode(allOriginInfo);

        b = Buffer.alloc(2);
        b.writeUint16BE(allOriginInfoBytes.length);
        output.push(b);

        b = Buffer.from(allOriginInfoBytes);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

export interface PrivateToken {
    challenge: TokenChallenge; // contains a TokenChallenge.
    challengeSerialized: Uint8Array; // contains a serialized version of the TokenChallenge value.
    tokenKey: Uint8Array; //  contains a base64url encoding of the public key for issuance.
    maxAge: number | undefined; // an optional parameter that consists of the number of seconds for which the challenge will be accepted by the origin.
}

export function parsePrivateToken(data: string): PrivateToken {
    // Consumes data:
    //   challenge="abc...", token-key="123..."

    const attributes = data.split(',');
    const pt: Partial<PrivateToken> = {};

    for (const attr of attributes) {
        const idx = attr.indexOf('=');
        let attrKey = attr.substring(0, idx);
        let attrValue = attr.substring(idx + 1);
        attrValue = attrValue.replaceAll('"', '');
        attrKey = attrKey.trim();
        attrValue = attrValue.trim();

        switch (attrKey) {
            case 'challenge':
                pt.challengeSerialized = base64url.parse(attrValue);
                pt.challenge = TokenChallenge.parse(pt.challengeSerialized);
                break;
            case 'token-key':
                pt.tokenKey = base64url.parse(attrValue);
                break;
            case 'max-age':
                pt.maxAge = parseInt(attrValue);
                break;
        }
    }

    if (
        pt.challengeSerialized === undefined ||
        pt.challenge === undefined ||
        pt.tokenKey === undefined
    ) {
        throw new Error('cannot parse PrivateToken');
    }

    return pt as PrivateToken;
}

export function parsePrivateTokens(header: string): PrivateToken[] {
    // Consumes data:
    //   PrivateToken challenge="abc...", token-key="123...",
    //   PrivateToken challenge="def...", token-key="234..."

    const challenges = header.split('PrivateToken ');
    const listTokens = new Array<PrivateToken>();

    for (const challenge of challenges) {
        if (challenge.length === 0) {
            continue;
        }

        const privToken = parsePrivateToken(challenge);
        listTokens.push(privToken);
    }

    return listTokens;
}

export class TokenPayload {
    constructor(
        public tokenType: number,
        public nonce: Uint8Array,
        public challengeDigest: Uint8Array,
        public tokenKeyId: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<Buffer>();

        let b = Buffer.alloc(2);
        b.writeUint16BE(this.tokenType);
        output.push(b);

        b = Buffer.from(this.nonce);
        output.push(b);

        b = Buffer.from(this.challengeDigest);
        output.push(b);

        b = Buffer.from(this.tokenKeyId);
        output.push(b);

        return new Uint8Array(Buffer.concat(output));
    }
}

export class Token {
    // This class represents the Token structure (composed by a TokenPayload and an authenticator).
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    //     uint8_t authenticator[Nk];
    // } Token;

    constructor(
        public payload: TokenPayload,
        public authenticator: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        return new Uint8Array(Buffer.concat([this.payload.serialize(), this.authenticator]));
    }
}
