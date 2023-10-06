// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

import type { TokenTypeEntry } from '../src/index.js';

export function hexToString(x: string): string {
    return Buffer.from(x, 'hex').toString();
}

export function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

export function uint8ToHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex');
}

interface CanSerialize {
    serialize(): Uint8Array;
}

interface CanDeserialize<T extends CanSerialize> {
    deserialize(_b: Uint8Array): T;
}

export function testSerialize(classType: CanDeserialize<CanSerialize>, instance: CanSerialize) {
    const bytes = instance.serialize();
    const got = classType.deserialize(bytes);
    expect(got).toStrictEqual(instance);
}

interface CanDeserializeWithType<T extends CanSerialize> {
    deserialize(type: TokenTypeEntry, _b: Uint8Array): T;
}

export function testSerializeType(
    type: TokenTypeEntry,
    classType: CanDeserializeWithType<CanSerialize>,
    instance: CanSerialize,
) {
    const bytes = instance.serialize();
    const got = classType.deserialize(type, bytes);
    expect(got).toStrictEqual(instance);
}
