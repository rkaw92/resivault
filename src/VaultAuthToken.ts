import { randomBytes, timingSafeEqual } from 'node:crypto';

export class VaultAuthToken {
    constructor(private value = randomBytes(16)) { }

    toString() {
        return this.value.toString('hex');
    }

    static fromString(str: string) {
        return new VaultAuthToken(Buffer.from(str, 'hex'));
    }

    equals(other: VaultAuthToken) {
        return timingSafeEqual(this.value, other.value);
    }
}
