import { createCipheriv, createDecipheriv, createSecretKey, DecipherOCB, KeyObject, randomBytes, scryptSync } from 'node:crypto';

export interface CryptoProvider {
    generateKey(): KeyObject;
    keyBytes(): number;
    encrypt(plaintext: Buffer, key: KeyObject): Buffer;
    decrypt(cryptotext: Buffer, key: KeyObject): Buffer;
    describeLayout(): CryptotextLayout;
}

type CryptotextLayoutElement =
    { type: 'iv', len: number } |
    { type: 'payload', multipleOf: number } |
    { type: 'tag', len: number };

export class CryptotextLayout {
    constructor(private layout: Array<CryptotextLayoutElement>) {}

    toString() {
        return this.layout.map((elem) => {
            switch (elem.type) {
                case 'iv':
                case 'tag':
                    return `${elem.type}[len=${elem.len}B]`;
                case 'payload':
                    return `payload[multipleOf=${elem.multipleOf}B]`
            }
        }).join(' | ');
    }
}

export class PlaintextForMetadataOnly implements CryptoProvider {
    generateKey(): KeyObject {
        return createSecretKey(Buffer.from([]));
    }

    keyBytes() {
        return 0;
    }

    encrypt(plaintext: Buffer, key: KeyObject): Buffer {
        return Buffer.from(plaintext);
    }

    decrypt(cryptotext: Buffer, key: KeyObject): Buffer {
        return Buffer.from(cryptotext);
    }

    describeLayout(): CryptotextLayout {
        return new CryptotextLayout([{ type: 'payload', multipleOf: 1 }]);
    }
}

export class AES256KeyWrap implements CryptoProvider {
    protected ALGO = 'aes256-wrap' as const;
    protected IV_BYTES = 8;
    protected KEY_BYTES = 32;
    // All AES variants use 128-bit blocks, only the key size differs:
    protected BLOCK_SIZE = 16;
    // https://datatracker.ietf.org/doc/html/rfc3394#section-2.2.3.1
    protected RFC3394_IV = 'A6A6A6A6A6A6A6A6';

    generateKey() {
        return createSecretKey(randomBytes(this.KEY_BYTES));
    }

    keyBytes(): number {
        return this.KEY_BYTES;
    }

    protected validateKeySize(key: KeyObject) {
        if (key.symmetricKeySize !== this.KEY_BYTES) {
            throw new Error('key size incorrect for AES256 - must be 16 bytes');
        }
    }

    encrypt(plaintext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const iv = Buffer.from(this.RFC3394_IV, 'hex');
        const cipher = createCipheriv(this.ALGO, key, iv);
        const payload = Buffer.concat([
            cipher.update(plaintext),
            cipher.final(),
        ]);
        return payload;
    }

    decrypt(cryptotext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const iv = Buffer.from(this.RFC3394_IV, 'hex');
        const decipher = createDecipheriv(this.ALGO, key, iv);
        const plaintext = Buffer.concat([
            decipher.update(cryptotext),
            decipher.final(),
        ]);
        return plaintext;
    }

    describeLayout(): CryptotextLayout {
        return new CryptotextLayout([
            { type: 'iv', len: this.IV_BYTES },
            { type: 'payload', multipleOf: this.BLOCK_SIZE },
        ]);
    }
}

export class AES128GCM implements CryptoProvider {
    protected ALGO = 'aes-128-gcm' as const;
    // IV (GCM nonce) should optimally be 96 bits:
    protected IV_BYTES = 12;
    protected KEY_BYTES = 16;
    protected TAG_BYTES = 16;
    protected BLOCK_SIZE = 16;
    
    generateKey() {
        return createSecretKey(randomBytes(this.KEY_BYTES));
    }

    keyBytes(): number {
        return this.KEY_BYTES;
    }

    protected validateKeySize(key: KeyObject) {
        if (key.symmetricKeySize !== this.KEY_BYTES) {
            throw new Error('key size incorrect for AES128 - must be 16 bytes');
        }
    }

    encrypt(plaintext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const iv = randomBytes(this.IV_BYTES);
        const cipher = createCipheriv(this.ALGO, key, iv, { authTagLength: this.TAG_BYTES });
        const payload = Buffer.concat([
            cipher.update(plaintext),
            cipher.final(),
        ]);
        return Buffer.concat([ iv, payload, cipher.getAuthTag() ]);
    }

    decrypt(cryptotext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const [ iv, payload, tag ] = [
            cryptotext.subarray(0, this.IV_BYTES),
            cryptotext.subarray(0 + this.IV_BYTES, cryptotext.length - this.TAG_BYTES),
            cryptotext.subarray(-this.TAG_BYTES),
        ];
        const decipher = createDecipheriv(this.ALGO, key, iv, { authTagLength: this.TAG_BYTES });
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([
            decipher.update(payload),
            decipher.final(),
        ]);
        return plaintext;
    }

    describeLayout(): CryptotextLayout {
        return new CryptotextLayout([
            { type: 'iv', len: this.IV_BYTES },
            { type: 'payload', multipleOf: this.BLOCK_SIZE },
            { type: 'tag', len: this.TAG_BYTES },
        ]);
    }
}

export class AES128OCB implements CryptoProvider {
    protected ALGO = 'aes-128-ocb' as const;
    // "Other values can be accommodated, but 96 bits (12 bytes) is the recommended nonce length."
    protected IV_BYTES = 12;
    protected KEY_BYTES = 16;
    protected TAG_BYTES = 16;
    protected BLOCK_SIZE = 16;
    
    generateKey() {
        return createSecretKey(randomBytes(this.KEY_BYTES));
    }

    keyBytes(): number {
        return this.KEY_BYTES;
    }

    protected validateKeySize(key: KeyObject) {
        if (key.symmetricKeySize !== this.KEY_BYTES) {
            throw new Error('key size incorrect for AES128 - must be 16 bytes');
        }
    }

    encrypt(plaintext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const iv = randomBytes(this.IV_BYTES);
        const cipher = createCipheriv(this.ALGO, key, iv, { authTagLength: this.TAG_BYTES });
        const payload = Buffer.concat([
            cipher.update(plaintext),
            cipher.final(),
        ]);
        return Buffer.concat([ iv, payload, cipher.getAuthTag() ]);
    }

    decrypt(cryptotext: Buffer, key: KeyObject): Buffer {
        this.validateKeySize(key);
        const [ iv, payload, tag ] = [
            cryptotext.subarray(0, this.IV_BYTES),
            cryptotext.subarray(0 + this.IV_BYTES, cryptotext.length - this.TAG_BYTES),
            cryptotext.subarray(-this.TAG_BYTES),
        ];
        const decipher: DecipherOCB = createDecipheriv(this.ALGO, key, iv, { authTagLength: this.TAG_BYTES });
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([
            decipher.update(payload),
            decipher.final(),
        ]);
        return plaintext;
    }

    describeLayout(): CryptotextLayout {
        return new CryptotextLayout([
            { type: 'iv', len: this.IV_BYTES },
            { type: 'payload', multipleOf: this.BLOCK_SIZE },
            { type: 'tag', len: this.TAG_BYTES },
        ]);
    }
}

export interface Encryptor {
    encrypt(plaintext: Buffer): Buffer;
}

export class DefaultEncryptor {
    constructor(private provider: CryptoProvider, private key: KeyObject) {}

    encrypt(plaintext: Buffer): Buffer {
        try {
            const cryptotext = this.provider.encrypt(plaintext, this.key);
            return cryptotext;
        } finally {
            plaintext.fill(0);
        }
    }
}

export interface Decryptor {
    decrypt<T>(cryptotext: Buffer, processValue: (plain: Buffer) => T): T;
}

export class DefaultDecryptor implements Decryptor {
    constructor(private provider: CryptoProvider, private key: KeyObject) {}

    decrypt<T>(cryptotext: Buffer, processValue: (plain: Buffer) => T): T {
        const plain = this.provider.decrypt(cryptotext, this.key);
        try {
            const result = processValue(plain);
            return result;
        } finally {
            plain.fill(0);
        }
    }
}

export interface KeyDeriver {
    deriveNewKey(password: string, keyBytes: number): { key: KeyObject, salt: Buffer };
    deriveKey(password: string, salt: Buffer, keyBytes: number): KeyObject;
    getName(): string;
}

export class ScryptKDFv1 implements KeyDeriver {
    protected SCRYPT_OPTS = {
        cost: 16384,
        blockSize: 8,
        parallelization: 1,
        maxmem: 32 * 1024 * 1024,
    };
    protected SALT_BYTES = 16;

    deriveNewKey(password: string, keyBytes: number): { key: KeyObject; salt: Buffer; } {
        const salt = randomBytes(this.SALT_BYTES);
        const key = this.deriveKey(password, salt, keyBytes);
        return { key, salt };
    }

    deriveKey(password: string, salt: Buffer, keyBytes: number): KeyObject {
        const input = password.normalize('NFC');
        return createSecretKey(scryptSync(input, salt, keyBytes, this.SCRYPT_OPTS));
    }

    getName(): string {
        return 'ScryptKDFv1';
    }
}
