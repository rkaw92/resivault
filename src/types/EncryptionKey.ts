import { Static, Type } from "@sinclair/typebox";
import { Secret, Sealer, secretAbstractFactory } from "../Secret";
import { Decryptor, Encryptor } from '../cryptography';

const EncryptionKeySchema = Type.Object({
    base64: Type.String(),
});

class EncryptionKeySealer extends Sealer<typeof EncryptionKeySchema, EncryptionKey> {
    constructor() {
        super(EncryptionKeySchema, (encryptedValue) => new EncryptionKey(encryptedValue));
    }
    
    override seal(input: Static<typeof EncryptionKeySchema>, encryptor: Encryptor): EncryptionKey {
        const plaintext = Buffer.from(input.base64, 'base64');
        return this.construct(encryptor.encrypt(plaintext));
    }
}

export class EncryptionKey extends Secret<typeof EncryptionKeySchema> {
    protected schema = EncryptionKeySchema;
    public static readonly sealer = new EncryptionKeySealer();
    public static readonly type = 'EncryptionKey' as const;

    getType() {
        return EncryptionKey.type;
    }

    override reveal(decryptor: Decryptor): Static<typeof EncryptionKeySchema> {
        return decryptor.decrypt(this.encryptedValue, (plain) => ({ base64: plain.toString('base64') }));
    }
}

secretAbstractFactory.register(EncryptionKey.type, (encryptedValue) => new EncryptionKey(encryptedValue));
