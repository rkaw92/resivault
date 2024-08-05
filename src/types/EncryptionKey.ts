import { Static, Type } from "@sinclair/typebox";
import { Secret, Sealer } from "../Secret";
import { Decryptor, Encryptor } from '../cryptography';

const EncryptionKeySchema = Type.Object({
    base64: Type.String(),
});

const encryptionKeyFactory = (label: string, encryptedValue: Buffer) => new EncryptionKey(label, encryptedValue);

class EncryptionKeySealer extends Sealer<typeof EncryptionKeySchema, EncryptionKey> {
    constructor() {
        super(EncryptionKeySchema, encryptionKeyFactory);
    }
    
    override seal(label: string, input: Static<typeof EncryptionKeySchema>, encryptor: Encryptor): EncryptionKey {
        const plaintext = Buffer.from(input.base64, 'base64');
        return this.factory(label, encryptor.encrypt(plaintext));
    }
}

export class EncryptionKey extends Secret<typeof EncryptionKeySchema> {
    protected schema = EncryptionKeySchema;
    public static readonly type = 'EncryptionKey' as const;
    public static readonly factory = encryptionKeyFactory;
    public static readonly sealer = new EncryptionKeySealer();

    getType() {
        return EncryptionKey.type;
    }

    override reveal(decryptor: Decryptor): Static<typeof EncryptionKeySchema> {
        return decryptor.decrypt(this.encryptedValue, (plain) => ({ base64: plain.toString('base64') }));
    }
}

Secret.registerType(EncryptionKey);
