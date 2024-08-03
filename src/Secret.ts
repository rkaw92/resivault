import { Static, TSchema } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import { Decryptor, Encryptor } from './cryptography';
import { SecretEnvelopeSchema } from './base-schema';
import { AbstractFactory } from './AbstractFactory';

export const secretAbstractFactory = new AbstractFactory<Secret<TSchema>, Buffer>();

export abstract class Secret<Schema extends TSchema> {
    protected abstract schema: Schema;
    constructor(protected encryptedValue: Buffer) {}

    abstract getType(): string;

    reveal(decryptor: Decryptor): Static<Schema> {
        const parsed = decryptor.decrypt(this.encryptedValue, (raw) => JSON.parse(raw.toString('utf-8')));
        const data = Value.Decode(this.schema, parsed);
        return data;
    }

    toJSON(): Static<typeof SecretEnvelopeSchema> {
        return {
            type: this.getType(),
            encryptedValue: this.encryptedValue.toString('base64'),
        };
    }

    static fromJSON(input: Static<typeof SecretEnvelopeSchema>) {
        return secretAbstractFactory.create(input.type, Buffer.from(input.encryptedValue, 'base64'));
    }
}

export class Sealer<Schema extends TSchema, SecretType extends Secret<Schema>> {
    constructor(protected readonly schema: Schema, protected construct: (encryptedValue: Buffer) => SecretType) {}

    getSchema() {
        return this.schema;
    }

    seal(input: Static<Schema>, encryptor: Encryptor): SecretType {
        const validated = Value.Decode(this.schema, input);
        const plaintext = Buffer.from(JSON.stringify(validated), 'utf-8');
        return this.construct(encryptor.encrypt(plaintext));
    }
}
