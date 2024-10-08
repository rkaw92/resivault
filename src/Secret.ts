import { Static, TSchema } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import { Decryptor, Encryptor } from './cryptography';
import { SecretEnvelopeSchema } from './base-schema';
import { AbstractFactory } from './AbstractFactory';
import { SecretTypeNotSupportedError } from './errors';

interface SecretFactory<SecretType extends Secret<TSchema> = Secret<TSchema>> {
    (label: string, encryptedValue: Buffer): SecretType;
}

const secretAbstractFactory = new AbstractFactory<Secret<TSchema>, [ string, Buffer ]>();
const sealersByType = new Map<string, Sealer<TSchema, Secret<TSchema>>>();

interface Registerable {
    type: string;
    factory: SecretFactory;
    sealer: Sealer<TSchema, Secret<TSchema>>;
}

export abstract class Secret<Schema extends TSchema> {
    protected abstract schema: Schema;
    constructor(protected label: string, protected encryptedValue: Buffer) {}

    abstract getType(): string;

    getLabel(): string {
        return this.label;
    }

    reveal(decryptor: Decryptor): Static<Schema> {
        const parsed = decryptor.decrypt(this.encryptedValue, (raw) => JSON.parse(raw.toString('utf-8')));
        const data = Value.Decode(this.schema, parsed);
        return data;
    }

    toJSON(): Static<typeof SecretEnvelopeSchema> {
        return {
            type: this.getType(),
            label: this.getLabel(),
            encryptedValue: this.encryptedValue.toString('base64'),
        };
    }

    static registerType(secretImpl: Registerable): void {
        secretAbstractFactory.register(secretImpl.type, secretImpl.factory);
        sealersByType.set(secretImpl.type, secretImpl.sealer);
    }

    static fromJSON(input: Static<typeof SecretEnvelopeSchema>): Secret<TSchema> {
        return secretAbstractFactory.create(input.type, input.label, Buffer.from(input.encryptedValue, 'base64'));
    }

    static getSealer(typeName: string): Sealer<TSchema, Secret<TSchema>> {
        const sealer = sealersByType.get(typeName);
        if (!sealer) {
            throw new SecretTypeNotSupportedError(typeName);
        }
        return sealer;
    }
}

export class Sealer<Schema extends TSchema, SecretType extends Secret<Schema>> {
    constructor(
        protected readonly schema: Schema,
        protected factory: SecretFactory<SecretType>
    ) {}

    getSchema() {
        return this.schema;
    }

    seal(label: string, input: Static<Schema>, encryptor: Encryptor): SecretType {
        const validated = Value.Decode(this.schema, input);
        const plaintext = Buffer.from(JSON.stringify(validated), 'utf-8');
        return this.factory(label, encryptor.encrypt(plaintext));
    }
}
