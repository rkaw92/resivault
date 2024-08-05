import { Static, TSchema } from "@sinclair/typebox";
import { Secret } from "./Secret";
import { Tag } from "./Tag";
import { Usage } from "./Usage";
import { createId as cuid2 } from '@paralleldrive/cuid2';
import { EntrySchema } from './base-schema';
import { Value } from '@sinclair/typebox/value';

/**
 * An Entry is a singular item in the user's encrypted vault. This is the smallest unit of synchronization.
 * All Entries are encrypted at rest. After decryption and loading into memory, a special protected part remains
 *  in its encrypted form to limit exposure time. This protected part is decrypted on demand only.
 */
export class Entry {
    constructor(
        private id: string,
        private name: string,
        private tags: Tag[],
        private usage: Usage<TSchema>,
        private secrets: Secret<TSchema>[],
    ) {}

    getId() {
        return this.id;
    }
    
    getName() {
        return this.name;
    }

    getTags() {
        return this.tags.slice();
    }

    getUsage() {
        return this.usage;
    }

    getSecrets() {
        return this.secrets.slice();
    }

    addSecret(secret: Secret<TSchema>) {
        this.secrets.push(secret);
    }

    // TODO: Secret removal

    toJSON(): Static<typeof EntrySchema> {
        return Value.Encode(EntrySchema, {
            id: this.getId(),
            name: this.getName(),
            tags: this.getTags(),
            usage: this.getUsage().toJSON(),
            secrets: this.getSecrets().map((secret) => secret.toJSON()),
        });
    }

    static fromJSON(input: unknown) {
        const my = Value.Decode(EntrySchema, input);
        return new Entry(
            my.id,
            my.name,
            my.tags,
            Usage.fromJSON(my.usage),
            my.secrets.map((storedSecret) => Secret.fromJSON(storedSecret)),
        );
    }

    static generateId() {
        return cuid2();
    }
}
