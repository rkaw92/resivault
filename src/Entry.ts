import { TSchema } from "@sinclair/typebox";
import { Secret } from "./Secret";
import { Tag } from "./Tag";
import { Usage } from "./Usage";


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
}
