import { Encryptor, Decryptor } from "./cryptography";
import { Entry } from "./Entry";
import { BlobStorage } from './storage';

export class EntryRepository {
    constructor(
        private outerEncryptor: Encryptor,
        private outerDecryptor: Decryptor,
        private storage: BlobStorage,
    ) {}

    async save(entry: Entry): Promise<string> {
        const entryId = entry.getId();
        const rawOutput = Buffer.from(JSON.stringify(entry.toJSON(), null, 2) + '\n', 'utf-8');
        await this.storage.save(entryId, this.outerEncryptor.encrypt(rawOutput));
        return entryId;
    }

    async load(id: string): Promise<Entry | null> {
        const rawInput = await this.storage.load(id);
        if (rawInput === null) {
            return null;
        }
        return this.outerDecryptor.decrypt(rawInput, (plaintext) => {
            const storedObject = JSON.parse(plaintext.toString('utf-8'));
            return Entry.fromJSON(storedObject);
        });
    }

    async delete(id: string): Promise<void> {
        return this.storage.delete(id);
    }

    async listKeys(): Promise<string[]> {
        return this.storage.listKeys();
    }
}
