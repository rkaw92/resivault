import { writeFile, readFile } from 'node:fs/promises';
import { Encryptor, Decryptor } from "./cryptography";
import { Entry } from "./Entry";
import { join } from 'node:path';

type FilePath = string;

export class EntryStorage {
    constructor(
        private outerEncryptor: Encryptor,
        private outerDecryptor: Decryptor,
        private basePath = process.cwd(),
    ) {}

    async save(entry: Entry): Promise<FilePath> {
        const targetName = `${entry.getId()}.secret`;
        const targetPath = join(this.basePath, targetName);
        const rawOutput = Buffer.from(JSON.stringify(entry.toJSON(), null, 2), 'utf-8');
        await writeFile(targetPath, this.outerEncryptor.encrypt(rawOutput));
        return targetPath;
    }

    async load(file: FilePath): Promise<Entry> {
        const rawInput = await readFile(file);
        return this.outerDecryptor.decrypt(rawInput, (plaintext) => {
            const storedObject = JSON.parse(plaintext.toString('utf-8'));
            return Entry.fromJSON(storedObject);
        });
    }
}
