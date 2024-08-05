import { readFile, writeFile, readdir, unlink } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { getSystemErrorName } from 'node:util';
import { isNativeError } from 'node:util/types';
import { StorageError } from './errors';

// NOTE: In the context of storage, "key" refers to identifiers of stored blobs, not crypto keys.

export interface BlobStorage {
    save(key: string, data: Buffer): Promise<void>;
    load(key: string): Promise<Buffer | null>;
    delete(key: string): Promise<void>;
    listKeys(): Promise<string[]>;
}

export class Filesystem implements BlobStorage {
    constructor(private basePath: string = process.cwd(), private suffix = '.secret') {}

    private keyToPath(key: string) {
        return join(this.basePath, basename(key)) + this.suffix;
    }

    async save(key: string, data: Buffer): Promise<void> {
        return writeFile(this.keyToPath(key), data);
    }
    
    async load(key: string): Promise<Buffer | null> {
        try {
            return await readFile(this.keyToPath(key));
        } catch (err) {
            if (isNativeError(err) && (err as NodeJS.ErrnoException).code === 'ENOENT') {
                return null;
            } else {
                throw new StorageError(`Failed to load file by key: ${key}`);
            }
        }
    }

    async delete(key: string): Promise<void> {
        await unlink(this.keyToPath(key));
    }

    async listKeys(): Promise<string[]> {
        const dirents = await readdir(this.basePath, { withFileTypes: true });
        return dirents.filter((dirent) => dirent.isFile() && dirent.name.endsWith(this.suffix)).map((entry) => entry.name.slice(0, -this.suffix.length));
    }
}
