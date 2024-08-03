import { createSecretKey, KeyObject, randomUUID } from 'node:crypto';
import { AES128OCB, AES256KeyWrap, DefaultEncDec, PlaintextForMetadataOnly, ScryptKDFv1 } from './cryptography';
import { BlobStorage } from './storage';
import { Entry } from './Entry';
import { VaultAccess } from './types/VaultAccess';
import { EncryptionKey } from './types/EncryptionKey';
import { EntryRepository } from './EntryRepository';
import { CryptographyIncompatibleError, RootEntryMalformedError, RootEntryNotFoundError, VaultEntryNotFoundError, VaultNotUnlockedError } from './errors';

export class Vault {
    protected readonly ROOT_ENTRY_ID = 'root';

    protected unlocked = false;
    protected outerKey: KeyObject | null = null;
    protected innerKey: KeyObject | null = null;
    // TODO: Extract all sensitive objects to VaultSensitivePart.
    protected crypto = {
        key: new AES256KeyWrap(),
        outer: new AES128OCB(),
        // TODO: ChaCha20-Poly1305 for inner crypto
        inner: new AES128OCB(),
        kdf: new ScryptKDFv1(),
    };
    protected metaRepository: EntryRepository;
    protected entryRepository: EntryRepository | null = null;
    protected entries = new Map<string, Entry>();
    protected loadingErrors = new Map<string, Error>();

    constructor(
        protected metaStore: BlobStorage,
        protected entryStore: BlobStorage,
    ) {
        const plain = new PlaintextForMetadataOnly();
        const noKey = plain.generateKey();
        const outerCrypto = new DefaultEncDec(plain, noKey);
        this.metaRepository = new EntryRepository(
            outerCrypto,
            outerCrypto,
            metaStore,
        );
    }

    async initializeNew(password: string) {
        const { key: kek, salt } = this.crypto.kdf.deriveNewKey(password, this.crypto.key.keyBytes());
        const keyEncryptor = new DefaultEncDec(this.crypto.key, kek);
        const outerKey = this.crypto.outer.generateKey();
        const innerKey = this.crypto.inner.generateKey();
        const vaultId = this.generateVaultId();
        const rootEntry = new Entry(
            this.ROOT_ENTRY_ID,
            '(this vault)',
            [],
            new VaultAccess({
                vaultId: vaultId,
                kdf: this.crypto.kdf.getName(),
                saltBase64: salt.toString('base64'),
            }),
            [
                EncryptionKey.sealer.seal({ base64: outerKey.export().toString('base64') }, keyEncryptor),
                EncryptionKey.sealer.seal({ base64: innerKey.export().toString('base64') }, keyEncryptor),
            ]
        );
        await this.metaRepository.save(rootEntry);
    }

    protected generateVaultId(): string {
        return randomUUID();
    }

    async unlock(password: string) {
        const rootEntry = await this.metaRepository.load(this.ROOT_ENTRY_ID);
        if (!rootEntry) {
            throw new RootEntryNotFoundError();
        }
        const access = rootEntry.getUsage();
        if (!(access instanceof VaultAccess)) {
            throw new RootEntryMalformedError('Usage type must be VaultAccess');
        }
        if (access.getDetails().kdf !== this.crypto.kdf.getName()) {
            // NOTE: If we add more KDF versions, this shouldn't be an equality check.
            throw new CryptographyIncompatibleError(`Unsupported KDF ${access.getDetails().kdf}`);
        }
        const kdfSalt = Buffer.from(access.getSalt());
        const kek = this.crypto.kdf.deriveKey(password, kdfSalt, this.crypto.key.keyBytes());
        const rootSecrets = rootEntry.getSecrets();
        const [ outerKeySecret, innerKeySecret ] = rootSecrets;
        if (!outerKeySecret || !innerKeySecret) {
            throw new RootEntryMalformedError('wrong number of secrets in root entry, must have 2')
        }
        if (!(outerKeySecret instanceof EncryptionKey)) {
            throw new RootEntryMalformedError('outer key is not an EncryptionKey');
        }
        if (!(innerKeySecret instanceof EncryptionKey)) {
            throw new RootEntryMalformedError('inner key is not an EncryptionKey');
        }
        const keyDecryptor = new DefaultEncDec(this.crypto.key, kek);
        this.outerKey = createSecretKey(
            Buffer.from(outerKeySecret.reveal(keyDecryptor).base64, 'base64')
        );
        this.innerKey = createSecretKey(
            Buffer.from(innerKeySecret.reveal(keyDecryptor).base64, 'base64')
        );
        const outer = new DefaultEncDec(this.crypto.outer, this.outerKey);
        this.entryRepository = new EntryRepository(
            outer,
            outer,
            this.entryStore,
        )
        this.unlocked = true;
    }

    async loadEntry(id: string) {
        if (!this.entryRepository) {
            throw new VaultNotUnlockedError();
        }
        const entry = await this.entryRepository.load(id);
        if (!entry) {
            throw new VaultEntryNotFoundError(id);
        }
        this.entries.set(entry.getId(), entry);
    }

    async loadEntries() {
        if (!this.entryRepository) {
            throw new VaultNotUnlockedError();
        }
        for (const id of await this.entryRepository.listKeys()) {
            try {
                await this.loadEntry(id);
            } catch (error) {
                this.loadingErrors.set(id, error as Error);
            }
        }
    }

    getEntry(id: string): Entry | null {
        if (!this.unlocked) {
            throw new VaultNotUnlockedError();
        }
        return this.entries.get(id) ?? null;
    }

    async saveEntry(entry: Entry): Promise<string> {
        if (!this.entryRepository) {
            throw new VaultNotUnlockedError();
        }
        await this.entryRepository.save(entry);
        this.entries.set(entry.getId(), entry);
        return entry.getId();
    }

    async lock() {
        this.entries.clear();
        this.entryRepository = null;
        this.outerKey = null;
        this.innerKey = null;
        this.unlocked = false;
    }
}
