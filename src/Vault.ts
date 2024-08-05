import { createSecretKey, KeyObject, randomUUID } from 'node:crypto';
import { AES128OCB, AES256KeyWrap, CryptoProvider, Decryptor, DefaultEncDec, Encryptor, PlaintextForMetadataOnly, ScryptKDFv1 } from './cryptography';
import { BlobStorage } from './storage';
import { Entry } from './Entry';
import { EntryRepository } from './EntryRepository';
import { CryptographyIncompatibleError, RootEntryMalformedError, RootEntryNotFoundError, VaultEntryNotFoundError, VaultNotUnlockedError } from './errors';
import * as types from './types';
import { Secret } from './Secret';
import { Static, TSchema } from '@sinclair/typebox';

const kEntryRepository = Symbol('kEntryRepository');
const kInnerEncryptor = Symbol('kInnerEncryptor');
const kInnerDecryptor = Symbol('kInnerDecryptor');
const kEntries = Symbol('kEntries');

const LABEL_OUTER_KEY = 'outer';
const LABEL_INNER_KEY = 'inner';

class VaultSensitivePart {
    public [kEntryRepository]: EntryRepository;
    public [kInnerEncryptor]: Encryptor;
    public [kInnerDecryptor]: Decryptor;
    public [kEntries] = new Map<string, Entry>();
    constructor(
        outerProvider: CryptoProvider,
        outerKey: KeyObject,
        innerProvider: CryptoProvider,
        innerKey: KeyObject,
        storage: BlobStorage,
    ) {
        const outerCrypto = new DefaultEncDec(outerProvider, outerKey);
        this[kEntryRepository] = new EntryRepository(outerCrypto, outerCrypto, storage);
        const innerCrypto = new DefaultEncDec(innerProvider, innerKey);
        this[kInnerEncryptor] = innerCrypto;
        this[kInnerDecryptor] = innerCrypto;
    }
}

export class Vault {
    protected readonly ROOT_ENTRY_ID = 'root';
    protected providers = {
        key: new AES256KeyWrap(),
        outer: new AES128OCB(),
        // TODO: ChaCha20-Poly1305 for inner crypto
        inner: new AES128OCB(),
        kdf: new ScryptKDFv1(),
    };
    protected metaRepository: EntryRepository;
    protected sensitiveData: VaultSensitivePart | null = null;
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
        const { key: kek, salt } = this.providers.kdf.deriveNewKey(password, this.providers.key.keyBytes());
        const keyEncryptor = new DefaultEncDec(this.providers.key, kek);
        const outerKey = this.providers.outer.generateKey();
        const innerKey = this.providers.inner.generateKey();
        const vaultId = this.generateVaultId();
        const rootEntry = new Entry(
            this.ROOT_ENTRY_ID,
            '(this vault)',
            [],
            new types.VaultAccess({
                vaultId: vaultId,
                kdf: this.providers.kdf.getName(),
                saltBase64: salt.toString('base64'),
            }),
            [
                types.EncryptionKey.sealer.seal(LABEL_OUTER_KEY, { base64: outerKey.export().toString('base64') }, keyEncryptor),
                types.EncryptionKey.sealer.seal(LABEL_INNER_KEY, { base64: innerKey.export().toString('base64') }, keyEncryptor),
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
        if (!(access instanceof types.VaultAccess)) {
            throw new RootEntryMalformedError('Usage type must be VaultAccess');
        }
        if (access.getDetails().kdf !== this.providers.kdf.getName()) {
            // NOTE: If we add more KDF versions, this shouldn't be an equality check.
            throw new CryptographyIncompatibleError(`Unsupported KDF ${access.getDetails().kdf}`);
        }
        const kdfSalt = Buffer.from(access.getSalt());
        const kek = this.providers.kdf.deriveKey(password, kdfSalt, this.providers.key.keyBytes());
        const outerKeySecret = rootEntry.getSecret(LABEL_OUTER_KEY);
        const innerKeySecret = rootEntry.getSecret(LABEL_INNER_KEY);
        if (!outerKeySecret || !innerKeySecret) {
            throw new RootEntryMalformedError('wrong number of secrets in root entry, must have 2')
        }
        if (!(outerKeySecret instanceof types.EncryptionKey)) {
            throw new RootEntryMalformedError('outer key is not an EncryptionKey');
        }
        if (!(innerKeySecret instanceof types.EncryptionKey)) {
            throw new RootEntryMalformedError('inner key is not an EncryptionKey');
        }
        const keyDecryptor = new DefaultEncDec(this.providers.key, kek);

        this.sensitiveData = new VaultSensitivePart(
            this.providers.outer,
            createSecretKey(
                Buffer.from(outerKeySecret.reveal(keyDecryptor).base64, 'base64')
            ),
            this.providers.inner,
            createSecretKey(
                Buffer.from(innerKeySecret.reveal(keyDecryptor).base64, 'base64')
            ),
            this.entryStore,
        );
    }

    isUnlocked() {
        return Boolean(this.sensitiveData);
    }

    async loadEntry(id: string) {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        const entry = await this.sensitiveData[kEntryRepository].load(id);
        if (!entry) {
            throw new VaultEntryNotFoundError(id);
        }
        this.sensitiveData[kEntries].set(entry.getId(), entry);
    }

    async loadEntries() {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        for (const id of await this.sensitiveData[kEntryRepository].listKeys()) {
            try {
                await this.loadEntry(id);
            } catch (error) {
                this.loadingErrors.set(id, error as Error);
            }
        }
    }

    getEntry(id: string): Entry | null {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        return this.sensitiveData[kEntries].get(id) ?? null;
    }

    async saveEntry(entry: Entry): Promise<string> {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        await this.sensitiveData[kEntryRepository].save(entry);
        this.sensitiveData[kEntries].set(entry.getId(), entry);
        return entry.getId();
    }

    sealSecret<T extends TSchema>(type: string, label: string, input: Static<T>): Secret<T> {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        const sealer = Secret.getSealer(type);
        return sealer.seal(label, input, this.sensitiveData[kInnerEncryptor]) as Secret<T>;
    }

    revealSecret<T extends TSchema>(secret: Secret<T>): Static<T> {
        if (!this.sensitiveData) {
            throw new VaultNotUnlockedError();
        }
        return secret.reveal(this.sensitiveData[kInnerDecryptor]);
    }

    async lock() {
        this.sensitiveData = null;
    }
}
