export const ERROR_CODES = {
    ERR_LISTEN: 5,
} as const;

export class AppError extends Error {
    public readonly statusCode: number = 500;
    public override readonly name;
    constructor(message: string, public override readonly cause?: Error) {
        super(message + (cause ? ` (cause: ${cause.message ?? 'unknown'})` : ''));
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class StorageError extends AppError {
    constructor(message: string, cause?: Error) {
        super(`Storage error: ${message}`, cause);
    }
}

export class RootEntryNotFoundError extends AppError {
    constructor() {
        super('Root entry not found - cannot open vault. Not initialized?');
    }
}

export class RootEntryMalformedError extends AppError {
    constructor(specificReason: string) {
        super(`Root entry malformed: ${specificReason}`);
    }
}

export class CryptoError extends AppError {
    constructor(cause?: unknown) {
        super('Encryption/decryption failed - wrong key or password?', cause instanceof Error ? cause : undefined);
    }
}

export class CryptographyIncompatibleError extends AppError {
    constructor(specificReason: string) {
        super(`Cannot open vault - incompatible cryptographic settings: ${specificReason}`);
    }
}

export class VaultNotUnlockedError extends AppError {
    public override readonly statusCode = 400;
    constructor() {
        super('Vault not unlocked');
    }
}

export class VaultEntryNotFoundError extends AppError {
    constructor(id: string) {
        super(`Vault entry file ${id} not found in storage`);
    }
}

export class SecretTypeNotSupportedError extends AppError {
    constructor(typeName: string) {
        super(`Secret type ${typeName} not supported`);
    }
}

export class SecretLabelAlreadyExistsError extends AppError {
    constructor(label: string) {
        super(`This entry already has a secret with label ${label}`);
    }
}
export class UnauthorizedError extends AppError {
    public override readonly statusCode = 401;
    constructor() {
        super('Authorization token not present in request headers');
    }
}

export class VaultAlreadyInitializedError extends AppError {
    public override readonly statusCode = 409;
    constructor() {
        super('Vault already initialized - refusing to overwrite file root.meta');
    }
}

export class PasswordNotProvidedError extends AppError {
    constructor() {
        super('Vault password was not provided on input - required in request body or as basic auth password');
    }
}