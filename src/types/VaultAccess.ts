import { Type } from '@sinclair/typebox';
import { Usage, usageAbstractFactory } from '../Usage';
import { Tag } from '../Tag';
import { Value } from '@sinclair/typebox/value';

const VaultAccessSchema = Type.Object({
    vaultId: Type.String(),
    kdf: Type.String(),
    saltBase64: Type.String(),
});

export class VaultAccess extends Usage<typeof VaultAccessSchema> {
    protected readonly schema = VaultAccessSchema;
    public static readonly type = 'VaultAccess' as const;
    
    getType() {
        return VaultAccess.type;
    }

    getAutoTags(): Tag[] {
        return [];
    }

    getSalt() {
        return Buffer.from(this.details.saltBase64, 'base64');
    }

    static override fromJSON(input: unknown) {
        const details = Value.Decode(VaultAccessSchema, input);
        return new VaultAccess(details);
    }
}

usageAbstractFactory.register(VaultAccess.type, (details) => VaultAccess.fromJSON(details));
