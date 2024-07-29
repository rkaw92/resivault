import { Type } from '@sinclair/typebox';

export const TagSchema = Type.Object({
    key: Type.String(),
    value: Type.String(),
});

export const UsageEnvelopeSchema = Type.Object({
    type: Type.String(),
    details: Type.Any(),
});

export const SecretEnvelopeSchema = Type.Object({
    type: Type.String(),
    encryptedValue: Type.String(),
});

export const EntrySchema = Type.Object({
    id: Type.String(),
    name: Type.String(),
    tags: Type.Array(TagSchema),
    usage: UsageEnvelopeSchema,
    secrets: Type.Array(SecretEnvelopeSchema)
});
