import { Static, TSchema } from "@sinclair/typebox";
import { Tag } from "./Tag";
import { UsageEnvelopeSchema } from './base-schema';
import { AbstractFactory } from './AbstractFactory';
import { Value } from '@sinclair/typebox/value';

export const usageAbstractFactory = new AbstractFactory<Usage<TSchema>, unknown>();

export abstract class Usage<Schema extends TSchema> {
    protected abstract schema: Schema;
    constructor(protected details: Static<Schema>) {}

    abstract getType(): string;
    abstract getAutoTags(): Tag[];

    getDetails(): Static<Schema> {
        return this.details;
    }

    toJSON(): Static<typeof UsageEnvelopeSchema> {
        return {
            type: this.getType(),
            details: Value.Encode(this.schema, this.getDetails())
        };
    }

    static fromJSON(input: Static<typeof UsageEnvelopeSchema>) {
        return usageAbstractFactory.create(input.type, input.details);
    }
}
