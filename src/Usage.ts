import { Static, TSchema } from "@sinclair/typebox";
import { Tag } from "./Tag";

export abstract class Usage<Schema extends TSchema> {
    protected abstract schema: Schema;
    constructor(protected details: Static<Schema>) {}

    abstract getType(): string;
    abstract getAutoTags(): Tag[];

    getDetails(): Static<Schema> {
        return this.details;
    }
}
