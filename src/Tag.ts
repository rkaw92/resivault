/**
 * A Tag is a key/value pair that makes finding Entries easier.
 */
export class Tag {
    constructor(
        public readonly key: string,
        public readonly value: string,
    ) {}
}