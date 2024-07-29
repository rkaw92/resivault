import { FormatRegistry, Type } from "@sinclair/typebox";
import { Usage, usageAbstractFactory } from "../Usage";
import { Tag } from "../Tag";
import { Value } from '@sinclair/typebox/value';

FormatRegistry.Set('uri', (value) => URL.canParse(value));

const WebLoginSchema = Type.Object({
    url: Type.String({ format: 'uri' }),
    username: Type.String(),
});

export class WebLogin extends Usage<typeof WebLoginSchema> {
    protected readonly schema = WebLoginSchema;
    public static readonly type = 'WebLogin' as const;
    
    getType() {
        return WebLogin.type;
    }

    getAutoTags(): Tag[] {
        try {
            return [
                new Tag('domain', new URL(this.details.url).hostname),
            ];
        } catch (err) {
            // We check for "uri" format on input, but it doesn't make sense to crash if it's not a valid URL.
            return [];
        }
    }

    static fromJSON(input: unknown) {
        const details = Value.Decode(WebLoginSchema, input);
        return new WebLogin(details);
    }
}

usageAbstractFactory.register(WebLogin.type, (details) => WebLogin.fromJSON(details));
