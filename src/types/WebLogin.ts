import { Type } from "@sinclair/typebox";
import { Usage } from "../Usage";
import { Tag } from "../Tag";

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
}
