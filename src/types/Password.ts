import { Type } from "@sinclair/typebox";
import { Secret, Sealer } from "../Secret";

const PasswordSchema = Type.String();

export class Password extends Secret<typeof PasswordSchema> {
    protected schema = PasswordSchema;
    public static readonly factory = (encryptedValue: Buffer) => new Password(encryptedValue);
    public static readonly sealer = new Sealer(PasswordSchema, (encryptedValue) => new Password(encryptedValue));
    public static readonly type = 'Password' as const;

    getType() {
        return Password.type;
    }
}

Secret.registerType(Password);
