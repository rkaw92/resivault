import { Type } from "@sinclair/typebox";
import { Secret, Sealer } from "../Secret";

const PasswordSchema = Type.String();

export class Password extends Secret<typeof PasswordSchema> {
    protected schema = PasswordSchema;
    public static readonly schema = PasswordSchema;
    public static readonly factory = (label: string, encryptedValue: Buffer) => new Password(label, encryptedValue);
    public static readonly sealer = new Sealer(PasswordSchema, Password.factory);
    public static readonly type = 'Password' as const;

    getType() {
        return Password.type;
    }
}

Secret.registerType(Password);
