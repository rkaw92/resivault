import { Type } from "@sinclair/typebox";
import { Secret, SecretFactory } from "../Secret";

const PasswordSchema = Type.String();

export class Password extends Secret<typeof PasswordSchema> {
    protected schema = PasswordSchema;
    public static readonly factory = new SecretFactory(PasswordSchema, (encryptedValue) => new Password(encryptedValue));
    public static readonly type = 'password' as const;

    getType() {
        return Password.type;
    }
}
