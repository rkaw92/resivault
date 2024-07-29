import { Type } from "@sinclair/typebox";
import { Secret, Sealer, secretAbstractFactory } from "../Secret";

const PasswordSchema = Type.String();

export class Password extends Secret<typeof PasswordSchema> {
    protected schema = PasswordSchema;
    public static readonly sealer = new Sealer(PasswordSchema, (encryptedValue) => new Password(encryptedValue));
    public static readonly type = 'password' as const;

    getType() {
        return Password.type;
    }
}

secretAbstractFactory.register(Password.type, (encryptedValue) => new Password(encryptedValue));
