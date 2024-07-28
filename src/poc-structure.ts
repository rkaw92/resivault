import { AES128OCB, DefaultDecryptor, DefaultEncryptor } from "./cryptography";
import { Entry } from "./Entry";
import { Password } from "./types/Password";
import { WebLogin } from "./types/WebLogin";

const provider = new AES128OCB();
const key = provider.generateKey();
const [ encryptor, decryptor ] = [ new DefaultEncryptor(provider, key), new DefaultDecryptor(provider, key) ];

const myLogin = new Entry(
    'a7b5b86d-059c-48d6-9c59-7bc8ce465ede',
    'Widgets shop',
    [],
    new WebLogin({ url: 'https://shop.example.com/', username: 'user@example.com' }),
    [
        Password.factory.create('foobar', encryptor),
    ]
);

console.log('entry dump: %j', myLogin);
console.log('usage details: %j', myLogin.getUsage().getDetails());
console.log('tags: %j', myLogin.getUsage().getAutoTags());
for (const [ i, secret ] of myLogin.getSecrets().entries()) {
    console.log('secrets[%d](%s): %s', i, secret.getType(), secret.reveal(decryptor));
}
