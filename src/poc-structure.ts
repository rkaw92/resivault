import { AES128OCB, DefaultDecryptor, DefaultEncryptor } from "./cryptography";
import { Entry } from "./Entry";
import { EntryRepository } from './EntryRepository';
import { Filesystem } from './storage';
import { Password } from "./types/Password";
import { WebLogin } from "./types/WebLogin";

const provider = new AES128OCB();
const outerKey = provider.generateKey();
const innerKey = provider.generateKey();
const [ outerEncryptor, outerDecryptor ] = [ new DefaultEncryptor(provider, outerKey), new DefaultDecryptor(provider, outerKey) ];
const [ innerEncryptor, innerDecryptor ] = [ new DefaultEncryptor(provider, innerKey), new DefaultDecryptor(provider, innerKey) ];

const myLogin = new Entry(
    Entry.generateId(),
    'Widgets shop',
    [],
    new WebLogin({ url: 'https://shop.example.com/', username: 'user@example.com' }),
    [
        Password.sealer.seal('foobar', innerEncryptor),
    ]
);

console.log('%j', myLogin);

for (const [ i, secret ] of myLogin.getSecrets().entries()) {
    // console.log('secrets[%d](%s): %s', i, secret.getType(), secret.reveal(innerDecryptor));
}

(async function() {
    const repo = new EntryRepository(outerEncryptor, outerDecryptor, new Filesystem('poc'));
    const path = await repo.save(myLogin);
    const myLogin2 = await repo.load(path);
    console.log('%j', myLogin2);
})()
