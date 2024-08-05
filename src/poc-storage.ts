import { Entry } from './Entry';
import { Filesystem } from './storage';
import { Password } from './types/Password';
import { WebLogin } from './types/WebLogin';
import { Vault } from './Vault';

const metaStore = new Filesystem('poc/meta', '.meta');
const entryStore = new Filesystem('poc/entries');
const vault = new Vault(metaStore, entryStore);

const myLogin = new Entry(
    'cmj7v7tzoj4rx1kkkgisgxgl',
    'Widgets shop',
    [],
    new WebLogin({ url: 'https://shop.example.com/', username: 'user@example.com' }),
    [
        // TODO: Add an API for attaching a secret to an Entry
        // Password.sealer.seal('foobar', innerEncryptor),
    ]
);

(async function() {
    // await vault.initializeNew('hunter2');
    await vault.unlock('hunter2');
    // myLogin.addSecret(vault.sealSecret('Password', 'myVeryPrivatePassword123!@#'));
    // await vault.saveEntry(myLogin);
    await vault.loadEntries();
    console.log('%j', vault.getEntry('cmj7v7tzoj4rx1kkkgisgxgl'));
    console.log('Password: %s', vault.revealSecret(
        vault.getEntry('cmj7v7tzoj4rx1kkkgisgxgl')!.getSecrets()[0]!
    ));
})()
