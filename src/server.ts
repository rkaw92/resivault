import fastify from 'fastify';
import { pino } from 'pino';
import { env } from './env';
import { resolve } from 'node:path';
import { unlinkSync } from 'node:fs';
import { AES128GCM, AES128OCB } from './cryptography';
import { ERROR_CODES } from './errors';

// Important for UNIX socket security and also to protect the password files themselves:
process.umask(0o0077);

const log = pino();
const app = fastify({
    logger: log
});

app.get('/', async function() {
    return { hello: 'world' };
});

const socketPath = resolve(env('HOME'), '.resivault.sock');

try {
    unlinkSync(socketPath);
} catch (err) {
    // no-op - it's OK if the file was not found
}
app.listen({
    path: socketPath,
}).catch(function(err: Error) {
    log.fatal({ err, code: ERROR_CODES.ERR_LISTEN }, 'Failed to set up listener on socket');
    process.exit(ERROR_CODES.ERR_LISTEN);
});

const cryptoProvider = new AES128OCB();
const key = cryptoProvider.generateKey();
console.log('key: %s', key.export().toString('hex'));
const encrypted = cryptoProvider.encrypt(Buffer.from('Hello, world!'), key);
console.log('encrypted: %s', encrypted.toString('hex'));
const decrypted = cryptoProvider.decrypt(encrypted, key);
console.log('decrypted: %s', decrypted.toString('utf-8'));
console.log('layout: %s', cryptoProvider.describeLayout());
