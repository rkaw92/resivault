import fastify from 'fastify';
import { pino } from 'pino';
import { env } from './env';
import { resolve } from 'node:path';
import { unlinkSync } from 'node:fs';
import { AES128GCM, AES128OCB } from './cryptography';
import { ERROR_CODES } from './errors';
import { Vault } from './Vault';
import { Filesystem } from './storage';
import { routes } from './http/routes';

// Important for UNIX socket security and also to protect the password files themselves:
process.umask(0o0077);

const log = pino();
const app = fastify({
    logger: log
});

const vault = new Vault(
    new Filesystem('poc/meta', '.meta'),
    new Filesystem('poc/entries'),
);

app.register(routes, { vault });

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
