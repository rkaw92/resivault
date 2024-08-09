import { Type, FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { Vault } from '../Vault'
import { sensitiveRoutes } from './routes-sensitive';
import { VaultAuthToken } from '../VaultAuthToken';
import fastifyCookie from '@fastify/cookie';
import { negotiate } from '@fastify/accept-negotiator';

function parseBasicAuth(headerValue: string) {
    if (!headerValue || !headerValue.startsWith('Basic ')) {
        return undefined;
    }
    const [ _user, ...password ] = Buffer.from(headerValue.slice(6).trim(), 'base64').toString('utf-8').split(':');
    return password.join();
}

export const routes: FastifyPluginAsyncTypebox<{
    vault: Vault
}> = async function(app, { vault }) {
    const tokens = new Set<VaultAuthToken>();
    app.register(fastifyCookie, {
        hook: 'onRequest',
    });

    app.get('/status', {
        schema: {
            response: {
                200: Type.Object({
                    unlocked: Type.Boolean(),
                })
            }
        }
    }, async function() {
        return { unlocked: vault.isUnlocked() };
    });

    // TODO: vault init route

    app.post('/unlock', {
        schema: {
            body: Type.Union([
                Type.String(),
                Type.Object({
                    password: Type.String({  maxLength: 128 }),
                }),
            ]),
            response: {
                200: {
                    description: 'Vault unlocked',
                    content: {
                        'application/json': {
                            schema: Type.Object({
                                token: Type.String(),
                            })
                        },
                        'text/plain': {
                            schema: Type.String(),
                        }
                    },
                    headers: {
                        'Set-Cookie': {
                            schema: Type.String(),
                        }
                    }
                }
            }
        }
    }, async function(req, reply) {
        let password;
        if (typeof req.body === 'string' && req.body) {
            password = req.body;
        } else if (typeof req.body === 'object' && req.body) {
            password = req.body.password;
        } else if (req.headers.authorization) {
            password = parseBasicAuth(req.headers.authorization);
        }
        if (!password) {
            return reply.status(400).send('Missing password on input - required in body or as basic auth password');
        }
        await vault.unlock(password);
        await vault.loadEntries();
        const issuedToken = new VaultAuthToken();
        tokens.add(issuedToken);
        reply.setCookie('token', issuedToken.toString(), {
            secure: false,
            sameSite: 'strict',
            httpOnly: true,
        });
        switch (negotiate(req.headers.accept ?? '', [ 'application/json', 'text/plain' ])) {
            case 'application/json':
                return { token: issuedToken.toString() };
            case 'text/plain':
            default:
                return issuedToken.toString();
        }
    });

    app.register(sensitiveRoutes, { vault, tokens });
};
