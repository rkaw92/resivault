import { Type, FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { Vault } from '../Vault';
import { EntrySchema, SecretEnvelopeSchema } from '../base-schema';
import { Entry } from '../Entry';
import { EncryptionKey, Password } from '../types';
import { Secret } from '../Secret';
import { VaultAuthToken } from '../VaultAuthToken';
import { createAuthenticator } from './auth';

export const sensitiveRoutes: FastifyPluginAsyncTypebox<{
    vault: Vault,
    tokens: Set<VaultAuthToken>,
}> = async function(app, { vault, tokens }) {
    app.addHook('preValidation', createAuthenticator(tokens))
    
    app.post('/entries', {
        schema: {
            body: EntrySchema,
        }
    }, async function(req, reply) {
        const entry = Entry.fromJSON({
            ...req.body,
            id: req.body.id || Entry.generateId(),
        });
        await vault.saveEntry(entry);
        reply.header('Location', `/entry/${entry.getId()}`);
    });

    app.get('/entries/:entryId', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
            })
        }
    }, async function(req, reply) {
        const entry = vault.getEntry(req.params.entryId);
        if (!entry) {
            reply.status(404);
        }
        return entry;
    });

    app.delete('/entries/:entryId', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
            }),
            response: {
                200: Type.Union([
                    Password.schema,
                    EncryptionKey.schema,
                ])
            }
        },
    }, async function(req, reply) {
        await vault.deleteEntry(req.params.entryId);
    });

    app.post('/entries/:entryId/secrets', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
            }),
            body: Type.Union([
                Type.Object({ type: Type.Literal(Password.type), label: Type.String(), value: Password.schema }),
                Type.Object({ type: Type.Literal(EncryptionKey.type), label: Type.String(), value: EncryptionKey.schema }),
            ]),
        }
    }, async function(req, reply) {
        const entry = vault.getEntry(req.params.entryId);
        if (!entry) {
            return reply.status(404).send('Entry not found');
        }
        entry.addSecret(vault.sealSecret(req.body.type, req.body.label, req.body.value));
        await vault.saveEntry(entry);
    });

    app.get('/entries/:entryId/secrets/:secretLabel', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
                secretLabel: Type.String(),
            }),
            response: {
                200: Type.Union([
                    Password.schema,
                    EncryptionKey.schema,
                ])
            }
        },
    }, async function(req, reply) {
        const entry = vault.getEntry(req.params.entryId);
        if (!entry) {
            return reply.status(404).send('Entry not found');
        }
        const secret = entry.getSecret(req.params.secretLabel);
        if (!secret) {
            return reply.status(404).send('Cannot find a secret with this label');
        }
        return vault.revealSecret(secret) as any;
    });

    app.delete('/entries/:entryId/secrets/:secretLabel', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
                secretLabel: Type.String(),
            }),
            response: {
                200: Type.Union([
                    Password.schema,
                    EncryptionKey.schema,
                ])
            }
        },
    }, async function(req, reply) {
        const entry = vault.getEntry(req.params.entryId);
        if (!entry) {
            return reply.status(404).send('Entry not found');
        }
        entry.deleteSecret(req.params.secretLabel);
        await vault.saveEntry(entry);
    });
};