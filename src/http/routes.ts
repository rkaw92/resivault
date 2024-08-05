import { Type, FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { Vault } from '../Vault'
import { EntrySchema, SecretEnvelopeSchema } from '../base-schema';
import { Entry } from '../Entry';
import { EncryptionKey, Password } from '../types';
import { Secret } from '../Secret';

export const routes: FastifyPluginAsyncTypebox<{
    vault: Vault
}> = async function(app, { vault }) {
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

    app.post('/unlock', {
        schema: {
            body: Type.String(),
        }
    }, async function(req) {
        // TODO: Alternatively support HTTP Basic Auth instead
        await vault.unlock(req.body);
        await vault.loadEntries();
    });

    // TODO: Extract this into a "sensitive routes" plugin!

    app.post('/entry', {
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

    app.get('/entry/:entryId', {
        schema: {
            params: Type.Object({
                entryId: Type.String(),
            })
        }
    }, async function(req, reply) {
        // TODO: Require session token!
        const entry = vault.getEntry(req.params.entryId);
        if (!entry) {
            reply.status(404);
        }
        return entry;
    });

    app.delete('/entry/:entryId', {
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

    app.post('/entry/:entryId/secret', {
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

    app.get('/entry/:entryId/secret/:secretLabel', {
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

    app.delete('/entry/:entryId/secret/:secretLabel', {
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
