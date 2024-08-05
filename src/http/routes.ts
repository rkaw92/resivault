import { Type, FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox'
import { Vault } from '../Vault'

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
    }, async function(req, reply) {
        await vault.unlock(req.body);
        await vault.loadEntries();
    });

    // TODO: Extract this into a "sensitive routes" plugin!

    app.get('/entry/:id', {
        schema: {
            params: Type.Object({
                id: Type.String(),
            })
        }
    }, async function(req) {
        // TODO: Require session token!
        return vault.getEntry(req.params.id);
    });
};
