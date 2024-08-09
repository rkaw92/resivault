import { FastifyReply, FastifyRequest } from 'fastify';
import { UnauthorizedError } from '../errors';
import { VaultAuthToken } from '../VaultAuthToken';

function parseBearerAuth(headerValue: string | undefined) {
    if (!headerValue) {
        return undefined;
    }
    if (headerValue.startsWith('Bearer ')) {
        return headerValue.slice(7).trim();
    }
    return headerValue;
}

export function createAuthenticator(recognizedTokens: Set<VaultAuthToken>) {
    return async function authenticate(req: FastifyRequest, reply: FastifyReply) {
        const headerValue = parseBearerAuth(req.headers.authorization);
        const cookieValue = req.cookies.token;
        const tokenValue = headerValue ?? cookieValue;
        if (!tokenValue) {
            throw new UnauthorizedError();
        }
        const userToken = VaultAuthToken.fromString(tokenValue);
        for (const recognizedToken of recognizedTokens.values()) {
            if (recognizedToken.equals(userToken)) {
                return;
            }
        }
        throw new UnauthorizedError();
    };
};