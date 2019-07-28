module.exports = createContextCreator;

const jwt = require(`jsonwebtoken`);

function createContextCreator({
    laxTokenHeader = false,
    queryTokenName = `token`,
    bodyTokenName = `token`,
    authorizationHeaderName = `authorization`,
    tokenTypeName = `bearer`,
    createLogger = defaultCreateLogger,
    createStat = defaultCreateStat,
    loadVerificationInformation
}) {
    return async function createContext(request) {
        const user = await authenticateRequest(request);
        const log = createLogger(request, user);
        const stat = createStat(request, user);
        const context = { log, stat, user };
        return context;
    };

    async function authenticateRequest(request) {
        const checks = {
            body: bodyTokenName && request && request.body && request.body[bodyTokenName],
            query: queryTokenName && request && request.query && request.query[queryTokenName],
            [`authorization header (${authorizationHeaderName})`]: authorizationHeaderName &&
                request &&
                request.headers[authorizationHeaderName] &&
                extractBearerFromAuthorization(request.headers[authorizationHeaderName])
        };

        for (const [source, token] of Object.entries(checks)) {
            if (!token) {
                continue;
            }
            const user = await verifyToken(source, token);
            if (user) {
                return user;
            }
        }
        return undefined;
    }

    function extractBearerFromAuthorization(authorization) {
        if (typeof authorization !== `string`) {
            return undefined;
        }
        const authParts = authorization.split(`,`);
        for (let part = 0; part < authParts.length; part++) {
            const result = extractBearer(authParts[part]);
            if (result) {
                return result;
            }
        }
        return undefined;
    }

    function extractBearer(authorization) {
        const [type, token] = authorization.split(` `);
        if (laxTokenHeader && !token) {
            return type;
        } else if (type.toLowerCase() === tokenTypeName) {
            return token;
        } else {
            return undefined;
        }
    }

    async function verifyToken(source, token) {
        try {
            const decoded = await jwt.decode(token, { complete: true });
            const { key, options } = await loadVerificationInformation(decoded.payload.iss, decoded.header.kid);
            const user = await jwt.verify(token, key, options);
            return user;
        } catch (ex) {
            switch (ex.name) {
                case `JsonWebTokenError`:
                    throw new Error(`Token error: ${ex.message}`);
                case `TokenExpiredError`:
                    throw new Error(`Token expired at ${ex.expiredAt.toISOString()}`);
                default: {
                    const id = uuid.v4().replace(/-/g, ``);
                    createLogger(req).warn(`Unable to validate token "${token}" received in ${source}. ${id} ` +
                        `${ex.name} ${ex.stack}`);
                    throw new Error(`Internal server error. Please send "${id}" to support to assist with ` +
                        `identifying error`);
                }
            }
        }
    }
}

function defaultCreateLogger() {
    return console;
}

function defaultCreateStat() {
    // This is just a placeholder so a stats client can be passed in
    return {
        increment: () => undefined,
        decrement: () => undefined,
        timing: () => undefined,
        counter: () => undefined,
        gauge: () => undefined,
        gaugeDelta: () => undefined,
        set: () => undefined,
        histogram: () => undefined,
    };
}
