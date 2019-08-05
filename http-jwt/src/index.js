module.exports = createContextCreator;

const uuid = require(`uuid`);
const jwt = require(`jsonwebtoken`);

function createContextCreator({
    laxTokenHeader = false,
    queryTokenName = `token`,
    bodyTokenName = `token`,
    authorizationHeaderName = `authorization`,
    tokenTypeName = `bearer`,
    createLogger = defaultCreateLogger,
    createStat = defaultCreateStat,
    createMaintenanceNotifier = defaultCreateNotifier,
    loadVerificationInformation
}) {
    return async function createContext(request) {
        const { tokens, token, user } = await authenticateRequest(request);
        const log = createLogger(request, user);
        const stat = createStat(request, user);
        const maintain = createMaintenanceNotifier(request, user);
        const context = {
            log,
            stat,
            user,
            token,
            tokens,
            maintain
        };
        return context;
    };

    async function authenticateRequest(request) {
        const checks = {
            body: bodyTokenName && request && request.body && [request.body[bodyTokenName]],
            query: queryTokenName && request && request.query && [request.query[queryTokenName]],
            [`authorization header (${authorizationHeaderName})`]: authorizationHeaderName &&
                request &&
                request.headers[authorizationHeaderName] &&
                Array.from(extractBearerFromAuthorization(request.headers[authorizationHeaderName]))
        };

        for (const [source, tokens] of Object.entries(checks)) {
            if (!tokens) {
                continue;
            }
            for (const token of tokens) {
                const user = await verifyToken(source, request, token);
                if (user) {
                    return { tokens, token, user };
                }
            }
        }
        return { };
    }

    function *extractBearerFromAuthorization(authorization) {
        if (typeof authorization !== `string`) {
            return;
        }
        const authParts = authorization.split(`,`);
        for (let part = 0; part < authParts.length; part++) {
            const result = extractBearer(authParts[part]);
            if (result) {
                yield result;
            }
        }
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

    async function verifyToken(source, request, token) {
        try {
            const decoded = await jwt.decode(token, { complete: true });
            if (loadVerificationInformation) {
                const { key, options } = await loadVerificationInformation(
                    decoded.payload.iss,
                    decoded.header.kid
                );
                const user = await jwt.verify(token, key, options);
                return user;
            } else {
                return decoded.payload;
            }
        } catch (ex) {
            switch (ex.name) {
                case `JsonWebTokenError`:
                    throw new Error(`Token error: ${ex.message}`);
                case `TokenExpiredError`:
                    throw new Error(`Token expired at ${ex.expiredAt.toISOString()}`);
                default: {
                    const id = uuid.v4().replace(/-/g, ``);
                    createLogger(request).warn(`Unable to validate token "${token}" received in ${source}. ${id} ` +
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
        increment: log,
        decrement: log,
        timing: log,
        counter: log,
        gauge: log,
        gaugeDelta: log,
        set: log,
        histogram: log
    };

    function log(...args) {
        // eslint-disable-next-line no-console
        console.debug(...args);
    }
}

function defaultCreateNotifier() {
    // eslint-disable-next-line no-console
    return (...args) => console.warn(...args);
}
