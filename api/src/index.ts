import simplifyPlugin from "@graphile-contrib/pg-simplify-inflector";
import PgPubsub from "@graphile/pg-pubsub";
import crypto from "crypto";
import express from "express";
import { graphqlUploadExpress } from "graphql-upload-ts";
import {
  makePluginHook,
  postgraphile,
  PostGraphileOptions,
} from "postgraphile";
import { migrate, MigrateDBConfig } from "postgres-migrations";
import config from "./config";
import createTasKPlugin from "./plugins/createTask";
import importCtfPlugin from "./plugins/importCtf";
import uploadLogoPlugin from "./plugins/uploadLogo";
import uploadScalar from "./plugins/uploadScalar";
import { Pool } from "pg";
import { IncomingMessage } from "http";
import { icalRoute } from "./routes/ical";
import { restRoutes } from "./routes/rest";
import ConnectionFilterPlugin from "postgraphile-plugin-connection-filter";
import OperationHook from "@graphile/operation-hooks";
import discordHooks from "./discord/hooks";
import { initDiscordBot } from "./discord";
import PgManyToManyPlugin from "@graphile-contrib/pg-many-to-many";
import ProfileSubscriptionPlugin from "./plugins/ProfileSubscriptionPlugin";

function getDbUrl(role: "user" | "admin") {
  const login = config.db[role].login;
  const password = config.db[role].password;
  return `postgres://${login}:${password}@${config.db.host}:${config.db.port}/${config.db.database}`;
}

// The secret PostGraphile uses to sign/verify JWTs. Resolved once and shared
// with the API-key middleware so the JWTs it mints are accepted here.
function resolveJwtSecret(): string {
  if (config.env === "development") return "DEV";
  if (config.sessionSecret.length < 64) {
    console.info(
      "Using random session secret since SESSION_SECRET is too short. All users will be logged out."
    );
    return crypto.randomBytes(32).toString("hex");
  }
  return config.sessionSecret;
}

function createOptions(secret: string) {
  const postgraphileOptions: PostGraphileOptions = {
    pluginHook: makePluginHook([PgPubsub, OperationHook]),
    subscriptions: true,
    dynamicJson: true,
    simpleSubscriptions: true,
    setofFunctionsContainNulls: false,
    ignoreRBAC: false,
    disableQueryLog: true,
    ignoreIndexes: false,
    subscriptionAuthorizationFunction: "ctfnote_private.validate_subscription",
    jwtPgTypeIdentifier: "ctfnote.jwt",
    pgDefaultRole: "user_anonymous",
    jwtSecret: secret,
    appendPlugins: [
      simplifyPlugin,
      uploadScalar,
      importCtfPlugin,
      uploadLogoPlugin,
      createTasKPlugin,
      ConnectionFilterPlugin,
      discordHooks,
      PgManyToManyPlugin,
      ProfileSubscriptionPlugin,
    ],
    ownerConnectionString: getDbUrl("admin"),
    enableQueryBatching: true,
    legacyRelations: "omit" as const,
  };

  if (config.env == "development") {
    postgraphileOptions.watchPg = true;
    postgraphileOptions.disableQueryLog = false;
    postgraphileOptions.graphiql = true;
    postgraphileOptions.exportGqlSchemaPath = "schema.graphql";
    postgraphileOptions.retryOnInitFail = true;
    postgraphileOptions.enhanceGraphiql = true;
    postgraphileOptions.allowExplain = true;
    postgraphileOptions.showErrorStack = "json" as const;
    postgraphileOptions.extendedErrors = [
      "severity",
      "code",
      "detail",
      "hint",
      "position",
      "internalPosition",
      "internalQuery",
      "where",
      "schema",
      "table",
      "column",
      "dataType",
      "constraint",
      "file",
      "line",
      "routine",
    ];

    postgraphileOptions.graphileBuildOptions = {
      connectionFilterAllowedOperators: ["includesInsensitive"],
      connectionFilterAllowedFieldTypes: ["String"],
      connectionFilterComputedColumns: false,
      connectionFilterSetofFunctions: false,
      connectionFilterArrays: false,
    };
  }
  return postgraphileOptions;
}

function base64url(input: string): string {
  return Buffer.from(input).toString("base64url");
}

// Mint a short-lived JWT matching PostGraphile's expectations for the
// `ctfnote.jwt` type (claims user_id + role), signed HS256 with the same
// secret PostGraphile verifies with, and audience "postgraphile".
function signApiKeyJwt(
  claims: { user_id: number; role: string },
  secret: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      user_id: claims.user_id,
      role: claims.role,
      aud: "postgraphile",
      iat: now,
      exp: now + 300,
    })
  );
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

/*
 * Authenticate a request presenting an `X-API-Key` header.
 *
 * API keys are long-lived credentials (see migration 57-api-keys.sql). When a
 * valid key is presented (and no Authorization header is already set), we mint
 * a short-lived JWT for its owner and inject it as `Authorization: Bearer ...`,
 * so PostGraphile's normal JWT path handles it and every existing permission
 * check applies unchanged. A missing/unknown key is left untouched, so the
 * request stays anonymous (or uses its own JWT).
 *
 * A dedicated header is used on purpose: PostGraphile would try to parse an
 * API key sent in `Authorization` as a JWT and reject it.
 */
function makeApiKeyMiddleware(pool: Pool, secret: string) {
  return async (
    req: IncomingMessage,
    _res: unknown,
    next: (err?: unknown) => void
  ): Promise<void> => {
    const header = req.headers["x-api-key"];
    const token = Array.isArray(header) ? header[0] : header;
    if (!token || req.headers.authorization) {
      next();
      return;
    }
    try {
      const { rows } = await pool.query(
        "SELECT user_id, role FROM ctfnote_private.api_key_claims($1)",
        [token]
      );
      if (rows.length > 0) {
        const { user_id, role } = rows[0];
        req.headers.authorization = `Bearer ${signApiKeyJwt(
          { user_id, role },
          secret
        )}`;
      }
    } catch (e) {
      console.error("API key validation failed", e);
    }
    next();
  };
}

function createApp(postgraphileOptions: PostGraphileOptions, secret: string) {
  const pool = new Pool({
    connectionString: getDbUrl("user"),
  });

  const app = express();
  app.use(makeApiKeyMiddleware(pool, secret));
  app.use(graphqlUploadExpress());
  app.use(
    "/uploads",
    express.static("uploads", {
      setHeaders: function (res) {
        res.set("Content-Disposition", "attachment");
      },
    })
  );
  app.use(postgraphile(pool, "ctfnote", postgraphileOptions));
  app.use("/calendar.ics", icalRoute(pool));
  app.use("/api", restRoutes());
  return app;
}

async function performMigrations() {
  const dbConfig: MigrateDBConfig = {
    database: config.db.database,
    user: config.db.admin.login,
    password: config.db.admin.password,
    host: config.db.host,
    port: config.db.port,
    ensureDatabaseExists: true,
    defaultDatabase: "postgres",
  };

  await migrate(dbConfig, "./migrations");
}

async function main() {
  await performMigrations();
  if (config.db.migrateOnly) {
    console.log("Migrations done. Exiting.");
    return;
  }
  const secret = resolveJwtSecret();
  const postgraphileOptions = createOptions(secret);
  const app = createApp(postgraphileOptions, secret);

  await initDiscordBot();

  app.listen(config.web.port, () => {
    //sendMessageToDiscord("CTFNote API started");
    console.log(`Listening on :${config.web.port}`);
  });
}

main();
