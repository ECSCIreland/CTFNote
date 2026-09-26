/*
 * API keys: long-lived, non-expiring credentials for programmatic access.
 *
 * A key authenticates a request as the user that owns it, carrying that
 * user's role. Unlike the 30-day JWT issued by `login`, a key is valid until
 * it is explicitly revoked. Requests present it in the `X-API-Key` header;
 * the API translates it into the same `jwt.claims.*` settings a JWT would set
 * (see api/src/index.ts), so every existing permission check applies unchanged.
 */
CREATE TABLE ctfnote_private.api_key (
  "id" serial PRIMARY KEY,
  "token" text NOT NULL UNIQUE,
  "user_id" int NOT NULL REFERENCES ctfnote_private.user (id) ON DELETE CASCADE,
  "description" text NOT NULL DEFAULT '',
  "created" timestamptz NOT NULL DEFAULT now(),
  "last_used" timestamptz
);

CREATE INDEX api_key_user_id_idx ON ctfnote_private.api_key ("user_id");

/*
 * Resolve a raw token to its owner's id + role and stamp last_used.
 * Called directly by the API's connection role (user_postgraphile), so it is
 * SECURITY DEFINER to read the private table regardless of the caller's role.
 * Returns zero rows for an unknown/invalid token.
 */
CREATE FUNCTION ctfnote_private.api_key_claims ("token" text)
  RETURNS TABLE (
    "user_id" int,
    "role" ctfnote.role
  )
  AS $$
  WITH updated AS (
    UPDATE ctfnote_private.api_key k
    SET last_used = now()
    WHERE k.token = api_key_claims.token
    RETURNING k.user_id
  )
  SELECT u.id, u.role
  FROM updated
  JOIN ctfnote_private.user u ON u.id = updated.user_id;
$$
LANGUAGE sql
VOLATILE
SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION ctfnote_private.api_key_claims (text) TO user_postgraphile;

/*
 * Create an API key for the currently authenticated user.
 * Returns the plaintext token, which is shown only once (it is stored as-is
 * and cannot be retrieved again). Requires being logged in.
 */
CREATE FUNCTION ctfnote.create_api_key ("description" text)
  RETURNS text
  AS $$
DECLARE
  uid int;
  new_token text;
BEGIN
  uid := ctfnote_private.user_id ();
  IF uid IS NULL THEN
    RAISE EXCEPTION 'You must be logged in to create an API key';
  END IF;
  new_token := 'ctfnote_' || encode(gen_random_bytes(24), 'hex');
  INSERT INTO ctfnote_private.api_key ("token", "user_id", "description")
    VALUES (new_token, uid, COALESCE(create_api_key.description, ''));
  RETURN new_token;
END;
$$
LANGUAGE plpgsql
SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION ctfnote.create_api_key (text) TO user_member;

/*
 * List the calling user's own API keys (metadata only, never the token).
 * PostGraphile exposes this as the `myApiKeys` query.
 */
CREATE FUNCTION ctfnote.my_api_keys ()
  RETURNS TABLE (
    "id" int,
    "description" text,
    "created" timestamptz,
    "last_used" timestamptz
  )
  AS $$
  SELECT k.id, k.description, k.created, k.last_used
  FROM ctfnote_private.api_key k
  WHERE k.user_id = ctfnote_private.user_id ()
  ORDER BY k.created DESC;
$$
LANGUAGE sql
STABLE
SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION ctfnote.my_api_keys () TO user_member;

/*
 * Revoke one of the calling user's keys by id (admins may revoke any key).
 * Returns the number of keys deleted (0 if not found / not owned).
 */
CREATE FUNCTION ctfnote.revoke_api_key ("id" int)
  RETURNS int
  AS $$
DECLARE
  uid int;
  deleted int;
BEGIN
  uid := ctfnote_private.user_id ();
  IF uid IS NULL THEN
    RAISE EXCEPTION 'You must be logged in to revoke an API key';
  END IF;
  DELETE FROM ctfnote_private.api_key k
  WHERE k.id = revoke_api_key.id
    AND (k.user_id = uid OR ctfnote_private.is_admin ());
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END;
$$
LANGUAGE plpgsql
SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION ctfnote.revoke_api_key (int) TO user_member;
