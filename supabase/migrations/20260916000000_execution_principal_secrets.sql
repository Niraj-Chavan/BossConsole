-- Execution-principal ownership and explicit human grants for secrets.
--
-- Existing rows remain human-owned: both execution_owner columns are NULL. They keep every
-- browser/Secret Manager behaviour they had before this migration and are invisible to plugin,
-- tool and MCP access unless a human adds one row to secret_execution_grants.

ALTER TABLE public.secrets
    ADD COLUMN IF NOT EXISTS execution_owner_type text,
    ADD COLUMN IF NOT EXISTS execution_owner_id text;

ALTER TABLE public.secrets
    DROP CONSTRAINT IF EXISTS secrets_execution_owner_pair;
ALTER TABLE public.secrets
    ADD CONSTRAINT secrets_execution_owner_pair CHECK (
        (execution_owner_type IS NULL AND execution_owner_id IS NULL)
        OR
        (execution_owner_type IS NOT NULL AND execution_owner_id IS NOT NULL
            AND length(execution_owner_type) BETWEEN 1 AND 64
            AND length(execution_owner_id) BETWEEN 1 AND 500)
    );

CREATE INDEX IF NOT EXISTS idx_secrets_execution_owner
    ON public.secrets (execution_owner_type, execution_owner_id)
    WHERE execution_owner_type IS NOT NULL;

COMMENT ON COLUMN public.secrets.execution_owner_type IS
    'Host-derived execution principal kind. NULL means a human-owned legacy/general vault secret.';
COMMENT ON COLUMN public.secrets.execution_owner_id IS
    'Host-derived execution principal id. Never accepted from an untrusted plugin UI.';

CREATE TABLE IF NOT EXISTS public.secret_execution_grants (
    secret_id uuid NOT NULL REFERENCES public.secrets(id) ON DELETE CASCADE,
    principal_type text NOT NULL CHECK (length(principal_type) BETWEEN 1 AND 64),
    principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 500),
    granted_by uuid NOT NULL REFERENCES auth.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (secret_id, principal_type, principal_id)
);

ALTER TABLE public.secret_execution_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.secret_execution_grants FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.secret_execution_grants TO service_role;

COMMENT ON TABLE public.secret_execution_grants IS
    'Explicit human grants from one secret to one host-known plugin/tool principal. Access is only through SECURITY DEFINER RPCs.';

-- One policy predicate used by every scoped read. Human vault authorization remains a separate
-- requirement, so the same globally stable plugin id cannot cross from one user/account to another.
CREATE OR REPLACE FUNCTION public.execution_principal_can_use_secret(
    p_secret_id uuid,
    p_principal_type text,
    p_principal_id text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
    SELECT auth.uid() IS NOT NULL
       AND public.can_access_secret(p_secret_id)
       AND EXISTS (
            SELECT 1
            FROM public.secrets s
            WHERE s.id = p_secret_id
              AND (
                    (s.execution_owner_type = p_principal_type
                     AND s.execution_owner_id = p_principal_id)
                    OR EXISTS (
                        SELECT 1
                        FROM public.secret_execution_grants g
                        WHERE g.secret_id = s.id
                          AND g.principal_type = p_principal_type
                          AND g.principal_id = p_principal_id
                    )
              )
       );
$$;

REVOKE EXECUTE ON FUNCTION public.execution_principal_can_use_secret(uuid,text,text)
    FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.execution_principal_can_use_secret(uuid,text,text) TO postgres;

CREATE OR REPLACE FUNCTION public.list_execution_secrets(
    p_principal_type text,
    p_principal_id text,
    p_query text DEFAULT NULL,
    p_limit integer DEFAULT 50,
    p_offset integer DEFAULT 0
) RETURNS TABLE(
    id uuid,
    website text,
    username text,
    expiration_date timestamptz,
    tags jsonb,
    created_at timestamptz,
    updated_at timestamptz,
    access_level text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF auth.uid() IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;
    IF coalesce(length(p_principal_type), 0) = 0 OR coalesce(length(p_principal_id), 0) = 0 THEN
        RAISE EXCEPTION 'Execution principal is required' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT
        s.id,
        s.website,
        s.username,
        s.expiration_date,
        COALESCE((SELECT jsonb_agg(st.tag ORDER BY st.tag)
                  FROM public.secret_tags st WHERE st.secret_id = s.id), '[]'::jsonb),
        s.created_at,
        s.updated_at,
        CASE
            WHEN s.execution_owner_type = p_principal_type
             AND s.execution_owner_id = p_principal_id THEN 'owner'::text
            ELSE 'use'::text
        END
    FROM public.secrets s
    WHERE public.execution_principal_can_use_secret(s.id, p_principal_type, p_principal_id)
      AND (p_query IS NULL OR p_query = ''
           OR s.website ILIKE '%' || p_query || '%'
           OR s.username ILIKE '%' || p_query || '%')
    ORDER BY s.created_at DESC, s.id DESC
    LIMIT greatest(0, least(p_limit, 500)) OFFSET greatest(0, p_offset);
END;
$$;

CREATE OR REPLACE FUNCTION public.get_execution_secret(
    p_principal_type text,
    p_principal_id text,
    p_secret_id uuid
) RETURNS TABLE(
    id uuid, website text, username text, password text, notes text,
    expiration_date timestamptz, tags jsonb, metadata jsonb,
    created_at timestamptz, updated_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT public.execution_principal_can_use_secret(
        p_secret_id, p_principal_type, p_principal_id
    ) THEN
        -- Missing and unauthorized deliberately have the same empty result.
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        s.id, s.website, s.username,
        COALESCE(public.try_decrypt_text(s.password_encrypted), ''),
        s.notes, s.expiration_date,
        COALESCE((SELECT jsonb_agg(st.tag ORDER BY st.tag)
                  FROM public.secret_tags st WHERE st.secret_id = s.id), '[]'::jsonb),
        COALESCE((
            SELECT jsonb_build_object(
                'twofa_enabled', sm.twofa_enabled,
                'twofa_type', sm.twofa_type,
                'twofa_secret', public.safe_decrypt_twofa_secret(sm.twofa_secret),
                'recovery_codes', public.safe_decrypt_recovery_codes(sm.recovery_codes_encrypted)
            )
            FROM public.secret_metadata sm WHERE sm.secret_id = s.id
        ), '{}'::jsonb),
        s.created_at, s.updated_at
    FROM public.secrets s
    WHERE s.id = p_secret_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.create_execution_secret(
    p_principal_type text,
    p_principal_id text,
    p_website text,
    p_username text,
    p_password text,
    p_notes text DEFAULT NULL,
    p_expiration_date timestamptz DEFAULT NULL,
    p_tags text[] DEFAULT NULL,
    p_twofa_enabled boolean DEFAULT false,
    p_twofa_type text DEFAULT NULL,
    p_recovery_codes text[] DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO ''
AS $$
DECLARE
    result jsonb;
    created_id uuid;
BEGIN
    IF auth.uid() IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Not authenticated');
    END IF;
    IF coalesce(length(p_principal_type), 0) = 0 OR coalesce(length(p_principal_id), 0) = 0 THEN
        RETURN jsonb_build_object('success', false, 'error', 'Execution principal is required');
    END IF;

    result := public.create_secret(
        p_website, p_username, p_password, p_notes, p_expiration_date, p_tags,
        p_twofa_enabled, p_twofa_type, p_recovery_codes, NULL
    );
    IF COALESCE((result->>'success')::boolean, false) = false THEN
        RETURN result;
    END IF;

    created_id := (result->>'secret_id')::uuid;
    UPDATE public.secrets
    SET execution_owner_type = p_principal_type,
        execution_owner_id = p_principal_id
    WHERE id = created_id AND user_id = auth.uid();

    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION public.update_execution_secret(
    p_principal_type text,
    p_principal_id text,
    p_secret_id uuid,
    p_website text,
    p_username text,
    p_password text,
    p_notes text DEFAULT NULL,
    p_expiration_date timestamptz DEFAULT NULL,
    p_tags text[] DEFAULT NULL,
    p_twofa_enabled boolean DEFAULT false,
    p_twofa_type text DEFAULT NULL,
    p_recovery_codes text[] DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.secrets s
        WHERE s.id = p_secret_id
          AND s.execution_owner_type = p_principal_type
          AND s.execution_owner_id = p_principal_id
          AND public.can_access_secret(s.id)
    ) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Secret not found');
    END IF;

    RETURN public.update_secret(
        p_secret_id, p_website, p_username, p_password, p_notes, p_expiration_date,
        p_tags, p_twofa_enabled, p_twofa_type, p_recovery_codes, NULL, false
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.delete_execution_secret(
    p_principal_type text,
    p_principal_id text,
    p_secret_id uuid
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.secrets s
        WHERE s.id = p_secret_id
          AND s.execution_owner_type = p_principal_type
          AND s.execution_owner_id = p_principal_id
          AND public.can_access_secret(s.id)
    ) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Secret not found');
    END IF;
    RETURN public.delete_secret(p_secret_id);
END;
$$;

CREATE OR REPLACE FUNCTION public.list_secret_execution_grants(p_secret_id uuid)
RETURNS TABLE(
    principal_type text,
    principal_id text,
    granted_at timestamptz,
    granted_by_user_id uuid,
    access_level text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT public.can_manage_secret(p_secret_id) THEN
        RAISE EXCEPTION 'Secret not found' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT s.execution_owner_type, s.execution_owner_id, s.created_at, s.user_id, 'owner'::text
    FROM public.secrets s
    WHERE s.id = p_secret_id
      AND s.execution_owner_type IS NOT NULL
    UNION ALL
    SELECT g.principal_type, g.principal_id, g.created_at, g.granted_by, 'use'::text
    FROM public.secret_execution_grants g
    WHERE g.secret_id = p_secret_id
      AND NOT EXISTS (
          SELECT 1 FROM public.secrets s
          WHERE s.id = g.secret_id
            AND s.execution_owner_type = g.principal_type
            AND s.execution_owner_id = g.principal_id
      )
    ORDER BY 3, 1, 2;
END;
$$;

CREATE OR REPLACE FUNCTION public.grant_secret_to_execution_principal(
    p_secret_id uuid,
    p_principal_type text,
    p_principal_id text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT public.can_manage_secret(p_secret_id) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Secret not found');
    END IF;
    IF coalesce(length(p_principal_type), 0) = 0 OR coalesce(length(p_principal_id), 0) = 0 THEN
        RETURN jsonb_build_object('success', false, 'error', 'Execution principal is required');
    END IF;

    INSERT INTO public.secret_execution_grants(
        secret_id, principal_type, principal_id, granted_by
    ) VALUES (
        p_secret_id, p_principal_type, p_principal_id, auth.uid()
    )
    ON CONFLICT (secret_id, principal_type, principal_id)
    DO UPDATE SET granted_by = EXCLUDED.granted_by, created_at = now();
    RETURN jsonb_build_object('success', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.revoke_secret_from_execution_principal(
    p_secret_id uuid,
    p_principal_type text,
    p_principal_id text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO ''
AS $$
BEGIN
    IF NOT public.can_manage_secret(p_secret_id) THEN
        RETURN jsonb_build_object('success', false, 'error', 'Secret not found');
    END IF;
    DELETE FROM public.secret_execution_grants
    WHERE secret_id = p_secret_id
      AND principal_type = p_principal_type
      AND principal_id = p_principal_id;
    RETURN jsonb_build_object('success', true);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.list_execution_secrets(text,text,text,integer,integer) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.get_execution_secret(text,text,uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.create_execution_secret(text,text,text,text,text,text,timestamptz,text[],boolean,text,text[]) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.update_execution_secret(text,text,uuid,text,text,text,text,timestamptz,text[],boolean,text,text[]) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.delete_execution_secret(text,text,uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.list_secret_execution_grants(uuid) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.grant_secret_to_execution_principal(uuid,text,text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.revoke_secret_from_execution_principal(uuid,text,text) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.list_execution_secrets(text,text,text,integer,integer) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_execution_secret(text,text,uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_execution_secret(text,text,text,text,text,text,timestamptz,text[],boolean,text,text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.update_execution_secret(text,text,uuid,text,text,text,text,timestamptz,text[],boolean,text,text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.delete_execution_secret(text,text,uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.list_secret_execution_grants(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.grant_secret_to_execution_principal(uuid,text,text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_secret_from_execution_principal(uuid,text,text) TO authenticated, service_role;
