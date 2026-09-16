-- pgTAP coverage for host-bound plugin/tool ownership and explicit human grants.
BEGIN;
SELECT no_plan();

DO $fixture$
DECLARE existing uuid;
BEGIN
    SELECT id INTO existing FROM vault.secrets WHERE name = 'master_encryption_key';
    IF existing IS NULL THEN
        PERFORM vault.create_secret('execution-principal-test-key-32-bytes', 'master_encryption_key', 'pgTAP only');
    ELSE
        PERFORM vault.update_secret(existing, 'execution-principal-test-key-32-bytes', 'master_encryption_key', 'pgTAP only');
    END IF;
END;
$fixture$;

INSERT INTO auth.users (id, email) VALUES
    ('e1600000-0000-4000-8000-000000000001', 'execution-owner@pgtap.test'),
    ('e1600000-0000-4000-8000-000000000002', 'other-owner@pgtap.test');

INSERT INTO public.secrets(
    id, user_id, website, username, password_encrypted, execution_owner_type, execution_owner_id
) VALUES
    ('e1600000-0000-4000-8000-000000000011', 'e1600000-0000-4000-8000-000000000001',
     'human.example', 'human', public.encrypt_text('human-value'), NULL, NULL),
    ('e1600000-0000-4000-8000-000000000012', 'e1600000-0000-4000-8000-000000000001',
     'plugin.example', 'plugin', public.encrypt_text('plugin-value'), 'plugin', 'plugin-a'),
    ('e1600000-0000-4000-8000-000000000013', 'e1600000-0000-4000-8000-000000000002',
     'other-user.example', 'plugin', public.encrypt_text('other-value'), 'plugin', 'plugin-a');

SELECT set_config(
    'request.jwt.claims',
    '{"sub":"e1600000-0000-4000-8000-000000000001","role":"authenticated"}',
    true
);
SET LOCAL ROLE authenticated;

SELECT is(
    (SELECT count(*)::integer FROM public.list_execution_secrets('plugin', 'plugin-a')),
    1,
    'the owning plugin sees its own secret without crossing into another user account'
);
SELECT is(
    (SELECT count(*)::integer FROM public.list_execution_secrets('plugin', 'plugin-b')),
    0,
    'another plugin sees neither the ownerless human secret nor plugin-a secret'
);
SELECT is(
    (SELECT password FROM public.get_execution_secret(
        'plugin', 'plugin-a', 'e1600000-0000-4000-8000-000000000012')),
    'plugin-value',
    'the owning principal can explicitly resolve plaintext'
);
SELECT is(
    (SELECT access_level FROM public.list_secret_execution_grants(
        'e1600000-0000-4000-8000-000000000012')),
    'owner',
    'the human grant view identifies immutable creator ownership'
);
SELECT is(
    (SELECT count(*)::integer FROM public.get_execution_secret(
        'plugin', 'plugin-b', 'e1600000-0000-4000-8000-000000000012')),
    0,
    'missing and unauthorized get calls are indistinguishable empty results'
);

SELECT is(
    (public.grant_secret_to_execution_principal(
        'e1600000-0000-4000-8000-000000000011', 'plugin', 'plugin-b')->>'success'),
    'true',
    'a human manager may grant one ownerless secret to one plugin'
);
SELECT is(
    (SELECT access_level FROM public.list_execution_secrets('plugin', 'plugin-b')),
    'use',
    'an explicit recipient sees the granted secret with use access'
);
SELECT is(
    (SELECT password FROM public.get_execution_secret(
        'plugin', 'plugin-b', 'e1600000-0000-4000-8000-000000000011')),
    'human-value',
    'a use grant permits an explicit plaintext read'
);
SELECT is(
    (public.update_execution_secret(
        'plugin', 'plugin-b', 'e1600000-0000-4000-8000-000000000011',
        'human.example', 'human', 'changed')->>'success'),
    'false',
    'a use grant does not permit mutation'
);
SELECT is(
    (public.delete_execution_secret(
        'plugin', 'plugin-b', 'e1600000-0000-4000-8000-000000000011')->>'success'),
    'false',
    'a use grant does not permit deletion'
);

SELECT is(
    (public.revoke_secret_from_execution_principal(
        'e1600000-0000-4000-8000-000000000011', 'plugin', 'plugin-b')->>'success'),
    'true',
    'a human manager may revoke a grant'
);
SELECT is(
    (SELECT count(*)::integer FROM public.get_execution_secret(
        'plugin', 'plugin-b', 'e1600000-0000-4000-8000-000000000011')),
    0,
    'revocation takes effect on the next read'
);

SELECT is(
    (public.create_execution_secret(
        'mcp_tool', 'secret-manager/secret_create', 'tool.example', 'tool', 'tool-value')->>'success'),
    'true',
    'a tool creates a secret through the scoped RPC'
);
SELECT is(
    (SELECT execution_owner_id FROM public.secrets WHERE website = 'tool.example'),
    'secret-manager/secret_create',
    'the created row records the supplied host principal identity'
);
SELECT is(
    (SELECT count(*)::integer FROM public.list_execution_secrets(
        'mcp_tool', 'secret-manager/secret_get') WHERE website = 'tool.example'),
    0,
    'another tool in the same plugin does not inherit the creating tool ownership'
);

RESET ROLE;
SELECT ok(
    NOT has_table_privilege('authenticated', 'public.secret_execution_grants', 'SELECT'),
    'authenticated clients cannot enumerate the grant table directly'
);
SELECT ok(
    NOT has_function_privilege('anon', 'public.get_execution_secret(text,text,uuid)', 'EXECUTE'),
    'anonymous clients cannot call scoped plaintext retrieval'
);

SELECT * FROM finish();
ROLLBACK;
