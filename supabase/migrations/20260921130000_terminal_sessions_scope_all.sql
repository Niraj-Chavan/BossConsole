-- ShareScope has three values (TAB, WINDOW, ALL); the original check allowed two, so an
-- "all windows" share was rejected with 23514 on every heartbeat. Measured on the first real
-- publish from a dev build.
ALTER TABLE public.terminal_sessions DROP CONSTRAINT IF EXISTS terminal_sessions_scope_check;
ALTER TABLE public.terminal_sessions
    ADD CONSTRAINT terminal_sessions_scope_check CHECK (scope IN ('TAB', 'WINDOW', 'ALL'));
