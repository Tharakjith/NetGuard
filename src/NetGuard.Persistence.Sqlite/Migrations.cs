namespace NetGuard.Persistence.Sqlite;

/// <summary>
/// Ordered, append-only schema migrations. Never edit a released migration; add a new one. The database is backed
/// up before any migration runs, and each migration runs in its own transaction.
/// </summary>
internal static class Migrations
{
    public static IReadOnlyList<(int Version, string Description, string Sql)> All { get; } =
    [
        (1, "Initial schema", """
            CREATE TABLE applications (
                id                TEXT PRIMARY KEY,
                display_name      TEXT NOT NULL,
                publisher         TEXT NULL,
                install_directory TEXT NULL,
                policy_json       TEXT NOT NULL,
                profile_id        TEXT NULL,
                is_enabled        INTEGER NOT NULL,
                source            INTEGER NOT NULL,
                include_children  INTEGER NOT NULL,
                follow_updates    INTEGER NOT NULL,
                created_at        TEXT NOT NULL,
                created_by        TEXT NOT NULL,
                modified_at       TEXT NOT NULL,
                modified_by       TEXT NOT NULL,
                revision          INTEGER NOT NULL
            );

            CREATE TABLE executables (
                id                   TEXT PRIMARY KEY,
                application_id       TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                path                 TEXT NOT NULL COLLATE NOCASE UNIQUE,
                is_primary           INTEGER NOT NULL,
                origin               INTEGER NOT NULL,
                sha256               TEXT NULL,
                file_size            INTEGER NULL,
                file_version         TEXT NULL,
                product_name         TEXT NULL,
                company_name         TEXT NULL,
                original_file_name   TEXT NULL,
                signature_status     INTEGER NOT NULL,
                signer_subject       TEXT NULL,
                signer_thumbprint    TEXT NULL,
                added_at             TEXT NOT NULL,
                identity_verified_at TEXT NULL
            );

            CREATE TABLE profiles (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL COLLATE NOCASE UNIQUE,
                description TEXT NOT NULL,
                is_builtin  INTEGER NOT NULL,
                is_enabled  INTEGER NOT NULL,
                source      INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                modified_by TEXT NOT NULL
            );

            CREATE TABLE temporary_exceptions (
                application_id TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
                granted_at     TEXT NOT NULL,
                expires_at     TEXT NOT NULL,
                granted_by     TEXT NOT NULL,
                reason         TEXT NOT NULL
            );

            CREATE TABLE enforcement_status (
                application_id   TEXT PRIMARY KEY,
                state            INTEGER NOT NULL,
                message          TEXT NOT NULL,
                warnings_json    TEXT NOT NULL,
                expected_rules   INTEGER NOT NULL,
                verified_rules   INTEGER NOT NULL,
                evaluated_at     TEXT NOT NULL,
                last_verified_at TEXT NULL
            );

            CREATE TABLE settings (
                key        TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );

            CREATE TABLE audit_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ts               TEXT NOT NULL,
                type             INTEGER NOT NULL,
                outcome          INTEGER NOT NULL,
                actor            TEXT NOT NULL,
                application_id   TEXT NULL,
                application_name TEXT NULL,
                executable_path  TEXT NULL,
                message          TEXT NOT NULL,
                details          TEXT NULL
            );
            """),

        (2, "Audit query indexes", """
            CREATE INDEX ix_audit_ts ON audit_events(ts);
            CREATE INDEX ix_audit_type_ts ON audit_events(type, ts);
            CREATE INDEX ix_audit_app_ts ON audit_events(application_id, ts);
            CREATE INDEX ix_executables_app ON executables(application_id);
            """),
    ];

    public static int LatestVersion => All[^1].Version;
}
