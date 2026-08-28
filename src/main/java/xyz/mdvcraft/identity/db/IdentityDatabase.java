package xyz.mdvcraft.identity.db;

import xyz.mdvcraft.identity.FloodgateIdentityUtil;
import xyz.mdvcraft.identity.model.*;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class IdentityDatabase {
    private final String jdbcUrl;

    public IdentityDatabase(File file) {
        this.jdbcUrl = "jdbc:sqlite:" + file.getAbsolutePath();
    }

    public void initialize() throws SQLException {
        File parent = new File(jdbcUrl.substring("jdbc:sqlite:".length())).getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.exists()) {
            throw new SQLException("No se pudo crear la carpeta de la base de datos: " + parent);
        }

        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=NORMAL");
            statement.execute("PRAGMA foreign_keys=ON");

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS identities (
                        name_key TEXT PRIMARY KEY,
                        display_name TEXT NOT NULL,
                        platform TEXT NOT NULL,
                        uuid TEXT,
                        xuid TEXT,
                        java_type TEXT,
                        first_registered_at INTEGER NOT NULL,
                        source TEXT NOT NULL,
                        last_seen_at INTEGER
                    )
                    """);

            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_identities_uuid ON identities(uuid)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_identities_xuid ON identities(xuid)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_identities_platform ON identities(platform)");

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS conflicts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name_key TEXT NOT NULL,
                        winner_name TEXT NOT NULL,
                        winner_platform TEXT NOT NULL,
                        winner_uuid TEXT,
                        loser_name TEXT NOT NULL,
                        loser_platform TEXT NOT NULL,
                        loser_uuid TEXT,
                        detected_at INTEGER NOT NULL,
                        source TEXT NOT NULL
                    )
                    """);

            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS meta (
                        meta_key TEXT PRIMARY KEY,
                        meta_value TEXT NOT NULL
                    )
                    """);
        }
    }

    private Connection open() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA busy_timeout=5000");
            statement.execute("PRAGMA foreign_keys=ON");
        }
        return connection;
    }

    public static String normalizeName(String name) {
        return name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
    }

    public Optional<IdentityRecord> findByName(String name) {
        try {
            return findByNameStrict(name);
        } catch (SQLException exception) {
            return Optional.empty();
        }
    }

    public Optional<IdentityRecord> findByNameStrict(String name) throws SQLException {
        String key = normalizeName(name);
        if (key.isEmpty()) {
            return Optional.empty();
        }
        try (Connection connection = open()) {
            return findByName(connection, key);
        }
    }

    public Optional<IdentityRecord> findBedrockByUuidOrXuid(String uuid, String xuid) {
        String sql = """
                SELECT name_key, display_name, platform, uuid, xuid, java_type,
                       first_registered_at, source
                FROM identities
                WHERE platform = 'BEDROCK'
                  AND ((? IS NOT NULL AND uuid = ?) OR (? IS NOT NULL AND xuid = ?))
                ORDER BY first_registered_at ASC
                LIMIT 1
                """;
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            nullable(statement, 1, uuid);
            nullable(statement, 2, uuid);
            nullable(statement, 3, xuid);
            nullable(statement, 4, xuid);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.of(readIdentity(resultSet));
                }
            }
        } catch (SQLException ignored) {
        }
        return Optional.empty();
    }


    /**
     * Reclasifica una identidad creada por la migracion 1.0.0 como BEDROCK, pero solo si
     * el registro actual sigue siendo JAVA y su UUID coincide exactamente con la cuenta
     * nLogin sin-prefijo que fue verificada como alias del mismo Bedrock.
     */
    public boolean reclassifyVerifiedLegacyJavaAsBedrock(String displayName, String expectedJavaUuid,
                                                          String bedrockUuid, long registeredAt,
                                                          String source) throws SQLException {
        String key = normalizeName(displayName);
        if (key.isEmpty() || expectedJavaUuid == null || expectedJavaUuid.isBlank()
                || bedrockUuid == null || bedrockUuid.isBlank()) {
            return false;
        }

        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                Optional<IdentityRecord> currentOptional = findByName(connection, key);
                if (currentOptional.isEmpty()) {
                    connection.commit();
                    return false;
                }

                IdentityRecord current = currentOptional.get();
                if (current.platform() != PlatformType.JAVA
                        || current.uuid() == null
                        || !current.uuid().equalsIgnoreCase(expectedJavaUuid)) {
                    connection.commit();
                    return false;
                }

                // Deja constancia del arreglo para auditoria.
                recordConflict(connection,
                        displayName, PlatformType.BEDROCK, bedrockUuid,
                        current.displayName(), PlatformType.JAVA, current.uuid(),
                        key, source);

                String sql = """
                        UPDATE identities
                        SET display_name = ?,
                            platform = 'BEDROCK',
                            uuid = ?,
                            xuid = NULL,
                            java_type = NULL,
                            first_registered_at = CASE
                                WHEN first_registered_at < ? THEN first_registered_at
                                ELSE ?
                            END,
                            source = ?,
                            last_seen_at = NULL
                        WHERE name_key = ?
                          AND platform = 'JAVA'
                          AND lower(uuid) = lower(?)
                        """;
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setString(1, displayName);
                    statement.setString(2, bedrockUuid);
                    statement.setLong(3, registeredAt);
                    statement.setLong(4, registeredAt);
                    statement.setString(5, source);
                    statement.setString(6, key);
                    statement.setString(7, expectedJavaUuid);
                    boolean changed = statement.executeUpdate() > 0;
                    connection.commit();
                    return changed;
                }
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    public ClaimResult claimBedrock(String displayName, String uuid, String xuid, boolean strictOwnerCheck, String source) {
        String key = normalizeName(displayName);
        if (key.isEmpty()) {
            return ClaimResult.error("Nombre Bedrock vacio");
        }

        long now = System.currentTimeMillis();
        IdentityRecord candidate = new IdentityRecord(
                key,
                displayName,
                PlatformType.BEDROCK,
                uuid,
                xuid,
                null,
                now,
                source
        );

        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                boolean inserted = insertIfAbsent(connection, candidate);
                IdentityRecord owner = findByName(connection, key).orElseThrow();

                if (owner.platform() != PlatformType.BEDROCK) {
                    // Reparacion segura en caliente: si una version vieja/importacion guardo como JAVA
                    // exactamente el UUID que Floodgate esta verificando ahora, no es otro jugador.
                    // La igualdad de UUID es la prueba fuerte; el nombre por si solo nunca alcanza.
                    if (owner.platform() == PlatformType.JAVA
                            && owner.uuid() != null
                            && uuid != null
                            && owner.uuid().equalsIgnoreCase(uuid)
                            && isFloodgateUuid(uuid)) {
                        recordConflict(connection,
                                displayName, PlatformType.BEDROCK, uuid,
                                owner.displayName(), PlatformType.JAVA, owner.uuid(),
                                key, "runtime-same-floodgate-uuid-repair");
                        reclassifyJavaToBedrock(connection, key, displayName, uuid, xuid, now,
                                "runtime-same-floodgate-uuid-repair");
                        owner = findByName(connection, key).orElseThrow();
                    } else {
                        connection.commit();
                        return ClaimResult.conflictPlatform(owner);
                    }
                }

                if (strictOwnerCheck && !sameBedrockOwner(owner, uuid, xuid)) {
                    connection.commit();
                    return ClaimResult.conflictBedrockOwner(owner);
                }

                updateBedrockIdentifiers(connection, key, uuid, xuid, displayName, now);
                IdentityRecord refreshed = findByName(connection, key).orElse(owner);
                connection.commit();

                return inserted ? ClaimResult.claimed(refreshed) : ClaimResult.alreadyOwned(refreshed);
            } catch (Exception exception) {
                connection.rollback();
                return ClaimResult.error(exception.getMessage());
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException exception) {
            return ClaimResult.error(exception.getMessage());
        }
    }

    public ClaimResult claimJava(String displayName, String uuid, JavaType javaType, String source) {
        String key = normalizeName(displayName);
        if (key.isEmpty()) {
            return ClaimResult.error("Nombre Java vacio");
        }

        long now = System.currentTimeMillis();
        IdentityRecord candidate = new IdentityRecord(
                key,
                displayName,
                PlatformType.JAVA,
                uuid,
                null,
                javaType == null ? JavaType.UNKNOWN : javaType,
                now,
                source
        );

        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                boolean inserted = insertIfAbsent(connection, candidate);
                IdentityRecord owner = findByName(connection, key).orElseThrow();

                if (owner.platform() != PlatformType.JAVA) {
                    connection.commit();
                    return ClaimResult.conflictPlatform(owner);
                }

                updateJavaIdentifiers(connection, key, uuid, javaType, displayName, now);
                IdentityRecord refreshed = findByName(connection, key).orElse(owner);
                connection.commit();
                return inserted ? ClaimResult.claimed(refreshed) : ClaimResult.alreadyOwned(refreshed);
            } catch (Exception exception) {
                connection.rollback();
                return ClaimResult.error(exception.getMessage());
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException exception) {
            return ClaimResult.error(exception.getMessage());
        }
    }

    private boolean sameBedrockOwner(IdentityRecord owner, String uuid, String xuid) {
        boolean storedUuid = owner.uuid() != null && !owner.uuid().isBlank();
        boolean storedXuid = owner.xuid() != null && !owner.xuid().isBlank();
        boolean incomingUuid = uuid != null && !uuid.isBlank();
        boolean incomingXuid = xuid != null && !xuid.isBlank();

        // Si cualquiera de los identificadores fuertes coincide, es la misma cuenta Xbox.
        // Esto tambien permite reparar un XUID viejo/mal importado usando el UUID verificado actual.
        if (storedUuid && incomingUuid && owner.uuid().equalsIgnoreCase(uuid)) {
            return true;
        }
        if (storedXuid && incomingXuid && owner.xuid().equals(xuid)) {
            return true;
        }

        // Si disponemos de identificadores por ambos lados y ninguno coincide, es otra cuenta.
        if ((storedUuid || storedXuid) && (incomingUuid || incomingXuid)) {
            return false;
        }

        // Registro historico sin IDs suficientes: la primera conexion Floodgate verificada lo vincula.
        return true;
    }

    private boolean isFloodgateUuid(String uuid) {
        try {
            return FloodgateIdentityUtil.looksLikeFloodgateUuid(java.util.UUID.fromString(uuid));
        } catch (Exception ignored) {
            return false;
        }
    }

    private void reclassifyJavaToBedrock(Connection connection, String key, String displayName,
                                          String uuid, String xuid, long now, String source) throws SQLException {
        String sql = """
                UPDATE identities
                SET display_name = ?,
                    platform = 'BEDROCK',
                    uuid = ?,
                    xuid = ?,
                    java_type = NULL,
                    source = ?,
                    last_seen_at = ?
                WHERE name_key = ? AND platform = 'JAVA'
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, displayName);
            nullable(statement, 2, uuid);
            nullable(statement, 3, xuid);
            statement.setString(4, source);
            statement.setLong(5, now);
            statement.setString(6, key);
            statement.executeUpdate();
        }
    }

    private boolean insertIfAbsent(Connection connection, IdentityRecord record) throws SQLException {
        String sql = """
                INSERT OR IGNORE INTO identities
                (name_key, display_name, platform, uuid, xuid, java_type, first_registered_at, source, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, record.nameKey());
            statement.setString(2, record.displayName());
            statement.setString(3, record.platform().name());
            nullable(statement, 4, record.uuid());
            nullable(statement, 5, record.xuid());
            nullable(statement, 6, record.javaType() == null ? null : record.javaType().name());
            statement.setLong(7, record.firstRegisteredAt());
            statement.setString(8, record.source());
            statement.setLong(9, System.currentTimeMillis());
            return statement.executeUpdate() > 0;
        }
    }

    private void updateBedrockIdentifiers(Connection connection, String key, String uuid, String xuid,
                                           String displayName, long lastSeenAt) throws SQLException {
        String sql = """
                UPDATE identities
                SET display_name = ?,
                    uuid = CASE WHEN ? IS NULL THEN uuid ELSE ? END,
                    xuid = CASE WHEN ? IS NULL THEN xuid ELSE ? END,
                    last_seen_at = ?
                WHERE name_key = ? AND platform = 'BEDROCK'
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, displayName);
            nullable(statement, 2, uuid);
            nullable(statement, 3, uuid);
            nullable(statement, 4, xuid);
            nullable(statement, 5, xuid);
            statement.setLong(6, lastSeenAt);
            statement.setString(7, key);
            statement.executeUpdate();
        }
    }

    private void updateJavaIdentifiers(Connection connection, String key, String uuid, JavaType javaType,
                                       String displayName, long lastSeenAt) throws SQLException {
        String sql = """
                UPDATE identities
                SET display_name = ?,
                    uuid = COALESCE(uuid, ?),
                    java_type = CASE
                        WHEN java_type = 'PREMIUM' THEN java_type
                        WHEN ? = 'PREMIUM' THEN 'PREMIUM'
                        WHEN java_type IS NULL THEN ?
                        ELSE java_type
                    END,
                    last_seen_at = ?
                WHERE name_key = ? AND platform = 'JAVA'
                """;
        String type = (javaType == null ? JavaType.UNKNOWN : javaType).name();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, displayName);
            nullable(statement, 2, uuid);
            statement.setString(3, type);
            statement.setString(4, type);
            statement.setLong(5, lastSeenAt);
            statement.setString(6, key);
            statement.executeUpdate();
        }
    }

    private Optional<IdentityRecord> findByName(Connection connection, String key) throws SQLException {
        String sql = """
                SELECT name_key, display_name, platform, uuid, xuid, java_type,
                       first_registered_at, source
                FROM identities
                WHERE name_key = ?
                LIMIT 1
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, key);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.of(readIdentity(resultSet));
                }
            }
        }
        return Optional.empty();
    }

    private IdentityRecord readIdentity(ResultSet resultSet) throws SQLException {
        String javaTypeRaw = resultSet.getString("java_type");
        JavaType javaType = javaTypeRaw == null ? null : safeJavaType(javaTypeRaw);
        return new IdentityRecord(
                resultSet.getString("name_key"),
                resultSet.getString("display_name"),
                PlatformType.valueOf(resultSet.getString("platform")),
                resultSet.getString("uuid"),
                resultSet.getString("xuid"),
                javaType,
                resultSet.getLong("first_registered_at"),
                resultSet.getString("source")
        );
    }

    private JavaType safeJavaType(String raw) {
        try {
            return JavaType.valueOf(raw);
        } catch (IllegalArgumentException exception) {
            return JavaType.UNKNOWN;
        }
    }

    public ImportSummary importRecords(List<ImportIdentity> records) throws SQLException {
        List<ImportIdentity> sorted = new ArrayList<>(records);
        sorted.sort((a, b) -> {
            int time = Long.compare(a.registeredAt(), b.registeredAt());
            if (time != 0) return time;
            int name = a.nameKey().compareTo(b.nameKey());
            if (name != 0) return name;
            return a.platform().compareTo(b.platform());
        });

        int inserted = 0;
        int updated = 0;
        int conflicts = 0;
        int skipped = 0;

        try (Connection connection = open()) {
            connection.setAutoCommit(false);
            try {
                for (ImportIdentity incoming : sorted) {
                    if (incoming.nameKey() == null || incoming.nameKey().isBlank()) {
                        skipped++;
                        continue;
                    }

                    Optional<IdentityRecord> existingOptional = findByName(connection, incoming.nameKey());
                    if (existingOptional.isEmpty()) {
                        insertImported(connection, incoming);
                        inserted++;
                        continue;
                    }

                    IdentityRecord existing = existingOptional.get();
                    if (existing.platform() == incoming.platform()) {
                        mergeImportedSamePlatform(connection, existing, incoming);
                        updated++;
                        continue;
                    }

                    // El registro mas antiguo gana. Si empatan, conserva el ya existente.
                    if (incoming.registeredAt() < existing.firstRegisteredAt()) {
                        recordConflict(connection, incoming, existing, "nlogin-import-replaced-newer-owner");
                        replaceIdentity(connection, incoming);
                    } else {
                        recordConflict(connection, existing, incoming, "nlogin-import-conflict");
                    }
                    conflicts++;
                }

                connection.commit();
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            } finally {
                connection.setAutoCommit(true);
            }
        }

        return new ImportSummary(sorted.size(), inserted, updated, conflicts, skipped);
    }

    private void insertImported(Connection connection, ImportIdentity incoming) throws SQLException {
        String sql = """
                INSERT INTO identities
                (name_key, display_name, platform, uuid, xuid, java_type, first_registered_at, source, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, incoming.nameKey());
            statement.setString(2, incoming.displayName());
            statement.setString(3, incoming.platform().name());
            nullable(statement, 4, incoming.uuid());
            nullable(statement, 5, incoming.xuid());
            nullable(statement, 6, incoming.javaType() == null ? null : incoming.javaType().name());
            statement.setLong(7, incoming.registeredAt());
            statement.setString(8, incoming.source());
            statement.executeUpdate();
        }
    }

    private void mergeImportedSamePlatform(Connection connection, IdentityRecord existing,
                                           ImportIdentity incoming) throws SQLException {
        long oldest = Math.min(existing.firstRegisteredAt(), incoming.registeredAt());
        String sql = """
                UPDATE identities
                SET uuid = COALESCE(uuid, ?),
                    xuid = COALESCE(xuid, ?),
                    java_type = CASE
                        WHEN java_type = 'PREMIUM' THEN java_type
                        WHEN ? = 'PREMIUM' THEN 'PREMIUM'
                        WHEN java_type IS NULL THEN ?
                        ELSE java_type
                    END,
                    first_registered_at = ?,
                    source = CASE WHEN ? < first_registered_at THEN ? ELSE source END
                WHERE name_key = ?
                """;
        String incomingType = incoming.javaType() == null ? JavaType.UNKNOWN.name() : incoming.javaType().name();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            nullable(statement, 1, incoming.uuid());
            nullable(statement, 2, incoming.xuid());
            statement.setString(3, incomingType);
            statement.setString(4, incomingType);
            statement.setLong(5, oldest);
            statement.setLong(6, incoming.registeredAt());
            statement.setString(7, incoming.source());
            statement.setString(8, incoming.nameKey());
            statement.executeUpdate();
        }
    }

    private void replaceIdentity(Connection connection, ImportIdentity incoming) throws SQLException {
        try (PreparedStatement delete = connection.prepareStatement("DELETE FROM identities WHERE name_key = ?")) {
            delete.setString(1, incoming.nameKey());
            delete.executeUpdate();
        }
        insertImported(connection, incoming);
    }

    private void recordConflict(Connection connection, ImportIdentity winner, IdentityRecord loser,
                                String source) throws SQLException {
        recordConflict(connection,
                winner.displayName(), winner.platform(), winner.uuid(),
                loser.displayName(), loser.platform(), loser.uuid(),
                winner.nameKey(), source);
    }

    private void recordConflict(Connection connection, IdentityRecord winner, ImportIdentity loser,
                                String source) throws SQLException {
        recordConflict(connection,
                winner.displayName(), winner.platform(), winner.uuid(),
                loser.displayName(), loser.platform(), loser.uuid(),
                winner.nameKey(), source);
    }

    private void recordConflict(Connection connection, String winnerName, PlatformType winnerPlatform,
                                String winnerUuid, String loserName, PlatformType loserPlatform,
                                String loserUuid, String nameKey, String source) throws SQLException {
        String sql = """
                INSERT INTO conflicts
                (name_key, winner_name, winner_platform, winner_uuid,
                 loser_name, loser_platform, loser_uuid, detected_at, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, nameKey);
            statement.setString(2, winnerName);
            statement.setString(3, winnerPlatform.name());
            nullable(statement, 4, winnerUuid);
            statement.setString(5, loserName);
            statement.setString(6, loserPlatform.name());
            nullable(statement, 7, loserUuid);
            statement.setLong(8, System.currentTimeMillis());
            statement.setString(9, source);
            statement.executeUpdate();
        }
    }

    public boolean isMetaTrue(String key) {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT meta_value FROM meta WHERE meta_key = ? LIMIT 1")) {
            statement.setString(1, key);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() && Boolean.parseBoolean(resultSet.getString(1));
            }
        } catch (SQLException ignored) {
            return false;
        }
    }

    public void setMeta(String key, String value) throws SQLException {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO meta(meta_key, meta_value) VALUES(?, ?)
                     ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value
                     """)) {
            statement.setString(1, key);
            statement.setString(2, value);
            statement.executeUpdate();
        }
    }

    public int countIdentities() {
        return scalarInt("SELECT COUNT(*) FROM identities");
    }

    public int countByPlatform(PlatformType platform) {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM identities WHERE platform = ?")) {
            statement.setString(1, platform.name());
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getInt(1) : 0;
            }
        } catch (SQLException exception) {
            return 0;
        }
    }

    public int countConflicts() {
        return scalarInt("SELECT COUNT(*) FROM conflicts");
    }

    private int scalarInt(String sql) {
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            return resultSet.next() ? resultSet.getInt(1) : 0;
        } catch (SQLException exception) {
            return 0;
        }
    }

    public List<String[]> listConflicts(int limit) {
        List<String[]> rows = new ArrayList<>();
        String sql = """
                SELECT name_key, winner_name, winner_platform, loser_name, loser_platform, detected_at
                FROM conflicts
                ORDER BY id DESC
                LIMIT ?
                """;
        try (Connection connection = open(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, Math.max(1, limit));
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    rows.add(new String[]{
                            resultSet.getString("name_key"),
                            resultSet.getString("winner_name"),
                            resultSet.getString("winner_platform"),
                            resultSet.getString("loser_name"),
                            resultSet.getString("loser_platform"),
                            Long.toString(resultSet.getLong("detected_at"))
                    });
                }
            }
        } catch (SQLException ignored) {
        }
        return rows;
    }

    public boolean release(String name) throws SQLException {
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM identities WHERE name_key = ?")) {
            statement.setString(1, normalizeName(name));
            return statement.executeUpdate() > 0;
        }
    }

    private static void nullable(PreparedStatement statement, int index, String value) throws SQLException {
        if (value == null || value.isBlank()) {
            statement.setNull(index, Types.VARCHAR);
        } else {
            statement.setString(index, value);
        }
    }
}
