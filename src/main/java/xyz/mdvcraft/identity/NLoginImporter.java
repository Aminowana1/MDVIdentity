package xyz.mdvcraft.identity;

import com.nickuc.login.api.nLoginAPI;
import com.nickuc.login.api.types.AccountData;
import xyz.mdvcraft.identity.db.IdentityDatabase;
import xyz.mdvcraft.identity.model.ImportIdentity;
import xyz.mdvcraft.identity.model.ImportSummary;
import xyz.mdvcraft.identity.model.JavaType;
import xyz.mdvcraft.identity.model.PlatformType;

import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

public final class NLoginImporter {
    private final MDVIdentityPlugin plugin;
    private final IdentityDatabase database;
    private final nLoginAPI nLogin;

    public NLoginImporter(MDVIdentityPlugin plugin, IdentityDatabase database, nLoginAPI nLogin) {
        this.plugin = plugin;
        this.database = database;
        this.nLogin = nLogin;
    }

    public ImportSummary importExistingAccounts() throws SQLException {
        String legacyPrefix = plugin.getConfig().getString("migration.legacy-bedrock-prefix", "_");
        List<ImportIdentity> records = new ArrayList<>();

        Iterator<AccountData> iterator = nLogin.getAccounts();
        while (iterator.hasNext()) {
            AccountData account = iterator.next();
            if (account == null) {
                continue;
            }

            String lastName = account.getLastName();
            if (lastName == null || lastName.isBlank()) {
                continue;
            }

            long createdAt = instantToMillis(account.getCreationDate());
            if (createdAt <= 0L) {
                createdAt = System.currentTimeMillis();
            }

            if (account.getBedrockId().isPresent()) {
                UUID bedrockId = account.getBedrockId().orElse(null);
                String cleanName = stripLegacyBedrockPrefix(lastName, legacyPrefix);
                records.add(new ImportIdentity(
                        IdentityDatabase.normalizeName(cleanName),
                        cleanName,
                        PlatformType.BEDROCK,
                        bedrockId == null ? null : bedrockId.toString(),
                        null,
                        null,
                        createdAt,
                        "nlogin-import"
                ));
                continue;
            }

            UUID mojangId = account.getMojangId().orElse(null);
            UUID uniqueId = account.getUniqueId().orElse(null);
            JavaType javaType = mojangId != null ? JavaType.PREMIUM : JavaType.OFFLINE;
            UUID storedUuid = mojangId != null ? mojangId : uniqueId;

            records.add(new ImportIdentity(
                    IdentityDatabase.normalizeName(lastName),
                    lastName,
                    PlatformType.JAVA,
                    storedUuid == null ? null : storedUuid.toString(),
                    null,
                    javaType,
                    createdAt,
                    "nlogin-import"
            ));
        }

        return database.importRecords(records);
    }

    private static String stripLegacyBedrockPrefix(String name, String legacyPrefix) {
        if (legacyPrefix == null || legacyPrefix.isEmpty()) {
            return name;
        }
        return name.startsWith(legacyPrefix) && name.length() > legacyPrefix.length()
                ? name.substring(legacyPrefix.length())
                : name;
    }

    private static long instantToMillis(Instant instant) {
        return instant == null ? 0L : instant.toEpochMilli();
    }
}
