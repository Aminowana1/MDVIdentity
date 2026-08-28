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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
        List<RawAccount> snapshot = snapshotAccounts();
        Map<String, VerifiedLegacyAlias> verifiedAliases = findVerifiedLegacyAliases(snapshot, legacyPrefix);
        Set<RawAccount> staleJavaAliases = new HashSet<>();
        for (VerifiedLegacyAlias alias : verifiedAliases.values()) {
            staleJavaAliases.add(alias.staleJavaAccount());
        }

        List<ImportIdentity> records = new ArrayList<>();
        for (RawAccount account : snapshot) {
            if (account.lastName() == null || account.lastName().isBlank()) {
                continue;
            }

            UUID verifiedBedrockUuid = account.bedrockId();
            boolean inferredFromFloodgateUuid = false;

            // nLogin puede haber guardado una conexion Bedrock antigua sin bedrock_id cuando
            // Floodgate usaba prefijo vacio. Floodgate usa UUIDs con el formato documentado
            // 00000000-0000-0000-xxxx-xxxxxxxxxxxx. Un UUID Java premium/offline normal no usa
            // ese formato, por lo que podemos recuperar estas cuentas sin marcarlas como JAVA.
            if (verifiedBedrockUuid == null
                    && account.mojangId() == null
                    && FloodgateIdentityUtil.looksLikeFloodgateUuid(account.uniqueId())) {
                verifiedBedrockUuid = account.uniqueId();
                inferredFromFloodgateUuid = true;
            }

            if (verifiedBedrockUuid != null) {
                String cleanName = stripLegacyBedrockPrefix(account.lastName(), legacyPrefix);
                long registeredAt = account.createdAt();
                VerifiedLegacyAlias alias = verifiedAliases.get(IdentityDatabase.normalizeName(cleanName));
                if (alias != null && alias.bedrockAccount().equals(account)) {
                    // Conserva la fecha mas antigua del MISMO jugador, aunque nLogin lo haya guardado
                    // primero como cuenta sin-prefijo y luego como cuenta Bedrock con prefijo.
                    registeredAt = Math.min(registeredAt, alias.staleJavaAccount().createdAt());
                }

                String xuid = FloodgateIdentityUtil.xuidFromFloodgateUuid(verifiedBedrockUuid);
                records.add(new ImportIdentity(
                        IdentityDatabase.normalizeName(cleanName),
                        cleanName,
                        PlatformType.BEDROCK,
                        verifiedBedrockUuid.toString(),
                        xuid,
                        null,
                        registeredAt,
                        inferredFromFloodgateUuid ? "nlogin-import-floodgate-uuid" : "nlogin-import"
                ));
                continue;
            }

            // Si existe una cuenta _Nombre confirmada como Bedrock y la cuenta Nombre sin prefijo
            // comparte exactamente el UUID, esta entrada JAVA es un residuo de cuando nLogin no
            // reconocia Floodgate sin prefijo. No debe competir contra su propia cuenta Bedrock.
            if (staleJavaAliases.contains(account)) {
                continue;
            }

            JavaType javaType = account.mojangId() != null ? JavaType.PREMIUM : JavaType.OFFLINE;
            UUID storedUuid = account.mojangId() != null ? account.mojangId() : account.uniqueId();

            records.add(new ImportIdentity(
                    IdentityDatabase.normalizeName(account.lastName()),
                    account.lastName(),
                    PlatformType.JAVA,
                    storedUuid == null ? null : storedUuid.toString(),
                    null,
                    javaType,
                    account.createdAt(),
                    "nlogin-import"
            ));
        }

        return database.importRecords(records);
    }

    /**
     * Repara bases identities.db creadas por MDVIdentity 1.0.0.
     * Solo reclasifica JAVA -> BEDROCK cuando nLogin aporta evidencia fuerte:
     * existe la cuenta Bedrock prefijada y la cuenta antigua sin prefijo comparte el mismo UUID.
     * Nunca pisa un Java real solo porque el nombre coincida.
     */
    public int repairVerifiedLegacyBedrockAliases() throws SQLException {
        String legacyPrefix = plugin.getConfig().getString("migration.legacy-bedrock-prefix", "_");
        List<RawAccount> snapshot = snapshotAccounts();
        Map<String, VerifiedLegacyAlias> aliases = findVerifiedLegacyAliases(snapshot, legacyPrefix);

        int repaired = 0;
        for (VerifiedLegacyAlias alias : aliases.values()) {
            UUID staleUuid = alias.staleJavaAccount().uniqueId();
            UUID bedrockUuid = alias.bedrockAccount().bedrockId();
            if (bedrockUuid == null && alias.bedrockAccount().mojangId() == null
                    && FloodgateIdentityUtil.looksLikeFloodgateUuid(alias.bedrockAccount().uniqueId())) {
                bedrockUuid = alias.bedrockAccount().uniqueId();
            }
            if (staleUuid == null || bedrockUuid == null) {
                continue;
            }

            long oldest = Math.min(alias.staleJavaAccount().createdAt(), alias.bedrockAccount().createdAt());
            if (database.reclassifyVerifiedLegacyJavaAsBedrock(
                    alias.cleanName(),
                    staleUuid.toString(),
                    bedrockUuid.toString(),
                    oldest,
                    "legacy-bedrock-alias-repair-v1")) {
                repaired++;
                plugin.getLogger().info("Reparada identidad Bedrock historica: " + alias.cleanName()
                        + " (nLogin la habia clasificado antes como Java sin prefijo).");
            }
        }
        return repaired;
    }

    private List<RawAccount> snapshotAccounts() {
        List<RawAccount> snapshot = new ArrayList<>();
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

            snapshot.add(new RawAccount(
                    lastName,
                    createdAt,
                    account.getBedrockId().orElse(null),
                    account.getUniqueId().orElse(null),
                    account.getMojangId().orElse(null)
            ));
        }
        return snapshot;
    }

    private Map<String, VerifiedLegacyAlias> findVerifiedLegacyAliases(List<RawAccount> accounts,
                                                                        String legacyPrefix) {
        Map<String, List<RawAccount>> byName = new HashMap<>();
        for (RawAccount account : accounts) {
            byName.computeIfAbsent(IdentityDatabase.normalizeName(account.lastName()), k -> new ArrayList<>())
                    .add(account);
        }

        Map<String, VerifiedLegacyAlias> result = new HashMap<>();
        if (legacyPrefix == null || legacyPrefix.isEmpty()) {
            return result;
        }

        for (RawAccount bedrock : accounts) {
            UUID bedrockUuid = bedrock.bedrockId();
            if (bedrockUuid == null && bedrock.mojangId() == null
                    && FloodgateIdentityUtil.looksLikeFloodgateUuid(bedrock.uniqueId())) {
                bedrockUuid = bedrock.uniqueId();
            }

            if (bedrockUuid == null || !bedrock.lastName().startsWith(legacyPrefix)
                    || bedrock.lastName().length() <= legacyPrefix.length()) {
                continue;
            }

            String cleanName = stripLegacyBedrockPrefix(bedrock.lastName(), legacyPrefix);
            String cleanKey = IdentityDatabase.normalizeName(cleanName);
            List<RawAccount> candidates = byName.get(cleanKey);
            if (candidates == null) {
                continue;
            }

            for (RawAccount javaAlias : candidates) {
                if (javaAlias.bedrockId() != null || javaAlias.mojangId() != null || javaAlias.uniqueId() == null) {
                    continue;
                }

                if (sameUuid(javaAlias.uniqueId(), bedrockUuid)
                        || sameUuid(javaAlias.uniqueId(), bedrock.uniqueId())) {
                    result.put(cleanKey, new VerifiedLegacyAlias(cleanName, javaAlias, bedrock));
                    break;
                }
            }
        }

        return result;
    }

    private static boolean sameUuid(UUID a, UUID b) {
        return a != null && b != null && a.equals(b);
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

    private record RawAccount(String lastName, long createdAt, UUID bedrockId, UUID uniqueId, UUID mojangId) {}

    private record VerifiedLegacyAlias(String cleanName, RawAccount staleJavaAccount, RawAccount bedrockAccount) {}
}
