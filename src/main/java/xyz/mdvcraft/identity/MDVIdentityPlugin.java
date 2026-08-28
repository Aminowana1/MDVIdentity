package xyz.mdvcraft.identity;

import com.nickuc.login.api.nLoginAPI;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;
import org.geysermc.floodgate.api.FloodgateApi;
import xyz.mdvcraft.identity.command.IdentityCommand;
import xyz.mdvcraft.identity.db.IdentityDatabase;
import xyz.mdvcraft.identity.listener.IdentityListener;
import xyz.mdvcraft.identity.model.ImportSummary;
import xyz.mdvcraft.identity.model.PlatformType;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

public final class MDVIdentityPlugin extends JavaPlugin {
    private static final String IMPORT_META_KEY = "nlogin_initial_import_done";
    private static final String LEGACY_ALIAS_REPAIR_META_KEY = "legacy_bedrock_alias_repair_v1_done";

    private final AtomicBoolean ready = new AtomicBoolean(false);
    private IdentityDatabase database;
    private FloodgateApi floodgateApi;
    private nLoginAPI nLoginApi;
    private IdentityListener listener;

    @Override
    public void onEnable() {
        saveDefaultConfig();

        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException exception) {
            getLogger().severe("No se encontro el driver SQLite del servidor. MDVIdentity no puede iniciar.");
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }

        try {
            this.floodgateApi = FloodgateApi.getInstance();
            this.nLoginApi = nLoginAPI.getApi();
        } catch (Throwable throwable) {
            getLogger().log(Level.SEVERE, "No se pudo obtener Floodgate/nLogin API.", throwable);
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }

        String databaseName = getConfig().getString("storage.file", "identities.db");
        this.database = new IdentityDatabase(new File(getDataFolder(), databaseName));
        try {
            database.initialize();
        } catch (SQLException exception) {
            getLogger().log(Level.SEVERE, "No se pudo inicializar identities.db.", exception);
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }

        this.listener = new IdentityListener(this, database, floodgateApi, nLoginApi);
        Bukkit.getPluginManager().registerEvents(listener, this);

        IdentityCommand command = new IdentityCommand(this, database);
        if (getCommand("mdvidentity") != null) {
            getCommand("mdvidentity").setExecutor(command);
            getCommand("mdvidentity").setTabCompleter(command);
        }

        // nLogin suele estar listo por depend:, pero damos un margen corto si su API aun esta arrancando.
        tryFinishStartup(0);
    }

    private void tryFinishStartup(int attempt) {
        if (!isEnabled()) {
            return;
        }

        boolean available;
        try {
            available = nLoginApi != null && nLoginApi.isAvailable();
        } catch (Throwable throwable) {
            available = false;
        }

        if (!available) {
            if (attempt >= 100) {
                getLogger().severe("nLogin API no quedo disponible. Se deshabilita MDVIdentity por seguridad.");
                Bukkit.getPluginManager().disablePlugin(this);
                return;
            }
            Bukkit.getScheduler().runTaskLater(this, () -> tryFinishStartup(attempt + 1), 1L);
            return;
        }

        try {
            runInitialImportIfNeeded();
            runVerifiedLegacyAliasRepairIfNeeded();
            ready.set(true);
            printStatus();
        } catch (Throwable throwable) {
            getLogger().log(Level.SEVERE, "Fallo la importacion inicial. MDVIdentity NO abrira el acceso para evitar robar nombres.", throwable);
            ready.set(false);
        }
    }

    private void runInitialImportIfNeeded() throws SQLException {
        boolean enabled = getConfig().getBoolean("migration.import-existing-nlogin-on-first-start", false);
        if (!enabled || database.isMetaTrue(IMPORT_META_KEY)) {
            return;
        }

        getLogger().info("Importando cuentas existentes de nLogin antes de habilitar el acceso...");
        NLoginImporter importer = new NLoginImporter(this, database, nLoginApi);
        ImportSummary summary = importer.importExistingAccounts();
        database.setMeta(IMPORT_META_KEY, "true");

        getLogger().info("Importacion nLogin: total=" + summary.total()
                + ", nuevas=" + summary.inserted()
                + ", actualizadas=" + summary.updated()
                + ", conflictos=" + summary.conflicts()
                + ", omitidas=" + summary.skipped());

        if (getConfig().getBoolean("migration.write-conflicts-yml", true)) {
            writeConflictReport();
        }
    }

    private void runVerifiedLegacyAliasRepairIfNeeded() throws SQLException {
        if (!getConfig().getBoolean("migration.repair-verified-legacy-bedrock-aliases", false)
                || database.isMetaTrue(LEGACY_ALIAS_REPAIR_META_KEY)) {
            return;
        }

        NLoginImporter importer = new NLoginImporter(this, database, nLoginApi);
        int repaired = importer.repairVerifiedLegacyBedrockAliases();
        database.setMeta(LEGACY_ALIAS_REPAIR_META_KEY, "true");

        if (repaired > 0) {
            getLogger().warning("Se repararon " + repaired
                    + " identidades Bedrock historicas mal clasificadas como Java por la migracion 1.0.0.");
            if (getConfig().getBoolean("migration.write-conflicts-yml", true)) {
                writeConflictReport();
            }
        } else {
            getLogger().info("Reparacion de aliases Bedrock historicos: no se encontraron casos verificables.");
        }
    }

    public ImportSummary forceImport() throws SQLException {
        NLoginImporter importer = new NLoginImporter(this, database, nLoginApi);
        ImportSummary summary = importer.importExistingAccounts();
        database.setMeta(IMPORT_META_KEY, "true");
        if (getConfig().getBoolean("migration.write-conflicts-yml", true)) {
            writeConflictReport();
        }
        return summary;
    }

    public void writeConflictReport() {
        List<String[]> conflicts = database.listConflicts(1000);
        File file = new File(getDataFolder(), "conflicts.yml");
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.set("generated-at", Instant.now().toString());
        yaml.set("count", conflicts.size());

        int index = 0;
        for (String[] row : conflicts) {
            String path = "conflicts." + index++;
            yaml.set(path + ".name-key", row[0]);
            yaml.set(path + ".winner.name", row[1]);
            yaml.set(path + ".winner.platform", row[2]);
            yaml.set(path + ".loser.name", row[3]);
            yaml.set(path + ".loser.platform", row[4]);
            long time = Long.parseLong(row[5]);
            yaml.set(path + ".detected-at", DateTimeFormatter.ISO_OFFSET_DATE_TIME
                    .format(Instant.ofEpochMilli(time).atZone(ZoneId.systemDefault())));
        }

        try {
            yaml.save(file);
        } catch (IOException exception) {
            getLogger().log(Level.WARNING, "No se pudo escribir conflicts.yml", exception);
        }
    }

    public void printStatus() {
        String prefix;
        try {
            prefix = floodgateApi.getPlayerPrefix();
        } catch (Throwable throwable) {
            prefix = "?";
        }

        getLogger().info("MDVIdentity listo. Identidades=" + database.countIdentities()
                + " (JAVA=" + database.countByPlatform(PlatformType.JAVA)
                + ", BEDROCK=" + database.countByPlatform(PlatformType.BEDROCK)
                + "), conflictos=" + database.countConflicts());
        getLogger().info("Floodgate username-prefix actual: \"" + prefix + "\"");
        if (prefix != null && !prefix.isEmpty()) {
            getLogger().warning("La proteccion ya funciona, pero Bedrock aun tiene prefijo. Para modo final usa username-prefix: \"\" en Floodgate y reinicia.");
        } else {
            getLogger().info("Floodgate sin prefijo: MDVIdentity controlara las colisiones Java/Bedrock.");
        }
        getLogger().warning("IMPORTANTE: usa autologin.bedrock.enable=false en nLogin. MDVIdentity hace el autologin Bedrock por API; dejarlo en true puede abrir el formulario de contrasena.");
    }

    public boolean isReady() {
        return ready.get();
    }

    public IdentityDatabase database() {
        return database;
    }

    public FloodgateApi floodgateApi() {
        return floodgateApi;
    }

    public nLoginAPI nLoginApi() {
        return nLoginApi;
    }

    public String message(String path) {
        String prefix = getConfig().getString("messages.prefix", "");
        String body = getConfig().getString("messages." + path, path);
        return color(prefix + body);
    }

    public String message(String path, String name) {
        return message(path).replace("{name}", name == null ? "?" : name);
    }

    @SuppressWarnings("deprecation")
    private String color(String value) {
        return org.bukkit.ChatColor.translateAlternateColorCodes('&', value == null ? "" : value);
    }
}
