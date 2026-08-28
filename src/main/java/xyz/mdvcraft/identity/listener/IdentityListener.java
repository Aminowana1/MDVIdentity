package xyz.mdvcraft.identity.listener;

import com.nickuc.login.api.nLoginAPI;
import com.nickuc.login.api.event.bukkit.auth.AuthenticateEvent;
import com.nickuc.login.api.event.bukkit.auth.PremiumLoginEvent;
import com.nickuc.login.api.event.bukkit.auth.RegisterEvent;
import com.nickuc.login.api.types.AccountData;
import com.nickuc.login.api.types.Identity;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.geysermc.floodgate.api.FloodgateApi;
import org.geysermc.floodgate.api.player.FloodgatePlayer;
import xyz.mdvcraft.identity.FloodgateIdentityUtil;
import xyz.mdvcraft.identity.MDVIdentityPlugin;
import xyz.mdvcraft.identity.db.IdentityDatabase;
import xyz.mdvcraft.identity.model.*;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

public final class IdentityListener implements Listener {
    private static final char[] PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();

    private final MDVIdentityPlugin plugin;
    private final IdentityDatabase database;
    private final FloodgateApi floodgate;
    private final nLoginAPI nLogin;
    private final SecureRandom random = new SecureRandom();

    public IdentityListener(MDVIdentityPlugin plugin, IdentityDatabase database,
                            FloodgateApi floodgate, nLoginAPI nLogin) {
        this.plugin = plugin;
        this.database = database;
        this.floodgate = floodgate;
        this.nLogin = nLogin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!plugin.isReady()) {
            if (plugin.getConfig().getBoolean("security.deny-logins-until-ready", true)) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
            }
            return;
        }

        UUID uuid = event.getUniqueId();
        boolean bedrock;
        try {
            bedrock = floodgate.isFloodgatePlayer(uuid) || floodgate.getPlayer(uuid) != null;
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING, "No se pudo consultar Floodgate para " + event.getName(), throwable);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
            return;
        }

        if (bedrock) {
            handleBedrockPreLogin(event, uuid);
        } else if (FloodgateIdentityUtil.looksLikeFloodgateUuid(uuid)) {
            // Nunca dejamos que un UUID con formato Floodgate caiga por accidente en la rama JAVA.
            // Si Floodgate aun no expuso el jugador, es mas seguro pedir reintento que clasificarlo mal.
            plugin.getLogger().warning("UUID con formato Floodgate todavia no disponible en API para " + event.getName());
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
        } else {
            handleJavaPreLogin(event);
        }
    }

    private void handleBedrockPreLogin(AsyncPlayerPreLoginEvent event, UUID uuid) {
        FloodgatePlayer floodgatePlayer = floodgate.getPlayer(uuid);
        if (floodgatePlayer == null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
            return;
        }

        String cleanName = cleanBedrockServerName(floodgatePlayer, event.getName());
        String xuid = floodgatePlayer.getXuid();
        boolean strict = plugin.getConfig().getBoolean("security.strict-bedrock-owner-check", true);

        ClaimResult claim = database.claimBedrock(
                cleanName,
                uuid.toString(),
                xuid,
                strict,
                "bedrock-prelogin"
        );

        if (claim.allowed()) {
            if (claim.status() == ClaimStatus.CLAIMED) {
                plugin.getLogger().info("Identidad reservada: " + cleanName + " -> BEDROCK (" + uuid + ")");
            }
            return;
        }

        if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
            // Antes de expulsar, intentamos reparar SOLO si nLogin demuestra que el registro JAVA
            // historico y la conexion Floodgate actual son realmente la misma identidad.
            if (plugin.getConfig().getBoolean("security.runtime-repair-verified-bedrock", true)
                    && claim.owner() != null
                    && repairVerifiedBedrockMisclassification(cleanName, uuid, xuid, claim.owner())) {
                ClaimResult repairedClaim = database.claimBedrock(
                        cleanName, uuid.toString(), xuid, strict, "bedrock-prelogin-after-repair");
                if (repairedClaim.allowed()) {
                    return;
                }
                claim = repairedClaim;
            }

            if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.message("bedrock-name-owned-by-java", cleanName));
                return;
            }
        }

        if (claim.status() == ClaimStatus.CONFLICT_BEDROCK_OWNER) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.message("bedrock-name-owned-by-other-xbox", cleanName));
            return;
        }

        plugin.getLogger().warning("Error reservando identidad Bedrock " + cleanName + ": " + claim.error());
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
    }

    private boolean repairVerifiedBedrockMisclassification(String cleanName, UUID currentUuid,
                                                          String xuid, IdentityRecord owner) {
        if (owner.platform() != PlatformType.JAVA || owner.uuid() == null || owner.uuid().isBlank()) {
            return false;
        }

        try {
            Identity currentIdentity = Identity.ofBedrock(cleanName, currentUuid);
            Optional<AccountData> account = nLogin.getAccount(currentIdentity);

            if (account.isEmpty()) {
                String legacyPrefix = plugin.getConfig().getString("migration.legacy-bedrock-prefix", "_");
                if (legacyPrefix != null && !legacyPrefix.isEmpty()) {
                    account = nLogin.getAccount(Identity.ofBedrock(legacyPrefix + cleanName, currentUuid));
                }
            }

            if (account.isEmpty()) {
                return false;
            }

            AccountData data = account.get();
            UUID accountBedrock = data.getBedrockId().orElse(null);
            UUID accountUnique = data.getUniqueId().orElse(null);

            // Una cuenta Mojang real nunca se auto-reclasifica a Bedrock.
            if (data.getMojangId().isPresent()) {
                return false;
            }

            boolean currentMatchesAccount = currentUuid.equals(accountBedrock) || currentUuid.equals(accountUnique);
            boolean oldRowMatchesAccount = owner.uuid().equalsIgnoreCase(uuidText(accountBedrock))
                    || owner.uuid().equalsIgnoreCase(uuidText(accountUnique));

            if (!currentMatchesAccount || !oldRowMatchesAccount) {
                return false;
            }

            long registeredAt = owner.firstRegisteredAt();
            if (data.getCreationDate() != null) {
                registeredAt = Math.min(registeredAt, data.getCreationDate().toEpochMilli());
            }

            boolean repaired = database.reclassifyVerifiedLegacyJavaAsBedrock(
                    cleanName,
                    owner.uuid(),
                    currentUuid.toString(),
                    registeredAt,
                    "runtime-nlogin-floodgate-proof"
            );

            if (repaired) {
                plugin.getLogger().warning("Reparada en caliente identidad Bedrock mal clasificada: "
                        + cleanName + " (UUID Floodgate " + currentUuid + ")");
            }
            return repaired;
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING,
                    "No se pudo verificar reparacion Bedrock para " + cleanName, throwable);
            return false;
        }
    }

    private static String uuidText(UUID uuid) {
        return uuid == null ? "" : uuid.toString();
    }

    private void handleJavaPreLogin(AsyncPlayerPreLoginEvent event) {
        try {
            Optional<IdentityRecord> owner = database.findByNameStrict(event.getName());
            if (owner.isPresent() && owner.get().platform() == PlatformType.BEDROCK) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        plugin.message("java-name-owned-by-bedrock", event.getName()));
            }
        } catch (SQLException exception) {
            plugin.getLogger().log(Level.WARNING, "Fallo consultando identidad Java en pre-login: " + event.getName(), exception);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (!plugin.isReady() || !isBedrock(player)) {
            return;
        }

        if (!plugin.getConfig().getBoolean("bedrock-auth.enabled", true)) {
            return;
        }

        // 1.0.3: intentamos autenticar en el MISMO PlayerJoinEvent, antes de que nLogin
        // alcance a abrir su formulario Bedrock/generico. Los reintentos solo existen
        // para cubrir el pequeño margen en el que nLogin aun no haya terminado de crear
        // su estado interno para esa conexion.
        long delay = Math.max(0L, plugin.getConfig().getLong("bedrock-auth.delay-ticks", 0L));
        if (delay == 0L) {
            authenticateBedrock(player, 0);
        } else {
            Bukkit.getScheduler().runTaskLater(plugin, () -> authenticateBedrock(player, 0), delay);
        }
    }

    /**
     * nLogin 2.x puede no reconocer correctamente Bedrock cuando Floodgate usa prefijo vacio.
     *
     * MDVIdentity es la autoridad para decidir si ESTE nombre pertenece a ESTE UUID/XUID Bedrock.
     * Si la identidad ya esta en identities.db y coincide con Floodgate, se fuerza el login de
     * nLogin en cada conexion. Si la cuenta nLogin aun no existe, se crea una sola vez y acto
     * seguido se fuerza el login.
     */
    private void authenticateBedrock(Player player, int attempt) {
        if (!player.isOnline() || !isBedrock(player)) {
            return;
        }

        int maxAttempts = Math.max(1, plugin.getConfig().getInt("bedrock-auth.max-attempts", 20));
        if (attempt >= maxAttempts) {
            plugin.getLogger().warning("No se pudo completar el autologin Bedrock de "
                    + player.getName() + " tras " + maxAttempts + " intentos.");
            player.kickPlayer(plugin.message("bedrock-auth-failed"));
            return;
        }

        try {
            UUID uuid = player.getUniqueId();
            FloodgatePlayer floodgatePlayer = floodgate.getPlayer(uuid);
            String xuid = floodgatePlayer == null
                    ? FloodgateIdentityUtil.xuidFromFloodgateUuid(uuid)
                    : floodgatePlayer.getXuid();
            String cleanName = floodgatePlayer == null
                    ? player.getName()
                    : cleanBedrockServerName(floodgatePlayer, player.getName());

            // Revalidamos la propiedad del nombre justo antes de tocar nLogin. Esto evita que
            // "auto-login" se convierta en un bypass si identities.db no pertenece a esta Xbox.
            boolean strict = plugin.getConfig().getBoolean("security.strict-bedrock-owner-check", true);
            ClaimResult ownerClaim = database.claimBedrock(
                    cleanName,
                    uuid.toString(),
                    xuid,
                    strict,
                    "bedrock-join-auth"
            );

            if (!ownerClaim.allowed()) {
                if (ownerClaim.status() == ClaimStatus.CONFLICT_PLATFORM) {
                    player.kickPlayer(plugin.message("bedrock-name-owned-by-java", cleanName));
                } else if (ownerClaim.status() == ClaimStatus.CONFLICT_BEDROCK_OWNER) {
                    player.kickPlayer(plugin.message("bedrock-name-owned-by-other-xbox", cleanName));
                } else {
                    player.kickPlayer(plugin.message("bedrock-auth-failed"));
                }
                return;
            }

            Identity currentIdentity = Identity.ofBedrock(player.getName(), uuid);

            // Si nLogin ya quedo autenticado por cualquier motivo, terminamos.
            if (nLogin.isAuthenticated(currentIdentity) || nLogin.isAuthenticated(player.getName())) {
                return;
            }

            Identity identityToLogin = null;
            Optional<AccountData> account = nLogin.getAccount(currentIdentity);
            if (account.isPresent() && accountMatchesCurrentBedrock(account.get(), uuid)) {
                identityToLogin = currentIdentity;
            }

            // Con prefijo vacio algunas builds antiguas de nLogin pueden haber guardado la cuenta
            // por nombre conocido en vez de como Identity.ofBedrock. Solo aceptamos ese fallback
            // si sus IDs demuestran que es la misma conexion Floodgate; nunca por nombre solamente.
            Identity knownNameIdentity = Identity.ofKnownName(player.getName());
            if (identityToLogin == null) {
                Optional<AccountData> knownAccount = nLogin.getAccount(knownNameIdentity);
                if (knownAccount.isPresent()) {
                    if (knownAccount.get().getMojangId().isPresent()) {
                        plugin.getLogger().warning("Conflicto nLogin: " + player.getName()
                                + " tiene cuenta Mojang pero identities.db lo identifica como Bedrock.");
                        player.kickPlayer(plugin.message("bedrock-name-owned-by-java", cleanName));
                        return;
                    }

                    if (accountMatchesCurrentBedrock(knownAccount.get(), uuid)) {
                        account = knownAccount;
                        identityToLogin = knownNameIdentity;
                    }
                }
            }

            // Compatibilidad con la etapa en la que Floodgate usaba "_".
            if (identityToLogin == null) {
                String legacyPrefix = plugin.getConfig().getString("migration.legacy-bedrock-prefix", "_");
                if (legacyPrefix != null && !legacyPrefix.isEmpty() && !player.getName().startsWith(legacyPrefix)) {
                    String legacyName = legacyPrefix + player.getName();

                    Identity legacyBedrockIdentity = Identity.ofBedrock(legacyName, uuid);
                    Optional<AccountData> legacyAccount = nLogin.getAccount(legacyBedrockIdentity);
                    if (legacyAccount.isPresent() && accountMatchesCurrentBedrock(legacyAccount.get(), uuid)) {
                        account = legacyAccount;
                        identityToLogin = legacyBedrockIdentity;
                    } else {
                        Identity legacyKnownIdentity = Identity.ofKnownName(legacyName);
                        legacyAccount = nLogin.getAccount(legacyKnownIdentity);
                        if (legacyAccount.isPresent() && accountMatchesCurrentBedrock(legacyAccount.get(), uuid)) {
                            account = legacyAccount;
                            identityToLogin = legacyKnownIdentity;
                        }
                    }
                }
            }

            // Primera vez real en nLogin: la identidad ya fue autorizada/reservada por MDVIdentity,
            // asi que generamos una password interna que el jugador Bedrock nunca ve ni necesita.
            if (identityToLogin == null) {
                int length = Math.max(8, Math.min(32,
                        plugin.getConfig().getInt("bedrock-auth.internal-password-length", 24)));
                String internalPassword = randomPassword(length);
                String ip = playerIp(player);

                boolean registered = nLogin.performRegister(currentIdentity, internalPassword, ip);
                if (registered) {
                    identityToLogin = currentIdentity;
                    plugin.getLogger().info("Cuenta nLogin Bedrock creada automaticamente: " + cleanName);
                } else {
                    // Puede haber sido creada por nLogin durante el mismo tick. Reintentamos en vez
                    // de pedir password al jugador.
                    Optional<AccountData> racedAccount = nLogin.getAccount(currentIdentity);
                    if (racedAccount.isPresent() && accountMatchesCurrentBedrock(racedAccount.get(), uuid)) {
                        identityToLogin = currentIdentity;
                    } else {
                        Optional<AccountData> racedKnown = nLogin.getAccount(knownNameIdentity);
                        if (racedKnown.isPresent() && accountMatchesCurrentBedrock(racedKnown.get(), uuid)) {
                            identityToLogin = knownNameIdentity;
                        } else {
                            retryBedrockAuth(player, attempt);
                            return;
                        }
                    }
                }
            }

            boolean logged = nLogin.forceLogin(identityToLogin, false);

            // Fallback final: algunas implementaciones encuentran la cuenta Bedrock por UUID pero
            // resuelven la sesion online por el nombre actual.
            if (!logged && identityToLogin != currentIdentity) {
                logged = nLogin.forceLogin(currentIdentity, false);
            }
            if (!logged && identityToLogin != knownNameIdentity) {
                Optional<AccountData> knownAccount = nLogin.getAccount(knownNameIdentity);
                if (knownAccount.isPresent() && accountMatchesCurrentBedrock(knownAccount.get(), uuid)) {
                    logged = nLogin.forceLogin(knownNameIdentity, false);
                }
            }

            boolean authenticated = logged
                    || nLogin.isAuthenticated(currentIdentity)
                    || nLogin.isAuthenticated(player.getName());

            if (authenticated) {
                if (attempt > 0 || plugin.getConfig().getBoolean("bedrock-auth.log-success", true)) {
                    plugin.getLogger().info("Autologin Bedrock completado: " + cleanName
                            + " (" + uuid + ")");
                }
                return;
            }

            retryBedrockAuth(player, attempt);
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING,
                    "Fallo autenticando Bedrock " + player.getName() + " (intento " + (attempt + 1) + ")", throwable);
            retryBedrockAuth(player, attempt);
        }
    }

    /**
     * Un registro de nLogin solo se reutiliza sin password si demuestra que pertenece a la
     * conexion Floodgate actual. Nunca hacemos autologin de una cuenta Mojang real.
     */
    private boolean accountMatchesCurrentBedrock(AccountData account, UUID currentUuid) {
        if (account == null || currentUuid == null || account.getMojangId().isPresent()) {
            return false;
        }

        UUID bedrockId = account.getBedrockId().orElse(null);
        UUID uniqueId = account.getUniqueId().orElse(null);

        if (currentUuid.equals(bedrockId) || currentUuid.equals(uniqueId)) {
            return true;
        }

        // Si nLogin almaceno un UUID de Floodgate en unique_id pero bedrock_id quedo vacio,
        // el UUID sigue siendo una prueba fuerte de identidad.
        return FloodgateIdentityUtil.looksLikeFloodgateUuid(uniqueId)
                && currentUuid.equals(uniqueId);
    }

    private void retryBedrockAuth(Player player, int attempt) {
        long delay = Math.max(1L, plugin.getConfig().getLong("bedrock-auth.retry-delay-ticks", 1L));
        Bukkit.getScheduler().runTaskLater(plugin, () -> authenticateBedrock(player, attempt + 1), delay);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onRegister(RegisterEvent event) {
        Player player = event.getPlayer();
        if (isBedrock(player)) {
            // Los registros Bedrock los crea este mismo plugin por API.
            return;
        }

        ClaimResult claim = database.claimJava(
                player.getName(),
                player.getUniqueId().toString(),
                JavaType.OFFLINE,
                "nlogin-register"
        );

        if (claim.allowed()) {
            if (claim.status() == ClaimStatus.CLAIMED) {
                plugin.getLogger().info("Identidad reservada: " + player.getName() + " -> JAVA/OFFLINE");
            }
            return;
        }

        if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
            event.setCancelled(true);
            kickSync(player, plugin.message("registration-conflict"));
            return;
        }

        plugin.getLogger().warning("No se pudo reservar identidad Java durante /register de "
                + player.getName() + ": " + claim.error());
        event.setCancelled(true);
        kickSync(player, plugin.message("starting"));
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPremiumLogin(PremiumLoginEvent event) {
        Player player = event.getPlayer();
        if (isBedrock(player)) {
            return;
        }

        UUID uuid = resolveMojangUuid(player).orElse(player.getUniqueId());
        ClaimResult claim = database.claimJava(
                player.getName(),
                uuid.toString(),
                JavaType.PREMIUM,
                "nlogin-premium"
        );

        if (claim.status() == ClaimStatus.CLAIMED) {
            plugin.getLogger().info("Identidad reservada: " + player.getName() + " -> JAVA/PREMIUM");
        }

        if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
            kickSync(player, plugin.message("java-name-owned-by-bedrock", player.getName()));
        } else if (!claim.allowed()) {
            plugin.getLogger().warning("No se pudo guardar identidad premium de " + player.getName() + ": " + claim.error());
            kickSync(player, plugin.message("starting"));
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onAuthenticate(AuthenticateEvent event) {
        Player player = event.getPlayer();
        if (isBedrock(player)) {
            return;
        }

        Optional<IdentityRecord> owner;
        try {
            owner = database.findByNameStrict(player.getName());
        } catch (SQLException exception) {
            plugin.getLogger().log(Level.WARNING, "Fallo consultando identidad tras autenticar a " + player.getName(), exception);
            kickSync(player, plugin.message("starting"));
            return;
        }

        if (owner.isPresent()) {
            if (owner.get().platform() == PlatformType.BEDROCK) {
                kickSync(player, plugin.message("java-name-owned-by-bedrock", player.getName()));
            }
            return;
        }

        // Backfill de seguridad: una cuenta Java ya existente en nLogin nunca queda sin reservar.
        Optional<UUID> mojang = resolveMojangUuid(player);
        JavaType type = mojang.isPresent() ? JavaType.PREMIUM : JavaType.UNKNOWN;
        UUID uuid = mojang.orElse(player.getUniqueId());
        ClaimResult claim = database.claimJava(
                player.getName(),
                uuid.toString(),
                type,
                "nlogin-auth-backfill"
        );
        if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
            kickSync(player, plugin.message("java-name-owned-by-bedrock", player.getName()));
        } else if (!claim.allowed()) {
            plugin.getLogger().warning("No se pudo hacer backfill de " + player.getName() + ": " + claim.error());
            kickSync(player, plugin.message("starting"));
        }
    }

    private Optional<UUID> resolveMojangUuid(Player player) {
        try {
            Optional<AccountData> account = nLogin.getAccount(Identity.ofKnownName(player.getName()));
            if (account.isPresent()) {
                return account.get().getMojangId();
            }
        } catch (Throwable ignored) {
        }
        return Optional.empty();
    }

    private boolean isBedrock(Player player) {
        try {
            if (floodgate.isFloodgatePlayer(player.getUniqueId())) {
                return true;
            }
            if (floodgate.getPlayer(player.getUniqueId()) != null) {
                return true;
            }
        } catch (Throwable ignored) {
            // Fallback por UUID documentado de Floodgate.
        }
        return FloodgateIdentityUtil.looksLikeFloodgateUuid(player.getUniqueId());
    }

    private String cleanBedrockServerName(FloodgatePlayer player, String fallback) {
        String javaName = player.getJavaUsername();
        if (javaName == null || javaName.isBlank()) {
            javaName = fallback;
        }

        String currentPrefix;
        try {
            currentPrefix = floodgate.getPlayerPrefix();
        } catch (Throwable throwable) {
            currentPrefix = "";
        }

        if (currentPrefix != null && !currentPrefix.isEmpty()
                && javaName.startsWith(currentPrefix)
                && javaName.length() > currentPrefix.length()) {
            return javaName.substring(currentPrefix.length());
        }
        return javaName;
    }

    private String randomPassword(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(PASSWORD_CHARS[random.nextInt(PASSWORD_CHARS.length)]);
        }
        return builder.toString();
    }

    private String playerIp(Player player) {
        InetSocketAddress address = player.getAddress();
        if (address == null || address.getAddress() == null) {
            return null;
        }
        return address.getAddress().getHostAddress();
    }

    private void kickSync(Player player, String message) {
        Runnable action = () -> {
            if (player.isOnline()) {
                player.kickPlayer(message);
            }
        };

        if (Bukkit.isPrimaryThread()) {
            action.run();
        } else {
            Bukkit.getScheduler().runTask(plugin, action);
        }
    }
}
