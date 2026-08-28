package xyz.mdvcraft.identity.listener;

import com.nickuc.login.api.nLoginAPI;
import com.nickuc.login.api.event.bukkit.auth.AuthenticateEvent;
import com.nickuc.login.api.event.bukkit.auth.PremiumLoginEvent;
import com.nickuc.login.api.event.bukkit.auth.RegisterEvent;
import com.nickuc.login.api.event.bukkit.auth.request.LoginRequestEvent;
import com.nickuc.login.api.enums.AccountType;
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
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public final class IdentityListener implements Listener {
    private static final char[] PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();

    private final MDVIdentityPlugin plugin;
    private final IdentityDatabase database;
    private final FloodgateApi floodgate;
    private final nLoginAPI nLogin;
    private final SecureRandom random = new SecureRandom();
    private final Set<UUID> loginRequestSeen = ConcurrentHashMap.newKeySet();
    private final Set<UUID> requestedLogin = ConcurrentHashMap.newKeySet();

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

        // Arrancamos pronto, pero NO damos por fallida la autenticacion en ~1 segundo como 1.0.3.
        // nLogin puede crear su LoginRequest ligeramente despues del PlayerJoinEvent.
        long delay = Math.max(0L, plugin.getConfig().getLong("bedrock-auth.delay-ticks", 0L));
        if (delay == 0L) {
            authenticateBedrock(player, 0);
        } else {
            Bukkit.getScheduler().runTaskLater(plugin, () -> authenticateBedrock(player, 0), delay);
        }
    }

    /**
     * Este evento es la senal mas fiable de que nLogin YA creo el estado interno de login
     * para el Player actual. En 1.0.3 podiamos agotar 20 intentos antes de que ese estado
     * estuviera listo. Cuando aparece, marcamos la sesion y forzamos otro intento al tick
     * siguiente.
     */
    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onLoginRequest(LoginRequestEvent event) {
        Player player = event.getPlayer();
        if (!plugin.isReady() || !plugin.getConfig().getBoolean("bedrock-auth.enabled", true)
                || !isBedrock(player)) {
            return;
        }

        loginRequestSeen.add(player.getUniqueId());
        Bukkit.getScheduler().runTask(plugin, () -> authenticateBedrock(player, 0));
    }

    /**
     * Puente Bedrock -> nLogin.
     *
     * La autoridad de plataforma/nombre sigue siendo Floodgate + identities.db. nLogin solo
     * se utiliza como capa de autenticacion/limbo. Para evitar falsos negativos con prefijo
     * vacio, 1.0.4 prueba la identidad BEDROCK oficial, la identidad interna canonica de
     * nLogin y, si hace falta, localiza la cuenta por UUID Floodgate.
     */
    private void authenticateBedrock(Player player, int attempt) {
        if (!player.isOnline() || !isBedrock(player)) {
            cleanupAuthState(player.getUniqueId());
            return;
        }

        int maxAttempts = Math.max(1, plugin.getConfig().getInt("bedrock-auth.max-attempts", 120));
        if (attempt >= maxAttempts) {
            logBedrockAuthDiagnostics(player);
            cleanupAuthState(player.getUniqueId());
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

            // Revalidamos propiedad antes de tocar nLogin. Autologin nunca es un bypass.
            boolean strict = plugin.getConfig().getBoolean("security.strict-bedrock-owner-check", true);
            ClaimResult ownerClaim = database.claimBedrock(
                    cleanName,
                    uuid.toString(),
                    xuid,
                    strict,
                    "bedrock-join-auth"
            );

            if (!ownerClaim.allowed()) {
                cleanupAuthState(uuid);
                if (ownerClaim.status() == ClaimStatus.CONFLICT_PLATFORM) {
                    player.kickPlayer(plugin.message("bedrock-name-owned-by-java", cleanName));
                } else if (ownerClaim.status() == ClaimStatus.CONFLICT_BEDROCK_OWNER) {
                    player.kickPlayer(plugin.message("bedrock-name-owned-by-other-xbox", cleanName));
                } else {
                    player.kickPlayer(plugin.message("bedrock-auth-failed"));
                }
                return;
            }

            Identity bedrockIdentity = Identity.ofBedrock(cleanName, uuid);
            Identity internalBedrockIdentity = createInternalBedrockIdentity(cleanName, uuid);
            Identity knownNameIdentity = Identity.ofKnownName(player.getName());

            // Si nLogin ya autentico por su cuenta o por un intento previo, listo.
            if (isAuthenticatedAny(player, bedrockIdentity, internalBedrockIdentity, knownNameIdentity)) {
                finishBedrockAuth(cleanName, uuid, attempt);
                return;
            }

            Optional<AccountData> account = findVerifiedBedrockAccount(
                    cleanName, player.getName(), uuid,
                    bedrockIdentity, internalBedrockIdentity, knownNameIdentity
            );

            // Primera vez real: registramos como BEDROCK. Preferimos la identidad interna
            // canonica del propio nLogin, pero la factory publica sigue como fallback.
            if (account.isEmpty()) {
                int length = Math.max(8, Math.min(32,
                        plugin.getConfig().getInt("bedrock-auth.internal-password-length", 24)));
                String internalPassword = randomPassword(length);
                String ip = playerIp(player);

                boolean registered = false;
                try {
                    registered = nLogin.performRegister(internalBedrockIdentity, internalPassword, ip);
                } catch (Throwable first) {
                    // Algunas builds aceptan mejor la factory publica.
                    try {
                        registered = nLogin.performRegister(bedrockIdentity, internalPassword, ip);
                    } catch (Throwable second) {
                        first.addSuppressed(second);
                        throw first;
                    }
                }

                if (registered) {
                    plugin.getLogger().info("Cuenta nLogin Bedrock creada automaticamente: " + cleanName);
                }

                account = findVerifiedBedrockAccount(
                        cleanName, player.getName(), uuid,
                        bedrockIdentity, internalBedrockIdentity, knownNameIdentity
                );

                // performRegister puede terminar antes de que el cache/consulta de nLogin vea
                // la cuenta. Damos tiempo en vez de confundirlo con un fallo permanente.
                if (account.isEmpty()) {
                    retryBedrockAuth(player, attempt);
                    return;
                }
            }

            AccountData data = account.get();
            Identity accountIdentity = identityForVerifiedBedrockAccount(data, cleanName, uuid);

            boolean logged = tryForceLogin(
                    player,
                    accountIdentity,
                    internalBedrockIdentity,
                    bedrockIdentity,
                    knownNameIdentity
            );

            if (logged || isAuthenticatedAny(player, accountIdentity, internalBedrockIdentity,
                    bedrockIdentity, knownNameIdentity)) {
                finishBedrockAuth(cleanName, uuid, attempt);
                return;
            }

            // forceLogin trabaja sobre el login request vivo. Si nLogin todavia no lo creo con
            // la identidad que necesitamos, requestLogin es la API oficial para solicitarlo.
            // La propia API ignora esta llamada si ya hay una request en curso.
            if (plugin.getConfig().getBoolean("bedrock-auth.request-login-if-needed", true)
                    && requestedLogin.add(uuid)) {
                try {
                    nLogin.requestLogin(accountIdentity, plugin);
                } catch (Throwable throwable) {
                    plugin.getLogger().log(Level.FINE,
                            "nLogin requestLogin no disponible para " + cleanName, throwable);
                }
            }

            retryBedrockAuth(player, attempt);
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING,
                    "Fallo autenticando Bedrock " + player.getName() + " (intento " + (attempt + 1) + ")", throwable);
            retryBedrockAuth(player, attempt);
        }
    }

    private Identity createInternalBedrockIdentity(String name, UUID uuid) {
        try {
            Identity identity = nLogin.internal().createIdentity(name, null, uuid, AccountType.BEDROCK);
            return identity == null ? Identity.ofBedrock(name, uuid) : identity;
        } catch (Throwable ignored) {
            return Identity.ofBedrock(name, uuid);
        }
    }

    private Optional<AccountData> findVerifiedBedrockAccount(String cleanName,
                                                              String serverName,
                                                              UUID currentUuid,
                                                              Identity... candidates) {
        for (Identity candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            try {
                Optional<AccountData> account = nLogin.getAccount(candidate);
                if (account.isPresent() && accountMatchesCurrentBedrock(account.get(), currentUuid)) {
                    return account;
                }
            } catch (Throwable ignored) {
            }
        }

        // Fallback NATIVE: algunas builds no resuelven getAccount(ofBedrock(...)) con prefijo
        // vacio aunque el registro tenga el UUID correcto. Buscar por UUID evita depender del nombre.
        try {
            Iterator<AccountData> iterator = nLogin.getAccounts();
            while (iterator.hasNext()) {
                AccountData account = iterator.next();
                if (account != null && accountMatchesCurrentBedrock(account, currentUuid)) {
                    String lastName = account.getLastName();
                    if (lastName == null
                            || lastName.equalsIgnoreCase(cleanName)
                            || lastName.equalsIgnoreCase(serverName)) {
                        return Optional.of(account);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        return Optional.empty();
    }

    private Identity identityForVerifiedBedrockAccount(AccountData account, String fallbackName, UUID currentUuid) {
        String name = account.getLastName();
        if (name == null || name.isBlank()) {
            name = fallbackName;
        }

        UUID bedrockId = account.getBedrockId().orElse(currentUuid);
        try {
            if (account.getType() == AccountType.BEDROCK) {
                Identity identity = nLogin.internal().createIdentity(name, null, bedrockId, AccountType.BEDROCK);
                if (identity != null) {
                    return identity;
                }
            }
        } catch (Throwable ignored) {
        }
        return Identity.ofBedrock(name, bedrockId);
    }

    private boolean tryForceLogin(Player player, Identity... identities) {
        for (Identity identity : identities) {
            if (identity == null) {
                continue;
            }
            try {
                if (nLogin.forceLogin(identity, false)) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }

        // Compatibilidad: usa la resolucion por "known name" del propio nLogin.
        try {
            if (nLogin.forceLogin(player.getName(), false)) {
                return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private boolean isAuthenticatedAny(Player player, Identity... identities) {
        try {
            if (nLogin.isAuthenticated(player.getName())) {
                return true;
            }
        } catch (Throwable ignored) {
        }
        for (Identity identity : identities) {
            if (identity == null) {
                continue;
            }
            try {
                if (nLogin.isAuthenticated(identity)) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private void finishBedrockAuth(String cleanName, UUID uuid, int attempt) {
        cleanupAuthState(uuid);
        if (attempt > 0 || plugin.getConfig().getBoolean("bedrock-auth.log-success", true)) {
            plugin.getLogger().info("Autologin Bedrock completado: " + cleanName + " (" + uuid + ")");
        }
    }

    private void cleanupAuthState(UUID uuid) {
        loginRequestSeen.remove(uuid);
        requestedLogin.remove(uuid);
    }

    private void logBedrockAuthDiagnostics(Player player) {
        if (!plugin.getConfig().getBoolean("bedrock-auth.log-diagnostics-on-failure", true)) {
            return;
        }

        UUID uuid = player.getUniqueId();
        String name = player.getName();
        try {
            plugin.getLogger().warning("Diagnostico nLogin Bedrock: name=" + name
                    + ", uuid=" + uuid
                    + ", requestSeen=" + loginRequestSeen.contains(uuid)
                    + ", apiAvailable=" + nLogin.isAvailable()
                    + ", implementation=" + nLogin.getImplementationType()
                    + ", apiVersion=" + nLogin.getApiVersion());
        } catch (Throwable throwable) {
            plugin.getLogger().warning("Diagnostico nLogin Bedrock basico: name=" + name + ", uuid=" + uuid);
        }

        Identity[] candidates = new Identity[]{
                createInternalBedrockIdentity(name, uuid),
                Identity.ofBedrock(name, uuid),
                Identity.ofKnownName(name)
        };
        String[] labels = new String[]{"internal-bedrock", "public-bedrock", "known-name"};

        for (int i = 0; i < candidates.length; i++) {
            try {
                Optional<AccountData> account = nLogin.getAccount(candidates[i]);
                if (account.isEmpty()) {
                    plugin.getLogger().warning("Diagnostico " + labels[i] + ": account=EMPTY");
                    continue;
                }
                AccountData a = account.get();
                plugin.getLogger().warning("Diagnostico " + labels[i]
                        + ": lastName=" + a.getLastName()
                        + ", type=" + a.getType()
                        + ", uniqueId=" + a.getUniqueId().map(UUID::toString).orElse("-")
                        + ", bedrockId=" + a.getBedrockId().map(UUID::toString).orElse("-")
                        + ", mojangId=" + a.getMojangId().map(UUID::toString).orElse("-"));
            } catch (Throwable throwable) {
                plugin.getLogger().warning("Diagnostico " + labels[i] + ": ERROR "
                        + throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
            }
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
