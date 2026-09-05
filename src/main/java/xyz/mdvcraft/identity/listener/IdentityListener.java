package xyz.mdvcraft.identity.listener;

import com.nickuc.login.api.nLoginAPI;
import com.nickuc.login.api.event.bukkit.auth.AuthenticateEvent;
import com.nickuc.login.api.event.bukkit.auth.PremiumLoginEvent;
import com.nickuc.login.api.event.bukkit.auth.RegisterEvent;
import com.nickuc.login.api.event.bukkit.auth.request.LoginRequestEvent;
import com.nickuc.login.api.enums.AccountType;
import com.nickuc.login.api.enums.SpawnType;
import com.nickuc.login.api.types.AccountData;
import com.nickuc.login.api.types.Identity;
import org.bukkit.Bukkit;
import org.bukkit.Location;
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
    // Solo contiene jugadores Bedrock cuya cuenta nLogin acaba de ser creada por MDVIdentity.
    // Se usa para impedir que last-location los envie al spawn vanilla de world en su primer ingreso.
    private final Set<UUID> firstBedrockRegistration = ConcurrentHashMap.newKeySet();

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
     * vacio, 1.0.5 separa dos conceptos: MDVIdentity/Floodgate son la autoridad real de plataforma,
     * mientras nLogin solo mantiene el estado de registro/limbo. Con username-prefix vacio
     * nLogin 2.0.19 crea su LoginRequest como OFFLINE aunque Floodgate haya validado al jugador;
     * por eso esta version fuerza el login sobre la identidad OFFLINE exacta que nLogin creo.
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

            Identity offlineIdentity = Identity.ofOffline(cleanName);
            Identity internalKnownNameIdentity = createInternalKnownNameIdentity(player.getName());
            Identity knownNameIdentity = Identity.ofKnownName(player.getName());
            Identity bedrockIdentity = Identity.ofBedrock(cleanName, uuid);
            Identity internalBedrockIdentity = createInternalBedrockIdentity(cleanName, uuid);

            // DIAGNOSTICO 1.0.4 demostro que nLogin 2.0.19 + prefijo vacio crea la sesion
            // activa como OFFLINE (UUID offline, bedrockId vacio), aunque Floodgate confirme
            // correctamente que el Player es Bedrock. Por eso la primera identidad para
            // autenticar nLogin debe ser la OFFLINE que coincide con su LoginRequest vivo.
            // Esto NO rebaja la seguridad: antes de llegar aqui Floodgate + identities.db ya
            // demostraron que este UUID/XUID es el propietario BEDROCK del nombre.
            if (isAuthenticatedAny(player, offlineIdentity, internalKnownNameIdentity, knownNameIdentity,
                    bedrockIdentity, internalBedrockIdentity)) {
                finishBedrockAuth(player, cleanName, uuid, attempt);
                return;
            }

            Optional<AccountData> account = findNLoginSessionAccount(
                    cleanName, player.getName(), uuid,
                    offlineIdentity, internalKnownNameIdentity, knownNameIdentity, bedrockIdentity, internalBedrockIdentity
            );

            // Primera vez real: para nLogin registramos una cuenta OFFLINE interna con password
            // aleatorio. MDVIdentity sigue guardandola como BEDROCK y bloquea cualquier conexion
            // Java con el mismo nombre antes del login. Esto evita depender del detector Bedrock
            // de nLogin, que precisamente es el que necesita un prefijo no vacio.
            if (account.isEmpty()) {
                int length = Math.max(8, Math.min(32,
                        plugin.getConfig().getInt("bedrock-auth.internal-password-length", 24)));
                String internalPassword = randomPassword(length);
                String ip = playerIp(player);

                boolean registered = nLogin.performRegister(offlineIdentity, internalPassword, ip);
                if (registered) {
                    firstBedrockRegistration.add(uuid);
                    plugin.getLogger().info("Cuenta interna nLogin creada para Bedrock: " + cleanName
                            + " (tipo nLogin OFFLINE; propietario real BEDROCK en MDVIdentity)");
                }

                account = findNLoginSessionAccount(
                        cleanName, player.getName(), uuid,
                        offlineIdentity, internalKnownNameIdentity, knownNameIdentity, bedrockIdentity, internalBedrockIdentity
                );

                if (account.isEmpty()) {
                    retryBedrockAuth(player, attempt);
                    return;
                }
            }

            AccountData data = account.get();
            Identity accountIdentity = identityForNLoginSessionAccount(data, cleanName, uuid);

            boolean logged = tryForceLogin(
                    player,
                    offlineIdentity,
                    internalKnownNameIdentity,
                    accountIdentity,
                    knownNameIdentity,
                    bedrockIdentity,
                    internalBedrockIdentity
            );

            if (logged || isAuthenticatedAny(player, offlineIdentity, internalKnownNameIdentity, accountIdentity,
                    knownNameIdentity, bedrockIdentity, internalBedrockIdentity)) {
                finishBedrockAuth(player, cleanName, uuid, attempt);
                return;
            }

            // Si por timing aun no existe LoginRequest, la solicitamos usando la MISMA identidad
            // OFFLINE que nLogin usa naturalmente con username-prefix vacio. Si ya existe una
            // request, la API la ignora y el siguiente retry vuelve a forceLogin.
            if (plugin.getConfig().getBoolean("bedrock-auth.request-login-if-needed", true)
                    && requestedLogin.add(uuid)) {
                try {
                    nLogin.requestLogin(offlineIdentity, plugin);
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

    private Identity createInternalKnownNameIdentity(String knownName) {
        try {
            Identity identity = nLogin.internal().createIdentityFromKnownName(knownName);
            return identity == null ? Identity.ofKnownName(knownName) : identity;
        } catch (Throwable ignored) {
            return Identity.ofKnownName(knownName);
        }
    }

    /**
     * Busca la cuenta que nLogin usa para SU sesion. La autoridad de propiedad NO sale de aqui:
     * para llegar a este metodo el nombre ya esta reservado como BEDROCK por UUID/XUID en
     * identities.db.
     *
     * Con prefijo vacio nLogin 2.0.19 devuelve la cuenta como OFFLINE y con UUID offline. Eso es
     * esperado y se acepta solo para este jugador Floodgate ya verificado. Una cuenta Mojang
     * (mojangId presente) nunca se reutiliza como sesion Bedrock.
     */
    private Optional<AccountData> findNLoginSessionAccount(String cleanName,
                                                            String serverName,
                                                            UUID currentUuid,
                                                            Identity... candidates) {
        for (Identity candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            try {
                Optional<AccountData> account = nLogin.getAccount(candidate);
                if (account.isPresent()
                        && accountCanBackVerifiedBedrockSession(account.get(), cleanName, serverName, currentUuid)) {
                    return account;
                }
            } catch (Throwable ignored) {
            }
        }

        // Fallback NATIVE: buscar por nombre exacto. No aceptamos cuentas Mojang.
        try {
            Iterator<AccountData> iterator = nLogin.getAccounts();
            while (iterator.hasNext()) {
                AccountData account = iterator.next();
                if (account != null
                        && accountCanBackVerifiedBedrockSession(account, cleanName, serverName, currentUuid)) {
                    return Optional.of(account);
                }
            }
        } catch (Throwable ignored) {
        }

        return Optional.empty();
    }

    private boolean accountCanBackVerifiedBedrockSession(AccountData account, String cleanName,
                                                           String serverName, UUID currentUuid) {
        if (account == null || account.getMojangId().isPresent()) {
            return false;
        }

        String lastName = account.getLastName();
        boolean nameMatches = lastName != null
                && (lastName.equalsIgnoreCase(cleanName) || lastName.equalsIgnoreCase(serverName));
        if (!nameMatches) {
            return false;
        }

        // Si nLogin SI tiene bedrockId/UUID Floodgate, exigimos que coincida.
        UUID bedrockId = account.getBedrockId().orElse(null);
        UUID uniqueId = account.getUniqueId().orElse(null);
        if (bedrockId != null) {
            return currentUuid.equals(bedrockId);
        }
        if (uniqueId != null && FloodgateIdentityUtil.looksLikeFloodgateUuid(uniqueId)) {
            return currentUuid.equals(uniqueId);
        }

        // Caso comprobado por el log de 1.0.4: nLogin la materializa como OFFLINE normal
        // (UUID offline y sin bedrockId). Se puede usar como capa de limbo porque MDVIdentity
        // ya verifico por separado UUID/XUID y propiedad del nombre.
        return account.getType() == AccountType.OFFLINE;
    }

    private Identity identityForNLoginSessionAccount(AccountData account, String fallbackName, UUID currentUuid) {
        String name = account.getLastName();
        if (name == null || name.isBlank()) {
            name = fallbackName;
        }

        // Este es el caso normal con prefijo vacio en nLogin 2.0.19.
        if (account.getType() == AccountType.OFFLINE) {
            return Identity.ofOffline(name);
        }

        UUID bedrockId = account.getBedrockId().orElse(currentUuid);
        if (account.getType() == AccountType.BEDROCK) {
            try {
                Identity identity = nLogin.internal().createIdentity(name, null, bedrockId, AccountType.BEDROCK);
                if (identity != null) {
                    return identity;
                }
            } catch (Throwable ignored) {
            }
            return Identity.ofBedrock(name, bedrockId);
        }

        return Identity.ofKnownName(name);
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

    private void finishBedrockAuth(Player player, String cleanName, UUID uuid, int attempt) {
        boolean wasFirstRegistration = firstBedrockRegistration.remove(uuid);
        cleanupAuthState(uuid);

        if (wasFirstRegistration) {
            keepFirstBedrockRegistrationAtRegisterSpawn(player, cleanName);
        }

        if (attempt > 0 || plugin.getConfig().getBoolean("bedrock-auth.log-success", true)) {
            plugin.getLogger().info("Autologin Bedrock completado: " + cleanName + " (" + uuid + ")");
        }
    }

    /**
     * nLogin aplica correctamente su spawn REGISTER cuando un Java usa /register, pero los
     * Bedrock de MDVCRAFT se registran mediante performRegister(...) + forceLogin(...). Ese
     * camino de API no pasa por el flujo normal del comando /register y, con
     * teleport.last-location=true, nLogin puede restaurar la posicion vanilla inicial del
     * jugador nuevo (normalmente el spawn de world).
     *
     * Para la PRIMERA alta Bedrock solamente, reutilizamos el spawn REGISTER configurado en
     * nLogin. Los ingresos siguientes no pasan por aqui y conservan last-location normal.
     */
    private void keepFirstBedrockRegistrationAtRegisterSpawn(Player player, String cleanName) {
        if (!plugin.getConfig().getBoolean("bedrock-auth.first-registration.keep-at-register-spawn", true)) {
            return;
        }

        com.nickuc.login.api.types.Location nLoginTarget = null;
        try {
            nLoginTarget = nLogin.getSpawnLocation(SpawnType.REGISTER).orElse(null);
            if (nLoginTarget == null) {
                nLoginTarget = nLogin.getSpawnLocation(SpawnType.JOIN).orElse(null);
            }
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING,
                    "No se pudo obtener el spawn REGISTER/JOIN de nLogin para " + cleanName, throwable);
        }

        if (nLoginTarget == null) {
            plugin.getLogger().warning("Primer registro Bedrock de " + cleanName
                    + ": nLogin no tiene spawn REGISTER ni JOIN configurado; no se fuerza ubicacion.");
            return;
        }

        org.bukkit.World targetWorld = Bukkit.getWorld(nLoginTarget.getWorldName());
        if (targetWorld == null) {
            plugin.getLogger().warning("Primer registro Bedrock de " + cleanName
                    + ": el mundo del spawn de nLogin no esta cargado: " + nLoginTarget.getWorldName());
            return;
        }

        final Location destination = new Location(
                targetWorld,
                nLoginTarget.getX(),
                nLoginTarget.getY(),
                nLoginTarget.getZ(),
                nLoginTarget.getYaw(),
                nLoginTarget.getPitch()
        );
        long delay = Math.max(1L, plugin.getConfig().getLong(
                "bedrock-auth.first-registration.teleport-delay-ticks", 2L));
        long recheck = Math.max(0L, plugin.getConfig().getLong(
                "bedrock-auth.first-registration.safety-recheck-ticks", 10L));

        Runnable teleport = () -> {
            if (!player.isOnline() || !isBedrock(player)) {
                return;
            }
            player.teleportAsync(destination.clone());
        };

        Bukkit.getScheduler().runTaskLater(plugin, teleport, delay);
        if (recheck > delay) {
            // Segunda aplicacion corta para ganar una posible carrera contra el restore de
            // last-location de nLogin. Solo ocurre una vez en toda la vida de la cuenta.
            Bukkit.getScheduler().runTaskLater(plugin, teleport, recheck);
        }

        plugin.getLogger().info("Primer registro Bedrock: " + cleanName
                + " permanecera en el spawn REGISTER de nLogin ("
                + destination.getWorld().getName() + ").");
    }

    private void cleanupAuthState(UUID uuid) {
        loginRequestSeen.remove(uuid);
        requestedLogin.remove(uuid);
        firstBedrockRegistration.remove(uuid);
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
                Identity.ofOffline(name),
                createInternalKnownNameIdentity(name),
                createInternalBedrockIdentity(name, uuid),
                Identity.ofBedrock(name, uuid),
                Identity.ofKnownName(name)
        };
        String[] labels = new String[]{"offline-session", "internal-known-name", "internal-bedrock", "public-bedrock", "known-name"};

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
