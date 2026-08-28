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
            bedrock = floodgate.isFloodgatePlayer(uuid);
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING, "No se pudo consultar Floodgate para " + event.getName(), throwable);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
            return;
        }

        if (bedrock) {
            handleBedrockPreLogin(event, uuid);
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
            return;
        }

        if (claim.status() == ClaimStatus.CONFLICT_PLATFORM) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.message("bedrock-name-owned-by-java", cleanName));
            return;
        }

        if (claim.status() == ClaimStatus.CONFLICT_BEDROCK_OWNER) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.message("bedrock-name-owned-by-other-xbox", cleanName));
            return;
        }

        plugin.getLogger().warning("Error reservando identidad Bedrock " + cleanName + ": " + claim.error());
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.message("starting"));
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

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (!plugin.isReady()) {
            return;
        }

        if (!isBedrock(player)) {
            return;
        }

        if (!plugin.getConfig().getBoolean("bedrock-auth.enabled", true)) {
            return;
        }

        long delay = Math.max(0L, plugin.getConfig().getLong("bedrock-auth.delay-ticks", 2L));
        Bukkit.getScheduler().runTaskLater(plugin, () -> authenticateBedrock(player, 0), delay);
    }

    /**
     * nLogin 2.x puede no reconocer correctamente Bedrock cuando Floodgate usa prefijo vacio.
     * Este puente usa Identity.ofBedrock + el UUID verificado por Floodgate para registrar/login.
     */
    private void authenticateBedrock(Player player, int attempt) {
        if (!player.isOnline() || !isBedrock(player)) {
            return;
        }

        int maxAttempts = Math.max(1, plugin.getConfig().getInt("bedrock-auth.max-attempts", 8));
        if (attempt >= maxAttempts) {
            player.kickPlayer(plugin.message("bedrock-auth-failed"));
            return;
        }

        try {
            // Si nLogin ya lo autentico por su cuenta, no duplicamos nada.
            if (nLogin.isAuthenticated(player.getName())) {
                return;
            }

            Identity currentIdentity = Identity.ofBedrock(player.getName(), player.getUniqueId());
            Optional<AccountData> account = nLogin.getAccount(currentIdentity);

            // Compatibilidad con cuentas antiguas creadas cuando Floodgate tenia "_".
            // La busqueda principal por Bedrock UUID normalmente ya encuentra la misma cuenta.
            Identity identityToLogin = currentIdentity;
            if (account.isEmpty()) {
                String legacyPrefix = plugin.getConfig().getString("migration.legacy-bedrock-prefix", "_");
                if (legacyPrefix != null && !legacyPrefix.isEmpty() && !player.getName().startsWith(legacyPrefix)) {
                    Identity legacyIdentity = Identity.ofBedrock(legacyPrefix + player.getName(), player.getUniqueId());
                    Optional<AccountData> legacyAccount = nLogin.getAccount(legacyIdentity);
                    if (legacyAccount.isPresent()) {
                        account = legacyAccount;
                        identityToLogin = legacyIdentity;
                    }
                }
            }

            if (account.isEmpty()) {
                int length = Math.max(8, Math.min(32,
                        plugin.getConfig().getInt("bedrock-auth.internal-password-length", 24)));
                String internalPassword = randomPassword(length);
                String ip = playerIp(player);

                boolean registered = nLogin.performRegister(currentIdentity, internalPassword, ip);
                if (!registered) {
                    // Puede haber aparecido la cuenta entre la comprobacion y el INSERT.
                    account = nLogin.getAccount(currentIdentity);
                    if (account.isEmpty()) {
                        retryBedrockAuth(player, attempt);
                        return;
                    }
                } else {
                    identityToLogin = currentIdentity;
                }
            }

            boolean logged = nLogin.forceLogin(identityToLogin, false);
            if (!logged && identityToLogin != currentIdentity) {
                // Algunos builds resuelven la sesion por nombre actual aunque la cuenta se localizara por Bedrock ID.
                logged = nLogin.forceLogin(currentIdentity, false);
            }

            if (!logged && !nLogin.isAuthenticated(player.getName())) {
                retryBedrockAuth(player, attempt);
            }
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.WARNING,
                    "Fallo autenticando Bedrock " + player.getName() + " (intento " + (attempt + 1) + ")", throwable);
            retryBedrockAuth(player, attempt);
        }
    }

    private void retryBedrockAuth(Player player, int attempt) {
        long delay = Math.max(1L, plugin.getConfig().getLong("bedrock-auth.retry-delay-ticks", 5L));
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
            return floodgate.getPlayer(player.getUniqueId()) != null;
        } catch (Throwable throwable) {
            try {
                return floodgate.getPlayer(player.getUniqueId()) != null;
            } catch (Throwable ignored) {
                return false;
            }
        }
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
