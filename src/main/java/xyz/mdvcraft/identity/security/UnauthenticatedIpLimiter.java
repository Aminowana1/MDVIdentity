package xyz.mdvcraft.identity.security;

import com.nickuc.login.api.nLoginAPI;
import com.nickuc.login.api.types.Identity;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import xyz.mdvcraft.identity.MDVIdentityPlugin;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;

/**
 * Limita cuentas todavia NO registradas que intentan entrar simultaneamente desde una misma IP.
 *
 * La reserva se hace en AsyncPlayerPreLoginEvent, antes de que Bukkit cree un Player y antes de
 * PlayerJoinEvent. De esta forma el cuarto bot (por defecto) se rechaza antes de entrar al mundo.
 *
 * Una reserva se libera al registrarse/autenticarse o desconectarse. Tambien expira por seguridad
 * como respaldo adicional ante cualquier cierre de conexion que no llegue a notificarse normalmente.
 */
public final class UnauthenticatedIpLimiter {
    private final MDVIdentityPlugin plugin;
    private final nLoginAPI nLogin;

    private final Object lock = new Object();
    private final Map<UUID, Reservation> reservationsByUuid = new HashMap<>();
    private final Map<String, Set<UUID>> reservationsByIp = new HashMap<>();

    public UnauthenticatedIpLimiter(MDVIdentityPlugin plugin, nLoginAPI nLogin) {
        this.plugin = plugin;
        this.nLogin = nLogin;

        // Respaldo periodico contra cualquier reserva que no se haya podido liberar por evento.
        plugin.getServer().getScheduler().runTaskTimerAsynchronously(
                plugin,
                this::cleanupExpired,
                20L * 30L,
                20L * 30L
        );
    }

    /**
     * @return true si la conexion puede continuar; false si ya fue rechazada.
     */
    public boolean checkAndReserve(AsyncPlayerPreLoginEvent event) {
        if (!plugin.getConfig().getBoolean("security.unregistered-ip-limit.enabled", true)) {
            return true;
        }

        InetAddress address = event.getAddress();
        if (address == null) {
            return true;
        }

        String ip = normalizeIp(address.getHostAddress());
        if (ip.isEmpty() || isBypassedIp(ip)) {
            return true;
        }

        // Las cuentas que nLogin ya conoce como registradas NO consumen cupo.
        if (isAlreadyRegistered(event.getName())) {
            release(event.getUniqueId());
            return true;
        }

        int max = Math.max(1, plugin.getConfig().getInt("security.unregistered-ip-limit.max", 3));
        long now = System.currentTimeMillis();
        long timeoutMillis = reservationTimeoutMillis();
        UUID uuid = event.getUniqueId();

        synchronized (lock) {
            cleanupExpiredLocked(now, timeoutMillis);

            Reservation existing = reservationsByUuid.get(uuid);
            if (existing != null) {
                // Reprocesar el mismo UUID no debe consumir otro cupo.
                if (existing.ip.equals(ip)) {
                    return true;
                }
                removeLocked(uuid, existing);
            }

            Set<UUID> current = reservationsByIp.computeIfAbsent(ip, ignored -> new HashSet<>());
            if (current.size() >= max) {
                String message = plugin.message("too-many-unregistered-from-ip")
                        .replace("{max}", Integer.toString(max));
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, message);

                if (plugin.getConfig().getBoolean("security.unregistered-ip-limit.log-blocked", true)) {
                    plugin.getLogger().warning("Conexion rechazada por limite de no registrados: name="
                            + event.getName() + ", ip=" + ip + ", activos=" + current.size() + "/" + max);
                }
                return false;
            }

            current.add(uuid);
            reservationsByUuid.put(uuid, new Reservation(ip, now));
            return true;
        }
    }

    public void release(UUID uuid) {
        if (uuid == null) {
            return;
        }
        synchronized (lock) {
            Reservation reservation = reservationsByUuid.get(uuid);
            if (reservation != null) {
                removeLocked(uuid, reservation);
            }
        }
    }

    public int getReservedCount(String rawIp) {
        String ip = normalizeIp(rawIp);
        if (ip.isEmpty()) {
            return 0;
        }
        synchronized (lock) {
            cleanupExpiredLocked(System.currentTimeMillis(), reservationTimeoutMillis());
            Set<UUID> set = reservationsByIp.get(ip);
            return set == null ? 0 : set.size();
        }
    }

    private boolean isAlreadyRegistered(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }

        // Primero nLogin: cubre cuentas existentes aunque identities.db no se haya importado.
        try {
            if (nLogin.getAccount(Identity.ofKnownName(name)).isPresent()) {
                return true;
            }
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.FINE,
                    "No se pudo consultar nLogin por known-name para " + name, throwable);
        }

        try {
            if (nLogin.getAccount(Identity.ofOffline(name)).isPresent()) {
                return true;
            }
        } catch (Throwable throwable) {
            plugin.getLogger().log(Level.FINE,
                    "No se pudo consultar nLogin por identidad offline para " + name, throwable);
        }

        // Si no podemos demostrar que esta registrado, lo tratamos como no registrado.
        // Es fail-safe contra flood y no impide las primeras 'max' conexiones.
        return false;
    }

    private boolean isBypassedIp(String ip) {
        List<String> configured = plugin.getConfig().getStringList(
                "security.unregistered-ip-limit.bypass-ips");
        for (String raw : configured) {
            if (ip.equals(normalizeIp(raw))) {
                return true;
            }
            if ("localhost".equalsIgnoreCase(raw)
                    && ("127.0.0.1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip))) {
                return true;
            }
        }
        return false;
    }

    private long reservationTimeoutMillis() {
        long seconds = Math.max(10L, plugin.getConfig().getLong(
                "security.unregistered-ip-limit.reservation-timeout-seconds", 120L));
        return seconds * 1000L;
    }

    private void cleanupExpired() {
        synchronized (lock) {
            cleanupExpiredLocked(System.currentTimeMillis(), reservationTimeoutMillis());
        }
    }

    private void cleanupExpiredLocked(long now, long timeoutMillis) {
        reservationsByUuid.entrySet().removeIf(entry -> {
            Reservation reservation = entry.getValue();
            if (now - reservation.createdAtMillis < timeoutMillis) {
                return false;
            }

            Set<UUID> set = reservationsByIp.get(reservation.ip);
            if (set != null) {
                set.remove(entry.getKey());
                if (set.isEmpty()) {
                    reservationsByIp.remove(reservation.ip);
                }
            }
            return true;
        });
    }

    private void removeLocked(UUID uuid, Reservation reservation) {
        reservationsByUuid.remove(uuid);
        Set<UUID> set = reservationsByIp.get(reservation.ip);
        if (set != null) {
            set.remove(uuid);
            if (set.isEmpty()) {
                reservationsByIp.remove(reservation.ip);
            }
        }
    }

    private static String normalizeIp(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    private record Reservation(String ip, long createdAtMillis) {
    }
}
