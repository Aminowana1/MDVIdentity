package xyz.mdvcraft.identity;

import java.util.Locale;
import java.util.UUID;

/**
 * Helpers for identities created by Floodgate when account linking is not used.
 * Floodgate documents its Bedrock UUIDs as 00000000-0000-0000-xxxx-xxxxxxxxxxxx,
 * where the last 64 bits are the hexadecimal XUID.
 */
public final class FloodgateIdentityUtil {
    private FloodgateIdentityUtil() {
    }

    public static boolean looksLikeFloodgateUuid(UUID uuid) {
        if (uuid == null) {
            return false;
        }
        String value = uuid.toString().toLowerCase(Locale.ROOT);
        return value.startsWith("00000000-0000-0000-");
    }

    public static String xuidFromFloodgateUuid(UUID uuid) {
        if (!looksLikeFloodgateUuid(uuid)) {
            return null;
        }

        String raw = uuid.toString().replace("-", "");
        if (raw.length() != 32) {
            return null;
        }

        String xuidHex = raw.substring(16);
        try {
            long value = Long.parseUnsignedLong(xuidHex, 16);
            return Long.toUnsignedString(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
