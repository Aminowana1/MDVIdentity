package xyz.mdvcraft.identity.model;

public record IdentityRecord(
        String nameKey,
        String displayName,
        PlatformType platform,
        String uuid,
        String xuid,
        JavaType javaType,
        long firstRegisteredAt,
        String source
) {
}
