package xyz.mdvcraft.identity.model;

public record ImportIdentity(
        String nameKey,
        String displayName,
        PlatformType platform,
        String uuid,
        String xuid,
        JavaType javaType,
        long registeredAt,
        String source
) {
}
