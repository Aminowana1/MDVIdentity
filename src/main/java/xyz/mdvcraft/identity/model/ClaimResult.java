package xyz.mdvcraft.identity.model;

public record ClaimResult(ClaimStatus status, IdentityRecord owner, String error) {
    public static ClaimResult claimed(IdentityRecord owner) {
        return new ClaimResult(ClaimStatus.CLAIMED, owner, null);
    }

    public static ClaimResult alreadyOwned(IdentityRecord owner) {
        return new ClaimResult(ClaimStatus.ALREADY_OWNED, owner, null);
    }

    public static ClaimResult conflictPlatform(IdentityRecord owner) {
        return new ClaimResult(ClaimStatus.CONFLICT_PLATFORM, owner, null);
    }

    public static ClaimResult conflictBedrockOwner(IdentityRecord owner) {
        return new ClaimResult(ClaimStatus.CONFLICT_BEDROCK_OWNER, owner, null);
    }

    public static ClaimResult error(String error) {
        return new ClaimResult(ClaimStatus.ERROR, null, error);
    }

    public boolean allowed() {
        return status == ClaimStatus.CLAIMED || status == ClaimStatus.ALREADY_OWNED;
    }
}
