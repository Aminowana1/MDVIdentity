package xyz.mdvcraft.identity.model;

public record ImportSummary(int total, int inserted, int updated, int conflicts, int skipped) {
}
