package xyz.mdvcraft.identity.command;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import xyz.mdvcraft.identity.MDVIdentityPlugin;
import xyz.mdvcraft.identity.db.IdentityDatabase;
import xyz.mdvcraft.identity.model.IdentityRecord;
import xyz.mdvcraft.identity.model.ImportSummary;
import xyz.mdvcraft.identity.model.PlatformType;

import java.sql.SQLException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class IdentityCommand implements CommandExecutor, TabCompleter {
    private final MDVIdentityPlugin plugin;
    private final IdentityDatabase database;

    public IdentityCommand(MDVIdentityPlugin plugin, IdentityDatabase database) {
        this.plugin = plugin;
        this.database = database;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("mdvidentity.admin")) {
            sender.sendMessage(color("&cNo tienes permiso."));
            return true;
        }

        if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
            status(sender);
            return true;
        }

        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "info" -> info(sender, args);
            case "conflicts" -> conflicts(sender);
            case "import" -> importNLogin(sender);
            case "release" -> release(sender, args);
            case "reload" -> reload(sender);
            default -> help(sender);
        }
        return true;
    }

    private void status(CommandSender sender) {
        sender.sendMessage(color("&5&lMDVIdentity &7- estado"));
        sender.sendMessage(color("&7Listo: " + (plugin.isReady() ? "&aSI" : "&cNO")));
        sender.sendMessage(color("&7Identidades: &f" + database.countIdentities()
                + " &8(&7Java: &f" + database.countByPlatform(PlatformType.JAVA)
                + "&8, &7Bedrock: &f" + database.countByPlatform(PlatformType.BEDROCK) + "&8)"));
        sender.sendMessage(color("&7Conflictos registrados: &f" + database.countConflicts()));
        try {
            sender.sendMessage(color("&7Floodgate prefix: &f\"" + plugin.floodgateApi().getPlayerPrefix() + "\""));
        } catch (Throwable throwable) {
            sender.sendMessage(color("&7Floodgate prefix: &cno disponible"));
        }
    }

    private void info(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(color("&cUso: /mdvidentity info <nombre>"));
            return;
        }

        Optional<IdentityRecord> record = database.findByName(args[1]);
        if (record.isEmpty()) {
            sender.sendMessage(color("&cNo hay una identidad reservada para &f" + args[1] + "&c."));
            return;
        }

        IdentityRecord id = record.get();
        sender.sendMessage(color("&5&lMDVIdentity &7- &f" + id.displayName()));
        sender.sendMessage(color("&7Plataforma: &f" + id.platform()));
        sender.sendMessage(color("&7UUID: &f" + value(id.uuid())));
        sender.sendMessage(color("&7XUID: &f" + value(id.xuid())));
        sender.sendMessage(color("&7Java type: &f" + (id.javaType() == null ? "-" : id.javaType())));
        sender.sendMessage(color("&7Registrado: &f" + formatTime(id.firstRegisteredAt())));
        sender.sendMessage(color("&7Origen: &f" + id.source()));
    }

    private void conflicts(CommandSender sender) {
        List<String[]> rows = database.listConflicts(20);
        if (rows.isEmpty()) {
            sender.sendMessage(color("&aNo hay conflictos historicos registrados."));
            return;
        }

        sender.sendMessage(color("&5&lMDVIdentity &7- ultimos conflictos &8(" + database.countConflicts() + ")"));
        for (String[] row : rows) {
            sender.sendMessage(color("&8- &f" + row[0] + " &7gano &a" + row[1] + " " + row[2]
                    + " &7sobre &c" + row[3] + " " + row[4]));
        }
        sender.sendMessage(color("&7Reporte completo: &fplugins/MDVIdentity/conflicts.yml"));
    }

    private void importNLogin(CommandSender sender) {
        try {
            ImportSummary summary = plugin.forceImport();
            sender.sendMessage(color("&aImportacion completada. &7Total=&f" + summary.total()
                    + " &7nuevas=&f" + summary.inserted()
                    + " &7actualizadas=&f" + summary.updated()
                    + " &7conflictos=&f" + summary.conflicts()
                    + " &7omitidas=&f" + summary.skipped()));
        } catch (Throwable throwable) {
            sender.sendMessage(color("&cFallo la importacion. Revisa consola."));
            plugin.getLogger().severe("Fallo /mdvidentity import: " + throwable.getMessage());
        }
    }

    private void release(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(color("&cUso: /mdvidentity release <nombre>"));
            sender.sendMessage(color("&eEsto solo libera la reserva de MDVIdentity; NO borra la cuenta de nLogin."));
            return;
        }

        try {
            boolean removed = database.release(args[1]);
            if (removed) {
                sender.sendMessage(color("&aReserva liberada para &f" + args[1] + "&a."));
                sender.sendMessage(color("&eLa cuenta nLogin no fue modificada."));
            } else {
                sender.sendMessage(color("&cNo existia una reserva para &f" + args[1] + "&c."));
            }
        } catch (SQLException exception) {
            sender.sendMessage(color("&cNo se pudo liberar la identidad. Revisa consola."));
            plugin.getLogger().severe("Error liberando " + args[1] + ": " + exception.getMessage());
        }
    }

    private void reload(CommandSender sender) {
        plugin.reloadConfig();
        sender.sendMessage(color("&aConfig de MDVIdentity recargada."));
        plugin.printStatus();
    }

    private void help(CommandSender sender) {
        sender.sendMessage(color("&5&lMDVIdentity"));
        sender.sendMessage(color("&7/mdvidentity status"));
        sender.sendMessage(color("&7/mdvidentity info <nombre>"));
        sender.sendMessage(color("&7/mdvidentity conflicts"));
        sender.sendMessage(color("&7/mdvidentity import"));
        sender.sendMessage(color("&7/mdvidentity release <nombre>"));
        sender.sendMessage(color("&7/mdvidentity reload"));
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission("mdvidentity.admin")) {
            return List.of();
        }
        if (args.length == 1) {
            List<String> base = Arrays.asList("status", "info", "conflicts", "import", "release", "reload");
            String start = args[0].toLowerCase(Locale.ROOT);
            List<String> result = new ArrayList<>();
            for (String entry : base) {
                if (entry.startsWith(start)) result.add(entry);
            }
            return result;
        }
        return List.of();
    }

    private static String value(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private static String formatTime(long millis) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault())
                .format(Instant.ofEpochMilli(millis));
    }

    @SuppressWarnings("deprecation")
    private static String color(String value) {
        return ChatColor.translateAlternateColorCodes('&', value);
    }
}
