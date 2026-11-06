part of "dnsc.dart";

// Command descriptions, in the order they are listed in the usage
const Map<String, String> _commands = {
  "a": "IPv4 addresses (A records)",
  "aaaa": "IPv6 addresses (AAAA records)",
  "cname": "Canonical name (CNAME record)",
  "mx": "Mail servers, sorted by priority (MX records)",
  "ns": "Name servers (NS records)",
  "ptr": "Reverse lookup of an IP address (PTR records)",
  "soa": "Start of authority of the zone (SOA record)",
  "srv": "Services, sorted by priority (SRV records)",
  "txt": "Text records (TXT records)",
  "spf": "SPF policy, from the TXT records of the domain",
  "dkim": "DKIM key, from TXT on <selector>._domainkey.<domain>",
  "dmarc": "DMARC policy, from TXT on _dmarc.<domain>",
  "m365": "Microsoft 365 records (MX, SPF, DKIM, DMARC, Autodiscover, Intune)",
};

ArgParser buildParser() {
  return ArgParser(usageLineLength: 80)
    ..addFlag(
      "help",
      abbr: "h",
      negatable: false,
      help: "Print this usage information.",
    )
    ..addFlag("version", negatable: false, help: "Print the version.")
    ..addSeparator("Lookup:")
    ..addOption(
      "nameserver",
      abbr: "n",
      valueHelp: "ip",
      help: "Query this nameserver instead of the system one.",
    )
    ..addOption(
      "timeout",
      abbr: "t",
      valueHelp: "seconds",
      defaultsTo: "5",
      help: "Timeout of each DNS query.",
    )
    ..addSeparator("Output:")
    ..addFlag(
      "count",
      abbr: "c",
      negatable: false,
      help: "Number the output rows.",
    )
    ..addFlag(
      "full",
      abbr: "f",
      negatable: false,
      help: "Print long values in full instead of truncating them.",
    )
    ..addFlag(
      "simple",
      negatable: false,
      help: "Print plain lines instead of tables.",
    )
    ..addFlag(
      "raw",
      abbr: "r",
      negatable: false,
      help: "Same as --simple --full.",
    )
    ..addFlag(
      "first",
      abbr: "1",
      negatable: false,
      help: "Print only the first record of the answer.",
    )
    ..addFlag(
      "last",
      abbr: "9",
      negatable: false,
      help: "Print only the last record of the answer.",
    )
    ..addSeparator("Analysis (spf, dkim and dmarc only):")
    ..addFlag(
      "analyze",
      abbr: "a",
      negatable: false,
      help: "Break the records down into their terms or tags and check them.",
    )
    ..addFlag(
      "recursive",
      abbr: "R",
      negatable: false,
      help:
          "Follow SPF includes and redirects and count all DNS lookups "
          "(spf only, implies --analyze).",
    )
    // * Lookup
    ..addCommand("a")
    ..addCommand("aaaa")
    ..addCommand("cname")
    ..addCommand("mx")
    ..addCommand("ns")
    ..addCommand("ptr")
    ..addCommand("soa")
    ..addCommand("srv")
    ..addCommand("txt")
    // ! Advanced commands
    ..addCommand("spf")
    ..addCommand(
      "dkim",
      ArgParser()..addOption(
        "selector",
        abbr: "s",
        valueHelp: "selector",
        help: "DKIM selector to query.",
        mandatory: true,
      ),
    )
    ..addCommand("dmarc")
    ..addCommand("m365");
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc [flags] <command> <domain> [command options]");
  print("");
  print(argParser.usage);
  print("");
  print("Commands:");
  final int width = argParser.commands.keys
      .map((e) => e.length)
      .reduce((a, b) => a > b ? a : b);
  for (final String command in argParser.commands.keys) {
    print("   ${command.padRight(width)}   ${_commands[command] ?? ""}");
  }
  print("");
  print(
    argParser.commands.entries
        .where((e) => e.value.usage.isNotEmpty)
        .map((e) => "${e.key} options:\n   ${e.value.usage}")
        .join("\n"),
  );
  print("");
  print("Examples:");
  print("   dnsc a example.com");
  print("   dnsc --simple mx example.com");
  print("   dnsc -t 10 -n 1.1.1.1 cname www.example.com");
  print("   dnsc ptr 93.184.216.34");
  print("   dnsc dkim example.com -s selector1");
  print("   dnsc --analyze dmarc example.com");
  print("   dnsc --recursive spf example.com");
}
