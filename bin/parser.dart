part of "dnsc.dart";

ArgParser buildParser() {
  return ArgParser()
    // ! Help
    ..addFlag(
      "help",
      abbr: "h",
      negatable: false,
      help: "Print this usage information.",
    )
    ..addFlag("version", negatable: false, help: "Print the tool version.")
    // * Configuration
    ..addFlag(
      "full",
      abbr: "f",
      negatable: false,
      help: "Print full output without cutting.",
    )
    ..addOption(
      "nameserver",
      abbr: "n",
      help: "Use a custom nameserver for lookups.",
    )
    ..addFlag(
      "simple",
      negatable: false,
      help: "Print simple output without tables.",
    )
    ..addOption(
      "timeout",
      abbr: "t",
      help: "Set the timeout for DNS lookups in seconds.",
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
        help: "DKIM selector to query.",
        mandatory: true,
      ),
    )
    ..addCommand("dmarc");
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc <flags> [command] [record]");
  print(argParser.usage);
  print("");
  print("Commands: ${argParser.commands.entries.map((e) => e.key).join(", ")}");
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
  print("   dnsc mx example.com");
  print("   dnsc --simple cname example.com");
  print("   dnsc -t 5 -n 1.1.1.1 cname example.com");
}
