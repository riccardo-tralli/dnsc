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
    ..addOption(
      "nameserver",
      abbr: "n",
      help: "Use a custom nameserver for lookups.",
    )
    ..addOption(
      "timeout",
      abbr: "t",
      help: "Set the timeout for DNS lookups in seconds.",
    )
    // * Output
    ..addFlag(
      "count",
      abbr: "c",
      negatable: false,
      help: "Prepend record number to each output line.",
    )
    ..addFlag(
      "full",
      abbr: "f",
      negatable: false,
      help: "Print full output without cutting.",
    )
    ..addFlag(
      "simple",
      negatable: false,
      help: "Print simple output without tables.",
    )
    ..addFlag(
      "raw",
      abbr: "r",
      negatable: false,
      help: "Print raw output without formatting (--full + --simple).",
    )
    ..addFlag(
      "first",
      abbr: "1",
      negatable: false,
      help: "Only print the first record of the answer.",
    )
    ..addFlag(
      "last",
      abbr: "9",
      negatable: false,
      help: "Only print the last record of the answer.",
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
    ..addCommand("dmarc")
    ..addCommand("m365");
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
