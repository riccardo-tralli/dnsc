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
      "server",
      abbr: "s",
      help: "Use a custom nameserver for lookups.",
    )
    ..addOption(
      "timeout",
      abbr: "t",
      help: "Set the timeout for DNS lookups in seconds.",
    )
    ..addFlag(
      "simple",
      negatable: false,
      help: "Print simple output without tables.",
    )
    // * Lookup
    ..addCommand(
      "a",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    )
    ..addCommand(
      "aaaa",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    )
    ..addCommand(
      "cname",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    )
    ..addCommand(
      "mx",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    )
    ..addCommand(
      "ns",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    )
    ..addCommand(
      "txt",
      ArgParser()..addOption(
        "record",
        abbr: "r",
        mandatory: true,
        help: "DNS record to lookup.",
      ),
    );
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc <flags> [command] -r <record>");
  print(argParser.usage);
  print("");
  print("Commands: ${argParser.commands.entries.map((e) => e.key).join(", ")}");
  print("");
  print("Examples:");
  print("  dnsc a -r example.com");
  print("  dnsc mx -r example.com");
  print("  dnsc cname -r example.com --simple");
  print("  dnsc cname -r example.com -t 5 -s 1.1.1.1");
}
