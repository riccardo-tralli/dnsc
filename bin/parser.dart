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
    ..addCommand("a")
    ..addCommand("aaaa")
    ..addCommand("cname")
    ..addCommand("mx")
    ..addCommand("ns")
    ..addCommand("ptr")
    ..addCommand("soa")
    ..addCommand("srv")
    ..addCommand("txt");
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc <flags> [command] [record]");
  print(argParser.usage);
  print("");
  print("Commands: ${argParser.commands.entries.map((e) => e.key).join(", ")}");
  print("");
  print("Examples:");
  print("  dnsc a example.com");
  print("  dnsc mx example.com");
  print("  dnsc --simple cname example.com");
  print("  dnsc -t 5 -s 1.1.1.1 cname example.com");
}
