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
    // Configuration
    ..addFlag(
      "simple",
      abbr: "s",
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
    );
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc <flags> [arguments]");
  print(argParser.usage);
}
