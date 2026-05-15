part of "dnsc.dart";

ArgParser buildParser() {
  return ArgParser()
    ..addFlag(
      "help",
      abbr: "h",
      negatable: false,
      help: "Print this usage information.",
    )
    ..addFlag("version", negatable: false, help: "Print the tool version.");
}

void printUsage(ArgParser argParser) {
  print("Usage: dnsc <flags> [arguments]");
  print(argParser.usage);
}
