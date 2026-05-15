import "package:args/args.dart";

part "parser.dart";

const String version = "0.0.1";

void main(List<String> arguments) {
  print("dnsc - DNS Checker CLI Tool");
  print("Version: $version");
  print("");

  final ArgParser parser = buildParser();

  try {
    final ArgResults results = parser.parse(arguments);

    if (results.flag("help")) {
      printUsage(parser);
      return;
    }
    if (results.flag("version")) {
      print("dnsc version: $version");
      return;
    }
  } on FormatException catch (e) {
    print(e.message);
    print("");
    printUsage(parser);
  }
}
