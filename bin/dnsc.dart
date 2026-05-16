import "dart:developer";

import "package:args/args.dart";
import "dns_lookup.dart";
import "misc/app.dart";

part "parser.dart";

Future<void> main(List<String> arguments) async {
  final ArgParser parser = buildParser();

  try {
    // Parse arguments
    final ArgResults args = parser.parse(arguments);

    // Help
    if (args.flag("help")) {
      App.logo();
      print("");
      printUsage(parser);
      return;
    }
    if (args.flag("version")) {
      App.version();
      return;
    }

    // Handle lookup commands
    switch (args.command?.name) {
      case "a":
        await DnsLookup.a(
          args.command!.option("record"),
          simple: args.flag("simple"),
        );
        break;
      default:
        print("Unknown command. Use --help for usage information.");
    }
  } on FormatException catch (_) {
    printUsage(parser);
  } catch (e) {
    log("An error occurred: $e");
  }
}
