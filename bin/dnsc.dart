import "dart:developer";

import "package:args/args.dart";
import "package:dnsolve/dnsolve.dart";
import "dns_lookup.dart";
import "misc/app.dart";

part "parser.dart";

Future<void> main(List<String> arguments) async {
  final ArgParser parser = buildParser();

  DnsLookup dns;

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

    // Configuration
    dns = DnsLookup(
      nameserver: args.option("server"),
      timeout: int.tryParse(args.option("timeout") ?? "1") ?? 1,
      simple: args.flag("simple"),
    );

    // Handle lookup commands
    switch (args.command!.name) {
      case "a":
        await dns.typed(args.command!.option("record"), RecordType.A);
        break;
      case "aaaa":
        await dns.typed(args.command!.option("record"), RecordType.aaaa);
        break;
      case "cname":
        await dns.typed(args.command!.option("record"), RecordType.cname);
        break;
      case "mx":
        await dns.mx(args.command!.option("record"));
        break;
      case "ns":
        await dns.typed(args.command!.option("record"), RecordType.ns);
        break;
      case "txt":
        await dns.typed(args.command!.option("record"), RecordType.txt);
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
