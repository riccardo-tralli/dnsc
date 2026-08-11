import "dart:developer";
import "dart:io";

import "package:args/args.dart";
import "package:dnsolve/dnsolve.dart";
import "lookup/dns_lookup.dart";
import "lookup/typed.dart";
import "lookup/mx.dart";
import "lookup/soa.dart";
import "lookup/srv.dart";
import "lookup/m365.dart";
import "misc/app.dart";

part "parser.dart";

Future<void> main(List<String> arguments) async {
  final ArgParser parser = buildParser();

  DnsLookup dns;

  try {
    // Parse arguments
    ArgResults args = parser.parse(arguments);

    // Loop for continuous execution
    bool loop = args.arguments.isEmpty && args.command == null;
    if (loop) {
      App.logo();
      print("");
      print("Enter a command (type 'help' for info or type 'exit' to quit)");
    }
    do {
      if (loop) {
        stdout.write("> ");
        String? input = stdin.readLineSync();
        if (input == null || input.trim().toLowerCase() == "exit") {
          break;
        }
        if (input == "help") {
          input = "--help";
        }
        // Re-parse the new input
        final List<String> newArgs = input.split(" ");
        args = parser.parse(newArgs);
      }

      // Help
      if (args.flag("help")) {
        App.logo();
        print("");
        printUsage(parser);
        if (loop) {
          continue;
        }
        return;
      }
      if (args.flag("version")) {
        App.version();
        if (loop) {
          continue;
        }
        return;
      }

      if (args.command == null) {
        print("No command provided. Use --help for usage information.");
        if (loop) {
          continue;
        }
        return;
      }

      // Configuration
      dns = DnsLookup(
        nameserver: args.option("nameserver"),
        timeout: int.tryParse(args.option("timeout") ?? "5") ?? 5,
        simple: args.flag("simple"),
        full: args.flag("full"),
        count: args.flag("count"),
        first: args.flag("first"),
        last: args.flag("last"),
      );

      // Domain validation
      String? domain = args.arguments
          .where(
            (e) =>
                // Ignore flags, commands, and options
                !parser.commands.containsKey(e) &&
                !parser.options.containsKey(e) &&
                !e.startsWith("-") &&
                // FQDN validation
                RegExp(
                  r"^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?\.)+[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?$",
                ).hasMatch(e),
          )
          .lastOrNull;
      if (domain == null) {
        print("No valid domain provided. Use --help for usage information.");
        if (loop) {
          continue;
        }
        return;
      }

      // Lookup commands
      switch (args.command!.name) {
        case "a":
          await Typed(dns).query(domain, RecordType.A);
          break;
        case "aaaa":
          await Typed(dns).query(domain, RecordType.aaaa);
          break;
        case "cname":
          await Typed(dns).query(domain, RecordType.cname);
          break;
        case "mx":
          await Mx(dns).query(domain);
          break;
        case "ns":
          await Typed(dns).query(domain, RecordType.ns);
          break;
        case "ptr":
          await Typed(dns).query(domain, RecordType.ptr);
          break;
        case "soa":
          await Soa(dns).query(domain);
          break;
        case "srv":
          await Srv(dns).query(domain);
          break;
        case "txt":
          await Typed(dns).query(domain, RecordType.txt);
          break;
        // ! Advanced commands
        case "spf":
          await Typed(dns).query(
            domain,
            RecordType.txt,
            filter: (e) => e.data.contains("v=spf1"),
          );
          break;
        case "dkim":
          if (!args.command!.options.any((e) => e == "selector")) {
            print(
              "DKIM selector is required. Use --help for usage information.",
            );
            if (loop) {
              continue;
            }
            return;
          }
          final String? selector = args.command!.option("selector");
          await Typed(
            dns,
          ).query("$selector._domainkey.$domain", RecordType.txt);
          break;
        case "dmarc":
          await Typed(dns).query("_dmarc.$domain", RecordType.txt);
          break;
        case "m365":
          await M365(dns).query(domain);
          break;
        default:
          print("Unknown command. Use --help for usage information.");
      }
    } while (loop);
  } on FormatException catch (_) {
    printUsage(parser);
  } catch (e) {
    log("An error occurred: $e");
  }
}
