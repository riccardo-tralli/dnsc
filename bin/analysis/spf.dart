import "analysis.dart";

/// SPF record analysis (RFC 7208)
class SpfAnalyzer extends RecordAnalyzer {
  // Terms that cost a DNS lookup, limited to 10 per evaluation (RFC 7208, 4.6.4)
  static const Set<String> _lookupTerms = {
    "include",
    "a",
    "mx",
    "ptr",
    "exists",
    "redirect",
  };
  static const int _maxLookups = 10;

  static const Map<String, String> _results = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
  };

  const SpfAnalyzer();

  @override
  String get type => "SPF";

  @override
  List<String> get columns => [
    "Qualifier",
    "Mechanism",
    "Value",
    "Description",
  ];

  @override
  Analysis analyze(String data) {
    final List<List<String>> rows = [];
    final List<String> warnings = [];
    final List<String> terms = data.trim().split(RegExp(r"\s+"));

    if (terms.first.toLowerCase() != "v=spf1") {
      warnings.add("The record does not start with 'v=spf1': it is not SPF.");
    }

    int lookups = 0;
    String? all;
    bool redirect = false;
    bool afterAll = false;
    final Set<String> modifiers = {};

    for (final (int index, String term) in terms.indexed) {
      final String lower = term.toLowerCase();
      if (index == 0 && lower == "v=spf1") {
        rows.add(["", "v", "spf1", "SPF version 1"]);
        continue;
      }
      if (all != null) {
        afterAll = true;
      }

      // Modifiers: name=value
      final RegExpMatch? modifier = RegExp(
        r"^([a-z][a-z0-9_.-]*)=(.*)$",
        caseSensitive: false,
      ).firstMatch(term);
      if (modifier != null) {
        final String name = modifier[1]!.toLowerCase();
        final String value = modifier[2]!;
        if (!modifiers.add(name) && (name == "redirect" || name == "exp")) {
          warnings.add(
            "Duplicate '$name' modifier: receivers return permerror.",
          );
        }
        if (_lookupTerms.contains(name)) {
          lookups++;
        }
        rows.add(["", name, value, _modifierDescription(name, value)]);
        if (name == "redirect") {
          redirect = true;
        }
        continue;
      }

      // Mechanisms: [qualifier]name[:value][/cidr]
      String qualifier = "+";
      String rest = term;
      if (_results.containsKey(term[0])) {
        qualifier = term[0];
        rest = term.substring(1);
      }
      final int separator = rest.indexOf(RegExp(r"[:/]"));
      final String name = (separator < 0 ? rest : rest.substring(0, separator))
          .toLowerCase();
      final String value = separator < 0
          ? ""
          : rest.substring(rest[separator] == ":" ? separator + 1 : separator);

      final String? description = _mechanismDescription(name, value, qualifier);
      if (description == null) {
        warnings.add("Unknown mechanism '$name': receivers return permerror.");
      }
      if (_lookupTerms.contains(name)) {
        lookups++;
      }
      if (name == "ptr") {
        warnings.add(
          "The 'ptr' mechanism is deprecated and should not be used.",
        );
      }
      if (name == "all") {
        all ??= qualifier;
      }
      rows.add([
        "$qualifier ${_results[qualifier]}",
        name,
        value,
        description ?? "Unknown mechanism",
      ]);
    }

    switch (all) {
      case "+":
        warnings.add(
          "'+all' authorizes any server to send mail as the domain.",
        );
      case "?":
        warnings.add("'?all' gives no protection against spoofing.");
      case null when !redirect:
        warnings.add(
          "No 'all' mechanism: unmatched senders get a neutral result.",
        );
    }
    if (afterAll) {
      warnings.add("Terms after 'all' are never evaluated.");
    }
    if (all != null && redirect) {
      warnings.add("'redirect' is ignored because the record has 'all'.");
    }
    if (lookups > _maxLookups) {
      warnings.add(
        "Too many DNS lookups ($lookups, max $_maxLookups): receivers return permerror.",
      );
    }

    return Analysis(
      rows,
      notes: [
        "DNS lookups: $lookups/$_maxLookups (nested includes and redirects not counted).",
      ],
      warnings: warnings,
    );
  }

  String? _mechanismDescription(String name, String value, String qualifier) {
    final String result = _results[qualifier]!;
    switch (name) {
      case "all":
        return switch (qualifier) {
          "-" => "Reject any other sender",
          "~" => "Mark any other sender as suspicious",
          "?" => "No policy for any other sender",
          _ => "Allow any other sender",
        };
      case "include":
        return "Senders authorized by $value ($result)";
      case "a":
        return "A/AAAA addresses of ${_target(value)} ($result)";
      case "mx":
        return "MX hosts of ${_target(value)} ($result)";
      case "ptr":
        return "Senders whose PTR name is in ${_target(value)} ($result)";
      case "ip4":
        return "IPv4 address or range ($result)";
      case "ip6":
        return "IPv6 address or range ($result)";
      case "exists":
        return "Matches if $value has an A record ($result)";
      default:
        return null;
    }
  }

  /// Domain a mechanism applies to: the record's own domain if omitted,
  /// optionally followed by a CIDR length (e.g. "/24")
  String _target(String value) {
    if (value.isEmpty) {
      return "the domain";
    }
    if (value.startsWith("/")) {
      return "the domain$value";
    }
    return value;
  }

  String _modifierDescription(String name, String value) => switch (name) {
    "redirect" => "Use the SPF policy of $value if nothing matches",
    "exp" => "Rejection message from the TXT record of $value",
    _ => "Unknown modifier, ignored",
  };
}
