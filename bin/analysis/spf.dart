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

  /// DNS lookups of the included and redirected records, when resolved
  final int? nestedLookups;

  /// Term ("include" or "redirect") the record is evaluated through, when
  /// nested in another record
  final String? via;

  const SpfAnalyzer({this.nestedLookups, this.via});

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
  SpfAnalysis analyze(String data) {
    final List<List<String>> rows = [];
    final List<(String, String)> targets = [];
    final List<Issue> issues = [];
    final String record = data.trim();
    // One row per term, so a term index is also its row index
    final List<String> terms = record.split(RegExp(r"\s+"));

    // Terms are still split on any whitespace, so the breakdown stays
    // readable, but only spaces are valid separators (RFC 7208, 4.6.1)
    for (final (int index, RegExpMatch separator) in RegExp(
      r"\s+",
    ).allMatches(record).indexed) {
      final Set<String> invalid = separator[0]!.runes
          .where((e) => e != 0x20)
          .map(_whitespaceName)
          .toSet();
      if (invalid.isNotEmpty) {
        issues.add(
          Issue(
            Severity.error,
            "${invalid.join(", ")} between '${terms[index]}' and '${terms[index + 1]}': "
            "only spaces are allowed, strict receivers return permerror.",
            [index, index + 1],
          ),
        );
      }
    }

    if (terms.first.toLowerCase() != "v=spf1") {
      issues.add(
        Issue(
          Severity.error,
          "The record does not start with 'v=spf1': it is not SPF.",
          [0],
        ),
      );
    }

    int lookups = 0;
    int? all;
    String? allQualifier;
    int? redirect;
    final Map<String, int> modifiers = {};

    for (final (int index, String term) in terms.indexed) {
      void report(Severity severity, String message) =>
          issues.add(Issue(severity, message, [index]));

      final String lower = term.toLowerCase();
      if (index == 0 && lower == "v=spf1") {
        rows.add(["", "v", "spf1", "SPF version 1"]);
        continue;
      }
      if (all != null) {
        report(Severity.warning, "'$term' comes after 'all': never evaluated.");
      }

      // Modifiers: name=value
      final RegExpMatch? modifier = RegExp(
        r"^([a-z][a-z0-9_.-]*)=(.*)$",
        caseSensitive: false,
      ).firstMatch(term);
      if (modifier != null) {
        final String name = modifier[1]!.toLowerCase();
        final String value = modifier[2]!;
        if (modifiers.containsKey(name) &&
            (name == "redirect" || name == "exp")) {
          issues.add(
            Issue(
              Severity.error,
              "Duplicate '$name' modifier: receivers return permerror.",
              [modifiers[name]!, index],
            ),
          );
        }
        modifiers[name] ??= index;
        if (_lookupTerms.contains(name)) {
          lookups++;
        }
        rows.add(["", name, value, _modifierDescription(name, value)]);
        if (name == "redirect") {
          redirect ??= index;
          targets.add((name, value));
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
        report(
          Severity.error,
          "Unknown mechanism '$name': receivers return permerror.",
        );
      }
      if (_lookupTerms.contains(name)) {
        lookups++;
      }
      if (name == "ptr") {
        report(
          Severity.warning,
          "The 'ptr' mechanism is deprecated and should not be used.",
        );
      }
      if (name == "all" && all == null) {
        all = index;
        allQualifier = qualifier;
      }
      if (name == "include") {
        targets.add((name, value));
      }
      rows.add([
        "$qualifier ${_results[qualifier]}",
        name,
        value,
        description ?? "Unknown mechanism",
      ]);
    }

    switch (allQualifier) {
      case "+":
        issues.add(
          Issue(
            Severity.error,
            "'+all' authorizes any server to send mail as the domain.",
            [all!],
          ),
        );
      // In an include, no match is fine: the evaluation goes on in the parent
      case "?" when via != "include":
        issues.add(
          Issue(
            Severity.warning,
            "'?all' gives no protection against spoofing.",
            [all!],
          ),
        );
      case null when redirect == null && via != "include":
        issues.add(
          Issue(
            Severity.warning,
            "No 'all' mechanism: unmatched senders get a neutral result.",
          ),
        );
    }
    if (all != null && redirect != null) {
      issues.add(
        Issue(
          Severity.warning,
          "'redirect' is ignored because the record has 'all'.",
          [redirect],
        ),
      );
      targets.removeWhere((e) => e.$1 == "redirect");
    }
    final int total = lookups + (nestedLookups ?? 0);
    // Nested records count towards the limit of the parent record
    if (via == null && total > _maxLookups) {
      issues.add(
        Issue(
          Severity.error,
          "Too many DNS lookups ($total, max $_maxLookups): receivers return permerror.",
        ),
      );
    }

    return SpfAnalysis(
      rows,
      lookups: lookups,
      targets: targets,
      notes: [
        nestedLookups == null
            ? "DNS lookups: $lookups/$_maxLookups (nested includes and redirects not counted, use --recursive)."
            : "DNS lookups: $total/$_maxLookups ($lookups in this record, $nestedLookups in nested records).",
      ],
      issues: issues,
    );
  }

  String _whitespaceName(int rune) => switch (rune) {
    0x0a => "Newline (LF)",
    0x0d => "Carriage return (CR)",
    0x09 => "Tab",
    0xa0 => "Non-breaking space",
    _ => "Character U+${rune.toRadixString(16).toUpperCase().padLeft(4, "0")}",
  };

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

class SpfAnalysis extends Analysis {
  /// DNS lookups of this record only
  final int lookups;

  /// Records to evaluate next, as (term, domain): includes and the redirect
  final List<(String, String)> targets;

  const SpfAnalysis(
    super.rows, {
    required this.lookups,
    required this.targets,
    super.notes,
    super.issues,
  });
}
