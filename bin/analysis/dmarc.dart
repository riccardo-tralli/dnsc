import "analysis.dart";

/// DMARC record analysis (RFC 7489)
class DmarcAnalyzer extends RecordAnalyzer {
  static const Map<String, String> _policies = {
    "none": "no action, monitoring only",
    "quarantine": "treat failing mail as suspicious",
    "reject": "reject failing mail",
  };

  static const Map<String, String> _alignments = {
    "r": "relaxed (organizational domain match)",
    "s": "strict (exact domain match)",
  };

  static const Map<String, String> _failureOptions = {
    "0": "all mechanisms fail",
    "1": "any mechanism fails",
    "d": "DKIM fails",
    "s": "SPF fails",
  };

  const DmarcAnalyzer();

  @override
  String get type => "DMARC";

  @override
  List<String> get columns => ["Tag", "Value", "Description"];

  @override
  Analysis analyze(String data) {
    final List<Issue> issues = [];
    final List<(String, String)> tags = parseTags(data, issues);
    final Map<String, String> values = {
      for (final (name, value) in tags) name.toLowerCase(): value,
    };
    // Rows of a tag, for the issues found by looking at the whole record
    List<int> rowsOf(String name) => [
      for (final (int row, (String, String) tag) in tags.indexed)
        if (tag.$1.toLowerCase() == name) row,
    ];

    if (tags.isEmpty || tags.first.$1 != "v" || tags.first.$2 != "DMARC1") {
      issues.add(
        Issue(
          Severity.error,
          "The record does not start with 'v=DMARC1': receivers ignore it.",
          rowsOf("v"),
        ),
      );
    }

    final List<List<String>> rows = [
      for (final (int row, (String name, String value)) in tags.indexed)
        [
          name,
          value,
          _describe(
            name.toLowerCase(),
            value,
            (severity, message) => issues.add(Issue(severity, message, [row])),
          ),
        ],
    ];

    final String? policy = values["p"]?.toLowerCase();
    if (policy == null) {
      issues.add(Issue(Severity.error, "Missing required 'p' tag."));
    } else if (policy == "none") {
      issues.add(
        Issue(
          Severity.warning,
          "'p=none' only monitors: failing mail is still delivered.",
          rowsOf("p"),
        ),
      );
    }
    if (values["sp"]?.toLowerCase() == "none" && policy != "none") {
      issues.add(
        Issue(
          Severity.warning,
          "'sp=none' leaves subdomains unprotected.",
          rowsOf("sp"),
        ),
      );
    }
    final int? pct = int.tryParse(values["pct"] ?? "");
    if (pct != null && pct >= 0 && pct < 100) {
      issues.add(
        Issue(
          Severity.warning,
          "'pct=$pct': the policy only applies to part of the mail.",
          rowsOf("pct"),
        ),
      );
    }
    if (!values.containsKey("rua")) {
      issues.add(
        Issue(
          Severity.warning,
          "No 'rua' tag: no aggregate reports will be received.",
        ),
      );
    }

    return Analysis(
      rows,
      notes: [
        if (!values.containsKey("sp") && _policies.containsKey(policy))
          "Subdomains inherit p=$policy.",
        if (!values.containsKey("adkim") || !values.containsKey("aspf"))
          "Alignment not set defaults to relaxed.",
      ],
      issues: issues,
    );
  }

  String _describe(String name, String value, Report report) {
    switch (name) {
      case "v":
        return "DMARC version";
      case "p":
        return "Domain policy: ${_lookup(_policies, name, value, report)}";
      case "sp":
        return "Subdomain policy: ${_lookup(_policies, name, value, report)}";
      case "np":
        return "Non-existent subdomain policy: ${_lookup(_policies, name, value, report)}";
      case "pct":
        final int? pct = int.tryParse(value);
        if (pct == null || pct < 0 || pct > 100) {
          report(
            Severity.error,
            "Invalid 'pct' value '$value': must be 0-100.",
          );
          return "Invalid percentage";
        }
        return "Policy applied to $pct% of failing mail";
      case "rua":
        return "Aggregate reports to ${_uris(value)}";
      case "ruf":
        return "Failure reports to ${_uris(value)}";
      case "adkim":
        return "DKIM alignment: ${_lookup(_alignments, name, value, report)}";
      case "aspf":
        return "SPF alignment: ${_lookup(_alignments, name, value, report)}";
      case "fo":
        final List<String> options = value
            .split(":")
            .map((e) => e.trim())
            .toList();
        for (final String option in options) {
          if (!_failureOptions.containsKey(option)) {
            report(Severity.error, "Invalid 'fo' option '$option'.");
          }
        }
        return "Failure reports when ${options.map((e) => _failureOptions[e] ?? e).join(" or ")}";
      case "rf":
        return "Failure report format";
      case "ri":
        final int? seconds = int.tryParse(value);
        if (seconds == null) {
          report(
            Severity.error,
            "Invalid 'ri' value '$value': must be seconds.",
          );
          return "Invalid report interval";
        }
        return seconds % 3600 == 0
            ? "Aggregate report interval: ${seconds ~/ 3600} hours"
            : "Aggregate report interval: $seconds seconds";
      default:
        return "Unknown tag, ignored";
    }
  }

  String _lookup(
    Map<String, String> meanings,
    String name,
    String value,
    Report report,
  ) {
    final String? meaning = meanings[value.toLowerCase()];
    if (meaning == null) {
      report(Severity.error, "Invalid '$name' value '$value'.");
      return "invalid";
    }
    return meaning;
  }

  String _uris(String value) => value
      .split(",")
      .map((e) => e.trim().replaceFirst(RegExp(r"^mailto:"), ""))
      .join(", ");
}
