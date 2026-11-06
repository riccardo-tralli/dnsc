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
    final List<String> warnings = [];
    final List<(String, String)> tags = parseTags(data, warnings);
    final Map<String, String> values = {
      for (final (name, value) in tags) name.toLowerCase(): value,
    };

    if (tags.isEmpty || tags.first.$1 != "v" || tags.first.$2 != "DMARC1") {
      warnings.add(
        "The record does not start with 'v=DMARC1': receivers ignore it.",
      );
    }

    final List<List<String>> rows = [
      for (final (name, value) in tags)
        [name, value, _describe(name.toLowerCase(), value, warnings)],
    ];

    final String? policy = values["p"]?.toLowerCase();
    if (policy == null) {
      warnings.add("Missing required 'p' tag.");
    } else if (policy == "none") {
      warnings.add("'p=none' only monitors: failing mail is still delivered.");
    }
    if (values["sp"]?.toLowerCase() == "none" && policy != "none") {
      warnings.add("'sp=none' leaves subdomains unprotected.");
    }
    final int? pct = int.tryParse(values["pct"] ?? "");
    if (pct != null && pct >= 0 && pct < 100) {
      warnings.add("'pct=$pct': the policy only applies to part of the mail.");
    }
    if (!values.containsKey("rua")) {
      warnings.add("No 'rua' tag: no aggregate reports will be received.");
    }

    return Analysis(
      rows,
      notes: [
        if (!values.containsKey("sp") && _policies.containsKey(policy))
          "Subdomains inherit p=$policy.",
        if (!values.containsKey("adkim") || !values.containsKey("aspf"))
          "Alignment not set defaults to relaxed.",
      ],
      warnings: warnings,
    );
  }

  String _describe(String name, String value, List<String> warnings) {
    switch (name) {
      case "v":
        return "DMARC version";
      case "p":
        return "Domain policy: ${_lookup(_policies, name, value, warnings)}";
      case "sp":
        return "Subdomain policy: ${_lookup(_policies, name, value, warnings)}";
      case "np":
        return "Non-existent subdomain policy: ${_lookup(_policies, name, value, warnings)}";
      case "pct":
        final int? pct = int.tryParse(value);
        if (pct == null || pct < 0 || pct > 100) {
          warnings.add("Invalid 'pct' value '$value': must be 0-100.");
          return "Invalid percentage";
        }
        return "Policy applied to $pct% of failing mail";
      case "rua":
        return "Aggregate reports to ${_uris(value)}";
      case "ruf":
        return "Failure reports to ${_uris(value)}";
      case "adkim":
        return "DKIM alignment: ${_lookup(_alignments, name, value, warnings)}";
      case "aspf":
        return "SPF alignment: ${_lookup(_alignments, name, value, warnings)}";
      case "fo":
        final List<String> options = value
            .split(":")
            .map((e) => e.trim())
            .toList();
        for (final String option in options) {
          if (!_failureOptions.containsKey(option)) {
            warnings.add("Invalid 'fo' option '$option'.");
          }
        }
        return "Failure reports when ${options.map((e) => _failureOptions[e] ?? e).join(" or ")}";
      case "rf":
        return "Failure report format";
      case "ri":
        final int? seconds = int.tryParse(value);
        if (seconds == null) {
          warnings.add("Invalid 'ri' value '$value': must be seconds.");
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
    List<String> warnings,
  ) {
    final String? meaning = meanings[value.toLowerCase()];
    if (meaning == null) {
      warnings.add("Invalid '$name' value '$value'.");
      return "invalid";
    }
    return meaning;
  }

  String _uris(String value) => value
      .split(",")
      .map((e) => e.trim().replaceFirst(RegExp(r"^mailto:"), ""))
      .join(", ");
}
