enum Severity {
  warning("WARN", "Warning"),
  error("ERROR", "Error");

  /// Marker shown in the table check column
  final String marker;

  /// Prefix of the message printed below the table
  final String label;

  const Severity(this.marker, this.label);
}

/// Most severe of [issues], or null if there are none
Severity? maxSeverity(Iterable<Issue> issues) => issues.isEmpty
    ? null
    : issues
          .map((e) => e.severity)
          .reduce((a, b) => a.index >= b.index ? a : b);

class Issue {
  final Severity severity;
  final String message;

  /// Rows the issue refers to; empty for the record as a whole
  final List<int> rows;

  const Issue(this.severity, this.message, [this.rows = const []]);
}

/// Reports an issue about a single row
typedef Report = void Function(Severity severity, String message);

/// Result of the analysis of a single record: one row per term or tag, plus
/// informational notes and issues about rows or the record as a whole.
class Analysis {
  final List<List<String>> rows;
  final List<String> notes;
  final List<Issue> issues;

  const Analysis(this.rows, {this.notes = const [], this.issues = const []});

  /// Most severe issue of [row], or null if it has none
  Severity? severityOf(int row) =>
      maxSeverity(issues.where((e) => e.rows.contains(row)));
}

abstract class RecordAnalyzer {
  const RecordAnalyzer();

  /// Record kind, e.g. "SPF"
  String get type;

  /// Table columns; the last one is a description and is never shortened
  List<String> get columns;

  Analysis analyze(String data);
}

/// Splits a tag-list record (DMARC, DKIM) into name/value pairs, one per
/// row, reporting malformed and duplicate tags in [issues].
List<(String, String)> parseTags(String data, List<Issue> issues) {
  final List<(String, String)> tags = [];
  final Set<String> seen = {};
  for (final String part in data.split(";")) {
    final String tag = part.trim();
    if (tag.isEmpty) {
      continue;
    }
    final int index = tag.indexOf("=");
    if (index <= 0) {
      issues.add(Issue(Severity.error, "Malformed tag '$tag'."));
      continue;
    }
    final String name = tag.substring(0, index).trim();
    final String value = tag.substring(index + 1).trim();
    if (!seen.add(name)) {
      issues.add(
        Issue(Severity.error, "Duplicate tag '$name': the record is invalid.", [
          tags.length,
        ]),
      );
    }
    tags.add((name, value));
  }
  return tags;
}

/// Joins the character-strings of a TXT record, which the resolver returns
/// quoted (e.g. "v=spf1 a" "-all"), into a single value.
String txtData(String data) {
  final Iterable<RegExpMatch> strings = RegExp(
    r'"((?:[^"\\]|\\.)*)"',
  ).allMatches(data);
  if (strings.isEmpty) {
    return data;
  }
  return strings
      .map((e) => e.group(1)!.replaceAllMapped(RegExp(r"\\(.)"), (m) => m[1]!))
      .join();
}
