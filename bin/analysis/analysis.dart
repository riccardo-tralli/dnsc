/// Result of the analysis of a single record: one row per term or tag, plus
/// informational notes and warnings about the record as a whole.
class Analysis {
  final List<List<String>> rows;
  final List<String> notes;
  final List<String> warnings;

  const Analysis(this.rows, {this.notes = const [], this.warnings = const []});
}

abstract class RecordAnalyzer {
  const RecordAnalyzer();

  /// Record kind, e.g. "SPF"
  String get type;

  /// Table columns; the last one is a description and is never shortened
  List<String> get columns;

  Analysis analyze(String data);
}

/// Splits a tag-list record (DMARC, DKIM) into name/value pairs, reporting
/// malformed and duplicate tags in [warnings].
List<(String, String)> parseTags(String data, List<String> warnings) {
  final List<(String, String)> tags = [];
  final Set<String> seen = {};
  for (final String part in data.split(";")) {
    final String tag = part.trim();
    if (tag.isEmpty) {
      continue;
    }
    final int index = tag.indexOf("=");
    if (index <= 0) {
      warnings.add("Malformed tag '$tag'.");
      continue;
    }
    final String name = tag.substring(0, index).trim();
    final String value = tag.substring(index + 1).trim();
    if (!seen.add(name)) {
      warnings.add("Duplicate tag '$name': the record is invalid.");
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
