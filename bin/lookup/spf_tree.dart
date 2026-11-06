import 'package:dnsolve/dnsolve.dart';
import "../analysis/analysis.dart";
import "../analysis/spf.dart";
import "dns_lookup.dart";

/// Follows the includes and redirects of an SPF record, counting the DNS
/// lookups of the whole evaluation (RFC 7208, 4.6.4)
class SpfTree {
  // Upper bound on followed records, against huge or looping chains
  static const int _maxRecords = 100;

  static const int _nxDomain = 3;

  final DnsLookup dns;

  /// One row per record: (term:domain indented by depth, lookups, status)
  final List<List<String>> rows = [];
  final List<String> warnings = [];

  /// DNS lookups of the nested records, the root record excluded
  int lookups = 0;

  int _records = 0;

  SpfTree(this.dns);

  Future<void> resolve(String domain, SpfAnalysis analysis) async {
    rows.add([domain, analysis.lookups.toString(), "OK"]);
    await _follow(analysis, 1, {_normalize(domain)});
  }

  Future<void> _follow(
    SpfAnalysis analysis,
    int depth,
    Set<String> path,
  ) async {
    for (final (String term, String target) in analysis.targets) {
      final String label = "${"  " * depth}$term:$target";
      final String domain = _normalize(target);

      if (target.contains("%{")) {
        rows.add([label, "", "Macro, not resolved"]);
        continue;
      }
      if (path.contains(domain)) {
        rows.add([label, "", "Loop"]);
        warnings.add("$term:$target loops back: receivers return permerror.");
        continue;
      }
      if (_records >= _maxRecords) {
        rows.add([label, "", "Not followed"]);
        continue;
      }
      _records++;

      // A non-existent domain is no SPF record, not a failed lookup
      List<String> records = [];
      try {
        records = (await dns.query(target, RecordType.txt))
            .cast<Record>()
            .map((e) => txtData(e.data))
            .where(
              (e) => RegExp(r"^v=spf1(\s|$)", caseSensitive: false).hasMatch(e),
            )
            .toList();
      } on DNSLookupException catch (e) {
        if (e.statusCode != _nxDomain) {
          rows.add([label, "", "Lookup failed"]);
          warnings.add("$term:$target lookup failed: ${e.message}.");
          continue;
        }
      } catch (e) {
        rows.add([label, "", "Lookup failed"]);
        warnings.add("$term:$target lookup failed: $e.");
        continue;
      }

      if (records.isEmpty) {
        rows.add([label, "", "No SPF record"]);
        warnings.add(
          "$term:$target has no SPF record: receivers return permerror.",
        );
        continue;
      }
      if (records.length > 1) {
        rows.add([label, "", "Multiple SPF records"]);
        warnings.add(
          "$term:$target has ${records.length} SPF records: receivers return permerror.",
        );
        continue;
      }

      final SpfAnalysis child = const SpfAnalyzer().analyze(records.first);
      lookups += child.lookups;
      rows.add([label, child.lookups.toString(), "OK"]);
      await _follow(child, depth + 1, {...path, domain});
    }

    if (depth == 1 && _records >= _maxRecords) {
      warnings.add(
        "Stopped after $_maxRecords records: the lookup count is partial.",
      );
    }
  }

  /// Domains compare case-insensitively and with or without the root dot
  String _normalize(String domain) {
    final String lower = domain.toLowerCase();
    return lower.endsWith(".") ? lower.substring(0, lower.length - 1) : lower;
  }
}
