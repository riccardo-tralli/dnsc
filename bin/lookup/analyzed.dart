import 'package:dnsolve/dnsolve.dart';
import "../analysis/analysis.dart";
import "../analysis/spf.dart";
import "dns_lookup.dart";
import "spf_tree.dart";

/// TXT lookup that breaks each record down into its terms with [analyzer]
class Analyzed {
  final DnsLookup dns;

  const Analyzed(this.dns);

  Future<void> query(
    String record,
    RecordAnalyzer analyzer, {
    bool Function(Record)? filter,
    bool recursive = false,
  }) async {
    final List<Record>? records = await dns.fetch<Record>(
      record,
      RecordType.txt,
      filter: filter,
    );
    if (records == null) {
      return;
    }
    if (records.isEmpty) {
      print("No ${analyzer.type} records found.");
      return;
    }

    if (records.length > 1) {
      print(
        "${Severity.error.label}: ${records.length} ${analyzer.type} records found, receivers treat this as an error.",
      );
      print("");
    }

    for (final (int index, Record e) in records.indexed) {
      if (index > 0) {
        print("");
      }
      final String data = txtData(e.data);
      Analysis analysis = analyzer.analyze(data);

      // Re-analyze with the nested lookups, so the total is checked too
      SpfTree? tree;
      if (recursive && analysis is SpfAnalysis) {
        tree = SpfTree(dns);
        await tree.resolve(e.name, analysis);
        analysis = SpfAnalyzer(nestedLookups: tree.lookups).analyze(data);
      }

      // Descriptions (last column) are never shortened
      _printRows(
        analysis.rows,
        analyzer.type,
        analyzer.columns,
        analysis.severityOf,
        fit: true,
      );
      final List<Issue> issues = [...analysis.issues];
      if (tree != null) {
        final Analysis nested = tree.analysis;
        final Analysis root = analysis;
        print("");
        _printRows(
          nested.rows,
          "SPF",
          ["Record", "Lookups", "Status"],
          // The first row is the queried record, whose issues are above
          (row) => row == 0 ? maxSeverity(root.issues) : nested.severityOf(row),
        );
        issues.addAll(nested.issues);
      }

      for (final Severity severity in Severity.values.reversed) {
        for (final Issue issue in issues.where((e) => e.severity == severity)) {
          print("${severity.label}: ${issue.message}");
        }
      }
      for (final String note in analysis.notes) {
        print("Note: $note");
      }
    }
  }

  /// Prints analysis rows after a check column that marks the rows with
  /// issues, shortening all but the last column if [fit]
  void _printRows(
    List<List<String>> rows,
    String type,
    List<String> columns,
    Severity? Function(int) severityOf, {
    bool fit = false,
  }) {
    String cell(List<String> row, int i) =>
        fit && i < row.length - 1 ? dns.fitData(row[i]) : row[i];
    dns.printRecords<(int, List<String>)>(
      rows.indexed.toList(),
      type: type,
      columns: ["Check", ...columns],
      row: (e) => [
        severityOf(e.$1)?.marker ?? "",
        for (int i = 0; i < e.$2.length; i++) cell(e.$2, i),
      ],
      line: (e) => [
        ?severityOf(e.$1)?.marker,
        for (int i = 0; i < e.$2.length; i++)
          if (e.$2[i].isNotEmpty) cell(e.$2, i),
      ].join(" | "),
    );
  }
}
