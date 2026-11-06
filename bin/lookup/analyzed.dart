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
        "Warning: ${records.length} ${analyzer.type} records found, receivers treat this as an error.",
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
      _printRows(analysis.rows, analyzer.type, analyzer.columns, fit: true);
      if (tree != null) {
        print("");
        _printRows(tree.rows, "SPF", ["Record", "Lookups", "Status"]);
      }
      for (final String note in analysis.notes) {
        print("Note: $note");
      }
      for (final String warning in [...analysis.warnings, ...?tree?.warnings]) {
        print("Warning: $warning");
      }
    }
  }

  /// Prints analysis rows, shortening all but the last column if [fit]
  void _printRows(
    List<List<String>> rows,
    String type,
    List<String> columns, {
    bool fit = false,
  }) {
    String cell(List<String> row, int i) =>
        fit && i < row.length - 1 ? dns.fitData(row[i]) : row[i];
    dns.printRecords<List<String>>(
      rows,
      type: type,
      columns: columns,
      row: (row) => [for (int i = 0; i < row.length; i++) cell(row, i)],
      line: (row) => [
        for (int i = 0; i < row.length; i++)
          if (row[i].isNotEmpty) cell(row, i),
      ].join(" | "),
    );
  }
}
