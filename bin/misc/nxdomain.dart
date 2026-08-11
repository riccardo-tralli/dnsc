import 'package:dnsolve/dnsolve.dart';
import 'ascii_table.dart';

void nxDomain(String name, RecordType type, bool simple) {
  if (simple) {
    print("No records found");
    return;
  }

  AsciiTable(
    columns: ["Name", "Type", "Data"],
    rows: [
      [name, type.name.toUpperCase(), "No records found"],
    ],
  ).printTable();
}
