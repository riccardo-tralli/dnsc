import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Mx {
  final DnsLookup dns;

  const Mx(this.dns);

  Future<void> query(String? record) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<MXRecord> res =
          await dns.query(record, RecordType.mx) as List<MXRecord>;
      if (res.isEmpty) {
        print("No MX records found for $record");
      } else {
        if (dns.simple) {
          print(res.map((e) => "${e.priority} ${e.exchange}").join("\n"));
          return;
        }
        AsciiTable(
          columns: ["Name", "Type", "Priority", "Exchange"],
          rows:
              res
                  .map((r) => [r.fqdn, "MX", r.priority.toString(), r.exchange])
                  .toList()
                ..sort((a, b) => int.parse(a[2]).compareTo(int.parse(b[2]))),
        ).printTable();
      }
    } catch (e) {
      rethrow;
    }
  }
}
