import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Typed {
  final DnsLookup dns;

  const Typed(this.dns);

  Future<void> query(String? record, RecordType type) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<Record> res = await dns.query(record, type) as List<Record>;
      if (res.isEmpty) {
        print("No ${type.name.toUpperCase()} records found for $record");
      } else {
        if (dns.simple) {
          print(res.map((e) => e.data).join("\n"));
          return;
        }
        AsciiTable(
          columns: ["Name", "Type", "TTL", "Data"],
          rows: res
              .map(
                (r) => [
                  r.name,
                  r.rType.name.toUpperCase(),
                  r.ttl.toString(),
                  r.data,
                ],
              )
              .toList(),
        ).printTable();
      }
    } catch (e) {
      print(e);
    }
  }
}
