import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Typed {
  final DnsLookup dns;

  const Typed(this.dns);

  Future<void> query(
    String? record,
    RecordType type, {
    Function(Record)? filter,
  }) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      List<Record> res = await dns.query(record, type) as List<Record>;
      if (filter != null) {
        res = res.where((e) => filter(e)).toList();
      }
      if (res.isEmpty) {
        print("No ${type.name.toUpperCase()} records found for $record");
      } else {
        if (dns.simple) {
          print(
            res
                .map(
                  (e) =>
                      "${dns.count ? "${res.indexOf(e) + 1}) " : ""}${dns.full
                          ? e.data
                          : e.data.length > 50
                          ? "${e.data.substring(0, 50)}..."
                          : e.data}",
                )
                .join("\n"),
          );
          return;
        }
        AsciiTable(
          columns: [if (dns.count) "#", "Name", "Type", "TTL", "Data"],
          rows: res
              .map(
                (r) => [
                  if (dns.count) "${res.indexOf(r) + 1}",
                  dns.full
                      ? r.name
                      : r.name.length > 35
                      ? "${r.name.substring(0, 35)}..."
                      : r.name,
                  r.rType.name.toUpperCase(),
                  r.ttl.toString(),
                  dns.full
                      ? r.data
                      : r.data.length > 50
                      ? "${r.data.substring(0, 50)}..."
                      : r.data,
                ],
              )
              .toList(),
        ).printTable();
      }
    } catch (e) {
      rethrow;
    }
  }
}
