import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Soa {
  const Soa(this.dns);

  final DnsLookup dns;

  Future<void> query(String? record) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<SOARecord> res =
          await dns.query(record, RecordType.soa) as List<SOARecord>;
      if (res.isEmpty) {
        print("No SOA records found for $record");
      } else {
        if (dns.simple) {
          print(
            res
                .map(
                  (e) =>
                      "${dns.count ? "${res.indexOf(e) + 1}) " : ""}${e.mname} ${e.rname} ${e.serial} ${e.refresh} ${e.retry} ${e.expire} ${e.minimum}",
                )
                .join("\n"),
          );
          return;
        }
        AsciiTable(
          columns: [
            if (dns.count) "#",
            "Name",
            "Type",
            "Primary",
            "Responsible",
            "Serial",
            "Refresh",
            "Retry",
            "Expire",
            "Minimum",
          ],
          rows: res
              .map(
                (r) => [
                  if (dns.count) "${res.indexOf(r) + 1}",
                  r.fqdn,
                  "SOA",
                  r.mname,
                  r.rname,
                  r.serial.toString(),
                  r.refresh.toString(),
                  r.retry.toString(),
                  r.expire.toString(),
                  r.minimum.toString(),
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
