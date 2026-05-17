import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Srv {
  const Srv(this.dns);

  final DnsLookup dns;

  Future<void> query(String? record) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<SRVRecord> res =
          await dns.query(record, RecordType.srv) as List<SRVRecord>;
      if (res.isEmpty) {
        print("No SRV records found for $record");
      } else {
        if (dns.simple) {
          print(
            res
                .map(
                  (e) =>
                      "${dns.count ? "${res.indexOf(e) + 1}) " : ""}${e.priority} ${e.weight} ${e.port} ${e.target}",
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
            "Priority",
            "Weight",
            "Port",
            "Target",
          ],
          rows:
              res
                  .map(
                    (r) => [
                      if (dns.count) "${res.indexOf(r) + 1}",
                      r.fqdn,
                      "SRV",
                      r.priority.toString(),
                      r.weight.toString(),
                      r.port.toString(),
                      r.target ?? "",
                    ],
                  )
                  .toList()
                ..sort(
                  (a, b) => int.parse(
                    a[dns.count ? 3 : 2],
                  ).compareTo(int.parse(b[dns.count ? 3 : 2])),
                ),
        ).printTable();
      }
    } catch (e) {
      rethrow;
    }
  }
}
