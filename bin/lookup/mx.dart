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
      List<MXRecord> res =
          await dns.query(record, RecordType.mx) as List<MXRecord>;
      if (res.isEmpty) {
        print("No MX records found for $record");
      } else {
        if (dns.first) {
          res = [res.first];
        } else if (dns.last) {
          res = [res.last];
        }
        if (dns.simple) {
          print(
            res
                .map(
                  (e) =>
                      "${dns.count ? "${res.indexOf(e) + 1}) " : ""}${e.priority} ${e.exchange}",
                )
                .join("\n"),
          );
          return;
        }
        AsciiTable(
          columns: [if (dns.count) "#", "Name", "Type", "Priority", "Exchange"],
          rows:
              res
                  .map(
                    (r) => [
                      if (dns.count) "${res.indexOf(r) + 1}",
                      r.fqdn,
                      "MX",
                      r.priority.toString(),
                      r.exchange,
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
