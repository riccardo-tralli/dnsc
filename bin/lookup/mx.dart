import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";
import "../misc/nxdomain.dart";

class Mx {
  final DnsLookup dns;

  const Mx(this.dns);

  Future<List<MXRecord>> query(
    String record, {
    Function(MXRecord)? filter,
    bool printResults = true,
  }) async {
    List<MXRecord> records = [];

    try {
      records = await dns.query(record, RecordType.mx) as List<MXRecord>;

      if (filter != null) {
        records = records.where((e) => filter(e)).toList();
      }

      if (records.isNotEmpty) {
        if (dns.first) {
          records = [records.first];
        } else if (dns.last) {
          records = [records.last];
        }
      }
    } catch (_) {
      if (printResults) {
        nxDomain(record, RecordType.mx, dns.simple);
      }
      return records;
    }

    if (printResults) {
      if (dns.simple) {
        print(
          records
              .map(
                (e) =>
                    "${dns.count ? "${records.indexOf(e) + 1}) " : ""}${e.priority} ${e.exchange}",
              )
              .join("\n"),
        );
      } else {
        AsciiTable(
          columns: [if (dns.count) "#", "Name", "Type", "Priority", "Exchange"],
          rows:
              records
                  .map(
                    (e) => [
                      if (dns.count) "${records.indexOf(e) + 1}",
                      dns.full
                          ? e.fqdn
                          : e.fqdn.length > 35
                          ? "${e.fqdn.substring(0, 35)}..."
                          : e.fqdn,
                      "MX",
                      e.priority.toString(),
                      e.exchange,
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
    }

    return records;
  }
}
