import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

class Srv {
  final DnsLookup dns;

  const Srv(this.dns);

  Future<List<SRVRecord>> query(
    String record, {
    Function(SRVRecord)? filter,
    bool printResults = true,
  }) async {
    List<SRVRecord> records = [];

    try {
      records = await dns.query(record, RecordType.srv) as List<SRVRecord>;

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
      records = [SRVRecord(priority: 0, weight: 0, port: 0, fqdn: record)];
    }

    if (printResults) {
      if (dns.simple) {
        if (records.isEmpty ||
            (records.length == 1 && records.first.port == 0)) {
          print("No SRV records found.");
        } else {
          print(
            records
                .map(
                  (e) =>
                      "${dns.count ? "${records.indexOf(e) + 1}) " : ""}${e.priority} ${e.weight} ${e.port} ${e.target}",
                )
                .join("\n"),
          );
        }
      } else {
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
              records
                  .map(
                    (e) => [
                      if (dns.count) "${records.indexOf(e) + 1}",
                      dns.full
                          ? e.fqdn
                          : e.fqdn.length > 35
                          ? "${e.fqdn.substring(0, 35)}..."
                          : e.fqdn,
                      "SRV",
                      e.priority.toString(),
                      e.weight.toString(),
                      e.port.toString(),
                      e.target ?? "",
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
