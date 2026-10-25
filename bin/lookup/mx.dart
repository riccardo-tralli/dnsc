import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

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
      // Sort by priority before first/last so numbering and every output mode
      // agree; sort a copy to leave the resolver's (cached) answer untouched
      records = [...records]..sort((a, b) => a.priority.compareTo(b.priority));

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
    } catch (e) {
      dns.printError(record, RecordType.mx, e);
      return [];
    }

    if (printResults) {
      if (records.isEmpty) {
        print("No MX records found.");
      } else if (dns.simple) {
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
          rows: records
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
              .toList(),
        ).printTable();
      }
    }

    return records;
  }
}
