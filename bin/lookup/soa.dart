import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";
import "../misc/nxdomain.dart";

class Soa {
  final DnsLookup dns;

  const Soa(this.dns);

  Future<List<SOARecord>> query(
    String record, {
    Function(SOARecord)? filter,
    bool printResults = true,
  }) async {
    List<SOARecord> records = [];

    try {
      records = await dns.query(record, RecordType.soa) as List<SOARecord>;

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
        nxDomain(record, RecordType.soa, dns.simple);
      }
      return records;
    }

    if (printResults) {
      if (dns.simple) {
        print(
          records
              .map(
                (e) =>
                    "${dns.count ? "${records.indexOf(e) + 1}) " : ""}${e.mname} ${e.rname} ${e.serial} ${e.refresh} ${e.retry} ${e.expire} ${e.minimum}",
              )
              .join("\n"),
        );
      } else {
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
          rows: records
              .map(
                (e) => [
                  if (dns.count) "${records.indexOf(e) + 1}",
                  dns.full
                      ? e.fqdn
                      : e.fqdn.length > 35
                      ? "${e.fqdn.substring(0, 35)}..."
                      : e.fqdn,
                  "SOA",
                  e.mname,
                  e.rname,
                  e.serial.toString(),
                  e.refresh.toString(),
                  e.retry.toString(),
                  e.expire.toString(),
                  e.minimum.toString(),
                ],
              )
              .toList(),
        ).printTable();
      }
    }

    return records;
  }
}
