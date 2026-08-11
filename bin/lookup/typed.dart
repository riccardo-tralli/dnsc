import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";
import "../misc/nxdomain.dart";

class Typed {
  final DnsLookup dns;

  const Typed(this.dns);

  Future<List<Record>> query(
    String record,
    RecordType type, {
    Function(Record)? filter,
    bool printResults = true,
  }) async {
    List<Record> records = [];

    try {
      records = await dns.query(record, type) as List<Record>;

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
        nxDomain(record, type, dns.simple);
      }
      return records;
    }

    if (printResults) {
      if (dns.simple) {
        print(
          records
              .map(
                (e) =>
                    "${dns.count ? "${records.indexOf(e) + 1}) " : ""}${dns.full
                        ? e.data
                        : e.data.length > 50
                        ? "${e.data.substring(0, 50)}..."
                        : e.data}",
              )
              .join("\n"),
        );
      } else {
        AsciiTable(
          columns: [if (dns.count) "#", "Name", "Type", "TTL", "Data"],
          rows: records
              .map(
                (e) => [
                  if (dns.count) "${records.indexOf(e) + 1}",
                  dns.full
                      ? e.name
                      : e.name.length > 35
                      ? "${e.name.substring(0, 35)}..."
                      : e.name,
                  type.name.toUpperCase(),
                  e.ttl.toString(),
                  dns.full
                      ? e.data
                      : e.data.length > 50
                      ? "${e.data.substring(0, 50)}..."
                      : e.data,
                ],
              )
              .toList(),
        ).printTable();
      }
    }

    return records;
  }
}
