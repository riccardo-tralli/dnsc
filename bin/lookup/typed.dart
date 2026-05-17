import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";
import "../misc/ascii_table.dart";

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
      records = [Record(name: record, rType: type, ttl: -1, data: "")];
    }

    if (printResults) {
      if (dns.simple) {
        if (records.isEmpty ||
            (records.length == 1 && records.first.data.isEmpty)) {
          print("No ${type.name.toUpperCase()} records found.");
        } else {
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
        }
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
                  e.rType.name.toUpperCase(),
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
