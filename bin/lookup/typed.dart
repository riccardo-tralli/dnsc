import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";

class Typed {
  final DnsLookup dns;

  const Typed(this.dns);

  Future<List<Record>> query(
    String record,
    RecordType type, {
    bool Function(Record)? filter,
    bool printResults = true,
  }) async {
    final List<Record>? records = await dns.fetch<Record>(
      record,
      type,
      filter: filter,
    );
    if (records == null) {
      return [];
    }

    if (printResults) {
      dns.printRecords<Record>(
        records,
        type: type.name.toUpperCase(),
        columns: ["Name", "Type", "TTL", "Data"],
        row: (e) => [
          dns.fitName(e.name),
          type.name.toUpperCase(),
          e.ttl.toString(),
          dns.fitData(e.data),
        ],
        line: (e) => dns.fitData(e.data),
      );
    }

    return records;
  }
}
