import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";

class Srv {
  final DnsLookup dns;

  const Srv(this.dns);

  Future<List<SRVRecord>> query(
    String record, {
    bool Function(SRVRecord)? filter,
    bool printResults = true,
  }) async {
    final List<SRVRecord>? records = await dns.fetch<SRVRecord>(
      record,
      RecordType.srv,
      filter: filter,
      // Sort before first/last so numbering and every output mode agree
      sort: (a, b) => a.priority.compareTo(b.priority),
    );
    if (records == null) {
      return [];
    }

    if (printResults) {
      dns.printRecords<SRVRecord>(
        records,
        type: "SRV",
        columns: ["Name", "Type", "Priority", "Weight", "Port", "Target"],
        row: (e) => [
          dns.fitName(e.fqdn),
          "SRV",
          e.priority.toString(),
          e.weight.toString(),
          e.port.toString(),
          e.target ?? "",
        ],
        line: (e) => "${e.priority} ${e.weight} ${e.port} ${e.target ?? ""}",
      );
    }

    return records;
  }
}
