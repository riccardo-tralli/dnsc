import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";

class Mx {
  final DnsLookup dns;

  const Mx(this.dns);

  Future<List<MXRecord>> query(
    String record, {
    bool Function(MXRecord)? filter,
    bool printResults = true,
  }) async {
    final List<MXRecord>? records = await dns.fetch<MXRecord>(
      record,
      RecordType.mx,
      filter: filter,
      // Sort before first/last so numbering and every output mode agree
      sort: (a, b) => a.priority.compareTo(b.priority),
    );
    if (records == null) {
      return [];
    }

    if (printResults) {
      dns.printRecords<MXRecord>(
        records,
        type: "MX",
        columns: ["Name", "Type", "Priority", "Exchange"],
        row: (e) => [
          dns.fitName(e.fqdn),
          "MX",
          e.priority.toString(),
          e.exchange,
        ],
        line: (e) => "${e.priority} ${e.exchange}",
      );
    }

    return records;
  }
}
