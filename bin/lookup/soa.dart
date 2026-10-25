import 'package:dnsolve/dnsolve.dart';
import "dns_lookup.dart";

class Soa {
  final DnsLookup dns;

  const Soa(this.dns);

  Future<List<SOARecord>> query(
    String record, {
    bool Function(SOARecord)? filter,
    bool printResults = true,
  }) async {
    final List<SOARecord>? records = await dns.fetch<SOARecord>(
      record,
      RecordType.soa,
      filter: filter,
    );
    if (records == null) {
      return [];
    }

    if (printResults) {
      dns.printRecords<SOARecord>(
        records,
        type: "SOA",
        columns: [
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
        row: (e) => [
          dns.fitName(e.fqdn),
          "SOA",
          e.mname,
          e.rname,
          e.serial.toString(),
          e.refresh.toString(),
          e.retry.toString(),
          e.expire.toString(),
          e.minimum.toString(),
        ],
        line: (e) =>
            "${e.mname} ${e.rname} ${e.serial} ${e.refresh} ${e.retry} ${e.expire} ${e.minimum}",
      );
    }

    return records;
  }
}
