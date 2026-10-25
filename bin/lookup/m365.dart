import "package:dnsolve/dnsolve.dart";

import "dns_lookup.dart";
import "mx.dart";
import "typed.dart";

class M365 {
  final DnsLookup dns;

  const M365(this.dns);

  Future<void> query(String record) async {
    // Each lookup reports its own errors and returns an empty list on failure
    final List<Object> records = [];

    // Exchange
    records.addAll(await Mx(dns).query(record, printResults: false));
    records.addAll(
      await Typed(dns).query(
        record,
        RecordType.txt,
        filter: (e) => e.data.contains("v=spf1"),
        printResults: false,
      ),
    );
    records.addAll(
      await Typed(dns).query(
        "selector1._domainkey.$record",
        RecordType.txt,
        printResults: false,
      ),
    );
    records.addAll(
      await Typed(dns).query(
        "selector2._domainkey.$record",
        RecordType.txt,
        printResults: false,
      ),
    );
    records.addAll(
      await Typed(
        dns,
      ).query("_dmarc.$record", RecordType.txt, printResults: false),
    );
    records.addAll(
      await Typed(
        dns,
      ).query("autodiscover.$record", RecordType.cname, printResults: false),
    );
    // Intune
    records.addAll(
      await Typed(dns).query(
        "enterpriseregistration.$record",
        RecordType.cname,
        printResults: false,
      ),
    );
    records.addAll(
      await Typed(dns).query(
        "enterpriseenrollment.$record",
        RecordType.cname,
        printResults: false,
      ),
    );

    dns.printRecords<Object>(
      records,
      type: "M365",
      emptyMessage: "No Microsoft 365 records found for $record",
      columns: ["Name", "Type", "Data"],
      row: (e) {
        final (name, type, data) = _fields(e);
        return [name, type, data];
      },
      line: (e) {
        final (name, type, data) = _fields(e);
        return "[$type] $name ==> $data";
      },
    );
  }

  /// Name, type and data of a record, shortened unless --full is set
  (String, String, String) _fields(Object e) => switch (e) {
    MXRecord e => (dns.fitName(e.fqdn), "MX", "${e.priority} ${e.exchange}"),
    Record e => (
      dns.fitName(e.name),
      e.rType.name.toUpperCase(),
      dns.fitData(e.data),
    ),
    _ => ("", "", ""),
  };
}
