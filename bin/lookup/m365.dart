import "package:dnsolve/dnsolve.dart";

import "dns_lookup.dart";
import "mx.dart";
import "typed.dart";
import "../misc/ascii_table.dart";

class M365 {
  final DnsLookup dns;

  const M365(this.dns);

  Future<void> query(String record) async {
    List<dynamic> records = [];

    try {
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
    } catch (_) {
      records = [];
    }

    if (dns.simple) {
      print(
        records
            .map((e) {
              final String count = dns.count
                  ? "${(records.indexOf(e) + 1).toString()}) "
                  : "";
              return switch (e) {
                MXRecord _ =>
                  "$count[MX] ${dns.full ? e.fqdn : (e.fqdn.length > 35 ? "${e.fqdn.substring(0, 35)}..." : e.fqdn)} ==> ${e.priority} ${e.exchange}",
                Record _ =>
                  "$count[${e.rType.name.toUpperCase()}] ${dns.full ? e.name : (e.name.length > 35 ? "${e.name.substring(0, 35)}..." : e.name)} ==> ${dns.full ? e.data : (e.data.length > 50 ? "${e.data.substring(0, 50)}..." : e.data)}",
                _ => "",
              };
            })
            .join("\n"),
      );
    } else {
      AsciiTable(
        columns: [if (dns.count) "#", "Name", "Type", "Data"],
        rows: records
            .map(
              (e) => switch (e) {
                MXRecord _ => [
                  if (dns.count) (records.indexOf(e) + 1).toString(),
                  dns.full
                      ? e.fqdn
                      : e.fqdn.length > 35
                      ? "${e.fqdn.substring(0, 35)}..."
                      : e.fqdn,
                  "MX",
                  "${e.priority} ${e.exchange}",
                ],
                _ => [
                  if (dns.count) (records.indexOf(e) + 1).toString(),
                  dns.full
                      ? (e as Record).name
                      : ((e as Record).name.length > 35
                            ? "${e.name.substring(0, 35)}..."
                            : e.name),
                  e.rType.name.toUpperCase(),
                  dns.full
                      ? e.data
                      : (e.data.length > 50
                            ? "${e.data.substring(0, 50)}..."
                            : e.data),
                ],
              },
            )
            .toList(),
      ).printTable();
    }
  }
}
