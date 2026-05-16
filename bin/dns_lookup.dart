import 'package:dnsolve/dnsolve.dart';
import "misc/ascii_table.dart";

class DnsLookup {
  final String? nameserver;
  final int timeout;
  final bool simple;

  late DNSolve _dns;

  DnsLookup({this.nameserver, this.timeout = 1, this.simple = false}) {
    if (nameserver == null || nameserver == "" || nameserver!.isEmpty) {
      _dns = DNSolve();
    } else {
      _dns = DNSolve(server: DNSServer.custom(nameserver!));
    }
  }

  Future<List<dynamic>> _query(String record, RecordType type) async {
    try {
      final ResolveResponse res = await _dns.lookup(
        record,
        type: type,
        timeout: Duration(seconds: timeout),
      );
      if (res.answer?.records?.isEmpty ?? true) {
        return [];
      }
      if (type == RecordType.mx) {
        return res.answer!.mxs!;
      }
      return res.answer!.records!;
    } catch (_) {
      rethrow;
    }
  }

  Future<void> typed(String? record, RecordType type) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<Record> res = await _query(record, type) as List<Record>;
      if (res.isEmpty) {
        print("No ${type.name} records found for $record");
      } else {
        if (simple) {
          print(res.map((e) => e.data).join("\n"));
          return;
        }
        AsciiTable(
          columns: ["Name", "Type", "TTL", "Data"],
          rows: res
              .map((r) => [r.name, r.rType.name, r.ttl.toString(), r.data])
              .toList(),
        ).printTable();
      }
    } catch (e) {
      print(e);
    }
  }

  Future<void> mx(String? record) async {
    if (record == null || record == "" || record.isEmpty) {
      print("Record cannot be null!");
      return;
    }
    try {
      final List<MXRecord> res =
          await _query(record, RecordType.mx) as List<MXRecord>;
      if (res.isEmpty) {
        print("No MX records found for $record");
      } else {
        if (simple) {
          print(res.map((e) => "${e.priority} ${e.exchange}").join("\n"));
          return;
        }
        AsciiTable(
          columns: ["Name", "Type", "Priority", "Exchange"],
          rows:
              res
                  .map((r) => [r.fqdn, "mx", r.priority.toString(), r.exchange])
                  .toList()
                ..sort((a, b) => int.parse(a[2]).compareTo(int.parse(b[2]))),
        ).printTable();
      }
    } catch (e) {
      print(e);
    }
  }
}
