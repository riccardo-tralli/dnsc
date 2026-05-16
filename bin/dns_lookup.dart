import 'package:dnsolve/dnsolve.dart';

class DnsLookup {
  static final DNSolve _dns = DNSolve();

  static Future<List<Record>> _query(String record, RecordType type) async {
    try {
      final ResolveResponse res = await _dns.lookup(
        record,
        type: type,
        timeout: const Duration(seconds: 1),
      );
      if (res.answer?.records?.isEmpty ?? true) {
        return [];
      }
      return res.answer!.records!;
    } catch (_) {
      rethrow;
    }
  }

  static Future<void> a(String? record) async {
    if (record == null) {
      throw ArgumentError("Record cannot be null");
    }
    try {
      final List<Record> res = await _query(record, RecordType.A);
      if (res.isEmpty) {
        print("No A records found for $record");
      } else {
        print(res.map((e) => e.data).join("\n"));
      }
    } catch (e) {
      print("Error looking up A record: $e");
    }
  }
}
