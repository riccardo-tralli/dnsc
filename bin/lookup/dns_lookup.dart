import 'package:dnsolve/dnsolve.dart';

class DnsLookup {
  final String? nameserver;
  final int timeout;
  final bool simple;
  final bool full;

  late final DNSolve _dns;

  DnsLookup({
    this.nameserver,
    this.timeout = 1,
    this.simple = false,
    this.full = false,
  }) {
    if (nameserver == null || nameserver == "" || nameserver!.isEmpty) {
      _dns = DNSolve();
    } else {
      _dns = DNSolve(server: DNSServer.custom(nameserver!));
    }
  }

  Future<List<dynamic>> query(String record, RecordType type) async {
    try {
      // PTR lookups use reverseLookup instead of lookup
      if (type == RecordType.ptr) {
        final List<Record> res = await _dns.reverseLookup(
          record,
          timeout: Duration(seconds: timeout),
        );
        if (res.isEmpty) {
          return [];
        }
        return res;
      }
      // All other lookups use lookup
      final ResolveResponse res = await _dns.lookup(
        record,
        type: type,
        timeout: Duration(seconds: timeout),
      );
      switch (type) {
        case RecordType.mx:
          if (res.answer?.mxs?.isEmpty ?? true) {
            return [];
          }
          return res.answer!.mxs!;
        case RecordType.soa:
          if (res.answer?.soas?.isEmpty ?? true) {
            return [];
          }
          return res.answer!.soas!;
        case RecordType.srv:
          if (res.answer?.srvs?.isEmpty ?? true) {
            return [];
          }
          return res.answer!.srvs!;
        default:
          if (res.answer?.records?.isEmpty ?? true) {
            return [];
          }
          return res.answer!.records!;
      }
    } catch (_) {
      rethrow;
    }
  }
}
