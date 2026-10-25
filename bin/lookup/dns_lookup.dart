import "dart:io";

import 'package:dnsolve/dnsolve.dart';
import "../misc/ascii_table.dart";
import "../misc/const.dart";

// Max characters shown for names and data unless --full is set
const int _nameWidth = 35;
const int _dataWidth = 50;

class DnsLookup {
  final String? nameserver;
  final int timeout;
  final bool simple;
  final bool full;
  final bool count;
  final bool first;
  final bool last;

  late final DNSolve _dns;

  DnsLookup({
    this.nameserver,
    this.timeout = 5,
    this.simple = false,
    this.full = false,
    this.count = false,
    this.first = false,
    this.last = false,
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
          return <Record>[];
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
            return <MXRecord>[];
          }
          return res.answer!.mxs!;
        case RecordType.soa:
          if (res.answer?.soas?.isEmpty ?? true) {
            return <SOARecord>[];
          }
          return res.answer!.soas!;
        case RecordType.srv:
          if (res.answer?.srvs?.isEmpty ?? true) {
            return <SRVRecord>[];
          }
          return res.answer!.srvs!;
        default:
          if (res.answer?.records?.isEmpty ?? true) {
            return <Record>[];
          }
          return res.answer!.records!;
      }
    } catch (_) {
      rethrow;
    }
  }

  /// Queries [record] and applies [sort], [filter] and --first/--last, in
  /// this order. Returns null if the lookup fails, after reporting the error.
  Future<List<T>?> fetch<T>(
    String record,
    RecordType type, {
    bool Function(T)? filter,
    int Function(T, T)? sort,
  }) async {
    try {
      // A copy, so sorting leaves the resolver's (cached) answer untouched
      List<T> records = List<T>.from(await query(record, type));

      if (sort != null) {
        records.sort(sort);
      }

      if (filter != null) {
        records = records.where(filter).toList();
      }

      if (records.isNotEmpty) {
        if (first) {
          records = [records.first];
        } else if (last) {
          records = [records.last];
        }
      }

      return records;
    } catch (e) {
      printError(record, type, e);
      return null;
    }
  }

  void printError(String record, RecordType type, Object error) {
    stderr.writeln(
      "${type.name.toUpperCase()} lookup for $record failed: $error",
    );
    exitCode = lookupErrorExitCode;
  }

  String fitName(String value) => _fit(value, _nameWidth);

  String fitData(String value) => _fit(value, _dataWidth);

  String _fit(String value, int width) =>
      full || value.length <= width ? value : "${value.substring(0, width)}...";

  /// Prints [records] as plain lines with --simple, as a table otherwise,
  /// prepending the record number when --count is set. Without records it
  /// prints [emptyMessage], or "No [type] records found.".
  void printRecords<T>(
    List<T> records, {
    required String type,
    required List<String> columns,
    required List<String> Function(T) row,
    required String Function(T) line,
    String? emptyMessage,
  }) {
    if (records.isEmpty) {
      print(emptyMessage ?? "No $type records found.");
    } else if (simple) {
      print(
        records.indexed
            .map((e) => "${count ? "${e.$1 + 1}) " : ""}${line(e.$2)}")
            .join("\n"),
      );
    } else {
      AsciiTable(
        columns: [if (count) "#", ...columns],
        rows: records.indexed
            .map((e) => [if (count) "${e.$1 + 1}", ...row(e.$2)])
            .toList(),
      ).printTable();
    }
  }

  /// Releases the resolver; call once all queries for a command are done,
  /// since a single command (e.g. m365) can run several queries.
  void dispose() => _dns.dispose();
}
