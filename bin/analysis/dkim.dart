import "dart:convert";

import "analysis.dart";

/// DKIM key record analysis (RFC 6376, 3.6.1)
class DkimAnalyzer extends RecordAnalyzer {
  static const int _minKeyBits = 1024;
  static const int _recommendedKeyBits = 2048;

  const DkimAnalyzer();

  @override
  String get type => "DKIM";

  @override
  List<String> get columns => ["Tag", "Value", "Description"];

  @override
  Analysis analyze(String data) {
    final List<String> warnings = [];
    final List<(String, String)> tags = parseTags(data, warnings);
    final Map<String, String> values = {
      for (final (name, value) in tags) name: value,
    };

    if (values.containsKey("v") &&
        (tags.first.$1 != "v" || values["v"] != "DKIM1")) {
      warnings.add("'v' must be the first tag and equal to 'DKIM1'.");
    }
    if (!values.containsKey("p")) {
      warnings.add("Missing required 'p' tag.");
    }

    final List<List<String>> rows = [
      for (final (name, value) in tags)
        [name, value, _describe(name, value, values["k"], warnings)],
    ];

    return Analysis(
      rows,
      notes: [
        if (!values.containsKey("k")) "Key type not set defaults to rsa.",
      ],
      warnings: warnings,
    );
  }

  String _describe(
    String name,
    String value,
    String? keyType,
    List<String> warnings,
  ) {
    switch (name) {
      case "v":
        return "DKIM version";
      case "k":
        if (value != "rsa" && value != "ed25519") {
          warnings.add("Unknown key type '$value'.");
        }
        return "Key type";
      case "p":
        return _describeKey(value, keyType ?? "rsa", warnings);
      case "h":
        final List<String> hashes = value
            .split(":")
            .map((e) => e.trim())
            .toList();
        if (!hashes.contains("sha256")) {
          warnings.add("'h=$value' does not allow sha256: sha1 is insecure.");
        }
        return "Allowed hash algorithms";
      case "s":
        return "Service types (* = all)";
      case "t":
        final List<String> flags = value
            .split(":")
            .map((e) => e.trim())
            .toList();
        if (flags.contains("y")) {
          warnings.add(
            "Testing mode (t=y): receivers may treat mail as unsigned.",
          );
        }
        return flags
            .map(
              (e) => switch (e) {
                "y" => "testing mode",
                "s" => "no subdomains in i= identity",
                _ => "unknown flag '$e'",
              },
            )
            .join(", ");
      case "n":
        return "Notes";
      case "g":
        return "Granularity (obsolete)";
      default:
        return "Unknown tag, ignored";
    }
  }

  String _describeKey(String value, String keyType, List<String> warnings) {
    final String key = value.replaceAll(RegExp(r"\s"), "");
    if (key.isEmpty) {
      warnings.add("Empty public key: the key has been revoked.");
      return "Public key (revoked)";
    }
    final List<int> bytes;
    try {
      bytes = base64.decode(base64.normalize(key));
    } on FormatException {
      warnings.add("The public key is not valid base64.");
      return "Public key (invalid)";
    }
    if (keyType == "ed25519") {
      return "Public key (Ed25519)";
    }
    final int? bits = _rsaKeyBits(bytes);
    if (bits == null) {
      warnings.add("The public key is not a valid RSA key.");
      return "Public key (invalid)";
    }
    if (bits < _minKeyBits) {
      warnings.add(
        "$bits-bit RSA key is insecure: use $_recommendedKeyBits bits.",
      );
    } else if (bits < _recommendedKeyBits) {
      warnings.add("$bits-bit RSA key is weak: use $_recommendedKeyBits bits.");
    }
    return "Public key ($bits-bit RSA)";
  }

  /// Modulus size of an RSA key, either a SubjectPublicKeyInfo or a bare
  /// RSAPublicKey in DER format
  int? _rsaKeyBits(List<int> der) {
    final (int, int)? outer = _element(der, 0, 0x30);
    if (outer == null) {
      return null;
    }
    int offset = outer.$1;
    // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE algorithm, BIT STRING key }
    final (int, int)? algorithm = _element(der, offset, 0x30);
    if (algorithm != null) {
      final (int, int)? key = _element(der, algorithm.$1 + algorithm.$2, 0x03);
      if (key == null) {
        return null;
      }
      // The bit string starts with the number of unused bits
      final (int, int)? publicKey = _element(der, key.$1 + 1, 0x30);
      if (publicKey == null) {
        return null;
      }
      offset = publicKey.$1;
    }
    // RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
    final (int, int)? modulus = _element(der, offset, 0x02);
    if (modulus == null) {
      return null;
    }
    int start = modulus.$1;
    final int end = modulus.$1 + modulus.$2;
    while (start < end && der[start] == 0) {
      start++;
    }
    if (start == end) {
      return null;
    }
    return (end - start - 1) * 8 + der[start].bitLength;
  }

  /// Content start and length of the DER element at [offset], or null if
  /// the element is not a [tag] or is truncated
  (int, int)? _element(List<int> der, int offset, int tag) {
    if (offset + 2 > der.length || der[offset] != tag) {
      return null;
    }
    int length = der[offset + 1];
    int start = offset + 2;
    if (length & 0x80 != 0) {
      final int size = length & 0x7f;
      if (size == 0 || size > 4 || start + size > der.length) {
        return null;
      }
      length = 0;
      for (int i = 0; i < size; i++) {
        length = (length << 8) | der[start + i];
      }
      start += size;
    }
    if (start + length > der.length) {
      return null;
    }
    return (start, length);
  }
}
