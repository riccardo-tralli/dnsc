class AsciiTable {
  final List<String> columns;
  final List<List<String>> rows;

  AsciiTable({required this.columns, required this.rows});

  String _pad(String text, int width) {
    return text.padRight(width);
  }

  String _separator(List<int> columnWidths) {
    final String body = columnWidths
        .map((width) => "-" * (width + 2))
        .join("+");
    return "+$body+";
  }

  String _row(List<String> values, List<int> columnWidths) {
    final String body = values
        .asMap()
        .entries
        .map((entry) => " ${_pad(entry.value, columnWidths[entry.key])} ")
        .join("|");
    return "|$body|";
  }

  void printTable() {
    final List<int> columnWidths = List.generate(columns.length, (index) {
      final int headerWidth = columns[index].length;
      final int maxRowWidth = rows
          .map((row) => row[index].length)
          .fold(0, (prev, curr) => curr > prev ? curr : prev);
      return headerWidth > maxRowWidth ? headerWidth : maxRowWidth;
    });

    final String separator = _separator(columnWidths);

    // Print header
    print(separator);
    print(_row(columns, columnWidths));
    print(separator);

    // Print rows
    for (final row in rows) {
      print(_row(row, columnWidths));
      print(separator);
    }
  }
}
