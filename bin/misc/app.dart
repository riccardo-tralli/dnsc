import "const.dart";

class App {
  static void logo() {
    print("""       __               
  ____/ /___  __________
 / __  / __ \\/ ___/ ___/
/ /_/ / / / (__  ) /__  
\\__,_/_/ /_/____/\\___/  """);
    print(" DNS Checker CLI Tool");
  }

  static void version() => print("dnsc version: $appVersion");
}
