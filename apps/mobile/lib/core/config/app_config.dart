class AppConfig {
  static const String appName = 'MaintenX Mobile';
  static const String appVersion = '0.1.0-bootstrap';

  // Default to Android emulator loopback; can be overridden via dart-define
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:5000',
  );
}
