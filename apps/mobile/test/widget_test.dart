import 'package:flutter_test/flutter_test.dart';
import 'package:maintenx_mobile/main.dart';

void main() {
  testWidgets('MaintenX startup screen renders title and status', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const MaintenXApp());

    // Verify that application title is rendered
    expect(find.text('MaintenX'), findsWidgets);
    expect(find.text('Bootstrap Ready'), findsOneWidget);
  });
}
