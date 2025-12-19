import 'package:flutter/material.dart';
import 'screens/lock_screen.dart';
import 'screens/vault_screen.dart';
import 'services/lock_state_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SecureVaultApp());
}

class SecureVaultApp extends StatefulWidget {
  const SecureVaultApp({super.key});

  @override
  State<SecureVaultApp> createState() => _SecureVaultAppState();
}

class _SecureVaultAppState extends State<SecureVaultApp>
    with WidgetsBindingObserver {
  final LockStateService _lockState = LockStateService.instance;
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _lockState.addListener(_handleLockStateChanged);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _lockState.removeListener(_handleLockStateChanged);
    super.dispose();
  }

  void _handleLockStateChanged() {
    if (!_lockState.isLocked) return;

    // MANUAL TEST: While on Vault, background the app (Home/Recents) and then
    // return. The app should land on Lock Screen with no back-navigation to Vault.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _navigatorKey.currentState?.pushNamedAndRemoveUntil(
        '/lock',
        (route) => false,
      );
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Zero-trust model:
    // - App starts locked (see LockStateService default).
    // - Any backgrounding locks immediately.
    // - On resume, if locked, force Lock Screen.

    // MANUAL TEST: Press Home or open Recents. This triggers paused/inactive on
    // Android, and we lock immediately.
    if (state == AppLifecycleState.inactive) {
      if (_lockState.suppressInactiveAutoLock) return;
      _lockState.lock();
      return;
    }

    if (state == AppLifecycleState.paused || state == AppLifecycleState.detached) {
      if (_lockState.suppressPausedAutoLock) return;
      _lockState.lock();
      return;
    }

    // MANUAL TEST: Reopen app from launcher/recents. On resume we redirect if
    // still locked.
    if (state == AppLifecycleState.resumed && _lockState.isLocked) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _navigatorKey.currentState?.pushNamedAndRemoveUntil(
          '/lock',
          (route) => false,
        );
      });
    }
  }

  Route<dynamic> _onGenerateRoute(RouteSettings settings) {
    final String name = settings.name ?? '/lock';

    // Prevent deep navigation into Vault when locked.
    if (name == '/vault' && _lockState.isLocked) {
      return MaterialPageRoute(
        builder: (_) => const LockScreen(),
        settings: const RouteSettings(name: '/lock'),
      );
    }

    switch (name) {
      case '/vault':
        return MaterialPageRoute(
          builder: (_) => const VaultScreen(),
          settings: settings,
        );
      case '/lock':
      default:
        return MaterialPageRoute(
          builder: (_) => const LockScreen(),
          settings: const RouteSettings(name: '/lock'),
        );
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true),
      navigatorKey: _navigatorKey,
      onGenerateRoute: _onGenerateRoute,
      initialRoute: _lockState.isLocked ? '/lock' : '/vault',
    );
  }
}
