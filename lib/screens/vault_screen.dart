import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'lock_screen.dart';
import '../services/lock_state_service.dart';

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key});

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  static const MethodChannel _cryptoChannel = MethodChannel('secure_vault/crypto');

  List<Map<String, Object?>> _files = const [];
  bool _loading = true;

  Future<bool> _ensureAuthenticated() async {
    LockStateService.instance
        .suppressInactiveAutoLockFor(const Duration(seconds: 10));

    final bool keyReady =
        (await _cryptoChannel.invokeMethod<bool>('generateKeyIfNeeded')) ?? false;
    if (!keyReady) return false;

    final bool authenticated =
        (await _cryptoChannel.invokeMethod<bool>('authenticate', {
              'force': false,
            })) ??
            false;
    return authenticated;
  }

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
    });

    try {
      final bool authenticated = await _ensureAuthenticated();
      if (!authenticated) {
        if (!mounted) return;
        setState(() {
          _files = const [];
          _loading = false;
        });
        return;
      }
    } on PlatformException {
      if (!mounted) return;
      setState(() {
        _files = const [];
        _loading = false;
      });
      return;
    }

    try {
      final List<dynamic> raw =
          (await _cryptoChannel.invokeMethod<List<dynamic>>('listVaultFiles')) ??
              const <dynamic>[];
      final List<Map<String, Object?>> parsed = raw
          .whereType<Map>()
          .map((e) => e.map((k, v) => MapEntry(k.toString(), v)))
          .toList();

      if (!mounted) return;
      setState(() {
        _files = parsed;
        _loading = false;
      });
    } on PlatformException {
      if (!mounted) return;
      setState(() {
        _files = const [];
        _loading = false;
      });
    }
  }

  Future<void> _importFile() async {
    try {
      LockStateService.instance
          .suppressInactiveAutoLockFor(const Duration(seconds: 120));
      LockStateService.instance
          .suppressPausedAutoLockFor(const Duration(seconds: 120));

      final String? uri = await _cryptoChannel.invokeMethod<String>('pickFile');

      LockStateService.instance.clearInactiveAutoLockSuppression();
      LockStateService.instance.clearPausedAutoLockSuppression();

      if (uri == null || uri.isEmpty) return;

      final bool authenticated = await _ensureAuthenticated();
      if (!authenticated) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Authentication required')),
        );
        return;
      }

      final bool imported =
          (await _cryptoChannel.invokeMethod<bool>('importFile', {
                'uri': uri,
                'path': null,
              })) ??
              false;

      if (!mounted) return;
      if (!imported) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Import failed (native returned false)')),
        );
        return;
      }

      await _refresh();
    } on PlatformException catch (e) {
      LockStateService.instance.clearInactiveAutoLockSuppression();
      LockStateService.instance.clearPausedAutoLockSuppression();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Import failed: ${e.code} ${e.message ?? ''}')),
      );
      return;
    }
  }

  Future<void> _openFile(String id) async {
    try {
      final bool authenticated = await _ensureAuthenticated();
      if (!authenticated) return;

      LockStateService.instance
          .suppressInactiveAutoLockFor(const Duration(seconds: 30));
      LockStateService.instance
          .suppressPausedAutoLockFor(const Duration(seconds: 30));

      final bool ok =
          (await _cryptoChannel.invokeMethod<bool>('openVaultFile', {
                'id': id,
              })) ??
              false;

      LockStateService.instance.clearInactiveAutoLockSuppression();
      LockStateService.instance.clearPausedAutoLockSuppression();

      if (!mounted) return;
      if (!ok) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Unable to open file')),
        );
      }
    } on PlatformException {
      LockStateService.instance.clearInactiveAutoLockSuppression();
      LockStateService.instance.clearPausedAutoLockSuppression();
      return;
    }
  }

  @override
  Widget build(BuildContext context) {
    // SECURITY NOTE: This screen must assume the app can lock at any time.
    // Do not store sensitive state here in Phase 2.

    return WillPopScope(
      onWillPop: () async {
        // MANUAL TEST: Press Back from Vault.
        // Expected: app locks and Vault is not reachable via back navigation.
        LockStateService.instance.lock();
        Navigator.pushAndRemoveUntil(
          context,
          MaterialPageRoute(builder: (_) => const LockScreen()),
          (_) => false,
        );
        return false;
      },
      child: Scaffold(
        appBar: AppBar(
          automaticallyImplyLeading: false,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back),
            onPressed: () {
              LockStateService.instance.lock();
              Navigator.pushAndRemoveUntil(
                context,
                MaterialPageRoute(builder: (_) => const LockScreen()),
                (_) => false,
              );
            },
          ),
          title: const Text('Vault'),
        ),
        floatingActionButton: FloatingActionButton(
          onPressed: _importFile,
          child: const Icon(Icons.add),
        ),
        body: RefreshIndicator(
          onRefresh: _refresh,
          child: _loading
              ? ListView(
                  children: const [
                    SizedBox(height: 280),
                    Center(child: CircularProgressIndicator()),
                  ],
                )
              : (_files.isEmpty
                  ? ListView(
                      children: [
                        const SizedBox(height: 140),
                        Icon(
                          Icons.lock_outline,
                          size: 72,
                          color: Theme.of(context)
                              .colorScheme
                              .onSurface
                              .withOpacity(0.75),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'No files yet',
                          style: Theme.of(context).textTheme.titleMedium,
                          textAlign: TextAlign.center,
                        ),
                      ],
                    )
                  : ListView.separated(
                      itemCount: _files.length,
                      separatorBuilder: (_, __) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final item = _files[index];
                        final id = (item['id'] ?? '').toString();
                        final name = (item['name'] ?? 'File').toString();
                        final mime = (item['mime'] ?? '').toString();
                        final size = item['size'];

                        return ListTile(
                          title: Text(name),
                          subtitle: Text(mime.isEmpty ? 'Unknown type' : mime),
                          trailing: Text(size?.toString() ?? ''),
                          onTap: id.isEmpty ? null : () => _openFile(id),
                        );
                      },
                    )),
        ),
      ),
    );
  }
}
