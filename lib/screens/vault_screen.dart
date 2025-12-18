import 'package:flutter/material.dart';

import '../services/lock_state_service.dart';

class VaultScreen extends StatelessWidget {
  const VaultScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // SECURITY NOTE: This screen must assume the app can lock at any time.
    // Do not store sensitive state here in Phase 2.

    return WillPopScope(
      onWillPop: () async {
        // MANUAL TEST: Press Back from Vault.
        // Expected: app locks and Vault is not reachable via back navigation.
        LockStateService.instance.lock();
        Navigator.of(context).pushNamedAndRemoveUntil('/lock', (route) => false);
        return false;
      },
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Vault'),
        ),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.lock_outline,
                  size: 72,
                  color:
                      Theme.of(context).colorScheme.onSurface.withOpacity(0.75),
                ),
                const SizedBox(height: 16),
                Text(
                  'No files yet',
                  style: Theme.of(context).textTheme.titleMedium,
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
