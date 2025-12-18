import 'package:flutter/material.dart';

import '../services/lock_state_service.dart';

class LockScreen extends StatelessWidget {
  const LockScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // SECURITY PLACEHOLDER (Phase 3): biometric/passcode unlock will replace the
    // current unlock action. Keep this screen stateless.
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Spacer(flex: 3),
                  Icon(
                    Icons.lock_outline,
                    size: 84,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 28),
                  Text(
                    'Secure Vault',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Unlock to access your files',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context)
                              .colorScheme
                              .onSurface
                              .withOpacity(0.75),
                        ),
                    textAlign: TextAlign.center,
                  ),
                  const Spacer(flex: 2),
                  SizedBox(
                    height: 52,
                    child: FilledButton(
                      onPressed: () {
                        // MANUAL TEST: Unlock -> Vault.
                        LockStateService.instance.unlock();
                        Navigator.of(context).pushReplacementNamed('/vault');
                      },
                      child: const Text('Unlock'),
                    ),
                  ),
                  const SizedBox(height: 18),
                  Text(
                    'For your security, the vault will auto-lock when the app is backgrounded.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context)
                              .colorScheme
                              .onSurface
                              .withOpacity(0.6),
                        ),
                    textAlign: TextAlign.center,
                  ),
                  const Spacer(flex: 2),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
