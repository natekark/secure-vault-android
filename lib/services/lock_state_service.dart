import 'package:flutter/foundation.dart';

class LockStateService extends ChangeNotifier {
  LockStateService._();

  static final LockStateService instance = LockStateService._();

  bool _isLocked = true;
  int _suppressInactiveUntilEpochMs = 0;
  int _suppressPausedUntilEpochMs = 0;

  bool get isLocked => _isLocked;

  bool get suppressInactiveAutoLock =>
      DateTime.now().millisecondsSinceEpoch < _suppressInactiveUntilEpochMs;

  bool get suppressPausedAutoLock =>
      DateTime.now().millisecondsSinceEpoch < _suppressPausedUntilEpochMs;

  void suppressInactiveAutoLockFor(Duration duration) {
    final now = DateTime.now().millisecondsSinceEpoch;
    _suppressInactiveUntilEpochMs = now + duration.inMilliseconds;
  }

  void suppressPausedAutoLockFor(Duration duration) {
    final now = DateTime.now().millisecondsSinceEpoch;
    _suppressPausedUntilEpochMs = now + duration.inMilliseconds;
  }

  void clearInactiveAutoLockSuppression() {
    _suppressInactiveUntilEpochMs = 0;
  }

  void clearPausedAutoLockSuppression() {
    _suppressPausedUntilEpochMs = 0;
  }

  void lock() {
    if (_isLocked) return;
    _isLocked = true;
    notifyListeners();
  }

  void unlock() {
    if (!_isLocked) return;
    _isLocked = false;
    notifyListeners();
  }
}
