import 'package:flutter/foundation.dart';

class LockStateService extends ChangeNotifier {
  LockStateService._();

  static final LockStateService instance = LockStateService._();

  bool _isLocked = true;

  bool get isLocked => _isLocked;

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
