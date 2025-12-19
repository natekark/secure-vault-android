package com.krish.securevault.secure_vault

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException

class MainActivity : FlutterFragmentActivity() {
  private val channelName = "secure_vault/crypto"
  private val keyAlias = "secure_vault_aes_gcm_key"

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "canAuthenticate" -> {
            result.success(canAuthenticate())
          }
          "authenticate" -> {
            authenticate(result)
          }
          "isKeyPresent" -> {
            result.success(isKeyPresent())
          }
          "generateKeyIfNeeded" -> {
            try {
              generateKeyIfNeeded()
              result.success(true)
            } catch (e: Exception) {
              result.error("KEY_GENERATION_FAILED", e.message, null)
            }
          }
          else -> result.notImplemented()
        }
      }
  }

  private fun canAuthenticate(): Boolean {
    val manager = BiometricManager.from(this)
    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
    return manager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
  }

  private fun authenticate(result: MethodChannel.Result) {
    if (!canAuthenticate()) {
      result.success(false)
      return
    }

    val cipher = try {
      val key = getSecretKeyOrNull() ?: run {
        result.success(false)
        return
      }
      Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, key)
      }
    } catch (e: KeyPermanentlyInvalidatedException) {
      deleteKeyIfPresent()
      result.success(false)
      return
    } catch (e: Exception) {
      result.success(false)
      return
    }

    val executor = ContextCompat.getMainExecutor(this)
    var responded = false
    val prompt = BiometricPrompt(
      this,
      executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(authenticationResult: BiometricPrompt.AuthenticationResult) {
          if (responded) return
          responded = true
          result.success(true)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          if (responded) return
          responded = true
          result.success(false)
        }

        override fun onAuthenticationFailed() {
          // Keep prompt open; don't respond yet.
        }
      }
    )

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Unlock Secure Vault")
      .setSubtitle("Authenticate to access your vault")
      .setConfirmationRequired(false)
      .setNegativeButtonText("Cancel")
      .apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
      }
      .build()

    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
  }

  private fun isKeyPresent(): Boolean {
    val ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    return ks.containsAlias(keyAlias)
  }

  private fun generateKeyIfNeeded() {
    if (isKeyPresent()) {
      val key = getSecretKeyOrNull()
      if (key != null) {
        try {
          Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, key)
          return
        } catch (e: UserNotAuthenticatedException) {
          return
        } catch (e: KeyPermanentlyInvalidatedException) {
          deleteKeyIfPresent()
        } catch (_: Exception) {
          return
        }
      } else {
        deleteKeyIfPresent()
      }
    }

    val keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES,
      "AndroidKeyStore"
    )

    val builder = KeyGenParameterSpec.Builder(
      keyAlias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_BIOMETRIC_STRONG
      )
    } else {
      @Suppress("DEPRECATION")
      builder.setUserAuthenticationValidityDurationSeconds(-1)
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      builder.setInvalidatedByBiometricEnrollment(true)
    }

    keyGenerator.init(builder.build())
    keyGenerator.generateKey()
  }

  private fun getSecretKeyOrNull(): SecretKey? {
    val ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    return ks.getKey(keyAlias, null) as SecretKey?
  }

  private fun deleteKeyIfPresent() {
    val ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    if (ks.containsAlias(keyAlias)) {
      ks.deleteEntry(keyAlias)
    }
  }
}
