package com.krish.securevault.secure_vault

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import android.os.Build
import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : FlutterFragmentActivity() {
  private val channelName = "secure_vault/crypto"
  private val keyAlias = "secure_vault_aes_gcm_key"
  private val vaultFolderName = "vault"
  private val metadataFileName = "metadata.enc"
  private val vaultIndexFileName = "index.json"
  private val tempDecryptedPrefix = "sv_tmp_"
  private val encryptedHeaderMagic = byteArrayOf('S'.code.toByte(), 'V'.code.toByte(), '1'.code.toByte())

  private val pickFileRequestCode = 24041
  private var pendingPickFileResult: MethodChannel.Result? = null

  override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
    super.configureFlutterEngine(flutterEngine)

    cleanupTempDecryptedFiles()

    MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
      .setMethodCallHandler { call, result ->
        when (call.method) {
          "canAuthenticate" -> {
            result.success(canAuthenticate())
          }
          "authenticate" -> {
            val args = call.arguments as? Map<*, *>
            val force = args?.get("force") as? Boolean ?: false
            authenticate(result, force)
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
          "importFile" -> {
            val args = call.arguments as? Map<*, *>
            val path = args?.get("path") as? String
            val uri = args?.get("uri") as? String
            try {
              importFile(path, uri, result)
            } catch (e: Exception) {
              Log.e("IMPORT", "Import failed", e)
              result.error("IMPORT_FAILED", e.message, null)
            }
          }
          "listVaultFiles" -> {
            try {
              val list = listVaultFiles()
              result.success(list)
            } catch (e: UserNotAuthenticatedException) {
              result.success(emptyList<Any>())
            } catch (e: KeyPermanentlyInvalidatedException) {
              deleteKeyIfPresent()
              result.success(emptyList<Any>())
            } catch (e: Exception) {
              result.error("LIST_FAILED", e.message, null)
            }
          }
          "openVaultFile" -> {
            val args = call.arguments as? Map<*, *>
            val id = args?.get("id") as? String
            if (id.isNullOrBlank()) {
              result.success(false)
              return@setMethodCallHandler
            }

            try {
              openVaultFile(id, result)
            } catch (e: Exception) {
              result.success(false)
            }
          }
          "pickFile" -> {
            pickFile(result)
          }
          else -> result.notImplemented()
        }
      }
  }

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)

    if (requestCode != pickFileRequestCode) return

    val pending = pendingPickFileResult ?: return
    pendingPickFileResult = null

    if (resultCode != Activity.RESULT_OK) {
      pending.success(null)
      return
    }

    val uri = data?.data
    if (uri == null) {
      pending.success(null)
      return
    }

    try {
      val takeFlags = (data.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION))
      contentResolver.takePersistableUriPermission(uri, takeFlags)
    } catch (e: Exception) {
      Log.e("IMPORT", "Import failed", e)
    }

    pending.success(uri.toString())
  }

  private fun pickFile(result: MethodChannel.Result) {
    if (pendingPickFileResult != null) {
      result.success(null)
      return
    }

    pendingPickFileResult = result
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
      addCategory(Intent.CATEGORY_OPENABLE)
      type = "*/*"
      addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
    }

    startActivityForResult(intent, pickFileRequestCode)
  }

  override fun onResume() {
    super.onResume()
    cleanupTempDecryptedFiles()
  }

  private fun cleanupTempDecryptedFiles() {
    try {
      val files = cacheDir.listFiles { f -> f.isFile && f.name.startsWith(tempDecryptedPrefix) } ?: return
      for (f in files) {
        try {
          f.delete()
        } catch (_: Exception) {
        }
      }
    } catch (_: Exception) {
    }
  }

  private fun canAuthenticate(): Boolean {
    val manager = BiometricManager.from(this)
    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
    return manager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
  }

  private fun authenticate(result: MethodChannel.Result, forcePrompt: Boolean) {
    // Vault listing and other non-crypto operations must not require biometric auth.
    // `force=false` is treated as a non-prompting readiness check.
    if (!forcePrompt) {
      result.success(true)
      return
    }

    cleanupTempDecryptedFiles()

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
        30,
        KeyProperties.AUTH_BIOMETRIC_STRONG
      )
    } else {
      @Suppress("DEPRECATION")
      builder.setUserAuthenticationValidityDurationSeconds(30)
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

  private fun vaultDir(): File {
    val dir = File(filesDir, vaultFolderName)
    if (!dir.exists()) {
      dir.mkdirs()
    }
    return dir
  }

  private fun metadataFile(): File {
    return File(vaultDir(), metadataFileName)
  }

  private fun vaultIndexFile(): File {
    return File(vaultDir(), vaultIndexFileName)
  }

  private fun readVaultIndex(): JSONArray {
    val f = vaultIndexFile()
    if (!f.exists()) return JSONArray()
    return try {
      val json = f.readText(Charsets.UTF_8)
      JSONArray(json)
    } catch (_: Exception) {
      JSONArray()
    }
  }

  private fun writeVaultIndex(entries: JSONArray) {
    vaultIndexFile().writeText(entries.toString(), Charsets.UTF_8)
  }

  private fun importFile(path: String?, uri: String?, result: MethodChannel.Result) {
    if (!canAuthenticate()) {
      result.error("IMPORT_FAILED", "BIOMETRIC_UNAVAILABLE", null)
      return
    }

    val key = getSecretKeyOrNull() ?: run {
      result.success(false)
      return
    }

    val (inputStream, displayName, size, mimeType, deleteFn) = openSourceForImport(path, uri)
    Log.d("IMPORT", "InputStream opened: ${inputStream != null}")

    val plaintextBytes = inputStream.use { input ->
      // Read before prompting so the InputStream/URI can be closed promptly.
      val bytes = input.readBytes()
      Log.d("IMPORT", "Read bytes size = ${bytes.size}")
      bytes
    }

    val id = UUID.randomUUID().toString()
    val vaultDir = vaultDir()
    Log.d("IMPORT", "Vault dir exists=${vaultDir.exists()} writable=${vaultDir.canWrite()}")
    val outFile = File(vaultDir, "$id.enc")

    // The keystore key requires user authentication for *each* crypto operation.
    // We pass an initialized Cipher into BiometricPrompt, then use the Cipher returned
    // by the success callback immediately (never cache/reuse it).
    val cipher = try {
      Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, key)
      }
    } catch (e: KeyPermanentlyInvalidatedException) {
      plaintextBytes.fill(0)
      deleteKeyIfPresent()
      result.success(false)
      return
    } catch (e: Exception) {
      plaintextBytes.fill(0)
      Log.e("IMPORT", "Import failed", e)
      result.error("IMPORT_FAILED", e.message, null)
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

          val authenticatedCipher = authenticationResult.cryptoObject?.cipher
          if (authenticatedCipher == null) {
            plaintextBytes.fill(0)
            result.error("IMPORT_FAILED", "AUTHENTICATION_FAILED", null)
            return
          }

          try {
            Log.d("IMPORT", "Starting AES-GCM encryption")

            // The authenticated keystore Cipher is effectively single-use.
            // Encrypt metadata + file bytes together in ONE doFinal() to avoid a second
            // keystore operation (which would require re-authentication).
            val effectiveSize = if (size >= 0) size else plaintextBytes.size.toLong()
            val metaObj = JSONObject()
            metaObj.put("id", id)
            metaObj.put("name", displayName)
            metaObj.put("size", effectiveSize)
            metaObj.put("mime", mimeType)
            metaObj.put("ts", System.currentTimeMillis())
            val metaBytes = metaObj.toString().toByteArray(Charsets.UTF_8)

            val combined = ByteBuffer
              .allocate(4 + metaBytes.size + plaintextBytes.size)
              .putInt(metaBytes.size)
              .put(metaBytes)
              .put(plaintextBytes)
              .array()

            // AES-GCM requires doFinal() exactly once per encryption operation.
            val encryptedBytes = authenticatedCipher.doFinal(combined)
            Log.d("IMPORT", "Encrypted bytes size = ${encryptedBytes.size}")
            val iv = authenticatedCipher.iv

            FileOutputStream(outFile).use { fos ->
              fos.write(encryptedHeaderMagic)
              fos.write(byteArrayOf(iv.size.toByte()))
              fos.write(iv)
              fos.write(encryptedBytes)
            }

            Log.d("IMPORT", "Encrypted file written: ${outFile.absolutePath}")

            encryptedBytes.fill(0)
            combined.fill(0)
            metaBytes.fill(0)

            deleteFn.invoke()

            try {
              val entries = readVaultIndex()
              entries.put(metaObj)
              writeVaultIndex(entries)
            } catch (e: Exception) {
              Log.e("IMPORT", "Import failed", e)
            }

            Log.d("IMPORT", "IMPORT_SUCCESS")
            result.success(true)
          } catch (e: Exception) {
            Log.e("IMPORT", "Import failed", e)
            result.error("IMPORT_FAILED", e.message, null)
          } finally {
            plaintextBytes.fill(0)
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          if (responded) return
          responded = true
          plaintextBytes.fill(0)
          Log.e("IMPORT", "Import failed", Exception(errString.toString()))
          result.error("IMPORT_FAILED", errString.toString(), null)
        }

        override fun onAuthenticationFailed() {
          // Keep prompt open; don't respond yet.
        }
      }
    )

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Unlock Secure Vault")
      .setSubtitle("Authenticate to import into your vault")
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

  private fun listVaultFiles(): List<Map<String, Any>> {
    val dir = vaultDir()
    val files = dir.listFiles { f ->
      f.isFile && f.name.endsWith(".enc") && f.name != metadataFileName
    } ?: return emptyList()

    val index = readVaultIndex()
    val indexById = HashMap<String, JSONObject>(index.length())
    for (i in 0 until index.length()) {
      val o = index.optJSONObject(i) ?: continue
      val id = o.optString("id")
      if (id.isNotBlank()) {
        indexById[id] = o
      }
    }

    val out = ArrayList<Map<String, Any>>(files.size)
    for (f in files) {
      val id = f.name.removeSuffix(".enc")
      val idx = indexById[id]
      val name = idx?.optString("name").takeUnless { it.isNullOrBlank() } ?: id
      val mime = idx?.optString("mime").takeUnless { it.isNullOrBlank() } ?: "application/octet-stream"
      val size = (idx?.optLong("size") ?: -1L).let { if (it > 0) it else f.length() }
      out.add(
        mapOf(
          "id" to id,
          "name" to name,
          "size" to size,
          "mime" to mime,
          "ts" to (idx?.optLong("ts") ?: f.lastModified()),
        )
      )
    }

    return out
  }

  private fun openVaultFile(id: String, result: MethodChannel.Result) {
    cleanupTempDecryptedFiles()

    val encryptedFile = File(vaultDir(), "$id.enc")
    if (!encryptedFile.exists()) {
      result.success(false)
      return
    }

    var mime: String? = null
    var name: String? = null
    var size: Long = -1

    val index = readVaultIndex()
    for (i in 0 until index.length()) {
      val o = index.optJSONObject(i) ?: continue
      if (o.optString("id") == id) {
        mime = o.optString("mime")
        name = o.optString("name")
        size = o.optLong("size")
        break
      }
    }

    val safeName = (name ?: id)
      .replace("/", "_")
      .replace("\\\\", "_")

    // Read encrypted bytes + IV before prompting so we can build a DECRYPT_MODE cipher.
    val encryptedBlob = try {
      encryptedFile.readBytes()
    } catch (e: Exception) {
      Log.e("IMPORT", "Import failed", e)
      result.success(false)
      return
    }

    val parsed = parseEncryptedBlob(encryptedBlob)
    if (parsed == null) {
      encryptedBlob.fill(0)
      result.success(false)
      return
    }

    val iv = parsed.first
    val cipherBytes = parsed.second

    if (!canAuthenticate()) {
      encryptedBlob.fill(0)
      iv.fill(0)
      cipherBytes.fill(0)
      result.success(false)
      return
    }

    val cipher = try {
      val key = getSecretKeyOrNull() ?: run {
        encryptedBlob.fill(0)
        iv.fill(0)
        cipherBytes.fill(0)
        result.success(false)
        return
      }
      Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
      }
    } catch (e: KeyPermanentlyInvalidatedException) {
      encryptedBlob.fill(0)
      iv.fill(0)
      cipherBytes.fill(0)
      deleteKeyIfPresent()
      result.success(false)
      return
    } catch (e: Exception) {
      encryptedBlob.fill(0)
      iv.fill(0)
      cipherBytes.fill(0)
      Log.e("IMPORT", "Import failed", e)
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

          val authenticatedCipher = authenticationResult.cryptoObject?.cipher
          if (authenticatedCipher == null) {
            encryptedBlob.fill(0)
            iv.fill(0)
            cipherBytes.fill(0)
            result.success(false)
            return
          }

          try {
            val plaintext = authenticatedCipher.doFinal(cipherBytes)
            val embedded = parseEmbeddedVaultPayloadOrNull(plaintext)
            val fileOffset = embedded?.fileOffset ?: 0

            val tempFile = File(cacheDir, "$tempDecryptedPrefix$id-$safeName")
            FileOutputStream(tempFile).use { fos ->
              fos.write(plaintext, fileOffset, plaintext.size - fileOffset)
            }

            val fpAuthority = "${packageName}.fileprovider"
            val tempUri = FileProvider.getUriForFile(this@MainActivity, fpAuthority, tempFile)

            val intent = Intent(Intent.ACTION_VIEW).apply {
              setDataAndType(tempUri, if (mime.isNullOrBlank()) "application/octet-stream" else mime)
              addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
              clipData = ClipData.newUri(contentResolver, safeName, tempUri)
            }

            val ok = try {
              startActivity(Intent.createChooser(intent, "Open"))
              true
            } catch (e: Exception) {
              Log.e("IMPORT", "Import failed", e)
              false
            }

            result.success(ok)
            plaintext.fill(0)
          } catch (e: Exception) {
            Log.e("IMPORT", "Import failed", e)
            result.success(false)
          } finally {
            encryptedBlob.fill(0)
            iv.fill(0)
            cipherBytes.fill(0)
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          if (responded) return
          responded = true
          encryptedBlob.fill(0)
          iv.fill(0)
          cipherBytes.fill(0)
          result.success(false)
        }

        override fun onAuthenticationFailed() {
          // Keep prompt open; don't respond yet.
        }
      }
    )

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Unlock Secure Vault")
      .setSubtitle("Authenticate to open this file")
      .setConfirmationRequired(false)
      .setNegativeButtonText("Cancel")
      .apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
      }
      .build()

    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    return
  }

  private data class ImportSource(
    val inputStream: InputStream,
    val displayName: String,
    val size: Long,
    val mimeType: String,
    val deleteFn: () -> Unit,
  )

  private fun openSourceForImport(path: String?, uri: String?): ImportSource {
    val effectiveUri = when {
      !uri.isNullOrBlank() -> uri
      // Some pickers/plugins provide the selected document URI in `path`.
      // For content:// URIs, File(path) will fail under scoped storage; we must use ContentResolver.
      !path.isNullOrBlank() && path.startsWith("content://") -> path
      else -> null
    }

    if (!effectiveUri.isNullOrBlank()) {
      val parsed = Uri.parse(effectiveUri)
      val mimeType = contentResolver.getType(parsed) ?: "application/octet-stream"

      var displayName = "imported_file"
      var size: Long = -1
      contentResolver.query(parsed, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        val sizeIndex = cursor.getColumnIndex(android.provider.OpenableColumns.SIZE)
        if (cursor.moveToFirst()) {
          if (nameIndex >= 0) displayName = cursor.getString(nameIndex) ?: displayName
          if (sizeIndex >= 0) size = cursor.getLong(sizeIndex)
        }
      }

      val input = contentResolver.openInputStream(parsed)
        ?: throw IllegalStateException("Unable to open selected file")

      val deleteFn = {
        // No-op: we never delete user-owned external files.
      }

      return ImportSource(input, displayName, size, mimeType, deleteFn)
    }

    if (!path.isNullOrBlank()) {
      val f = File(path)
      val input = FileInputStream(f)
      val displayName = f.name
      val size = f.length()
      val mimeType = "application/octet-stream"
      val deleteFn = {
        try {
          f.delete()
          Unit
        } catch (e: Exception) {
          Log.e("IMPORT", "Import failed", e)
          Unit
        }
      }
      return ImportSource(input, displayName, size, mimeType, deleteFn)
    }

    throw IllegalArgumentException("Missing file source")
  }

  private fun readMetadata(key: SecretKey): JSONArray {
    val f = metadataFile()
    if (!f.exists()) return JSONArray()
    val bytes = f.readBytes()

    val parsed = parseEncryptedBlob(bytes) ?: return JSONArray()
    val iv = parsed.first
    val cipherBytes = parsed.second

    return try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
      val plaintext = cipher.doFinal(cipherBytes)
      val json = plaintext.toString(Charsets.UTF_8)
      JSONArray(json)
    } catch (_: Exception) {
      JSONArray()
    }
  }

  private fun writeMetadata(key: SecretKey, entries: JSONArray) {
    val jsonBytes = entries.toString().toByteArray(Charsets.UTF_8)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val iv = cipher.iv
    val cipherBytes = cipher.doFinal(jsonBytes)

    val headerSize = encryptedHeaderMagic.size + 1
    val out = ByteArray(headerSize + iv.size + cipherBytes.size)
    System.arraycopy(encryptedHeaderMagic, 0, out, 0, encryptedHeaderMagic.size)
    out[encryptedHeaderMagic.size] = iv.size.toByte()
    System.arraycopy(iv, 0, out, headerSize, iv.size)
    System.arraycopy(cipherBytes, 0, out, headerSize + iv.size, cipherBytes.size)
    metadataFile().writeBytes(out)
  }

  private fun parseEncryptedBlob(bytes: ByteArray): Pair<ByteArray, ByteArray>? {
    if (bytes.size < 13) return null

    if (
      bytes.size >= 4 &&
      bytes[0] == encryptedHeaderMagic[0] &&
      bytes[1] == encryptedHeaderMagic[1] &&
      bytes[2] == encryptedHeaderMagic[2]
    ) {
      val ivLen = bytes[3].toInt() and 0xFF
      val headerSize = 4
      if (ivLen <= 0) return null
      if (bytes.size < headerSize + ivLen + 1) return null
      val iv = bytes.copyOfRange(headerSize, headerSize + ivLen)
      val cipherBytes = bytes.copyOfRange(headerSize + ivLen, bytes.size)
      return Pair(iv, cipherBytes)
    }

    val iv = bytes.copyOfRange(0, 12)
    val cipherBytes = bytes.copyOfRange(12, bytes.size)
    return Pair(iv, cipherBytes)
  }

  private data class EmbeddedVaultPayload(
    val displayName: String?,
    val mimeType: String?,
    val fileSize: Long,
    val fileOffset: Int,
  )

  private fun parseEmbeddedVaultPayloadOrNull(plaintext: ByteArray): EmbeddedVaultPayload? {
    if (plaintext.size < 4) return null

    val metaLen = try {
      ByteBuffer.wrap(plaintext, 0, 4).int
    } catch (_: Exception) {
      return null
    }

    if (metaLen <= 0) return null
    val offset = 4 + metaLen
    if (offset > plaintext.size) return null

    val metaJson = try {
      val metaBytes = plaintext.copyOfRange(4, offset)
      val s = metaBytes.toString(Charsets.UTF_8)
      metaBytes.fill(0)
      JSONObject(s)
    } catch (_: Exception) {
      return null
    }

    val name = metaJson.optString("name", null)
    val mime = metaJson.optString("mime", null)
    val fileSize = metaJson.optLong("size", (plaintext.size - offset).toLong())
    return EmbeddedVaultPayload(displayName = name, mimeType = mime, fileSize = fileSize, fileOffset = offset)
  }
}
