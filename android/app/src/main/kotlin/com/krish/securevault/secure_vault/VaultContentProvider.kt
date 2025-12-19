package com.krish.securevault.secure_vault

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.provider.OpenableColumns
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class VaultContentProvider : ContentProvider() {
  private val encryptedHeaderMagic = byteArrayOf('S'.code.toByte(), 'V'.code.toByte(), '1'.code.toByte())

  override fun onCreate(): Boolean = true

  override fun query(
    uri: Uri,
    projection: Array<out String>?,
    selection: String?,
    selectionArgs: Array<out String>?,
    sortOrder: String?,
  ): Cursor? {
    val token = uri.pathSegments.getOrNull(1) ?: return null
    val entry = VaultStreamRegistry.peek(token) ?: return null

    val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
    val cursor = MatrixCursor(cols, 1)
    val row = cursor.newRow()
    for (c in cols) {
      when (c) {
        OpenableColumns.DISPLAY_NAME -> row.add(entry.displayName)
        OpenableColumns.SIZE -> row.add(entry.size)
        else -> row.add(null)
      }
    }
    return cursor
  }

  override fun getType(uri: Uri): String? {
    val token = uri.pathSegments.getOrNull(1) ?: return null
    val entry = VaultStreamRegistry.peek(token) ?: return null
    return entry.mimeType
  }

  override fun insert(uri: Uri, values: ContentValues?): Uri? = null

  override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

  override fun update(
    uri: Uri,
    values: ContentValues?,
    selection: String?,
    selectionArgs: Array<out String>?,
  ): Int = 0

  override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
    if (mode != "r") throw FileNotFoundException()

    val token = uri.pathSegments.getOrNull(1) ?: throw FileNotFoundException()
    val entry = VaultStreamRegistry.consume(token) ?: throw FileNotFoundException()

    val ctx = context ?: throw FileNotFoundException()
    val encryptedFile = File(File(ctx.filesDir, "vault"), "${entry.vaultId}.enc")
    if (!encryptedFile.exists()) throw FileNotFoundException()

    val key = getSecretKeyOrNull() ?: throw FileNotFoundException()

    val pipe = ParcelFileDescriptor.createPipe()
    val readSide = pipe[0]
    val writeSide = pipe[1]

    Thread {
      try {
        FileOutputStream(writeSide.fileDescriptor).use { out ->
          FileInputStream(encryptedFile).use { input ->
            val encryptedBlob = input.readBytes()
            val parsed = parseEncryptedBlob(encryptedBlob) ?: throw FileNotFoundException()
            val iv = parsed.first
            val cipherBytes = parsed.second

            // AES-GCM requires doFinal() exactly once per decryption operation.
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val plaintext = cipher.doFinal(cipherBytes)

            // New vault format: [metadataLength][metadataJson][fileBytes].
            // Stream only the file bytes portion (skip embedded metadata).
            val fileOffset = embeddedFileOffsetOrZero(plaintext)
            out.write(plaintext, fileOffset, plaintext.size - fileOffset)

            encryptedBlob.fill(0)
            plaintext.fill(0)
          }
        }
      } catch (_: UserNotAuthenticatedException) {
      } catch (_: KeyPermanentlyInvalidatedException) {
      } catch (_: Exception) {
      } finally {
        try {
          writeSide.close()
        } catch (_: Exception) {
        }
      }
    }.start()

    return readSide
  }

  private fun embeddedFileOffsetOrZero(plaintext: ByteArray): Int {
    if (plaintext.size < 4) return 0
    val metaLen = try {
      ByteBuffer.wrap(plaintext, 0, 4).int
    } catch (_: Exception) {
      return 0
    }

    if (metaLen <= 0) return 0
    val offset = 4 + metaLen
    if (offset <= 4) return 0
    if (offset > plaintext.size) return 0
    return offset
  }

  private fun readIvAndPositionStream(input: FileInputStream): ByteArray? {
    val header = ByteArray(4)
    val headerRead = input.read(header)
    if (headerRead != 4) return null

    if (
      header[0] == encryptedHeaderMagic[0] &&
      header[1] == encryptedHeaderMagic[1] &&
      header[2] == encryptedHeaderMagic[2]
    ) {
      val ivLen = header[3].toInt() and 0xFF
      if (ivLen <= 0) return null
      val iv = ByteArray(ivLen)
      val ivRead = input.read(iv)
      if (ivRead != ivLen) return null
      return iv
    }

    val iv = ByteArray(12)
    System.arraycopy(header, 0, iv, 0, 4)
    val restRead = input.read(iv, 4, 8)
    if (restRead != 8) return null
    return iv
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

  private fun getSecretKeyOrNull(): SecretKey? {
    val ctx = context ?: return null
    val ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    val alias = "secure_vault_aes_gcm_key"
    return ks.getKey(alias, null) as SecretKey?
  }
}
