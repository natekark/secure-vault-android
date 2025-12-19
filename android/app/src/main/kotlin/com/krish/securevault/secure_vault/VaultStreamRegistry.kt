package com.krish.securevault.secure_vault

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

object VaultStreamRegistry {
  data class Entry(
    val vaultId: String,
    val mimeType: String,
    val displayName: String,
    val size: Long,
  )

  private val entries = ConcurrentHashMap<String, Entry>()

  fun register(vaultId: String, mimeType: String, displayName: String, size: Long): String {
    val token = UUID.randomUUID().toString()
    entries[token] = Entry(vaultId = vaultId, mimeType = mimeType, displayName = displayName, size = size)
    return token
  }

  fun consume(token: String): Entry? {
    return entries.remove(token)
  }

  fun peek(token: String): Entry? {
    return entries[token]
  }
}
