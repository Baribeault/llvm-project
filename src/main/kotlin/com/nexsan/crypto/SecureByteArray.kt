package com.nexsan.crypto

import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.Charset

/**
 * A secure byte array implementation that provides encryption, decryption, and secure memory handling
 */
class SecureByteArray {
    private var data: ByteArray? = null
    private var encrypted: Boolean = false
    private var key: ByteArray? = null
    private var iv: ByteArray? = null
    private var aad: ByteArray? = null
    
    companion object {
        private const val AES_ALGORITHM = "AES"
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
        private val secureRandom = SecureRandom()
        
        /**
         * Create SecureByteArray from string
         */
        fun fromString(str: String, charset: Charset = Charsets.UTF_8): SecureByteArray {
            return SecureByteArray(str.toByteArray(charset))
        }
        
        /**
         * Create SecureByteArray from Base64 encoded string
         */
        fun fromBase64(base64: String): SecureByteArray {
            return SecureByteArray(Base64.getDecoder().decode(base64))
        }
        
        /**
         * Generate a random encryption key
         */
        fun generateKey(keySize: Int = 256): ByteArray {
            if (keySize <= 0) throw IllegalArgumentException("Key size must be positive")
            val key = ByteArray(keySize / 8)
            secureRandom.nextBytes(key)
            return key
        }
        
        /**
         * Create key from bytes
         */
        fun createKeyFromBytes(keyBytes: ByteArray): ByteArray {
            return keyBytes.copyOf()
        }
    }
    
    /**
     * Default constructor
     */
    constructor() {
        this.data = ByteArray(0)
    }
    
    /**
     * Constructor with byte array
     */
    constructor(data: ByteArray) {
        this.data = data.copyOf()
    }
    
    /**
     * Constructor with byte array and encryption key
     */
    constructor(data: ByteArray, key: ByteArray) {
        this.data = data.copyOf()
        this.key = key.copyOf()
    }
    
    /**
     * Constructor with byte array, key, and IV
     */
    constructor(data: ByteArray, key: ByteArray, iv: ByteArray) {
        this.data = data.copyOf()
        this.key = key.copyOf()
        this.iv = iv.copyOf()
    }
    
    /**
     * Constructor with all parameters
     */
    constructor(data: ByteArray, key: ByteArray, iv: ByteArray, aad: ByteArray?) {
        this.data = data.copyOf()
        this.key = key.copyOf()
        this.iv = iv.copyOf()
        this.aad = aad?.copyOf()
    }
    
    /**
     * Encrypt the data
     */
    fun encrypt(): SecureByteArray {
        if (encrypted) return this
        if (key == null) throw IllegalStateException("Encryption key not set")
        
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val keySpec = SecretKeySpec(key!!, AES_ALGORITHM)
        
        if (iv == null) {
            iv = ByteArray(GCM_IV_LENGTH)
            secureRandom.nextBytes(iv!!)
        }
        
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv!!)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        
        aad?.let { cipher.updateAAD(it) }
        
        data = cipher.doFinal(data!!)
        encrypted = true
        return this
    }
    
    /**
     * Decrypt the data
     */
    fun decrypt(): SecureByteArray {
        if (key == null) throw IllegalStateException("Decryption key not set")
        if (iv == null) throw IllegalStateException("IV not set")
        if (!encrypted) return this
        
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val keySpec = SecretKeySpec(key!!, AES_ALGORITHM)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv!!)
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        aad?.let { cipher.updateAAD(it) }
        
        data = cipher.doFinal(data!!)
        encrypted = false
        return this
    }
    
    /**
     * Set Additional Authenticated Data
     */
    fun setAAD(aad: ByteArray?): SecureByteArray {
        this.aad = aad?.copyOf()
        return this
    }
    
    /**
     * Get AAD
     */
    fun getAAD(): ByteArray? = aad?.copyOf()
    
    /**
     * Get the raw data (defensive copy)
     */
    fun getData(): ByteArray? = data?.copyOf()
    
    /**
     * Get data size
     */
    fun size(): Int = data?.size ?: 0
    
    /**
     * Check if empty
     */
    fun isEmpty(): Boolean = data?.isEmpty() ?: true
    
    /**
     * Encode to Base64
     */
    fun toBase64(): String {
        return data?.let { Base64.getEncoder().encodeToString(it) } ?: ""
    }
    
    /**
     * Convert to string
     */
    override fun toString(): String {
        return data?.let { String(it, Charsets.UTF_8) } ?: ""
    }
    
    /**
     * Convert to string with specified charset
     */
    fun toString(charset: Charset): String {
        return data?.let { String(it, charset) } ?: ""
    }
    
    /**
     * Secure comparison
     */
    fun contentEquals(other: SecureByteArray?): Boolean {
        if (other == null) return false
        val thisData = this.data
        val otherData = other.data
        
        if (thisData == null && otherData == null) return true
        if (thisData == null || otherData == null) return false
        if (thisData.size != otherData.size) return false
        
        var result = 0
        for (i in thisData.indices) {
            result = result or (thisData[i].toInt() xor otherData[i].toInt())
        }
        return result == 0
    }
    
    /**
     * Secure destruction of sensitive data
     */
    fun destroy() {
        data?.let { Arrays.fill(it, 0.toByte()) }
        key?.let { Arrays.fill(it, 0.toByte()) }
        iv?.let { Arrays.fill(it, 0.toByte()) }
        aad?.let { Arrays.fill(it, 0.toByte()) }
        
        data = null
        key = null
        iv = null
        aad = null
    }
    
    /**
     * Is encrypted
     */
    fun isEncrypted(): Boolean = encrypted
    
    /**
     * Set encryption key
     */
    fun setKey(key: ByteArray): SecureByteArray {
        this.key = key.copyOf()
        return this
    }
    
    /**
     * Set IV
     */
    fun setIV(iv: ByteArray): SecureByteArray {
        this.iv = iv.copyOf()
        return this
    }
    
    /**
     * Get IV
     */
    fun getIV(): ByteArray? = iv?.copyOf()
    
    protected fun finalize() {
        destroy()
    }
}