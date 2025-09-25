package com.nexsan.crypto

import java.security.SecureRandom
import java.util.*
import java.nio.charset.Charset

/**
 * A secure string implementation that provides secure memory handling and string operations
 */
class SecureString {
    private var data: CharArray? = null
    private var charset: Charset = Charsets.UTF_8
    
    companion object {
        private val secureRandom = SecureRandom()
        private const val DEFAULT_RANDOM_LENGTH = 16
        private const val RANDOM_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        
        /**
         * Create SecureString from regular string
         */
        fun fromString(str: String, charset: Charset = Charsets.UTF_8): SecureString {
            return SecureString(str.toCharArray(), charset)
        }
        
        /**
         * Generate random secure string
         */
        fun generateRandom(length: Int = DEFAULT_RANDOM_LENGTH): SecureString {
            val chars = CharArray(length)
            for (i in 0 until length) {
                chars[i] = RANDOM_CHARS[secureRandom.nextInt(RANDOM_CHARS.length)]
            }
            return SecureString(chars)
        }
    }
    
    /**
     * Default constructor
     */
    constructor() {
        this.data = CharArray(0)
    }
    
    /**
     * Constructor with char array
     */
    constructor(data: CharArray) {
        this.data = data.copyOf()
    }
    
    /**
     * Constructor with char array and charset
     */
    constructor(data: CharArray, charset: Charset) {
        this.data = data.copyOf()
        this.charset = charset
    }
    
    /**
     * Constructor with string
     */
    constructor(str: String) {
        this.data = str.toCharArray()
    }
    
    /**
     * Constructor with string and charset
     */
    constructor(str: String, charset: Charset) {
        this.data = str.toCharArray()
        this.charset = charset
    }
    
    /**
     * Constructor with byte array and charset
     */
    constructor(bytes: ByteArray, charset: Charset = Charsets.UTF_8) {
        this.data = String(bytes, charset).toCharArray()
        this.charset = charset
    }
    
    /**
     * Get the length of the string
     */
    fun length(): Int = data?.size ?: 0
    
    /**
     * Check if the string is empty
     */
    fun isEmpty(): Boolean = data?.isEmpty() ?: true
    
    /**
     * Check if the string is not empty
     */
    fun isNotEmpty(): Boolean = !isEmpty()
    
    /**
     * Concatenate with another SecureString
     */
    fun concat(other: SecureString): SecureString {
        val thisData = this.data ?: CharArray(0)
        val otherData = other.data ?: CharArray(0)
        
        val result = CharArray(thisData.size + otherData.size)
        System.arraycopy(thisData, 0, result, 0, thisData.size)
        System.arraycopy(otherData, 0, result, thisData.size, otherData.size)
        
        return SecureString(result, this.charset)
    }
    
    /**
     * Concatenate with a regular string
     */
    fun concat(str: String): SecureString {
        return concat(SecureString(str, this.charset))
    }
    
    /**
     * Get substring
     */
    fun substring(startIndex: Int): SecureString {
        if (data == null) return SecureString()
        if (startIndex < 0 || startIndex >= data!!.size) {
            throw IndexOutOfBoundsException("Start index out of bounds: $startIndex")
        }
        
        val newData = CharArray(data!!.size - startIndex)
        System.arraycopy(data!!, startIndex, newData, 0, newData.size)
        return SecureString(newData, this.charset)
    }
    
    /**
     * Get substring with end index
     */
    fun substring(startIndex: Int, endIndex: Int): SecureString {
        if (data == null) return SecureString()
        if (startIndex < 0 || endIndex > data!!.size || startIndex > endIndex) {
            throw IndexOutOfBoundsException("Invalid indices: start=$startIndex, end=$endIndex")
        }
        
        val newData = CharArray(endIndex - startIndex)
        System.arraycopy(data!!, startIndex, newData, 0, newData.size)
        return SecureString(newData, this.charset)
    }
    
    /**
     * Get character at index
     */
    fun charAt(index: Int): Char {
        if (data == null || index < 0 || index >= data!!.size) {
            throw IndexOutOfBoundsException("Index out of bounds: $index")
        }
        return data!![index]
    }
    
    /**
     * Convert to byte array with specified charset
     */
    fun toByteArray(charset: Charset = this.charset): ByteArray {
        return data?.let { String(it).toByteArray(charset) } ?: ByteArray(0)
    }
    
    /**
     * Convert to string (use with caution as it creates uncontrolled copy)
     */
    override fun toString(): String {
        return data?.let { String(it) } ?: ""
    }
    
    /**
     * Get charset
     */
    fun getCharset(): Charset = charset
    
    /**
     * Set charset
     */
    fun setCharset(charset: Charset): SecureString {
        this.charset = charset
        return this
    }
    
    /**
     * Time-constant comparison to prevent timing attacks
     */
    fun contentEquals(other: SecureString?): Boolean {
        if (other == null) return false
        val thisData = this.data
        val otherData = other.data
        
        if (thisData == null && otherData == null) return true
        if (thisData == null || otherData == null) return false
        if (thisData.size != otherData.size) return false
        
        var result = 0
        for (i in thisData.indices) {
            result = result or (thisData[i].code xor otherData[i].code)
        }
        return result == 0
    }
    
    /**
     * Time-constant comparison with regular string
     */
    fun contentEquals(str: String?): Boolean {
        if (str == null) return data == null
        return contentEquals(SecureString(str, this.charset))
    }
    
    /**
     * Copy the data (defensive copy)
     */
    fun copy(): SecureString {
        return SecureString(data?.copyOf() ?: CharArray(0), this.charset)
    }
    
    /**
     * Secure destruction of sensitive data
     */
    fun destroy() {
        data?.let { Arrays.fill(it, '\u0000') }
        data = null
    }
    
    /**
     * Clear the content (set to empty)
     */
    fun clear() {
        data?.let { Arrays.fill(it, '\u0000') }
        data = CharArray(0)
    }
    
    /**
     * Get raw char array (defensive copy)
     */
    fun toCharArray(): CharArray = data?.copyOf() ?: CharArray(0)
    
    /**
     * Check if contains a character
     */
    fun contains(char: Char): Boolean {
        return data?.contains(char) ?: false
    }
    
    /**
     * Check if starts with prefix
     */
    fun startsWith(prefix: String): Boolean {
        val prefixChars = prefix.toCharArray()
        val thisData = this.data ?: return prefix.isEmpty()
        
        if (prefixChars.size > thisData.size) return false
        
        for (i in prefixChars.indices) {
            if (thisData[i] != prefixChars[i]) return false
        }
        return true
    }
    
    /**
     * Check if ends with suffix
     */
    fun endsWith(suffix: String): Boolean {
        val suffixChars = suffix.toCharArray()
        val thisData = this.data ?: return suffix.isEmpty()
        
        if (suffixChars.size > thisData.size) return false
        
        val offset = thisData.size - suffixChars.size
        for (i in suffixChars.indices) {
            if (thisData[offset + i] != suffixChars[i]) return false
        }
        return true
    }
    
    protected fun finalize() {
        destroy()
    }
}