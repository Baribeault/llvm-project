package com.nexsan.crypto

import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.util.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SecureByteArrayTest {
    
    private lateinit var testData: ByteArray
    private lateinit var testKey: ByteArray
    private lateinit var testIV: ByteArray
    private lateinit var testAAD: ByteArray
    
    @BeforeEach
    fun setUp() {
        testData = "Hello, World! This is test data.".toByteArray()
        testKey = SecureByteArray.generateKey(256)
        testIV = ByteArray(12).apply { Random().nextBytes(this) }
        testAAD = "Additional authenticated data".toByteArray()
    }
    
    @AfterEach
    fun tearDown() {
        // Clear test data for security
        Arrays.fill(testData, 0.toByte())
        Arrays.fill(testKey, 0.toByte())
        Arrays.fill(testIV, 0.toByte())
        Arrays.fill(testAAD, 0.toByte())
    }
    
    @Nested
    @DisplayName("Constructor Tests")
    inner class ConstructorTests {
        
        @Test
        @DisplayName("Default constructor creates empty array")
        fun testDefaultConstructor() {
            val secureArray = SecureByteArray()
            assertTrue(secureArray.isEmpty())
            assertEquals(0, secureArray.size())
        }
        
        @Test
        @DisplayName("Constructor with byte array")
        fun testConstructorWithByteArray() {
            val secureArray = SecureByteArray(testData)
            assertEquals(testData.size, secureArray.size())
            assertFalse(secureArray.isEmpty())
            assertTrue(Arrays.equals(testData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("Constructor with byte array and key")
        fun testConstructorWithByteArrayAndKey() {
            val secureArray = SecureByteArray(testData, testKey)
            assertEquals(testData.size, secureArray.size())
            assertTrue(Arrays.equals(testData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("Constructor with byte array, key, and IV")
        fun testConstructorWithByteArrayKeyAndIV() {
            val secureArray = SecureByteArray(testData, testKey, testIV)
            assertEquals(testData.size, secureArray.size())
            assertTrue(Arrays.equals(testData, secureArray.getData()))
            assertTrue(Arrays.equals(testIV, secureArray.getIV()))
        }
        
        @Test
        @DisplayName("Constructor with all parameters")
        fun testConstructorWithAllParameters() {
            val secureArray = SecureByteArray(testData, testKey, testIV, testAAD)
            assertEquals(testData.size, secureArray.size())
            assertTrue(Arrays.equals(testData, secureArray.getData()))
            assertTrue(Arrays.equals(testIV, secureArray.getIV()))
            assertTrue(Arrays.equals(testAAD, secureArray.getAAD()))
        }
        
        @Test
        @DisplayName("Constructor with null AAD")
        fun testConstructorWithNullAAD() {
            val secureArray = SecureByteArray(testData, testKey, testIV, null)
            assertEquals(testData.size, secureArray.size())
            assertNull(secureArray.getAAD())
        }
    }
    
    @Nested
    @DisplayName("Factory Method Tests")
    inner class FactoryMethodTests {
        
        @Test
        @DisplayName("fromString creates correct SecureByteArray")
        fun testFromString() {
            val testString = "Hello, World!"
            val secureArray = SecureByteArray.fromString(testString)
            
            assertEquals(testString, secureArray.toString())
            assertEquals(testString.length, secureArray.size())
        }
        
        @ParameterizedTest
        @ValueSource(strings = ["", "a", "Hello", "Long test string with various characters!@#$%"])
        @DisplayName("fromString handles various input strings")
        fun testFromStringVariousInputs(input: String) {
            val secureArray = SecureByteArray.fromString(input)
            assertEquals(input, secureArray.toString())
        }
        
        @Test
        @DisplayName("fromBase64 creates correct SecureByteArray")
        fun testFromBase64() {
            val originalData = "Hello, World!".toByteArray()
            val base64String = Base64.getEncoder().encodeToString(originalData)
            val secureArray = SecureByteArray.fromBase64(base64String)
            
            assertTrue(Arrays.equals(originalData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("generateKey creates key of correct size")
        fun testGenerateKey() {
            val key128 = SecureByteArray.generateKey(128)
            val key256 = SecureByteArray.generateKey(256)
            
            assertEquals(16, key128.size) // 128 bits = 16 bytes
            assertEquals(32, key256.size) // 256 bits = 32 bytes
        }
        
        @Test
        @DisplayName("generateKey creates random keys")
        fun testGenerateKeyRandomness() {
            val key1 = SecureByteArray.generateKey(256)
            val key2 = SecureByteArray.generateKey(256)
            
            assertFalse(Arrays.equals(key1, key2))
        }
        
        @Test
        @DisplayName("createKeyFromBytes creates defensive copy")
        fun testCreateKeyFromBytes() {
            val originalKey = "test key bytes".toByteArray()
            val copiedKey = SecureByteArray.createKeyFromBytes(originalKey)
            
            assertTrue(Arrays.equals(originalKey, copiedKey))
            // Modify original to verify it's a copy
            originalKey[0] = 0
            assertFalse(Arrays.equals(originalKey, copiedKey))
        }
    }
    
    @Nested
    @DisplayName("Encryption/Decryption Tests")
    inner class EncryptionDecryptionTests {
        
        @Test
        @DisplayName("Encryption and decryption round trip")
        fun testEncryptionDecryptionRoundTrip() {
            val secureArray = SecureByteArray(testData, testKey)
            val originalData = secureArray.getData()
            
            // Encrypt
            secureArray.encrypt()
            assertTrue(secureArray.isEncrypted())
            
            // Decrypt
            secureArray.decrypt()
            assertFalse(secureArray.isEncrypted())
            
            // Verify data is same after round trip
            assertTrue(Arrays.equals(originalData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("Encryption without key throws exception")
        fun testEncryptionWithoutKey() {
            val secureArray = SecureByteArray(testData)
            
            assertThrows<IllegalStateException> {
                secureArray.encrypt()
            }
        }
        
        @Test
        @DisplayName("Decryption without key throws exception")
        fun testDecryptionWithoutKey() {
            val secureArray = SecureByteArray(testData)
            
            assertThrows<IllegalStateException> {
                secureArray.decrypt()
            }
        }
        
        @Test
        @DisplayName("Double encryption is idempotent")
        fun testDoubleEncryption() {
            val secureArray = SecureByteArray(testData, testKey)
            val dataAfterFirstEncrypt = secureArray.encrypt().getData()
            val dataAfterSecondEncrypt = secureArray.encrypt().getData()
            
            assertTrue(Arrays.equals(dataAfterFirstEncrypt, dataAfterSecondEncrypt))
        }
        
        @Test
        @DisplayName("Double decryption is idempotent")
        fun testDoubleDecryption() {
            val secureArray = SecureByteArray(testData, testKey)
            secureArray.encrypt()
            
            val dataAfterFirstDecrypt = secureArray.decrypt().getData()
            val dataAfterSecondDecrypt = secureArray.decrypt().getData()
            
            assertTrue(Arrays.equals(dataAfterFirstDecrypt, dataAfterSecondDecrypt))
        }
        
        @Test
        @DisplayName("Encryption with custom IV")
        fun testEncryptionWithCustomIV() {
            val secureArray = SecureByteArray(testData, testKey, testIV)
            val originalData = secureArray.getData()
            
            secureArray.encrypt().decrypt()
            
            assertTrue(Arrays.equals(originalData, secureArray.getData()))
        }
    }
    
    @Nested
    @DisplayName("AAD (Additional Authenticated Data) Tests")
    inner class AADTests {
        
        @Test
        @DisplayName("Set and get AAD")
        fun testSetAndGetAAD() {
            val secureArray = SecureByteArray(testData, testKey)
            secureArray.setAAD(testAAD)
            
            assertTrue(Arrays.equals(testAAD, secureArray.getAAD()))
        }
        
        @Test
        @DisplayName("Set null AAD")
        fun testSetNullAAD() {
            val secureArray = SecureByteArray(testData, testKey)
            secureArray.setAAD(null)
            
            assertNull(secureArray.getAAD())
        }
        
        @Test
        @DisplayName("Encryption/decryption with AAD")
        fun testEncryptionDecryptionWithAAD() {
            val secureArray = SecureByteArray(testData, testKey)
            secureArray.setAAD(testAAD)
            val originalData = secureArray.getData()
            
            secureArray.encrypt().decrypt()
            
            assertTrue(Arrays.equals(originalData, secureArray.getData()))
        }
    }
    
    @Nested
    @DisplayName("Base64 Encoding/Decoding Tests")
    inner class Base64Tests {
        
        @Test
        @DisplayName("toBase64 encoding")
        fun testToBase64() {
            val secureArray = SecureByteArray(testData)
            val base64String = secureArray.toBase64()
            val expectedBase64 = Base64.getEncoder().encodeToString(testData)
            
            assertEquals(expectedBase64, base64String)
        }
        
        @Test
        @DisplayName("Base64 round trip")
        fun testBase64RoundTrip() {
            val secureArray = SecureByteArray(testData)
            val base64String = secureArray.toBase64()
            val decodedArray = SecureByteArray.fromBase64(base64String)
            
            assertTrue(Arrays.equals(testData, decodedArray.getData()))
        }
        
        @Test
        @DisplayName("Empty array Base64 encoding")
        fun testEmptyArrayBase64() {
            val secureArray = SecureByteArray()
            assertEquals("", secureArray.toBase64())
        }
    }
    
    @Nested
    @DisplayName("Security Feature Tests")
    inner class SecurityFeatureTests {
        
        @Test
        @DisplayName("Content comparison - equal arrays")
        fun testContentEqualsEqual() {
            val array1 = SecureByteArray(testData)
            val array2 = SecureByteArray(testData)
            
            assertTrue(array1.contentEquals(array2))
        }
        
        @Test
        @DisplayName("Content comparison - different arrays")
        fun testContentEqualsDifferent() {
            val array1 = SecureByteArray(testData)
            val array2 = SecureByteArray("Different data".toByteArray())
            
            assertFalse(array1.contentEquals(array2))
        }
        
        @Test
        @DisplayName("Content comparison - null array")
        fun testContentEqualsNull() {
            val array1 = SecureByteArray(testData)
            
            assertFalse(array1.contentEquals(null))
        }
        
        @Test
        @DisplayName("Content comparison - empty arrays")
        fun testContentEqualsEmpty() {
            val array1 = SecureByteArray()
            val array2 = SecureByteArray()
            
            assertTrue(array1.contentEquals(array2))
        }
        
        @Test
        @DisplayName("Destroy clears all data")
        fun testDestroy() {
            val secureArray = SecureByteArray(testData, testKey, testIV, testAAD)
            secureArray.destroy()
            
            assertNull(secureArray.getData())
            assertNull(secureArray.getIV())
            assertNull(secureArray.getAAD())
        }
        
        @Test
        @DisplayName("Defensive copying in getData")
        fun testDefensiveCopyingGetData() {
            val secureArray = SecureByteArray(testData)
            val retrievedData = secureArray.getData()
            
            // Modify retrieved data
            retrievedData?.set(0, 0)
            
            // Original should be unchanged
            assertFalse(Arrays.equals(retrievedData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("Defensive copying in getIV")
        fun testDefensiveCopyingGetIV() {
            val secureArray = SecureByteArray(testData, testKey, testIV)
            val retrievedIV = secureArray.getIV()
            
            // Modify retrieved IV
            retrievedIV?.set(0, 0)
            
            // Original should be unchanged
            assertFalse(Arrays.equals(retrievedIV, secureArray.getIV()))
        }
        
        @Test
        @DisplayName("Defensive copying in getAAD")
        fun testDefensiveCopyingGetAAD() {
            val secureArray = SecureByteArray(testData, testKey, testIV, testAAD)
            val retrievedAAD = secureArray.getAAD()
            
            // Modify retrieved AAD
            retrievedAAD?.set(0, 0)
            
            // Original should be unchanged
            assertFalse(Arrays.equals(retrievedAAD, secureArray.getAAD()))
        }
    }
    
    @Nested
    @DisplayName("Error Handling and Edge Cases")
    inner class ErrorHandlingTests {
        
        @Test
        @DisplayName("Empty data encryption")
        fun testEmptyDataEncryption() {
            val secureArray = SecureByteArray(ByteArray(0), testKey)
            secureArray.encrypt().decrypt()
            
            assertTrue(secureArray.isEmpty())
        }
        
        @Test
        @DisplayName("Large data handling")
        fun testLargeDataHandling() {
            val largeData = ByteArray(10000) { it.toByte() }
            val secureArray = SecureByteArray(largeData, testKey)
            
            secureArray.encrypt().decrypt()
            
            assertTrue(Arrays.equals(largeData, secureArray.getData()))
        }
        
        @Test
        @DisplayName("Invalid Base64 handling")
        fun testInvalidBase64() {
            assertThrows<IllegalArgumentException> {
                SecureByteArray.fromBase64("Invalid Base64!")
            }
        }
        
        @Test
        @DisplayName("Zero-length key generation")
        fun testZeroLengthKeyGeneration() {
            assertThrows<IllegalArgumentException> {
                SecureByteArray.generateKey(0)
            }
        }
    }
    
    @Nested
    @DisplayName("Utility Methods Tests")
    inner class UtilityMethodsTests {
        
        @Test
        @DisplayName("Size method")
        fun testSize() {
            val secureArray = SecureByteArray(testData)
            assertEquals(testData.size, secureArray.size())
        }
        
        @Test
        @DisplayName("isEmpty method")
        fun testIsEmpty() {
            val emptyArray = SecureByteArray()
            val nonEmptyArray = SecureByteArray(testData)
            
            assertTrue(emptyArray.isEmpty())
            assertFalse(nonEmptyArray.isEmpty())
        }
        
        @Test
        @DisplayName("toString method")
        fun testToString() {
            val testString = "Hello, World!"
            val secureArray = SecureByteArray(testString.toByteArray())
            
            assertEquals(testString, secureArray.toString())
        }
        
        @Test
        @DisplayName("setKey method")
        fun testSetKey() {
            val secureArray = SecureByteArray(testData)
            secureArray.setKey(testKey)
            
            // Test that key is set by attempting encryption
            assertDoesNotThrow {
                secureArray.encrypt()
            }
        }
        
        @Test
        @DisplayName("setIV method")
        fun testSetIV() {
            val secureArray = SecureByteArray(testData, testKey)
            secureArray.setIV(testIV)
            
            assertTrue(Arrays.equals(testIV, secureArray.getIV()))
        }
    }
}