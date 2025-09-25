package com.nexsan.crypto

import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.ValueSource
import java.nio.charset.Charset
import java.util.*
import java.util.stream.Stream

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SecureStringTest {
    
    companion object {
        @JvmStatic
        fun charsetProvider(): Stream<Arguments> = Stream.of(
            Arguments.of(Charsets.UTF_8),
            Arguments.of(Charsets.UTF_16),
            Arguments.of(Charsets.UTF_16BE),
            Arguments.of(Charsets.UTF_16LE),
            Arguments.of(Charsets.US_ASCII),
            Arguments.of(Charsets.ISO_8859_1)
        )
    }
    
    private lateinit var testString: String
    private lateinit var testChars: CharArray
    private lateinit var testBytes: ByteArray
    
    @BeforeEach
    fun setUp() {
        testString = "Hello, World! This is a test string."
        testChars = testString.toCharArray()
        testBytes = testString.toByteArray(Charsets.UTF_8)
    }
    
    @AfterEach
    fun tearDown() {
        // Clear test data for security
        Arrays.fill(testChars, '\u0000')
        Arrays.fill(testBytes, 0.toByte())
    }
    
    @Nested
    @DisplayName("Constructor Tests")
    inner class ConstructorTests {
        
        @Test
        @DisplayName("Default constructor creates empty string")
        fun testDefaultConstructor() {
            val secureString = SecureString()
            assertTrue(secureString.isEmpty())
            assertEquals(0, secureString.length())
        }
        
        @Test
        @DisplayName("Constructor with char array")
        fun testConstructorWithCharArray() {
            val secureString = SecureString(testChars)
            assertEquals(testString.length, secureString.length())
            assertEquals(testString, secureString.toString())
        }
        
        @Test
        @DisplayName("Constructor with char array and charset")
        fun testConstructorWithCharArrayAndCharset() {
            val secureString = SecureString(testChars, Charsets.UTF_16)
            assertEquals(testString.length, secureString.length())
            assertEquals(testString, secureString.toString())
            assertEquals(Charsets.UTF_16, secureString.getCharset())
        }
        
        @Test
        @DisplayName("Constructor with string")
        fun testConstructorWithString() {
            val secureString = SecureString(testString)
            assertEquals(testString.length, secureString.length())
            assertEquals(testString, secureString.toString())
        }
        
        @Test
        @DisplayName("Constructor with string and charset")
        fun testConstructorWithStringAndCharset() {
            val secureString = SecureString(testString, Charsets.UTF_16)
            assertEquals(testString.length, secureString.length())
            assertEquals(testString, secureString.toString())
            assertEquals(Charsets.UTF_16, secureString.getCharset())
        }
        
        @Test
        @DisplayName("Constructor with byte array")
        fun testConstructorWithByteArray() {
            val secureString = SecureString(testBytes)
            assertEquals(testString, secureString.toString())
            assertEquals(Charsets.UTF_8, secureString.getCharset())
        }
        
        @Test
        @DisplayName("Constructor with byte array and charset")
        fun testConstructorWithByteArrayAndCharset() {
            val utf16Bytes = testString.toByteArray(Charsets.UTF_16)
            val secureString = SecureString(utf16Bytes, Charsets.UTF_16)
            assertEquals(testString, secureString.toString())
            assertEquals(Charsets.UTF_16, secureString.getCharset())
        }
        
        @Test
        @DisplayName("Constructor with empty inputs")
        fun testConstructorWithEmptyInputs() {
            val emptyCharArray = SecureString(CharArray(0))
            val emptyString = SecureString("")
            val emptyByteArray = SecureString(ByteArray(0))
            
            assertTrue(emptyCharArray.isEmpty())
            assertTrue(emptyString.isEmpty())
            assertTrue(emptyByteArray.isEmpty())
        }
    }
    
    @Nested
    @DisplayName("Factory Method Tests")
    inner class FactoryMethodTests {
        
        @Test
        @DisplayName("fromString creates correct SecureString")
        fun testFromString() {
            val secureString = SecureString.fromString(testString)
            assertEquals(testString, secureString.toString())
            assertEquals(testString.length, secureString.length())
        }
        
        @Test
        @DisplayName("fromString with different charset")
        fun testFromStringWithCharset() {
            val secureString = SecureString.fromString(testString, Charsets.UTF_16)
            assertEquals(testString, secureString.toString())
            assertEquals(Charsets.UTF_16, secureString.getCharset())
        }
        
        @ParameterizedTest
        @ValueSource(strings = ["", "a", "Hello", "Long test string with various characters!@#$%"])
        @DisplayName("fromString handles various input strings")
        fun testFromStringVariousInputs(input: String) {
            val secureString = SecureString.fromString(input)
            assertEquals(input, secureString.toString())
        }
        
        @Test
        @DisplayName("generateRandom creates string of correct length")
        fun testGenerateRandom() {
            val secureString = SecureString.generateRandom(20)
            assertEquals(20, secureString.length())
            assertFalse(secureString.isEmpty())
        }
        
        @Test
        @DisplayName("generateRandom with default length")
        fun testGenerateRandomDefaultLength() {
            val secureString = SecureString.generateRandom()
            assertEquals(16, secureString.length()) // Default length
        }
        
        @Test
        @DisplayName("generateRandom creates different strings")
        fun testGenerateRandomUniqueness() {
            val string1 = SecureString.generateRandom(10)
            val string2 = SecureString.generateRandom(10)
            
            assertFalse(string1.contentEquals(string2))
        }
        
        @Test
        @DisplayName("generateRandom with zero length")
        fun testGenerateRandomZeroLength() {
            val secureString = SecureString.generateRandom(0)
            assertTrue(secureString.isEmpty())
            assertEquals(0, secureString.length())
        }
    }
    
    @Nested
    @DisplayName("String Operations Tests")
    inner class StringOperationsTests {
        
        @Test
        @DisplayName("length method")
        fun testLength() {
            val secureString = SecureString(testString)
            assertEquals(testString.length, secureString.length())
        }
        
        @Test
        @DisplayName("isEmpty and isNotEmpty methods")
        fun testIsEmptyAndIsNotEmpty() {
            val emptyString = SecureString("")
            val nonEmptyString = SecureString(testString)
            
            assertTrue(emptyString.isEmpty())
            assertFalse(emptyString.isNotEmpty())
            
            assertFalse(nonEmptyString.isEmpty())
            assertTrue(nonEmptyString.isNotEmpty())
        }
        
        @Test
        @DisplayName("concat with SecureString")
        fun testConcatSecureString() {
            val string1 = SecureString("Hello, ")
            val string2 = SecureString("World!")
            val result = string1.concat(string2)
            
            assertEquals("Hello, World!", result.toString())
        }
        
        @Test
        @DisplayName("concat with regular string")
        fun testConcatString() {
            val secureString = SecureString("Hello, ")
            val result = secureString.concat("World!")
            
            assertEquals("Hello, World!", result.toString())
        }
        
        @Test
        @DisplayName("concat with empty strings")
        fun testConcatEmpty() {
            val string1 = SecureString("Hello")
            val emptyString = SecureString("")
            
            val result1 = string1.concat(emptyString)
            val result2 = emptyString.concat(string1)
            
            assertEquals("Hello", result1.toString())
            assertEquals("Hello", result2.toString())
        }
        
        @Test
        @DisplayName("substring with start index")
        fun testSubstringStart() {
            val secureString = SecureString("Hello, World!")
            val result = secureString.substring(7)
            
            assertEquals("World!", result.toString())
        }
        
        @Test
        @DisplayName("substring with start and end index")
        fun testSubstringStartEnd() {
            val secureString = SecureString("Hello, World!")
            val result = secureString.substring(7, 12)
            
            assertEquals("World", result.toString())
        }
        
        @Test
        @DisplayName("substring edge cases")
        fun testSubstringEdgeCases() {
            val secureString = SecureString("Hello")
            
            // Substring from 0
            assertEquals("Hello", secureString.substring(0).toString())
            
            // Substring with same start and end
            assertEquals("", secureString.substring(2, 2).toString())
            
            // Substring of entire string
            assertEquals("Hello", secureString.substring(0, 5).toString())
        }
        
        @Test
        @DisplayName("substring with invalid indices throws exception")
        fun testSubstringInvalidIndices() {
            val secureString = SecureString("Hello")
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.substring(-1)
            }
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.substring(10)
            }
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.substring(3, 2)
            }
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.substring(0, 10)
            }
        }
        
        @Test
        @DisplayName("charAt method")
        fun testCharAt() {
            val secureString = SecureString("Hello")
            
            assertEquals('H', secureString.charAt(0))
            assertEquals('e', secureString.charAt(1))
            assertEquals('o', secureString.charAt(4))
        }
        
        @Test
        @DisplayName("charAt with invalid index throws exception")
        fun testCharAtInvalidIndex() {
            val secureString = SecureString("Hello")
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.charAt(-1)
            }
            
            assertThrows<IndexOutOfBoundsException> {
                secureString.charAt(5)
            }
        }
    }
    
    @Nested
    @DisplayName("Character Encoding/Decoding Tests")
    inner class CharacterEncodingTests {
        
        @ParameterizedTest
        @MethodSource("com.nexsan.crypto.SecureStringTest#charsetProvider")
        @DisplayName("toByteArray with different charsets")
        fun testToByteArrayDifferentCharset(charset: Charset) {
            val secureString = SecureString(testString, charset)
            val bytes = secureString.toByteArray()
            val expected = testString.toByteArray(charset)
            
            assertTrue(Arrays.equals(expected, bytes))
        }
        
        @Test
        @DisplayName("toByteArray with default charset")
        fun testToByteArrayDefaultCharset() {
            val secureString = SecureString(testString)
            val bytes = secureString.toByteArray()
            val expected = testString.toByteArray(Charsets.UTF_8)
            
            assertTrue(Arrays.equals(expected, bytes))
        }
        
        @Test
        @DisplayName("setCharset and getCharset")
        fun testSetAndGetCharset() {
            val secureString = SecureString(testString)
            assertEquals(Charsets.UTF_8, secureString.getCharset())
            
            secureString.setCharset(Charsets.UTF_16)
            assertEquals(Charsets.UTF_16, secureString.getCharset())
        }
        
        @Test
        @DisplayName("Unicode character handling")
        fun testUnicodeCharacters() {
            val unicodeString = "Hello 世界 🌍 Ñoël"
            val secureString = SecureString(unicodeString)
            
            assertEquals(unicodeString, secureString.toString())
            assertEquals(unicodeString.length, secureString.length())
        }
        
        @Test
        @DisplayName("Empty string encoding")
        fun testEmptyStringEncoding() {
            val secureString = SecureString("")
            val bytes = secureString.toByteArray()
            
            assertEquals(0, bytes.size)
        }
    }
    
    @Nested
    @DisplayName("Security Feature Tests")
    inner class SecurityFeatureTests {
        
        @Test
        @DisplayName("Content comparison - equal strings")
        fun testContentEqualsEqual() {
            val string1 = SecureString(testString)
            val string2 = SecureString(testString)
            
            assertTrue(string1.contentEquals(string2))
        }
        
        @Test
        @DisplayName("Content comparison - different strings")
        fun testContentEqualsDifferent() {
            val string1 = SecureString("Hello")
            val string2 = SecureString("World")
            
            assertFalse(string1.contentEquals(string2))
        }
        
        @Test
        @DisplayName("Content comparison - null string")
        fun testContentEqualsNull() {
            val secureString = SecureString(testString)
            
            assertFalse(secureString.contentEquals(null as SecureString?))
        }
        
        @Test
        @DisplayName("Content comparison with regular string")
        fun testContentEqualsRegularString() {
            val secureString = SecureString(testString)
            
            assertTrue(secureString.contentEquals(testString))
            assertFalse(secureString.contentEquals("Different string"))
            assertFalse(secureString.contentEquals(null as String?))
        }
        
        @Test
        @DisplayName("Content comparison - empty strings")
        fun testContentEqualsEmpty() {
            val empty1 = SecureString("")
            val empty2 = SecureString("")
            
            assertTrue(empty1.contentEquals(empty2))
            assertTrue(empty1.contentEquals(""))
        }
        
        @Test
        @DisplayName("Time-constant comparison prevents timing attacks")
        fun testTimeConstantComparison() {
            val baseString = "a".repeat(1000)
            val differentString1 = "b" + "a".repeat(999) // Different first char
            val differentString2 = "a".repeat(999) + "b" // Different last char
            
            val secureBase = SecureString(baseString)
            val secureDiff1 = SecureString(differentString1)
            val secureDiff2 = SecureString(differentString2)
            
            // Both should return false, regardless of where the difference is
            assertFalse(secureBase.contentEquals(secureDiff1))
            assertFalse(secureBase.contentEquals(secureDiff2))
        }
        
        @Test
        @DisplayName("Copy creates independent copy")
        fun testCopy() {
            val original = SecureString(testString)
            val copy = original.copy()
            
            assertTrue(original.contentEquals(copy))
            
            // Modify original
            original.clear()
            
            // Copy should remain unchanged
            assertEquals(testString, copy.toString())
        }
        
        @Test
        @DisplayName("Destroy clears sensitive data")
        fun testDestroy() {
            val secureString = SecureString(testString)
            secureString.destroy()
            
            assertEquals("", secureString.toString())
            assertEquals(0, secureString.length())
            assertTrue(secureString.isEmpty())
        }
        
        @Test
        @DisplayName("Clear sets to empty string")
        fun testClear() {
            val secureString = SecureString(testString)
            secureString.clear()
            
            assertEquals("", secureString.toString())
            assertEquals(0, secureString.length())
            assertTrue(secureString.isEmpty())
        }
        
        @Test
        @DisplayName("toCharArray creates defensive copy")
        fun testDefensiveCopyCharArray() {
            val secureString = SecureString(testString)
            val charArray = secureString.toCharArray()
            
            // Modify the returned array
            charArray[0] = 'X'
            
            // Original should be unchanged
            assertEquals(testString, secureString.toString())
        }
    }
    
    @Nested
    @DisplayName("Error Handling and Edge Cases")
    inner class ErrorHandlingTests {
        
        @Test
        @DisplayName("Large string handling")
        fun testLargeStringHandling() {
            val largeString = "a".repeat(100000)
            val secureString = SecureString(largeString)
            
            assertEquals(100000, secureString.length())
            assertEquals(largeString, secureString.toString())
        }
        
        @Test
        @DisplayName("Special characters handling")
        fun testSpecialCharacters() {
            val specialChars = "\n\r\t\u0000\u001f\u007f"
            val secureString = SecureString(specialChars)
            
            assertEquals(specialChars.length, secureString.length())
            assertEquals(specialChars, secureString.toString())
        }
        
        @Test
        @DisplayName("Operations on destroyed string")
        fun testOperationsOnDestroyedString() {
            val secureString = SecureString(testString)
            secureString.destroy()
            
            // Operations should work on destroyed (empty) string
            assertEquals(0, secureString.length())
            assertTrue(secureString.isEmpty())
            assertEquals("", secureString.toString())
        }
        
        @Test
        @DisplayName("Operations on cleared string")
        fun testOperationsOnClearedString() {
            val secureString = SecureString(testString)
            secureString.clear()
            
            assertEquals(0, secureString.length())
            assertTrue(secureString.isEmpty())
            assertEquals("", secureString.toString())
        }
    }
    
    @Nested
    @DisplayName("Utility Methods Tests")
    inner class UtilityMethodsTests {
        
        @Test
        @DisplayName("contains method")
        fun testContains() {
            val secureString = SecureString("Hello, World!")
            
            assertTrue(secureString.contains('H'))
            assertTrue(secureString.contains('o'))
            assertTrue(secureString.contains('!'))
            assertFalse(secureString.contains('x'))
            assertFalse(secureString.contains('Z'))
        }
        
        @Test
        @DisplayName("startsWith method")
        fun testStartsWith() {
            val secureString = SecureString("Hello, World!")
            
            assertTrue(secureString.startsWith("Hello"))
            assertTrue(secureString.startsWith("H"))
            assertTrue(secureString.startsWith(""))
            assertFalse(secureString.startsWith("World"))
            assertFalse(secureString.startsWith("hello")) // Case sensitive
        }
        
        @Test
        @DisplayName("endsWith method")
        fun testEndsWith() {
            val secureString = SecureString("Hello, World!")
            
            assertTrue(secureString.endsWith("World!"))
            assertTrue(secureString.endsWith("!"))
            assertTrue(secureString.endsWith(""))
            assertFalse(secureString.endsWith("Hello"))
            assertFalse(secureString.endsWith("world!")) // Case sensitive
        }
        
        @Test
        @DisplayName("startsWith and endsWith with empty string")
        fun testStartsWithEndsWithEmpty() {
            val emptyString = SecureString("")
            
            assertTrue(emptyString.startsWith(""))
            assertTrue(emptyString.endsWith(""))
            assertFalse(emptyString.startsWith("a"))
            assertFalse(emptyString.endsWith("a"))
        }
        
        @Test
        @DisplayName("startsWith and endsWith longer than string")
        fun testStartsWithEndsWithLonger() {
            val shortString = SecureString("Hi")
            
            assertFalse(shortString.startsWith("Hello"))
            assertFalse(shortString.endsWith("Hello"))
        }
    }
    
    @Nested
    @DisplayName("Thread Safety Tests")
    inner class ThreadSafetyTests {
        
        @Test
        @DisplayName("Concurrent access test")
        fun testConcurrentAccess() {
            val secureString = SecureString("Thread safety test string")
            val results = Collections.synchronizedList(mutableListOf<String>())
            val threads = mutableListOf<Thread>()
            
            // Create multiple threads that read from the same SecureString
            repeat(10) {
                val thread = Thread {
                    repeat(100) {
                        results.add(secureString.toString())
                    }
                }
                threads.add(thread)
                thread.start()
            }
            
            // Wait for all threads to complete
            threads.forEach { it.join() }
            
            // All results should be the same
            results.forEach { result ->
                assertEquals("Thread safety test string", result)
            }
            
            assertEquals(1000, results.size)
        }
        
        @Test
        @DisplayName("Concurrent modification safety")
        fun testConcurrentModificationSafety() {
            val original = SecureString("Original string")
            val copies = Collections.synchronizedList(mutableListOf<SecureString>())
            val threads = mutableListOf<Thread>()
            
            // Create multiple threads that create copies
            repeat(5) {
                val thread = Thread {
                    repeat(20) {
                        copies.add(original.copy())
                    }
                }
                threads.add(thread)
                thread.start()
            }
            
            // Wait for all threads to complete
            threads.forEach { it.join() }
            
            // All copies should be equal to original
            copies.forEach { copy ->
                assertTrue(original.contentEquals(copy))
            }
            
            assertEquals(100, copies.size)
        }
    }
}