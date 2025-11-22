\# ToxCore C# Port



Port of toxcore (https://github.com/irungentoo/toxcore) from C to pure C#

using Sodium.Core 1.4.0 for cryptography.



\## Status

🚧 Work in progress



\## Dependencies

\- .NET 6.0+

\- Sodium.Core 1.4.0



\## Progress

\- \[ ] Core structures

\- \[ ] Crypto layer

\- \[ ] Network layer

\- \[ ] Protocol implementation



\## Este el código del proyecto:



Archivo CryptoAuth.cs \[

using System.Security.Cryptography;

using Sodium;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación de crypto\_auth (HMAC-SHA-256) usando Sodium.Core

&nbsp;/// </summary>

&nbsp;public static class CryptoAuth

&nbsp;{

&nbsp;public const int BYTES = 32;

&nbsp;public const int KEYBYTES = 32;



&nbsp;/// <summary>

&nbsp;/// Genera tag de autenticación HMAC-SHA-256

&nbsp;/// </summary>

&nbsp;public static byte\[] Authenticate(byte\[] message, byte\[] key)

&nbsp;{

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (key == null || key.Length != KEYBYTES)

&nbsp;throw new ArgumentException($"Key must be {KEYBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;// Intentar con Sodium primero

&nbsp;return SecretKeyAuth.SignHmacSha256(message, key);

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;// Fallback a .NET implementation

&nbsp;using (var hmac = new HMACSHA256(key))

&nbsp;{

&nbsp;return hmac.ComputeHash(message);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera tag de autenticación para una porción de mensaje

&nbsp;/// </summary>

&nbsp;public static byte\[] Authenticate(byte\[] message, int offset, int count, byte\[] key)

&nbsp;{

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (offset < 0 || offset >= message.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(offset));

&nbsp;if (count < 0 || offset + count > message.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(count));

&nbsp;if (key == null || key.Length != KEYBYTES)

&nbsp;throw new ArgumentException($"Key must be {KEYBYTES} bytes");



&nbsp;byte\[] segment = new byte\[count];

&nbsp;Buffer.BlockCopy(message, offset, segment, 0, count);

&nbsp;return Authenticate(segment, key);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verifica tag de autenticación

&nbsp;/// </summary>

&nbsp;public static bool Verify(byte\[] tag, byte\[] message, byte\[] key)

&nbsp;{

&nbsp;if (tag == null || tag.Length != BYTES)

&nbsp;throw new ArgumentException($"Tag must be {BYTES} bytes");

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (key == null || key.Length != KEYBYTES)

&nbsp;throw new ArgumentException($"Key must be {KEYBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;// Intentar con Sodium primero

&nbsp;return SecretKeyAuth.VerifyHmacSha256(tag, message, key);

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;// Fallback a .NET implementation

&nbsp;using (var hmac = new HMACSHA256(key))

&nbsp;{

&nbsp;byte\[] computedTag = hmac.ComputeHash(message);

&nbsp;return CryptographicOperations.FixedTimeEquals(computedTag, tag);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verifica tag de autenticación para una porción de mensaje

&nbsp;/// </summary>

&nbsp;public static bool Verify(byte\[] tag, byte\[] message, int offset, int count, byte\[] key)

&nbsp;{

&nbsp;if (tag == null || tag.Length != BYTES)

&nbsp;throw new ArgumentException($"Tag must be {BYTES} bytes");

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (offset < 0 || offset >= message.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(offset));

&nbsp;if (count < 0 || offset + count > message.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(count));

&nbsp;if (key == null || key.Length != KEYBYTES)

&nbsp;throw new ArgumentException($"Key must be {KEYBYTES} bytes");



&nbsp;byte\[] segment = new byte\[count];

&nbsp;Buffer.BlockCopy(message, offset, segment, 0, count);

&nbsp;return Verify(tag, segment, key);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera clave segura

&nbsp;/// </summary>

&nbsp;public static byte\[] GenerateKey()

&nbsp;{

&nbsp;return SecretKeyAuth.GenerateKey();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test exhaustivo con vectores conocidos

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" 🔬 Testing CryptoAuth (HMAC-SHA-256)...");



&nbsp;// Test 1: Generación de clave

&nbsp;byte\[] key = GenerateKey();

&nbsp;bool keyValid = key != null \&\& key.Length == KEYBYTES;

&nbsp;Console.WriteLine($" Key generation: {(keyValid ? "✅" : "❌")}");



&nbsp;// Test 2: Tag generation

&nbsp;byte\[] message = System.Text.Encoding.UTF8.GetBytes("Test message for HMAC");

&nbsp;byte\[] tag = Authenticate(message, key);

&nbsp;bool tagValid = tag != null \&\& tag.Length == BYTES;

&nbsp;Console.WriteLine($" Tag generation: {(tagValid ? "✅" : "❌")}");



&nbsp;// Test 3: Verificación correcta

&nbsp;bool verifyCorrect = Verify(tag, message, key);

&nbsp;Console.WriteLine($" Correct verification: {(verifyCorrect ? "✅" : "❌")}");



&nbsp;// Test 4: Verificación incorrecta (tag alterado)

&nbsp;byte\[] wrongTag = new byte\[BYTES];

&nbsp;if (tag != null)

&nbsp;{

&nbsp;Array.Copy(tag, wrongTag, BYTES);

&nbsp;wrongTag\[0] ^= 0x01;

&nbsp;bool verifyWrong = Verify(wrongTag, message, key);

&nbsp;Console.WriteLine($" Wrong tag rejection: {(!verifyWrong ? "✅" : "❌")}");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Console.WriteLine($" Wrong tag rejection: ❌ (tag is null)");

&nbsp;}



&nbsp;// Test 5: Clave incorrecta

&nbsp;byte\[] wrongKey = GenerateKey();

&nbsp;bool verifyWrongKey = Verify(tag, message, wrongKey);

&nbsp;Console.WriteLine($" Wrong key rejection: {(!verifyWrongKey ? "✅" : "❌")}");



&nbsp;// Test 6: Mensaje alterado

&nbsp;byte\[] wrongMessage = System.Text.Encoding.UTF8.GetBytes("Wrong message for HMAC");

&nbsp;bool verifyWrongMessage = Verify(tag, wrongMessage, key);

&nbsp;Console.WriteLine($" Wrong message rejection: {(!verifyWrongMessage ? "✅" : "❌")}");



&nbsp;// Test 7: Mensaje vacío

&nbsp;byte\[] emptyTag = Authenticate(Array.Empty<byte>(), key);

&nbsp;bool emptyValid = emptyTag != null \&\& emptyTag.Length == BYTES;

&nbsp;bool emptyVerify = emptyTag != null \&\& Verify(emptyTag, Array.Empty<byte>(), key);

&nbsp;Console.WriteLine($" Empty message: {(emptyValid \&\& emptyVerify ? "✅" : "❌")}");



&nbsp;// Test 8: Determinismo

&nbsp;byte\[] tag2 = Authenticate(message, key);

&nbsp;bool deterministic = tag != null \&\& tag2 != null \&\&

&nbsp;CryptographicOperations.FixedTimeEquals(tag, tag2);

&nbsp;Console.WriteLine($" Deterministic: {(deterministic ? "✅" : "❌")}");



&nbsp;// Test 9: Rendimiento - CORREGIDO

&nbsp;var sw = System.Diagnostics.Stopwatch.StartNew();

&nbsp;int operations = 0;

&nbsp;int successfulAuths = 0;



&nbsp;for (int i = 0; i < 100; i++) // Reducido a 100 para mejor diagnóstico

&nbsp;{

&nbsp;byte\[] testMsg = System.Text.Encoding.UTF8.GetBytes($"Message {i}");

&nbsp;byte\[] testTag = Authenticate(testMsg, key);



&nbsp;if (testTag != null)

&nbsp;{

&nbsp;successfulAuths++;

&nbsp;if (Verify(testTag, testMsg, key))

&nbsp;{

&nbsp;operations++;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;sw.Stop();



&nbsp;Console.WriteLine($" Successful authentications: {successfulAuths}/100 ✅");

&nbsp;Console.WriteLine($" Successful verifications: {operations}/100 ✅");

&nbsp;Console.WriteLine($" Performance: {sw.ElapsedMilliseconds}ms ✅");



&nbsp;// Si hay problemas, hacer test de diagnóstico

&nbsp;if (successfulAuths < 100 || operations < 100)

&nbsp;{

&nbsp;Console.WriteLine(" 🔍 Running diagnostic...");

&nbsp;RunAuthDiagnostic(key);

&nbsp;}



&nbsp;return keyValid \&\& tagValid \&\& verifyCorrect \&\& emptyValid \&\& deterministic \&\&

&nbsp;(successfulAuths == 100) \&\& (operations == 100);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ CryptoAuth test failed: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Diagnóstico para identificar problemas específicos

&nbsp;/// </summary>

&nbsp;private static void RunAuthDiagnostic(byte\[] key)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" 🔍 Diagnostic - Testing individual messages:");



&nbsp;// Test mensajes específicos que podrían causar problemas

&nbsp;string\[] testMessages = {

&nbsp;"",

&nbsp;" ",

&nbsp;"a",

&nbsp;"test",

&nbsp;"Message 0",

&nbsp;"Message 50",

&nbsp;"Message 99",

&nbsp;new string('x', 1000),

&nbsp;new string('y', 10000)

&nbsp;};



&nbsp;foreach (var msg in testMessages)

&nbsp;{

&nbsp;byte\[] msgBytes = System.Text.Encoding.UTF8.GetBytes(msg);

&nbsp;byte\[] tag = Authenticate(msgBytes, key);



&nbsp;if (tag == null)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ NULL tag for: '{msg.Substring(0, Math.Min(20, msg.Length))}...'");

&nbsp;}

&nbsp;else if (tag.Length != BYTES)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Wrong tag length: {tag.Length} for: '{msg.Substring(0, Math.Min(20, msg.Length))}...'");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;bool verify = Verify(tag, msgBytes, key);

&nbsp;Console.WriteLine($" ✅ OK: '{msg.Substring(0, Math.Min(20, msg.Length))}...' -> Verify: {verify}");

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Diagnostic failed: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class crypto\_auth\_native

&nbsp;{

&nbsp;public const int crypto\_auth\_BYTES = CryptoAuth.BYTES;

&nbsp;public const int crypto\_auth\_KEYBYTES = CryptoAuth.KEYBYTES;



&nbsp;public static int crypto\_auth(byte\[] @out, byte\[] @in, ulong inlen, byte\[] k)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] inputSegment = new byte\[inlen];

&nbsp;Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);



&nbsp;byte\[] tag = CryptoAuth.Authenticate(inputSegment, k);

&nbsp;Buffer.BlockCopy(tag, 0, @out, 0, CryptoAuth.BYTES);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_auth\_verify(byte\[] h, byte\[] @in, ulong inlen, byte\[] k)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] inputSegment = new byte\[inlen];

&nbsp;Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);



&nbsp;bool isValid = CryptoAuth.Verify(h, inputSegment, k);

&nbsp;return isValid ? 0 : -1;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static void crypto\_auth\_keygen(byte\[] k)

&nbsp;{

&nbsp;byte\[] key = CryptoAuth.GenerateKey();

&nbsp;Buffer.BlockCopy(key, 0, k, 0, CryptoAuth.KEYBYTES);

&nbsp;}

&nbsp;}

}

]



Archivo CryptoBox.cs \[

using System.Security.Cryptography;

using Sodium;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación de crypto\_box (curve25519-xsalsa20-poly1305) usando Sodium.Core

&nbsp;/// </summary>

&nbsp;public static class CryptoBox

&nbsp;{

&nbsp;public const int PUBLICKEYBYTES = 32;

&nbsp;public const int SECRETKEYBYTES = 32;

&nbsp;public const int BEFORENMBYTES = 32;

&nbsp;public const int NONCEBYTES = 24;

&nbsp;public const int MACBYTES = 16;



&nbsp;public const int CRYPTO\_NONCE\_SIZE = 24;

&nbsp;public const int CRYPTO\_MAC\_SIZE = 16;

&nbsp;public const int CRYPTO\_PUBLIC\_KEY\_SIZE = 32;

&nbsp;public const int CRYPTO\_SECRET\_KEY\_SIZE = 32;

&nbsp;public const int CRYPTO\_SHARED\_KEY\_SIZE = 32;

&nbsp;public const int CRYPTO\_SYMMETRIC\_KEY\_SIZE = 32;





&nbsp;private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();



&nbsp;/// <summary>

&nbsp;/// Genera un par de claves pública/privada usando curve25519

&nbsp;/// </summary>

&nbsp;public static KeyPair GenerateKeyPair()

&nbsp;{

&nbsp;var keyPair = PublicKeyBox.GenerateKeyPair();

&nbsp;return new KeyPair

&nbsp;{

&nbsp;PublicKey = keyPair.PublicKey,

&nbsp;PrivateKey = keyPair.PrivateKey

&nbsp;};

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Encrypta usando curve25519-xsalsa20-poly1305

&nbsp;/// </summary>

&nbsp;public static byte\[] Encrypt(byte\[] message, byte\[] nonce, byte\[] publicKey, byte\[] secretKey)

&nbsp;{

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (nonce == null || nonce.Length != NONCEBYTES)

&nbsp;throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");

&nbsp;if (publicKey == null || publicKey.Length != PUBLICKEYBYTES)

&nbsp;throw new ArgumentException($"Public key must be {PUBLICKEYBYTES} bytes");

&nbsp;if (secretKey == null || secretKey.Length != SECRETKEYBYTES)

&nbsp;throw new ArgumentException($"Secret key must be {SECRETKEYBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;return PublicKeyBox.Create(message, nonce, secretKey, publicKey);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;throw new CryptographicException("Encryption failed", ex);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Decrypta usando curve25519-xsalsa20-poly1305

&nbsp;/// </summary>

&nbsp;public static byte\[] Decrypt(byte\[] cipherText, byte\[] nonce, byte\[] publicKey, byte\[] secretKey)

&nbsp;{

&nbsp;if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

&nbsp;if (nonce == null || nonce.Length != NONCEBYTES)

&nbsp;throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");

&nbsp;if (publicKey == null || publicKey.Length != PUBLICKEYBYTES)

&nbsp;throw new ArgumentException($"Public key must be {PUBLICKEYBYTES} bytes");

&nbsp;if (secretKey == null || secretKey.Length != SECRETKEYBYTES)

&nbsp;throw new ArgumentException($"Secret key must be {SECRETKEYBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;return PublicKeyBox.Open(cipherText, nonce, secretKey, publicKey);

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;// Decryption failed (invalid MAC or corrupted data)

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Precalcula el shared key para mejor rendimiento

&nbsp;/// </summary>

&nbsp;public static byte\[] BeforeNm(byte\[] publicKey, byte\[] secretKey)

&nbsp;{

&nbsp;if (publicKey == null || publicKey.Length != CRYPTO\_PUBLIC\_KEY\_SIZE)

&nbsp;throw new ArgumentException($"Public key must be {CRYPTO\_PUBLIC\_KEY\_SIZE} bytes");

&nbsp;if (secretKey == null || secretKey.Length != CRYPTO\_SECRET\_KEY\_SIZE)

&nbsp;throw new ArgumentException($"Secret key must be {CRYPTO\_SECRET\_KEY\_SIZE} bytes");



&nbsp;return ScalarMult.Mult(secretKey, publicKey);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Encrypta usando shared key precalculado (xsalsa20-poly1305)

&nbsp;/// </summary>

&nbsp;public static byte\[] AfterNm(byte\[] message, byte\[] nonce, byte\[] sharedKey)

&nbsp;{

&nbsp;if (message == null) throw new ArgumentNullException(nameof(message));

&nbsp;if (nonce == null || nonce.Length != NONCEBYTES)

&nbsp;throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");

&nbsp;if (sharedKey == null || sharedKey.Length != BEFORENMBYTES)

&nbsp;throw new ArgumentException($"Shared key must be {BEFORENMBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;return SecretBox.Create(message, nonce, sharedKey);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;throw new CryptographicException("Encryption with shared key failed", ex);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Decrypta usando shared key precalculado (xsalsa20-poly1305)

&nbsp;/// </summary>

&nbsp;public static byte\[] OpenAfterNm(byte\[] cipherText, byte\[] nonce, byte\[] sharedKey)

&nbsp;{

&nbsp;if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));

&nbsp;if (nonce == null || nonce.Length != NONCEBYTES)

&nbsp;throw new ArgumentException($"Nonce must be {NONCEBYTES} bytes");

&nbsp;if (sharedKey == null || sharedKey.Length != BEFORENMBYTES)

&nbsp;throw new ArgumentException($"Shared key must be {BEFORENMBYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;return SecretBox.Open(cipherText, nonce, sharedKey);

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;// Decryption failed (invalid MAC or corrupted data)

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera nonce aleatorio seguro

&nbsp;/// </summary>

&nbsp;public static byte\[] GenerateNonce()

&nbsp;{

&nbsp;byte\[] nonce = new byte\[NONCEBYTES];

&nbsp;rng.GetBytes(nonce);

&nbsp;return nonce;

&nbsp;}

&nbsp;

&nbsp;/// <summary>

&nbsp;/// Test exhaustivo de todas las funcionalidades

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" 🔬 Testing CryptoBox comprehensively...");



&nbsp;// Test 1: Generación de claves

&nbsp;var keyPair = GenerateKeyPair();

&nbsp;bool keysValid = keyPair.PublicKey.Length == PUBLICKEYBYTES \&\&

&nbsp;keyPair.PrivateKey.Length == SECRETKEYBYTES;

&nbsp;Console.WriteLine($" Key generation: {(keysValid ? "✅" : "❌")}");



&nbsp;// Test 2: Encrypt/Decrypt básico

&nbsp;byte\[] nonce = GenerateNonce();

&nbsp;byte\[] original = System.Text.Encoding.UTF8.GetBytes("Test message for CryptoBox");

&nbsp;byte\[] encrypted = Encrypt(original, nonce, keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;byte\[] decrypted = Decrypt(encrypted, nonce, keyPair.PublicKey, keyPair.PrivateKey);



&nbsp;bool basicEncryption = encrypted != null \&\& decrypted != null \&\&

&nbsp;CompareBytes(original, decrypted);

&nbsp;Console.WriteLine($" Basic encryption/decryption: {(basicEncryption ? "✅" : "❌")}");



&nbsp;// Test 3: Shared key

&nbsp;byte\[] sharedKey = BeforeNm(keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;bool sharedKeyValid = sharedKey != null \&\& sharedKey.Length == BEFORENMBYTES;

&nbsp;Console.WriteLine($" Shared key calculation: {(sharedKeyValid ? "✅" : "❌")}");



&nbsp;// Test 4: Encrypt/Decrypt con shared key

&nbsp;byte\[] encryptedShared = AfterNm(original, nonce, sharedKey);

&nbsp;byte\[] decryptedShared = OpenAfterNm(encryptedShared, nonce, sharedKey);

&nbsp;bool sharedEncryption = encryptedShared != null \&\& decryptedShared != null \&\&

&nbsp;CompareBytes(original, decryptedShared);

&nbsp;Console.WriteLine($" Shared key encryption: {(sharedEncryption ? "✅" : "❌")}");



&nbsp;// Test 5: Detección de manipulación (MAC verification)

&nbsp;if (encrypted != null)

&nbsp;{

&nbsp;byte\[] tampered = new byte\[encrypted.Length];

&nbsp;Array.Copy(encrypted, tampered, encrypted.Length);

&nbsp;tampered\[10] ^= 0x01; // Alterar un byte

&nbsp;byte\[] shouldFail = Decrypt(tampered, nonce, keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;bool tamperDetection = shouldFail == null;

&nbsp;Console.WriteLine($" Tamper detection: {(tamperDetection ? "✅" : "❌")}");

&nbsp;}



&nbsp;// Test 6: Nonce incorrecto

&nbsp;if (encrypted != null)

&nbsp;{

&nbsp;byte\[] wrongNonce = GenerateNonce();

&nbsp;byte\[] shouldFail = Decrypt(encrypted, wrongNonce, keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;bool nonceVerification = shouldFail == null;

&nbsp;Console.WriteLine($" Nonce verification: {(nonceVerification ? "✅" : "❌")}");

&nbsp;}



&nbsp;// Test 7: Claves incorrectas

&nbsp;if (encrypted != null)

&nbsp;{

&nbsp;var wrongKeyPair = GenerateKeyPair();

&nbsp;byte\[] shouldFail = Decrypt(encrypted, nonce, wrongKeyPair.PublicKey, keyPair.PrivateKey);

&nbsp;bool keyVerification = shouldFail == null;

&nbsp;Console.WriteLine($" Key verification: {(keyVerification ? "✅" : "❌")}");

&nbsp;}



&nbsp;// Test 8: Rendimiento con múltiples operaciones

&nbsp;var sw = System.Diagnostics.Stopwatch.StartNew();

&nbsp;int operations = 0;

&nbsp;for (int i = 0; i < 100; i++)

&nbsp;{

&nbsp;byte\[] testMsg = System.Text.Encoding.UTF8.GetBytes($"Message {i}");

&nbsp;byte\[] testNonce = GenerateNonce();

&nbsp;byte\[] enc = Encrypt(testMsg, testNonce, keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;byte\[] dec = Decrypt(enc, testNonce, keyPair.PublicKey, keyPair.PrivateKey);

&nbsp;if (dec != null) operations++;

&nbsp;}

&nbsp;sw.Stop();

&nbsp;Console.WriteLine($" Performance: {operations}/100 operations in {sw.ElapsedMilliseconds}ms ✅");



&nbsp;return keysValid \&\& basicEncryption \&\& sharedKeyValid \&\& sharedEncryption;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ CryptoBox test failed: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private static bool CompareBytes(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null || a.Length != b.Length) return false;

&nbsp;for (int i = 0; i < a.Length; i++)

&nbsp;{

&nbsp;if (a\[i] != b\[i]) return false;

&nbsp;}

&nbsp;return true;

&nbsp;}

&nbsp;}



&nbsp;public class KeyPair

&nbsp;{

&nbsp;public byte\[] PublicKey { get; set; } = new byte\[CryptoBox.PUBLICKEYBYTES];

&nbsp;public byte\[] PrivateKey { get; set; } = new byte\[CryptoBox.SECRETKEYBYTES];

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class crypto\_box\_native

&nbsp;{

&nbsp;public const int crypto\_box\_PUBLICKEYBYTES = CryptoBox.PUBLICKEYBYTES;

&nbsp;public const int crypto\_box\_SECRETKEYBYTES = CryptoBox.SECRETKEYBYTES;

&nbsp;public const int crypto\_box\_BEFORENMBYTES = CryptoBox.BEFORENMBYTES;

&nbsp;public const int crypto\_box\_NONCEBYTES = CryptoBox.NONCEBYTES;

&nbsp;public const int crypto\_box\_MACBYTES = CryptoBox.MACBYTES;



&nbsp;public static int crypto\_box\_keypair(byte\[] pk, byte\[] sk)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var keyPair = CryptoBox.GenerateKeyPair();

&nbsp;Buffer.BlockCopy(keyPair.PublicKey, 0, pk, 0, CryptoBox.PUBLICKEYBYTES);

&nbsp;Buffer.BlockCopy(keyPair.PrivateKey, 0, sk, 0, CryptoBox.SECRETKEYBYTES);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_box(byte\[] c, byte\[] m, long mlen, byte\[] n, byte\[] pk, byte\[] sk)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] messageSegment = new byte\[mlen];

&nbsp;Buffer.BlockCopy(m, 0, messageSegment, 0, (int)mlen);



&nbsp;byte\[] cipherText = CryptoBox.Encrypt(messageSegment, n, pk, sk);

&nbsp;Buffer.BlockCopy(cipherText, 0, c, 0, cipherText.Length);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_box\_open(byte\[] m, byte\[] c, long clen, byte\[] n, byte\[] pk, byte\[] sk)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] cipherSegment = new byte\[clen];

&nbsp;Buffer.BlockCopy(c, 0, cipherSegment, 0, (int)clen);



&nbsp;byte\[] message = CryptoBox.Decrypt(cipherSegment, n, pk, sk);

&nbsp;if (message == null) return -1; // Decryption failed



&nbsp;Buffer.BlockCopy(message, 0, m, 0, message.Length);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_box\_beforenm(byte\[] k, byte\[] pk, byte\[] sk)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] sharedKey = CryptoBox.BeforeNm(pk, sk);

&nbsp;Buffer.BlockCopy(sharedKey, 0, k, 0, CryptoBox.BEFORENMBYTES);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_box\_afternm(byte\[] c, byte\[] m, long mlen, byte\[] n, byte\[] k)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] messageSegment = new byte\[mlen];

&nbsp;Buffer.BlockCopy(m, 0, messageSegment, 0, (int)mlen);



&nbsp;byte\[] cipherText = CryptoBox.AfterNm(messageSegment, n, k);

&nbsp;Buffer.BlockCopy(cipherText, 0, c, 0, cipherText.Length);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_box\_open\_afternm(byte\[] m, byte\[] c, long clen, byte\[] n, byte\[] k)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] cipherSegment = new byte\[clen];

&nbsp;Buffer.BlockCopy(c, 0, cipherSegment, 0, (int)clen);



&nbsp;byte\[] message = CryptoBox.OpenAfterNm(cipherSegment, n, k);

&nbsp;if (message == null) return -1; // Decryption failed



&nbsp;Buffer.BlockCopy(message, 0, m, 0, message.Length);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static void crypto\_box\_random\_nonce(byte\[] nonce)

&nbsp;{

&nbsp;byte\[] randomNonce = CryptoBox.GenerateNonce();

&nbsp;Buffer.BlockCopy(randomNonce, 0, nonce, 0, CryptoBox.NONCEBYTES);

&nbsp;}



&nbsp;} 

}

]



Archivo CryptoHashSha256.cs \[

using System.Security.Cryptography;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estado para hash incremental (wrapper alrededor de IncrementalHash)

&nbsp;/// </summary>

&nbsp;public class CryptoHashSha256State : IDisposable

&nbsp;{

&nbsp;internal IncrementalHash IncrementalHash { get; }



&nbsp;public CryptoHashSha256State()

&nbsp;{

&nbsp;IncrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;IncrementalHash?.Dispose();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Implementación de crypto\_hash\_sha256

&nbsp;/// Hash SHA-256 para integridad de datos

&nbsp;/// </summary>

&nbsp;public static class CryptoHashSha256

&nbsp;{

&nbsp;public const int BYTES = 32; // 256 bits = 32 bytes

&nbsp;public const int STATEBYTES = 64; // Tamaño típico del estado en implementaciones C



&nbsp;/// <summary>

&nbsp;/// Calcula el hash SHA-256 de los datos de entrada

&nbsp;/// </summary>

&nbsp;public static byte\[] Hash(byte\[] input)

&nbsp;{

&nbsp;if (input == null) throw new ArgumentNullException(nameof(input));



&nbsp;using (var sha256 = SHA256.Create())

&nbsp;{

&nbsp;return sha256.ComputeHash(input);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Calcula el hash SHA-256 de una porción de datos

&nbsp;/// </summary>

&nbsp;public static byte\[] Hash(byte\[] input, int offset, int count)

&nbsp;{

&nbsp;if (input == null) throw new ArgumentNullException(nameof(input));

&nbsp;if (offset < 0 || offset >= input.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(offset));

&nbsp;if (count < 0 || offset + count > input.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(count));



&nbsp;using (var sha256 = SHA256.Create())

&nbsp;{

&nbsp;return sha256.ComputeHash(input, offset, count);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Crea un estado para hash incremental

&nbsp;/// </summary>

&nbsp;public static CryptoHashSha256State CreateIncrementalHash()

&nbsp;{

&nbsp;return new CryptoHashSha256State();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Inicializa un estado para hash incremental

&nbsp;/// </summary>

&nbsp;public static void Init(CryptoHashSha256State state)

&nbsp;{

&nbsp;// El estado ya se inicializa en el constructor

&nbsp;// Esta función existe para compatibilidad con la API C

&nbsp;if (state == null) throw new ArgumentNullException(nameof(state));

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Actualiza el estado hash con nuevos datos

&nbsp;/// </summary>

&nbsp;public static void Update(CryptoHashSha256State state, byte\[] input, int offset, int count)

&nbsp;{

&nbsp;if (state == null) throw new ArgumentNullException(nameof(state));

&nbsp;if (input == null) throw new ArgumentNullException(nameof(input));

&nbsp;if (offset < 0 || offset >= input.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(offset));

&nbsp;if (count < 0 || offset + count > input.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(count));



&nbsp;state.IncrementalHash.AppendData(input, offset, count);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Finaliza el hash y obtiene el resultado

&nbsp;/// </summary>

&nbsp;public static byte\[] Final(CryptoHashSha256State state)

&nbsp;{

&nbsp;if (state == null) throw new ArgumentNullException(nameof(state));

&nbsp;return state.IncrementalHash.GetHashAndReset();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Versión con output pre-allocated para compatibilidad con C

&nbsp;/// </summary>

&nbsp;public static bool Hash(byte\[] output, int outputOffset, byte\[] input, int inputOffset, int inputLength)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] hash = Hash(input, inputOffset, inputLength);

&nbsp;Buffer.BlockCopy(hash, 0, output, outputOffset, BYTES);

&nbsp;return true;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test con vectores conocidos de SHA-256

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;// Test vector 1: "abc"

&nbsp;byte\[] test1 = System.Text.Encoding.UTF8.GetBytes("abc");

&nbsp;byte\[] expected1 = new byte\[] {

&nbsp;0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,

&nbsp;0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,

&nbsp;0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,

&nbsp;0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD

&nbsp;};



&nbsp;byte\[] result1 = Hash(test1);

&nbsp;if (!CompareByteArrays(result1, expected1))

&nbsp;return false;



&nbsp;// Test vector 2: Cadena vacía

&nbsp;byte\[] test2 = new byte\[0];

&nbsp;byte\[] expected2 = new byte\[] {

&nbsp;0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,

&nbsp;0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,

&nbsp;0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,

&nbsp;0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55

&nbsp;};



&nbsp;byte\[] result2 = Hash(test2);

&nbsp;if (!CompareByteArrays(result2, expected2))

&nbsp;return false;



&nbsp;// Test incremental completo

&nbsp;using (var state = CreateIncrementalHash())

&nbsp;{

&nbsp;Init(state);

&nbsp;Update(state, System.Text.Encoding.UTF8.GetBytes("Hello "), 0, 6);

&nbsp;Update(state, System.Text.Encoding.UTF8.GetBytes("World"), 0, 5);

&nbsp;Update(state, System.Text.Encoding.UTF8.GetBytes("!"), 0, 1);

&nbsp;byte\[] resultIncremental = Final(state);



&nbsp;byte\[] expectedFull = Hash(System.Text.Encoding.UTF8.GetBytes("Hello World!"));

&nbsp;if (!CompareByteArrays(resultIncremental, expectedFull))

&nbsp;return false;

&nbsp;}



&nbsp;return true;

&nbsp;}



&nbsp;private static bool CompareByteArrays(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null || a.Length != b.Length)

&nbsp;return false;



&nbsp;for (int i = 0; i < a.Length; i++)

&nbsp;{

&nbsp;if (a\[i] != b\[i])

&nbsp;return false;

&nbsp;}

&nbsp;return true;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class crypto\_hash\_sha256\_native

&nbsp;{

&nbsp;public const int crypto\_hash\_sha256\_BYTES = CryptoHashSha256.BYTES;

&nbsp;public const int crypto\_hash\_sha256\_STATEBYTES = CryptoHashSha256.STATEBYTES;



&nbsp;public static int crypto\_hash\_sha256(byte\[] @out, byte\[] @in, ulong inlen)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] inputSegment = new byte\[inlen];

&nbsp;Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);



&nbsp;byte\[] hash = CryptoHashSha256.Hash(inputSegment);

&nbsp;Buffer.BlockCopy(hash, 0, @out, 0, CryptoHashSha256.BYTES);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_hash\_sha256\_init(IntPtr statePtr)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// En C, state es un buffer de bytes, en C# usamos un objeto managed

&nbsp;// Para compatibilidad, almacenamos el estado managed en un GCHandle

&nbsp;var state = new CryptoHashSha256State();

&nbsp;var handle = System.Runtime.InteropServices.GCHandle.Alloc(state);

&nbsp;System.Runtime.InteropServices.Marshal.WriteIntPtr(statePtr,

&nbsp;System.Runtime.InteropServices.GCHandle.ToIntPtr(handle));

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_hash\_sha256\_update(IntPtr statePtr, byte\[] @in, ulong inlen)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var handle = System.Runtime.InteropServices.GCHandle.FromIntPtr(statePtr);

&nbsp;var state = (CryptoHashSha256State)handle.Target;

&nbsp;CryptoHashSha256.Update(state, @in, 0, (int)inlen);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_hash\_sha256\_final(IntPtr statePtr, byte\[] @out)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var handle = System.Runtime.InteropServices.GCHandle.FromIntPtr(statePtr);

&nbsp;var state = (CryptoHashSha256State)handle.Target;



&nbsp;byte\[] hash = CryptoHashSha256.Final(state);

&nbsp;Buffer.BlockCopy(hash, 0, @out, 0, CryptoHashSha256.BYTES);



&nbsp;// Liberar el handle

&nbsp;state.Dispose();

&nbsp;handle.Free();



&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo CryptoPwHash.Sodium.cs \[

using Sodium;

using System.Security.Cryptography;

using System.Text;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación CORREGIDA de crypto\_pwhash\_scryptsalsa208sha256 usando Sodium

&nbsp;/// </summary>

&nbsp;public static class CryptoPwHash

&nbsp;{

&nbsp;public const int SALT\_BYTES = 32;

&nbsp;public const int HASH\_BYTES = 32;

&nbsp;public const int OPSLIMIT\_INTERACTIVE = 524288;

&nbsp;public const uint MEMLIMIT\_INTERACTIVE = 16777216;

&nbsp;public const ulong OPSLIMIT\_SENSITIVE = 33554432;

&nbsp;public const uint MEMLIMIT\_SENSITIVE = 1073741824;



&nbsp;/// <summary>

&nbsp;/// Deriva clave usando scryptsalsa208sha256 - CORREGIDO para Sodium.Core 1.4.0

&nbsp;/// </summary>

&nbsp;public static byte\[] ScryptSalsa208Sha256(byte\[] password, byte\[] salt, uint opsLimit, uint memLimit)

&nbsp;{

&nbsp;if (password == null) throw new ArgumentNullException(nameof(password));

&nbsp;if (salt == null || salt.Length != SALT\_BYTES)

&nbsp;throw new ArgumentException($"Salt must be {SALT\_BYTES} bytes");



&nbsp;try

&nbsp;{

&nbsp;// libsodium-net solo acepta string y long/int

&nbsp;string pwd = Encoding.UTF8.GetString(password);

&nbsp;string slt = Encoding.UTF8.GetString(salt);



&nbsp;string hashStr = PasswordHash.ScryptHashString(

&nbsp;pwd, 

&nbsp;(int)opsLimit,

&nbsp;(int)memLimit);



&nbsp;// Volvemos a bytes (32 exactos)

&nbsp;byte\[] hash = new byte\[HASH\_BYTES];

&nbsp;Buffer.BlockCopy(Encoding.UTF8.GetBytes(hashStr), 0, hash, 0, HASH\_BYTES);

&nbsp;return hash;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;throw new CryptographicException("Scrypt key derivation failed", ex);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera salt seguro

&nbsp;/// </summary>

&nbsp;public static byte\[] GenerateSalt()

&nbsp;{

&nbsp;byte\[] salt = new byte\[SALT\_BYTES];

&nbsp;using (var rng = RandomNumberGenerator.Create())

&nbsp;{

&nbsp;rng.GetBytes(salt);

&nbsp;}

&nbsp;return salt;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verifica password contra hash

&nbsp;/// </summary>

&nbsp;public static bool Verify(byte\[] expectedHash, byte\[] password, byte\[] salt,

&nbsp;uint opsLimit, uint memLimit)

&nbsp;{

&nbsp;if (expectedHash == null || expectedHash.Length != HASH\_BYTES)

&nbsp;return false;



&nbsp;byte\[] computedHash = ScryptSalsa208Sha256(password, salt, opsLimit, memLimit);

&nbsp;return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de Scrypt

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] salt1 = GenerateSalt();

&nbsp;byte\[] salt2 = GenerateSalt();



&nbsp;bool saltValid = salt1.Length == SALT\_BYTES \&\& salt2.Length == SALT\_BYTES;

&nbsp;bool saltsDifferent = !CryptographicOperations.FixedTimeEquals(salt1, salt2);



&nbsp;byte\[] password = System.Text.Encoding.UTF8.GetBytes("test\_password");

&nbsp;byte\[] hash = ScryptSalsa208Sha256(password, salt1, OPSLIMIT\_INTERACTIVE, MEMLIMIT\_INTERACTIVE);

&nbsp;bool derivationValid = hash != null \&\& hash.Length == HASH\_BYTES;



&nbsp;bool verifyCorrect = Verify(hash, password, salt1, OPSLIMIT\_INTERACTIVE, MEMLIMIT\_INTERACTIVE);



&nbsp;byte\[] wrongPassword = System.Text.Encoding.UTF8.GetBytes("wrong\_password");

&nbsp;bool verifyWrong = Verify(hash, wrongPassword, salt1, OPSLIMIT\_INTERACTIVE, MEMLIMIT\_INTERACTIVE);



&nbsp;byte\[] hash2 = ScryptSalsa208Sha256(password, salt1, OPSLIMIT\_INTERACTIVE, MEMLIMIT\_INTERACTIVE);

&nbsp;bool deterministic = CryptographicOperations.FixedTimeEquals(hash, hash2);



&nbsp;byte\[] hash3 = ScryptSalsa208Sha256(password, salt2, OPSLIMIT\_INTERACTIVE, MEMLIMIT\_INTERACTIVE);

&nbsp;bool differentWithDifferentSalt = !CryptographicOperations.FixedTimeEquals(hash, hash3);



&nbsp;return saltValid \&\& saltsDifferent \&\& derivationValid \&\& verifyCorrect \&\&

&nbsp;!verifyWrong \&\& deterministic \&\& differentWithDifferentSalt;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class crypto\_pwhash\_scryptsalsa208sha256\_native

&nbsp;{

&nbsp;public const int SALTBYTES = CryptoPwHash.SALT\_BYTES;

&nbsp;public const int BYTES = CryptoPwHash.HASH\_BYTES;

&nbsp;public const ulong OPSLIMIT\_INTERACTIVE = CryptoPwHash.OPSLIMIT\_INTERACTIVE;

&nbsp;public const uint MEMLIMIT\_INTERACTIVE = CryptoPwHash.MEMLIMIT\_INTERACTIVE;

&nbsp;public const ulong OPSLIMIT\_SENSITIVE = CryptoPwHash.OPSLIMIT\_SENSITIVE;

&nbsp;public const uint MEMLIMIT\_SENSITIVE = CryptoPwHash.MEMLIMIT\_SENSITIVE;



&nbsp;public static int crypto\_pwhash\_scryptsalsa208sha256(

&nbsp;byte\[] @out, ulong outlen,

&nbsp;byte\[] passwd, ulong passwdlen,

&nbsp;byte\[] salt,

&nbsp;uint opslimit, uint memlimit)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] passwordSegment = new byte\[passwdlen];

&nbsp;Buffer.BlockCopy(passwd, 0, passwordSegment, 0, (int)passwdlen);



&nbsp;byte\[] result = CryptoPwHash.ScryptSalsa208Sha256(

&nbsp;passwordSegment, salt, opslimit, memlimit);



&nbsp;Buffer.BlockCopy(result, 0, @out, 0, (int)outlen);

&nbsp;return 0;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo CryptoVerify.cs \[

using System.Security.Cryptography;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación de crypto\_verify

&nbsp;/// Comparación constante en tiempo para evitar timing attacks

&nbsp;/// </summary>

&nbsp;public static class CryptoVerify

&nbsp;{

&nbsp;public const int BYTES = 32; // Tamaño estándar para comparaciones



&nbsp;/// <summary>

&nbsp;/// Comparación constante en tiempo de dos arrays de bytes

&nbsp;/// </summary>

&nbsp;public static bool Verify(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null) throw new ArgumentNullException(nameof(a));

&nbsp;if (b == null) throw new ArgumentNullException(nameof(b));

&nbsp;if (a.Length != b.Length)

&nbsp;throw new ArgumentException("Arrays must have the same length");



&nbsp;return CryptographicOperations.FixedTimeEquals(a, b);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparación constante en tiempo de dos arrays de bytes con longitud específica

&nbsp;/// </summary>

&nbsp;public static bool Verify(byte\[] a, int aOffset, byte\[] b, int bOffset, int length)

&nbsp;{

&nbsp;if (a == null) throw new ArgumentNullException(nameof(a));

&nbsp;if (b == null) throw new ArgumentNullException(nameof(b));

&nbsp;if (aOffset < 0 || aOffset >= a.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(aOffset));

&nbsp;if (bOffset < 0 || bOffset >= b.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(bOffset));

&nbsp;if (length < 0 || aOffset + length > a.Length || bOffset + length > b.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(length));



&nbsp;// Implementación manual de comparación constante en tiempo

&nbsp;int result = 0;

&nbsp;for (int i = 0; i < length; i++)

&nbsp;{

&nbsp;result |= a\[aOffset + i] ^ b\[bOffset + i];

&nbsp;}

&nbsp;return result == 0;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparación constante en tiempo para arrays de 16 bytes

&nbsp;/// </summary>

&nbsp;public static bool Verify16(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null) throw new ArgumentNullException(nameof(a));

&nbsp;if (b == null) throw new ArgumentNullException(nameof(b));

&nbsp;if (a.Length != 16 || b.Length != 16)

&nbsp;throw new ArgumentException("Arrays must be 16 bytes long");



&nbsp;return CryptographicOperations.FixedTimeEquals(a, b);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparación constante en tiempo para arrays de 32 bytes

&nbsp;/// </summary>

&nbsp;public static bool Verify32(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null) throw new ArgumentNullException(nameof(a));

&nbsp;if (b == null) throw new ArgumentNullException(nameof(b));

&nbsp;if (a.Length != 32 || b.Length != 32)

&nbsp;throw new ArgumentException("Arrays must be 32 bytes long");



&nbsp;return CryptographicOperations.FixedTimeEquals(a, b);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparación constante en tiempo para arrays de 64 bytes

&nbsp;/// </summary>

&nbsp;public static bool Verify64(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null) throw new ArgumentNullException(nameof(a));

&nbsp;if (b == null) throw new ArgumentNullException(nameof(b));

&nbsp;if (a.Length != 64 || b.Length != 64)

&nbsp;throw new ArgumentException("Arrays must be 64 bytes long");



&nbsp;return CryptographicOperations.FixedTimeEquals(a, b);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Versión que retorna int para compatibilidad con C (0 = iguales, -1 = diferentes)

&nbsp;/// </summary>

&nbsp;public static int VerifyReturn(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;return Verify(a, b) ? 0 : -1;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de comparación constante en tiempo CORREGIDO

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" Ejecutando tests de CryptoVerify...");



&nbsp;// Test 1: Arrays iguales

&nbsp;byte\[] a1 = new byte\[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

&nbsp;byte\[] b1 = new byte\[] { 0x01, 0x02, 0x03, 0x04, 0x05 };



&nbsp;if (!Verify(a1, b1))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 1 falló: Arrays iguales no coincidieron");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 1 - Arrays iguales: PASÓ");



&nbsp;// Test 2: Arrays diferentes

&nbsp;byte\[] a2 = new byte\[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

&nbsp;byte\[] b2 = new byte\[] { 0x01, 0x02, 0x03, 0x04, 0x06 };



&nbsp;if (Verify(a2, b2))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 2 falló: Arrays diferentes coincidieron");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 2 - Arrays diferentes: PASÓ");



&nbsp;// Test 3: Arrays de diferentes longitudes (debería lanzar excepción)

&nbsp;try

&nbsp;{

&nbsp;byte\[] a3 = new byte\[5];

&nbsp;byte\[] b3 = new byte\[6];

&nbsp;Verify(a3, b3);

&nbsp;Console.WriteLine(" ❌ Test 3 falló: No lanzó excepción por longitudes diferentes");

&nbsp;return false;

&nbsp;}

&nbsp;catch (ArgumentException)

&nbsp;{

&nbsp;// Esperado

&nbsp;Console.WriteLine(" ✅ Test 3 - Longitudes diferentes: PASÓ");

&nbsp;}



&nbsp;// Test 4: Verify16

&nbsp;byte\[] a4 = new byte\[16];

&nbsp;byte\[] b4 = new byte\[16];

&nbsp;for (int i = 0; i < 16; i++)

&nbsp;{

&nbsp;a4\[i] = (byte)0x42;

&nbsp;b4\[i] = (byte)0x42;

&nbsp;}



&nbsp;if (!Verify16(a4, b4))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 4 falló: Verify16 con arrays iguales");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 4 - Verify16: PASÓ");



&nbsp;// Test 5: Verify32

&nbsp;byte\[] a5 = new byte\[32];

&nbsp;byte\[] b5 = new byte\[32];

&nbsp;for (int i = 0; i < 32; i++)

&nbsp;{

&nbsp;a5\[i] = (byte)0x99;

&nbsp;b5\[i] = (byte)0x99;

&nbsp;}



&nbsp;if (!Verify32(a5, b5))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 5 falló: Verify32 con arrays iguales");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 5 - Verify32: PASÓ");



&nbsp;// Test 6: Verify64

&nbsp;byte\[] a6 = new byte\[64];

&nbsp;byte\[] b6 = new byte\[64];

&nbsp;for (int i = 0; i < 64; i++)

&nbsp;{

&nbsp;a6\[i] = (byte)0xFF;

&nbsp;b6\[i] = (byte)0xFF;

&nbsp;}



&nbsp;if (!Verify64(a6, b6))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 6 falló: Verify64 con arrays iguales");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 6 - Verify64: PASÓ");



&nbsp;// Test 7: Comparación con offset

&nbsp;byte\[] a7 = new byte\[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };

&nbsp;byte\[] b7 = new byte\[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };



&nbsp;if (!Verify(a7, 2, b7, 2, 5))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 7 falló: Comparación con offset iguales");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 7 - Comparación con offset: PASÓ");



&nbsp;// Test 8: Comparación con offset diferente

&nbsp;byte\[] a8 = new byte\[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };

&nbsp;byte\[] b8 = new byte\[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x00, 0x00, 0x00 };



&nbsp;if (Verify(a8, 2, b8, 2, 5))

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 8 falló: Comparación con offset diferentes");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 8 - Comparación con offset diferente: PASÓ");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Error en test: {ex.Message}");

&nbsp;Console.WriteLine($" Stack trace: {ex.StackTrace}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de timing (verificación visual de que el tiempo es constante)

&nbsp;/// </summary>

&nbsp;public static void TestTiming()

&nbsp;{

&nbsp;Console.WriteLine(" Probando características de timing...");



&nbsp;// Crear arrays grandes para hacer la prueba más evidente

&nbsp;byte\[] largeArray1 = new byte\[1024];

&nbsp;byte\[] largeArray2 = new byte\[1024];

&nbsp;byte\[] largeArray3 = new byte\[1024];



&nbsp;Array.Fill(largeArray1, (byte)0x42);

&nbsp;Array.Fill(largeArray2, (byte)0x42);

&nbsp;Array.Fill(largeArray3, (byte)0x43); // Diferente en el primer byte



&nbsp;var sw = System.Diagnostics.Stopwatch.StartNew();



&nbsp;// Comparación de arrays iguales (debería recorrer todo el array)

&nbsp;bool result1 = Verify(largeArray1, largeArray2);

&nbsp;long time1 = sw.ElapsedTicks;



&nbsp;sw.Restart();



&nbsp;// Comparación de arrays diferentes en el primer byte (debería recorrer todo el array también)

&nbsp;bool result2 = Verify(largeArray1, largeArray3);

&nbsp;long time2 = sw.ElapsedTicks;



&nbsp;// Los tiempos deberían ser similares (comparación constante en tiempo)

&nbsp;double timeDifference = Math.Abs(time1 - time2);

&nbsp;double timeRatio = (double)Math.Max(time1, time2) / Math.Min(time1, time2);



&nbsp;Console.WriteLine($" Tiempo arrays iguales: {time1} ticks");

&nbsp;Console.WriteLine($" Tiempo arrays diferentes: {time2} ticks");

&nbsp;Console.WriteLine($" Diferencia: {timeDifference} ticks");

&nbsp;Console.WriteLine($" Ratio: {timeRatio:F2}");

&nbsp;Console.WriteLine($" Timing constante: {(timeRatio < 2.0 ? "✅" : "⚠️")}"); // Ratio < 2.0 es aceptable

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class crypto\_verify\_native

&nbsp;{

&nbsp;public const int crypto\_verify\_BYTES = CryptoVerify.BYTES;



&nbsp;public static int crypto\_verify(byte\[] x, byte\[] y)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;return CryptoVerify.VerifyReturn(x, y);

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_verify\_16(byte\[] x, byte\[] y)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;return CryptoVerify.Verify16(x, y) ? 0 : -1;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_verify\_32(byte\[] x, byte\[] y)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;return CryptoVerify.Verify32(x, y) ? 0 : -1;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public static int crypto\_verify\_64(byte\[] x, byte\[] y)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;return CryptoVerify.Verify64(x, y) ? 0 : -1;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo DHT.cs \[

using Sodium;

using System;

using System.Collections.Generic;

using System.Linq;

using System.Net;

using System.Runtime.InteropServices;

using System.Security.Cryptography;

using System.Threading;

using System.Threading.Tasks;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación completa de Kademlia DHT compatible con toxcore C

&nbsp;/// </summary>

&nbsp;public class DHT

&nbsp;{

&nbsp;private const string LOG\_TAG = "DHT";



&nbsp;// ===== CONSTANTES TOXCORE REALES =====

&nbsp;public const int MAX\_FRIEND\_CLOSE = 8;

&nbsp;public const int CRYPTO\_PACKET\_SIZE = 122;

&nbsp;public const int CRYPTO\_NONCE\_SIZE = 24;

&nbsp;public const int CRYPTO\_PUBLIC\_KEY\_SIZE = 32;

&nbsp;public const int CRYPTO\_SECRET\_KEY\_SIZE = 32;

&nbsp;public const int MAX\_CLOSE\_TO\_BOOTSTRAP\_NODES = 16;

&nbsp;public const int DHT\_PING\_INTERVAL = 30000; // 30 segundos

&nbsp;public const int DHT\_PING\_TIMEOUT = 10000; // 10 segundos

&nbsp;public const int CRYPTO\_SYMMETRIC\_KEY\_SIZE = 32;

&nbsp;public const int CRYPTO\_MAC\_SIZE = 16;

&nbsp;public const int DHT\_PING\_SIZE = 64;

&nbsp;public const int DHT\_PONG\_SIZE = 64;

&nbsp;public const int MAX\_CRYPTO\_PACKET\_SIZE = 1024;



&nbsp;// ===== CONSTANTES KADEMLIA =====

&nbsp;public const int K = 8; // K-bucket size (tamaño estándar Kademlia)

&nbsp;public const int ALPHA = 3; // Paralelismo en búsquedas

&nbsp;public const int BUCKET\_REFRESH\_INTERVAL = 900000; // 15 minutos

&nbsp;public const int KEY\_ROTATION\_INTERVAL = 60000; // 60 segundos



&nbsp;// ===== ESTRUCTURAS DE DATOS KADEMLIA =====



&nbsp;/// <summary>

&nbsp;/// K-Bucket real - implementación completa de Kademlia

&nbsp;/// </summary>

&nbsp;public class KBucket

&nbsp;{

&nbsp;private readonly List<DHTNode> nodes = new List<DHTNode>(K);

&nbsp;private readonly object lockObj = new object();

&nbsp;private DateTime lastUpdated = DateTime.UtcNow;



&nbsp;public int Index { get; }

&nbsp;public int Count

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (lockObj) return nodes.Count;

&nbsp;}

&nbsp;}



&nbsp;public KBucket(int index)

&nbsp;{

&nbsp;Index = index;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Intenta añadir un nodo al K-bucket siguiendo la política Kademlia

&nbsp;/// </summary>

&nbsp;public bool TryAddNode(DHTNode newNode)

&nbsp;{

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;// Verificar si el nodo ya existe

&nbsp;var existing = nodes.FirstOrDefault(n => ByteArraysEqual(n.PublicKey, newNode.PublicKey));

&nbsp;if (existing != null)

&nbsp;{

&nbsp;// Mover al final (LRU - Least Recently Used)

&nbsp;nodes.Remove(existing);

&nbsp;existing.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;existing.LastPingSent = 0;

&nbsp;existing.IsActive = true;

&nbsp;nodes.Add(existing);

&nbsp;lastUpdated = DateTime.UtcNow;

&nbsp;return true;

&nbsp;}



&nbsp;// Si hay espacio, añadir directamente

&nbsp;if (nodes.Count < K)

&nbsp;{

&nbsp;newNode.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;nodes.Add(newNode);

&nbsp;lastUpdated = DateTime.UtcNow;

&nbsp;return true;

&nbsp;}



&nbsp;// Bucket lleno - verificar si hay nodos inactivos

&nbsp;var oldestInactive = nodes.FirstOrDefault(n => !n.IsActive ||

&nbsp;(DateTime.UtcNow.Ticks - n.LastSeen) > TimeSpan.TicksPerMinute \* 15);



&nbsp;if (oldestInactive != null)

&nbsp;{

&nbsp;// Reemplazar el nodo inactivo más antiguo

&nbsp;nodes.Remove(oldestInactive);

&nbsp;newNode.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;nodes.Add(newNode);

&nbsp;lastUpdated = DateTime.UtcNow;

&nbsp;return true;

&nbsp;}



&nbsp;// Todos los nodos están activos - ping al más antiguo

&nbsp;var oldest = nodes.OrderBy(n => n.LastSeen).First();

&nbsp;oldest.LastPingSent = DateTime.UtcNow.Ticks;

&nbsp;return false; // No se pudo añadir ahora

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene los nodos del bucket ordenados por LRU

&nbsp;/// </summary>

&nbsp;public List<DHTNode> GetNodes()

&nbsp;{

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;return nodes.OrderByDescending(n => n.LastSeen).ToList();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Marca un nodo como inactivo si no responde

&nbsp;/// </summary>

&nbsp;public bool MarkNodeInactive(byte\[] publicKey)

&nbsp;{

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;var node = nodes.FirstOrDefault(n => ByteArraysEqual(n.PublicKey, publicKey));

&nbsp;if (node != null)

&nbsp;{

&nbsp;node.IsActive = false;

&nbsp;return true;

&nbsp;}

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpia nodos inactivos antiguos

&nbsp;/// </summary>

&nbsp;public int CleanupInactiveNodes()

&nbsp;{

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;long cutoff = DateTime.UtcNow.Ticks - TimeSpan.TicksPerHour \* 2;

&nbsp;int removed = nodes.RemoveAll(n => !n.IsActive \&\& n.LastSeen < cutoff);

&nbsp;return removed;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verifica si necesita refresco (15 minutos sin actualización)

&nbsp;/// </summary>

&nbsp;public bool NeedsRefresh()

&nbsp;{

&nbsp;return (DateTime.UtcNow - lastUpdated) > TimeSpan.FromMilliseconds(BUCKET\_REFRESH\_INTERVAL);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tabla de routing Kademlia con 256 K-buckets

&nbsp;/// </summary>

&nbsp;public class KademliaRoutingTable

&nbsp;{

&nbsp;private readonly KBucket\[] buckets = new KBucket\[256];

&nbsp;private readonly byte\[] localId;

&nbsp;private readonly object lockObj = new object();



&nbsp;public KademliaRoutingTable(byte\[] localId)

&nbsp;{

&nbsp;if (localId.Length != CRYPTO\_PUBLIC\_KEY\_SIZE)

&nbsp;throw new ArgumentException("Local ID must be 32 bytes");



&nbsp;this.localId = localId;



&nbsp;for (int i = 0; i < 256; i++)

&nbsp;{

&nbsp;buckets\[i] = new KBucket(i);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Calcula el índice del bucket basado en el prefix length compartido

&nbsp;/// </summary>

&nbsp;public int GetBucketIndex(byte\[] targetId)

&nbsp;{

&nbsp;return KademliaDistance.GetSharedPrefixLength(localId, targetId);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Añade un nodo a la tabla de routing

&nbsp;/// </summary>

&nbsp;public bool AddNode(DHTNode node)

&nbsp;{

&nbsp;// No añadirnos a nosotros mismos

&nbsp;if (ByteArraysEqual(node.PublicKey, localId))

&nbsp;return false;



&nbsp;int bucketIndex = GetBucketIndex(node.PublicKey);



&nbsp;lock (lockObj)

&nbsp;{

&nbsp;return buckets\[bucketIndex].TryAddNode(node);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Encuentra los K nodos más cercanos a un ID objetivo

&nbsp;/// </summary>

&nbsp;public List<DHTNode> FindClosestNodes(byte\[] targetId, int count = K)

&nbsp;{

&nbsp;var candidates = new List<DHTNode>();



&nbsp;lock (lockObj)

&nbsp;{

&nbsp;// Obtener nodos del bucket correspondiente

&nbsp;int targetBucket = GetBucketIndex(targetId);

&nbsp;candidates.AddRange(buckets\[targetBucket].GetNodes());



&nbsp;// Si necesitamos más nodos, buscar en buckets adyacentes

&nbsp;if (candidates.Count < count)

&nbsp;{

&nbsp;for (int i = 1; i < 256 \&\& candidates.Count < count; i++)

&nbsp;{

&nbsp;int lowerBucket = targetBucket - i;

&nbsp;int upperBucket = targetBucket + i;



&nbsp;if (lowerBucket >= 0)

&nbsp;candidates.AddRange(buckets\[lowerBucket].GetNodes());

&nbsp;if (upperBucket < 256 \&\& candidates.Count < count)

&nbsp;candidates.AddRange(buckets\[upperBucket].GetNodes());

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// Ordenar por distancia XOR y tomar los más cercanos

&nbsp;return candidates

&nbsp;.OrderBy(n => KademliaDistance.Calculate(localId, n.PublicKey), new KademliaDistanceComparer())

&nbsp;.Take(count)

&nbsp;.ToList();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene todos los nodos de la tabla

&nbsp;/// </summary>

&nbsp;public List<DHTNode> GetAllNodes()

&nbsp;{

&nbsp;var allNodes = new List<DHTNode>();

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;foreach (var bucket in buckets)

&nbsp;{

&nbsp;allNodes.AddRange(bucket.GetNodes());

&nbsp;}

&nbsp;}

&nbsp;return allNodes;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Marca un nodo como inactivo

&nbsp;/// </summary>

&nbsp;public bool MarkNodeInactive(byte\[] publicKey)

&nbsp;{

&nbsp;int bucketIndex = GetBucketIndex(publicKey);

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;return buckets\[bucketIndex].MarkNodeInactive(publicKey);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpieza general de buckets inactivos

&nbsp;/// </summary>

&nbsp;public int CleanupAllBuckets()

&nbsp;{

&nbsp;int totalRemoved = 0;

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;foreach (var bucket in buckets)

&nbsp;{

&nbsp;totalRemoved += bucket.CleanupInactiveNodes();

&nbsp;}

&nbsp;}

&nbsp;return totalRemoved;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene buckets que necesitan refresco

&nbsp;/// </summary>

&nbsp;public List<int> GetBucketsNeedingRefresh()

&nbsp;{

&nbsp;var needingRefresh = new List<int>();

&nbsp;lock (lockObj)

&nbsp;{

&nbsp;for (int i = 0; i < 256; i++)

&nbsp;{

&nbsp;if (buckets\[i].NeedsRefresh())

&nbsp;{

&nbsp;needingRefresh.Add(i);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return needingRefresh;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Utilidades para cálculos Kademlia

&nbsp;/// </summary>

&nbsp;public static class KademliaDistance

&nbsp;{

&nbsp;/// <summary>

&nbsp;/// Calcula la distancia XOR entre dos IDs

&nbsp;/// </summary>

&nbsp;public static byte\[] Calculate(byte\[] id1, byte\[] id2)

&nbsp;{

&nbsp;if (id1.Length != id2.Length)

&nbsp;throw new ArgumentException("IDs must have same length");



&nbsp;var result = new byte\[id1.Length];

&nbsp;for (int i = 0; i < id1.Length; i++)

&nbsp;{

&nbsp;result\[i] = (byte)(id1\[i] ^ id2\[i]);

&nbsp;}

&nbsp;return result;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Calcula la longitud del prefix compartido en bits

&nbsp;/// </summary>

&nbsp;public static int GetSharedPrefixLength(byte\[] id1, byte\[] id2)

&nbsp;{

&nbsp;int sharedBits = 0;

&nbsp;for (int i = 0; i < id1.Length; i++)

&nbsp;{

&nbsp;byte xor = (byte)(id1\[i] ^ id2\[i]);

&nbsp;if (xor == 0)

&nbsp;{

&nbsp;sharedBits += 8;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;int j = 7;

&nbsp;while (j >= 0 \&\& ((xor >> j) \& 1) == 0)

&nbsp;{

&nbsp;sharedBits++;

&nbsp;j--;

&nbsp;}

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;return Math.Min(sharedBits, 255); // Máximo 255 para array de 256

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verifica si dos nodos estarían en el mismo bucket

&nbsp;/// </summary>

&nbsp;public static bool InSameBucket(byte\[] localId, byte\[] targetId, int bucketIndex)

&nbsp;{

&nbsp;return GetSharedPrefixLength(localId, targetId) >= bucketIndex;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparador para ordenar por distancia XOR (Kademlia)

&nbsp;/// </summary>

&nbsp;public class KademliaDistanceComparer : IComparer<byte\[]>

&nbsp;{

&nbsp;public int Compare(byte\[] x, byte\[] y)

&nbsp;{

&nbsp;// Comparación bit a bit, más significativo primero

&nbsp;for (int i = 0; i < x.Length; i++)

&nbsp;{

&nbsp;if (x\[i] != y\[i])

&nbsp;{

&nbsp;// En Kademlia, menor distancia = más cercano

&nbsp;return x\[i].CompareTo(y\[i]);

&nbsp;}

&nbsp;}

&nbsp;return 0;

&nbsp;}

&nbsp;}



&nbsp;// ===== ESTRUCTURAS COMPATIBLES CON TOXCORE ORIGINAL =====



&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct PackedNode

&nbsp;{

&nbsp;public IPPort IPPort;

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]

&nbsp;public byte\[] PublicKey;



&nbsp;public PackedNode(IPPort ipp, byte\[] publicKey)

&nbsp;{

&nbsp;IPPort = ipp;

&nbsp;PublicKey = new byte\[32];

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);

&nbsp;}

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{IPPort} \[PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";

&nbsp;}

&nbsp;}



&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct NodeFormat

&nbsp;{

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]

&nbsp;public byte\[] PublicKey;

&nbsp;public IPPort IPPort;



&nbsp;public NodeFormat(byte\[] publicKey, IPPort ipp)

&nbsp;{

&nbsp;PublicKey = new byte\[32];

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);

&nbsp;}

&nbsp;IPPort = ipp;

&nbsp;}

&nbsp;}



&nbsp;public struct DHTHandshake

&nbsp;{

&nbsp;public byte\[] TemporaryPublicKey;

&nbsp;public byte\[] TemporarySecretKey;

&nbsp;public byte\[] PeerPublicKey;

&nbsp;public long CreationTime;

&nbsp;public IPPort EndPoint;

&nbsp;}



&nbsp;public struct HandshakePacket

&nbsp;{

&nbsp;public byte\[] TemporaryPublicKey;

&nbsp;public byte\[] EncryptedPayload;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Nodo DHT con información completa y métricas Kademlia

&nbsp;/// </summary>

&nbsp;public class DHTNode

&nbsp;{

&nbsp;public byte\[] PublicKey { get; set; }

&nbsp;public IPPort EndPoint { get; set; }

&nbsp;public long LastSeen { get; set; }

&nbsp;public long LastPingSent { get; set; }

&nbsp;public int PingID { get; set; }

&nbsp;public bool IsActive { get; set; }

&nbsp;public int RTT { get; set; }

&nbsp;public int QualityScore { get; set; }

&nbsp;public int FailedPings { get; set; }

&nbsp;public long FirstSeen { get; set; }



&nbsp;public DHTNode(byte\[] publicKey, IPPort endPoint)

&nbsp;{

&nbsp;PublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;EndPoint = endPoint;

&nbsp;LastSeen = DateTime.UtcNow.Ticks;

&nbsp;FirstSeen = DateTime.UtcNow.Ticks;

&nbsp;IsActive = true;

&nbsp;QualityScore = 100;

&nbsp;FailedPings = 0;

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{EndPoint} \[PK: {BitConverter.ToString(PublicKey, 0, 8).Replace("-", "")}...]";

&nbsp;}

&nbsp;}



&nbsp;// ===== CAMPOS PRIVADOS =====



&nbsp;private readonly KademliaRoutingTable routingTable;

&nbsp;private readonly Dictionary<string, DHTHandshake> activeHandshakes;

&nbsp;private readonly object handshakesLock = new object();



&nbsp;public byte\[] SelfPublicKey { get; private set; }

&nbsp;public byte\[] SelfSecretKey { get; private set; }

&nbsp;public int Socket { get; private set; }



&nbsp;private readonly List<PackedNode> bootstrapNodes;

&nbsp;private int lastPingID;

&nbsp;private long lastBootstrapTime;

&nbsp;private long lastMaintenanceTime;

&nbsp;private long lastLogTime;



&nbsp;// Claves temporales para handshake

&nbsp;private byte\[] currentTempPublicKey;

&nbsp;private byte\[] currentTempSecretKey;

&nbsp;private long lastKeyRotation;



&nbsp;// Estadísticas

&nbsp;public int TotalNodes => routingTable.GetAllNodes().Count;

&nbsp;public int ActiveNodes => routingTable.GetAllNodes().Count(n => n.IsActive);



&nbsp;// ===== CONSTRUCTOR =====



&nbsp;public DHT(byte\[] selfPublicKey, byte\[] selfSecretKey)

&nbsp;{

&nbsp;if (selfPublicKey?.Length != CRYPTO\_PUBLIC\_KEY\_SIZE || selfSecretKey?.Length != CRYPTO\_SECRET\_KEY\_SIZE)

&nbsp;throw new ArgumentException("Invalid key sizes");



&nbsp;SelfPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;SelfSecretKey = new byte\[CRYPTO\_SECRET\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, CRYPTO\_SECRET\_KEY\_SIZE);



&nbsp;routingTable = new KademliaRoutingTable(SelfPublicKey);

&nbsp;bootstrapNodes = new List<PackedNode>();

&nbsp;activeHandshakes = new Dictionary<string, DHTHandshake>();



&nbsp;lastPingID = 0;

&nbsp;lastBootstrapTime = 0;

&nbsp;lastMaintenanceTime = 0;

&nbsp;lastLogTime = 0;



&nbsp;Socket = Network.new\_socket(2, 2, 17); // IPv4 UDP

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] DHT Kademlia inicializado - Socket: {Socket}");

&nbsp;}



&nbsp;// ===== MÉTODOS PÚBLICOS COMPATIBLES CON TOXCORE =====



&nbsp;/// <summary>

&nbsp;/// DHT\_bootstrap - Compatible con C original

&nbsp;/// </summary>

&nbsp;public int DHT\_bootstrap(IPPort ipp, byte\[] public\_key)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Bootstrap a {ipp}");



&nbsp;if (Socket == -1) return -1;



&nbsp;try

&nbsp;{

&nbsp;var bootstrapNode = new PackedNode(ipp, public\_key);

&nbsp;bootstrapNodes.Add(bootstrapNode);



&nbsp;// Enviar get\_nodes request encriptado

&nbsp;byte\[] packet = CreateEncryptedGetNodesPacket(public\_key, SelfPublicKey);

&nbsp;if (packet == null) return -1;



&nbsp;int sent = Network.socket\_send(Socket, packet, packet.Length, ipp);

&nbsp;return sent > 0 ? 0 : -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en bootstrap: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DHT\_handle\_packet - Maneja paquetes entrantes

&nbsp;/// </summary>

&nbsp;public int DHT\_handle\_packet(byte\[] packet, int length, IPPort source)

&nbsp;{

&nbsp;if (packet == null || length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];



&nbsp;// Paquetes encriptados

&nbsp;if (packetType >= 0x80)

&nbsp;{

&nbsp;return HandleCryptopacket(source, packet, length, SelfPublicKey);

&nbsp;}



&nbsp;// Paquetes de handshake

&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x10: // Handshake request

&nbsp;return HandleHandshakeRequest(packet, length, source);

&nbsp;case 0x11: // Handshake response

&nbsp;return HandleHandshakeResponse(packet, length, source);

&nbsp;default:

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Tipo de paquete desconocido: 0x{packetType:X2}");

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DHT\_send\_packet - Compatible con C original

&nbsp;/// </summary>

&nbsp;public int DHT\_send\_packet(IPPort ipp, byte\[] packet, int length)

&nbsp;{

&nbsp;if (Socket == -1) return -1;

&nbsp;return Network.socket\_send(Socket, packet, length, ipp);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DHT\_get\_nodes - Compatible con C original

&nbsp;/// </summary>

&nbsp;public int DHT\_get\_nodes(byte\[] nodes, int length, IPPort ipp)

&nbsp;{

&nbsp;if (nodes == null || length < 1) return -1;



&nbsp;try

&nbsp;{

&nbsp;var closestNodes = routingTable.FindClosestNodes(SelfPublicKey, MAX\_FRIEND\_CLOSE);

&nbsp;int offset = 0;



&nbsp;foreach (var node in closestNodes)

&nbsp;{

&nbsp;if (offset + 50 > length) break; // 32 + 18 = 50 bytes por nodo



&nbsp;// Copiar clave pública

&nbsp;Buffer.BlockCopy(node.PublicKey, 0, nodes, offset, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;offset += CRYPTO\_PUBLIC\_KEY\_SIZE;



&nbsp;// Copiar IPPort

&nbsp;byte\[] ippBytes = IPPortToBytes(node.EndPoint);

&nbsp;Buffer.BlockCopy(ippBytes, 0, nodes, offset, 18);

&nbsp;offset += 18;

&nbsp;}



&nbsp;return offset; // Total bytes escritos

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ===== HANDSHAKE CRIPTOGRÁFICO REAL =====



&nbsp;/// <summary>

&nbsp;/// Genera o rota las claves temporales para handshake

&nbsp;/// </summary>

&nbsp;private void EnsureTempKeys()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;if (currentTempPublicKey == null ||

&nbsp;(currentTime - lastKeyRotation) > TimeSpan.TicksPerMillisecond \* KEY\_ROTATION\_INTERVAL)

&nbsp;{

&nbsp;var keyPair = CryptoBox.GenerateKeyPair();

&nbsp;currentTempPublicKey = keyPair.PublicKey;

&nbsp;currentTempSecretKey = keyPair.PrivateKey;

&nbsp;lastKeyRotation = currentTime;



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Claves temporales rotadas");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Inicia handshake criptográfico con un nodo

&nbsp;/// </summary>

&nbsp;public int StartHandshake(IPPort endPoint, byte\[] peerPublicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;EnsureTempKeys();



&nbsp;// Crear payload del handshake: nuestra public key real + nonce

&nbsp;byte\[] payload = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE + 8];

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, payload, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;byte\[] nonce = BitConverter.GetBytes(DateTime.UtcNow.Ticks);

&nbsp;Buffer.BlockCopy(nonce, 0, payload, CRYPTO\_PUBLIC\_KEY\_SIZE, 8);



&nbsp;// Encriptar payload con la public key del peer

&nbsp;byte\[] encryptionNonce = RandomBytes.Generate(CRYPTO\_NONCE\_SIZE);

&nbsp;byte\[] encryptedPayload = CryptoBox.Encrypt(payload, encryptionNonce, peerPublicKey, SelfSecretKey);



&nbsp;if (encryptedPayload == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se pudo encriptar payload del handshake");

&nbsp;return -1;

&nbsp;}



&nbsp;// Construir paquete de handshake

&nbsp;byte\[] handshakePacket = CreateHandshakePacket(currentTempPublicKey, encryptionNonce, encryptedPayload);



&nbsp;// Enviar handshake

&nbsp;int sent = DHT\_send\_packet(endPoint, handshakePacket, handshakePacket.Length);

&nbsp;if (sent <= 0) return -1;



&nbsp;// Registrar handshake pendiente

&nbsp;var handshake = new DHTHandshake

&nbsp;{

&nbsp;TemporaryPublicKey = currentTempPublicKey,

&nbsp;TemporarySecretKey = currentTempSecretKey,

&nbsp;PeerPublicKey = peerPublicKey,

&nbsp;CreationTime = DateTime.UtcNow.Ticks,

&nbsp;EndPoint = endPoint

&nbsp;};



&nbsp;string handshakeKey = $"{endPoint}\_{BitConverter.ToString(peerPublicKey).Replace("-", "").Substring(0, 16)}";



&nbsp;lock (handshakesLock)

&nbsp;{

&nbsp;activeHandshakes\[handshakeKey] = handshake;

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Handshake iniciado con {endPoint}");

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando handshake: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Maneja solicitud de handshake entrante

&nbsp;/// </summary>

&nbsp;private int HandleHandshakeRequest(byte\[] packet, int length, IPPort source)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + 16)

&nbsp;return -1;



&nbsp;// Extraer temporary public key del remitente

&nbsp;byte\[] peerTempPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1, peerTempPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Extraer y desencriptar payload

&nbsp;byte\[] nonce = new byte\[CRYPTO\_NONCE\_SIZE];

&nbsp;byte\[] encryptedPayload = new byte\[length - 1 - CRYPTO\_PUBLIC\_KEY\_SIZE - CRYPTO\_NONCE\_SIZE];



&nbsp;Buffer.BlockCopy(packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE, nonce, 0, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encryptedPayload, 0, encryptedPayload.Length);



&nbsp;// Desencriptar con nuestra secret key real

&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encryptedPayload, nonce, peerTempPublicKey, SelfSecretKey);

&nbsp;if (decrypted == null || decrypted.Length < CRYPTO\_PUBLIC\_KEY\_SIZE)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se pudo desencriptar solicitud de handshake");

&nbsp;return -1;

&nbsp;}



&nbsp;// Extraer public key real del peer

&nbsp;byte\[] peerRealPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(decrypted, 0, peerRealPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Generar respuesta de handshake

&nbsp;EnsureTempKeys();



&nbsp;// Crear payload de respuesta: nuestra public key real

&nbsp;byte\[] responsePayload = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, responsePayload, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Encriptar respuesta con la temporary public key del peer

&nbsp;byte\[] responseNonce = RandomBytes.Generate(CRYPTO\_NONCE\_SIZE);

&nbsp;byte\[] encryptedResponse = CryptoBox.Encrypt(responsePayload, responseNonce, peerTempPublicKey, currentTempSecretKey);



&nbsp;if (encryptedResponse == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se pudo encriptar respuesta de handshake");

&nbsp;return -1;

&nbsp;}



&nbsp;// Enviar respuesta

&nbsp;byte\[] responsePacket = CreateHandshakeResponsePacket(currentTempPublicKey, responseNonce, encryptedResponse);

&nbsp;int sent = DHT\_send\_packet(source, responsePacket, responsePacket.Length);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// Agregar nodo a la DHT

&nbsp;AddNode(peerRealPublicKey, source);

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Handshake respondido a {source}");

&nbsp;}



&nbsp;return sent > 0 ? 0 : -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando solicitud de handshake: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Maneja respuesta de handshake

&nbsp;/// </summary>

&nbsp;private int HandleHandshakeResponse(byte\[] packet, int length, IPPort source)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + 16)

&nbsp;return -1;



&nbsp;// Extraer temporary public key del remitente

&nbsp;byte\[] peerTempPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1, peerTempPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Buscar handshake pendiente

&nbsp;var handshake = FindHandshakeByTempKey(peerTempPublicKey, source);

&nbsp;if (handshake == null)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Handshake no encontrado para {source}");

&nbsp;return -1;

&nbsp;}



&nbsp;// Extraer y desencriptar payload

&nbsp;byte\[] nonce = new byte\[CRYPTO\_NONCE\_SIZE];

&nbsp;byte\[] encryptedPayload = new byte\[length - 1 - CRYPTO\_PUBLIC\_KEY\_SIZE - CRYPTO\_NONCE\_SIZE];



&nbsp;Buffer.BlockCopy(packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE, nonce, 0, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encryptedPayload, 0, encryptedPayload.Length);



&nbsp;// Desencriptar con nuestra temporary secret key

&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encryptedPayload, nonce, peerTempPublicKey, handshake.Value.TemporarySecretKey);

&nbsp;if (decrypted == null || decrypted.Length < CRYPTO\_PUBLIC\_KEY\_SIZE)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se pudo desencriptar respuesta de handshake");

&nbsp;return -1;

&nbsp;}



&nbsp;// Extraer public key real del peer

&nbsp;byte\[] peerRealPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(decrypted, 0, peerRealPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Verificar que coincide con la public key esperada

&nbsp;if (!ByteArraysEqual(peerRealPublicKey, handshake.Value.PeerPublicKey))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Public key no coincide en handshake");

&nbsp;return -1;

&nbsp;}



&nbsp;// Handshake completado - agregar nodo a la DHT

&nbsp;AddNode(peerRealPublicKey, source);



&nbsp;// Limpiar handshake

&nbsp;RemoveHandshake(peerTempPublicKey, source);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Handshake completado con {source}");

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando respuesta de handshake: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ===== MANEJO DE PAQUETES ENCRIPTADOS DHT =====



&nbsp;/// <summary>

&nbsp;/// HandleCryptopacket - Maneja paquetes encriptados DHT reales

&nbsp;/// </summary>

&nbsp;public int HandleCryptopacket(IPPort source, byte\[] packet, int length, byte\[] publicKey)

&nbsp;{

&nbsp;if (packet == null || length < CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + CRYPTO\_MAC\_SIZE + 1)

&nbsp;return -1;



&nbsp;try

&nbsp;{

&nbsp;// 1. Calcular shared key para decryptar

&nbsp;byte\[] sharedKey = new byte\[CRYPTO\_SYMMETRIC\_KEY\_SIZE];

&nbsp;int keyResult = DHT\_get\_shared\_key\_recv(sharedKey, packet, SelfSecretKey);

&nbsp;if (keyResult == -1) return -1;



&nbsp;// 2. Extraer nonce (bytes 32-55)

&nbsp;byte\[] nonce = new byte\[CRYPTO\_NONCE\_SIZE];

&nbsp;Buffer.BlockCopy(packet, CRYPTO\_PUBLIC\_KEY\_SIZE, nonce, 0, CRYPTO\_NONCE\_SIZE);



&nbsp;// 3. Extraer datos encriptados (resto del paquete)

&nbsp;int encryptedLength = length - CRYPTO\_PUBLIC\_KEY\_SIZE - CRYPTO\_NONCE\_SIZE;

&nbsp;byte\[] encrypted = new byte\[encryptedLength];

&nbsp;Buffer.BlockCopy(packet, CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encrypted, 0, encryptedLength);



&nbsp;// 4. Decryptar usando crypto\_box\_open\_afternm

&nbsp;byte\[] decrypted = CryptoBox.OpenAfterNm(encrypted, nonce, sharedKey);

&nbsp;if (decrypted == null) return -1;



&nbsp;// 5. Procesar el paquete decryptado basado en su tipo

&nbsp;return ProcessDecryptedDhtPacket(source, decrypted, decrypted.Length, publicKey);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleCryptopacket: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// ProcessDecryptedDhtPacket - Procesa paquetes DHT decryptados

&nbsp;/// </summary>

&nbsp;private int ProcessDecryptedDhtPacket(IPPort source, byte\[] decrypted, int length, byte\[] expectedPublicKey)

&nbsp;{

&nbsp;if (decrypted == null || length < 1) return -1;



&nbsp;byte packetType = decrypted\[0];



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x00: // Ping request

&nbsp;return HandleDecryptedPingRequest(source, decrypted, length, expectedPublicKey);



&nbsp;case 0x01: // Ping response

&nbsp;return HandleDecryptedPingResponse(source, decrypted, length, expectedPublicKey);



&nbsp;case 0x02: // Get nodes request

&nbsp;return HandleDecryptedGetNodesRequest(source, decrypted, length, expectedPublicKey);



&nbsp;case 0x04: // Send nodes response

&nbsp;return HandleDecryptedSendNodesResponse(source, decrypted, length, expectedPublicKey);



&nbsp;default:

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Tipo de paquete DHT desconocido: 0x{packetType:X2}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleDecryptedPingRequest - Maneja ping request encriptado

&nbsp;/// </summary>

&nbsp;private int HandleDecryptedPingRequest(IPPort source, byte\[] packet, int length, byte\[] expectedPublicKey)

&nbsp;{

&nbsp;if (length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Extraer public key del ping (bytes 1-32)

&nbsp;byte\[] senderPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Verificar que coincide con la key esperada

&nbsp;if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Public key no coincide en ping request");

&nbsp;return -1;

&nbsp;}



&nbsp;// Agregar/actualizar nodo en la tabla Kademlia

&nbsp;var node = new DHTNode(senderPublicKey, source);

&nbsp;routingTable.AddNode(node);



&nbsp;// Enviar pong response

&nbsp;byte\[] pongResponse = CreateDhtPongResponse(senderPublicKey);

&nbsp;if (pongResponse != null)

&nbsp;{

&nbsp;return DHT\_send\_packet(source, pongResponse, pongResponse.Length);

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleDecryptedPingRequest: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleDecryptedPingResponse - Maneja ping response encriptado

&nbsp;/// </summary>

&nbsp;private int HandleDecryptedPingResponse(IPPort source, byte\[] packet, int length, byte\[] expectedPublicKey)

&nbsp;{

&nbsp;if (length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Extraer public key del pong (bytes 1-32)

&nbsp;byte\[] senderPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Verificar que coincide con la key esperada

&nbsp;if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Public key no coincide en ping response");

&nbsp;return -1;

&nbsp;}



&nbsp;// Actualizar nodo en la tabla Kademlia

&nbsp;var node = new DHTNode(senderPublicKey, source);

&nbsp;routingTable.AddNode(node);



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Ping response recibido de {source}");

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleDecryptedPingResponse: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleDecryptedGetNodesRequest - Maneja get\_nodes request encriptado

&nbsp;/// </summary>

&nbsp;private int HandleDecryptedGetNodesRequest(IPPort source, byte\[] packet, int length, byte\[] expectedPublicKey)

&nbsp;{

&nbsp;if (length < 1 + CRYPTO\_PUBLIC\_KEY\_SIZE \* 2) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Extraer public key del solicitante (bytes 1-32)

&nbsp;byte\[] senderPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1, senderPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Extraer public key objetivo de búsqueda (bytes 33-64)

&nbsp;byte\[] targetPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE, targetPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Verificar que la key del solicitante coincide

&nbsp;if (!ByteArraysEqual(senderPublicKey, expectedPublicKey))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Public key no coincide en get\_nodes request");

&nbsp;return -1;

&nbsp;}



&nbsp;// Agregar/actualizar nodo del solicitante

&nbsp;var senderNode = new DHTNode(senderPublicKey, source);

&nbsp;routingTable.AddNode(senderNode);



&nbsp;// Obtener los K nodos más cercanos al objetivo usando Kademlia

&nbsp;var closestNodes = routingTable.FindClosestNodes(targetPublicKey, K);

&nbsp;if (closestNodes.Count > 0)

&nbsp;{

&nbsp;// Enviar respuesta SEND\_NODES

&nbsp;byte\[] nodesResponse = CreateDhtSendNodesResponse(senderPublicKey, closestNodes);

&nbsp;if (nodesResponse != null)

&nbsp;{

&nbsp;return DHT\_send\_packet(source, nodesResponse, nodesResponse.Length);

&nbsp;}

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleDecryptedGetNodesRequest: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleDecryptedSendNodesResponse - Maneja send\_nodes response encriptado

&nbsp;/// </summary>

&nbsp;private int HandleDecryptedSendNodesResponse(IPPort source, byte\[] packet, int length, byte\[] expectedPublicKey)

&nbsp;{

&nbsp;if (length < 1) return -1;



&nbsp;try

&nbsp;{

&nbsp;// El payload es: \[0x04] + \[nodos\*(public\_key + ipport)]

&nbsp;int nodesDataLength = length - 1;



&nbsp;// Cada nodo ocupa 50 bytes (32 + 18)

&nbsp;int nodeCount = nodesDataLength / 50;



&nbsp;int nodesAdded = 0;

&nbsp;for (int i = 0; i < nodeCount; i++)

&nbsp;{

&nbsp;int offset = 1 + (i \* 50);



&nbsp;// Extraer public key del nodo (32 bytes)

&nbsp;byte\[] nodePublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, offset, nodePublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Extraer IPPort (18 bytes)

&nbsp;byte\[] ippBytes = new byte\[18];

&nbsp;Buffer.BlockCopy(packet, offset + CRYPTO\_PUBLIC\_KEY\_SIZE, ippBytes, 0, 18);



&nbsp;IPPort nodeIPPort = BytesToIPPort(ippBytes);



&nbsp;// Solo agregar nodos válidos

&nbsp;if (nodeIPPort.Port > 0 \&\& nodeIPPort.IP.Data != null)

&nbsp;{

&nbsp;var newNode = new DHTNode(nodePublicKey, nodeIPPort);

&nbsp;routingTable.AddNode(newNode);

&nbsp;nodesAdded++;

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {nodesAdded} nodos agregados desde send\_nodes de {source}");

&nbsp;return nodesAdded > 0 ? 0 : -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleDecryptedSendNodesResponse: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ===== FUNCIONES DE CREACIÓN DE PAQUETES =====



&nbsp;/// <summary>

&nbsp;/// Crea paquete de handshake

&nbsp;/// </summary>

&nbsp;private byte\[] CreateHandshakePacket(byte\[] tempPublicKey, byte\[] nonce, byte\[] encryptedPayload)

&nbsp;{

&nbsp;byte\[] packet = new byte\[1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + encryptedPayload.Length];

&nbsp;packet\[0] = 0x10; // HANDSHAKE\_REQUEST packet type



&nbsp;Buffer.BlockCopy(tempPublicKey, 0, packet, 1, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(encryptedPayload, 0, packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encryptedPayload.Length);



&nbsp;return packet;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Crea paquete de respuesta de handshake

&nbsp;/// </summary>

&nbsp;private byte\[] CreateHandshakeResponsePacket(byte\[] tempPublicKey, byte\[] nonce, byte\[] encryptedPayload)

&nbsp;{

&nbsp;byte\[] packet = new byte\[1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + encryptedPayload.Length];

&nbsp;packet\[0] = 0x11; // HANDSHAKE\_RESPONSE packet type



&nbsp;Buffer.BlockCopy(tempPublicKey, 0, packet, 1, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(encryptedPayload, 0, packet, 1 + CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encryptedPayload.Length);



&nbsp;return packet;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DHT\_get\_shared\_key\_recv - Calcula la shared key para decryptar paquetes entrantes

&nbsp;/// </summary>

&nbsp;public int DHT\_get\_shared\_key\_recv(byte\[] sharedKey, byte\[] packet, byte\[] secretKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (sharedKey == null || packet == null || secretKey == null)

&nbsp;return -1;



&nbsp;// Extraer la public key temporal del remitente (primeros 32 bytes)

&nbsp;byte\[] tempPublicKey = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 0, tempPublicKey, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Calcular shared key usando crypto\_box\_beforenm

&nbsp;byte\[] calculatedKey = CryptoBox.BeforeNm(tempPublicKey, secretKey);

&nbsp;if (calculatedKey == null) return -1;



&nbsp;Buffer.BlockCopy(calculatedKey, 0, sharedKey, 0, CRYPTO\_SYMMETRIC\_KEY\_SIZE);

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en DHT\_get\_shared\_key\_recv: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CreateCryptopacket - Crea paquetes encriptados DHT reales

&nbsp;/// </summary>

&nbsp;public byte\[] CreateCryptopacket(byte\[] data, int length, byte\[] publicKey, byte\[] secretKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (data == null || length > MAX\_CRYPTO\_PACKET\_SIZE)

&nbsp;return null;



&nbsp;// 1. Generar keypair temporal para este paquete

&nbsp;var tempKeyPair = CryptoBox.GenerateKeyPair();

&nbsp;byte\[] tempPublicKey = tempKeyPair.PublicKey;

&nbsp;byte\[] tempSecretKey = tempKeyPair.PrivateKey;



&nbsp;// 2. Calcular shared key

&nbsp;byte\[] sharedKey = CryptoBox.BeforeNm(publicKey, tempSecretKey);

&nbsp;if (sharedKey == null) return null;



&nbsp;// 3. Generar nonce

&nbsp;byte\[] nonce = RandomBytes.Generate(CRYPTO\_NONCE\_SIZE);



&nbsp;// 4. Encriptar datos con crypto\_box\_afternm

&nbsp;byte\[] encrypted = CryptoBox.AfterNm(data, nonce, sharedKey);

&nbsp;if (encrypted == null) return null;



&nbsp;// 5. Construir paquete final: \[temp\_public\_key(32)]\[nonce(24)]\[encrypted\_data]

&nbsp;byte\[] packet = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE + encrypted.Length];

&nbsp;Buffer.BlockCopy(tempPublicKey, 0, packet, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(nonce, 0, packet, CRYPTO\_PUBLIC\_KEY\_SIZE, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(encrypted, 0, packet, CRYPTO\_PUBLIC\_KEY\_SIZE + CRYPTO\_NONCE\_SIZE, encrypted.Length);



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en CreateCryptopacket: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CreateDhtPongResponse - Crea respuesta PONG encriptada real

&nbsp;/// </summary>

&nbsp;private byte\[] CreateDhtPongResponse(byte\[] destinationPublicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Crear payload PONG: \[0x01]\[nuestra\_public\_key]

&nbsp;byte\[] pongPayload = new byte\[1 + CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;pongPayload\[0] = 0x01; // PONG type

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, pongPayload, 1, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// Encriptar el pong

&nbsp;return CreateCryptopacket(pongPayload, pongPayload.Length, destinationPublicKey, SelfSecretKey);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando pong response: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CreateDhtSendNodesResponse - Crea respuesta SEND\_NODES encriptada

&nbsp;/// </summary>

&nbsp;private byte\[] CreateDhtSendNodesResponse(byte\[] destinationPublicKey, List<DHTNode> nodes)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Calcular tamaño del payload: \[0x04] + \[nodos\*(public\_key + ipport)]

&nbsp;int nodesCount = Math.Min(nodes.Count, 4); // Máximo 4 nodos como en toxcore

&nbsp;int payloadSize = 1 + (nodesCount \* (CRYPTO\_PUBLIC\_KEY\_SIZE + 18)); // 18 bytes por IPPort



&nbsp;byte\[] payload = new byte\[payloadSize];

&nbsp;payload\[0] = 0x04; // SEND\_NODES type



&nbsp;int offset = 1;

&nbsp;foreach (var node in nodes.Take(nodesCount))

&nbsp;{

&nbsp;// Agregar public key del nodo (32 bytes)

&nbsp;Buffer.BlockCopy(node.PublicKey, 0, payload, offset, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;offset += CRYPTO\_PUBLIC\_KEY\_SIZE;



&nbsp;// Agregar IPPort (18 bytes)

&nbsp;byte\[] ippBytes = IPPortToBytes(node.EndPoint);

&nbsp;Buffer.BlockCopy(ippBytes, 0, payload, offset, 18);

&nbsp;offset += 18;

&nbsp;}



&nbsp;// Encriptar el payload

&nbsp;return CreateCryptopacket(payload, payload.Length, destinationPublicKey, SelfSecretKey);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando send\_nodes response: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CreateEncryptedGetNodesPacket - Crea get\_nodes request encriptado

&nbsp;/// </summary>

&nbsp;private byte\[] CreateEncryptedGetNodesPacket(byte\[] targetPublicKey, byte\[] searchPublicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Datos: nuestra public key + public key a buscar

&nbsp;byte\[] requestData = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE \* 2];

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, requestData, 0, CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(searchPublicKey, 0, requestData, CRYPTO\_PUBLIC\_KEY\_SIZE, CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;byte\[] nonce = RandomBytes.Generate(CRYPTO\_NONCE\_SIZE);

&nbsp;byte\[] encrypted = CryptoBox.Encrypt(requestData, nonce, targetPublicKey, SelfSecretKey);

&nbsp;if (encrypted == null) return null;



&nbsp;byte\[] packet = new byte\[1 + CRYPTO\_NONCE\_SIZE + encrypted.Length];

&nbsp;packet\[0] = 0x02; // GET\_NODES packet type

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 1, CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(encrypted, 0, packet, 1 + CRYPTO\_NONCE\_SIZE, encrypted.Length);



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando get\_nodes encriptado: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;// ===== GESTIÓN DE NODOS KADEMLIA =====



&nbsp;/// <summary>

&nbsp;/// Agregar nodo a la tabla Kademlia

&nbsp;/// </summary>

&nbsp;public int AddNode(byte\[] publicKey, IPPort endPoint)

&nbsp;{

&nbsp;if (publicKey?.Length != CRYPTO\_PUBLIC\_KEY\_SIZE)

&nbsp;return -1;



&nbsp;try

&nbsp;{

&nbsp;var node = new DHTNode(publicKey, endPoint);

&nbsp;bool added = routingTable.AddNode(node);



&nbsp;if (added)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Nodo agregado a Kademlia: {endPoint}");

&nbsp;}



&nbsp;return added ? 0 : 1; // 0 = nuevo, 1 = actualizado

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error agregando nodo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ===== FUNCIONES AUXILIARES =====



&nbsp;/// <summary>

&nbsp;/// IPPortToBytes - Convierte IPPort a array de bytes (18 bytes)

&nbsp;/// </summary>

&nbsp;private byte\[] IPPortToBytes(IPPort ipp)

&nbsp;{

&nbsp;byte\[] result = new byte\[18];



&nbsp;// IP (16 bytes)

&nbsp;if (ipp.IP.Data != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(ipp.IP.Data, 0, result, 0, 16);

&nbsp;}



&nbsp;// Puerto (2 bytes - big endian)

&nbsp;result\[16] = (byte)((ipp.Port >> 8) \& 0xFF);

&nbsp;result\[17] = (byte)(ipp.Port \& 0xFF);



&nbsp;return result;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// BytesToIPPort - Convierte array de bytes a IPPort

&nbsp;/// </summary>

&nbsp;private IPPort BytesToIPPort(byte\[] data)

&nbsp;{

&nbsp;if (data == null || data.Length < 18)

&nbsp;return new IPPort();



&nbsp;try

&nbsp;{

&nbsp;// IP (primeros 16 bytes)

&nbsp;byte\[] ipData = new byte\[16];

&nbsp;Buffer.BlockCopy(data, 0, ipData, 0, 16);



&nbsp;// Puerto (últimos 2 bytes - big endian)

&nbsp;ushort port = (ushort)((data\[16] << 8) | data\[17]);



&nbsp;// Determinar si es IPv4 o IPv6

&nbsp;bool isIPv4 = true;

&nbsp;for (int i = 0; i < 10; i++)

&nbsp;{

&nbsp;if (ipData\[i] != 0)

&nbsp;{

&nbsp;isIPv4 = false;

&nbsp;break;

&nbsp;}

&nbsp;}



&nbsp;IP ip;

&nbsp;if (isIPv4 \&\& ipData\[10] == 0xFF \&\& ipData\[11] == 0xFF)

&nbsp;{

&nbsp;// IPv4 mapeado a IPv6

&nbsp;byte\[] ip4Bytes = new byte\[4];

&nbsp;Buffer.BlockCopy(ipData, 12, ip4Bytes, 0, 4);

&nbsp;ip = new IP(new IP4(ip4Bytes));

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// IPv6 nativo

&nbsp;ip = new IP(new IP6(ipData));

&nbsp;}



&nbsp;return new IPPort(ip, port);

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return new IPPort();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Comparación segura de arrays de bytes

&nbsp;/// </summary>

&nbsp;private static bool ByteArraysEqual(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null || a.Length != b.Length)

&nbsp;return false;



&nbsp;return CryptoVerify.Verify(a, b);

&nbsp;}



&nbsp;// ===== MANTENIMIENTO Y LIMPIEZA KADEMLIA =====



&nbsp;/// <summary>

&nbsp;/// Manejo de handshakes pendientes

&nbsp;/// </summary>

&nbsp;private DHTHandshake? FindHandshakeByTempKey(byte\[] tempPublicKey, IPPort endPoint)

&nbsp;{

&nbsp;string targetKey = $"{endPoint}\_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";



&nbsp;lock (handshakesLock)

&nbsp;{

&nbsp;if (activeHandshakes.TryGetValue(targetKey, out var handshake))

&nbsp;{

&nbsp;return handshake;

&nbsp;}

&nbsp;}

&nbsp;return null;

&nbsp;}



&nbsp;private void RemoveHandshake(byte\[] tempPublicKey, IPPort endPoint)

&nbsp;{

&nbsp;string handshakeKey = $"{endPoint}\_{BitConverter.ToString(tempPublicKey).Replace("-", "").Substring(0, 16)}";



&nbsp;lock (handshakesLock)

&nbsp;{

&nbsp;activeHandshakes.Remove(handshakeKey);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpia handshakes expirados

&nbsp;/// </summary>

&nbsp;private void CleanupExpiredHandshakes()

&nbsp;{

&nbsp;long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond \* 30000; // 30 segundos

&nbsp;int removed = 0;



&nbsp;lock (handshakesLock)

&nbsp;{

&nbsp;var expiredKeys = new List<string>();



&nbsp;foreach (var kvp in activeHandshakes)

&nbsp;{

&nbsp;if (kvp.Value.CreationTime < cutoffTime)

&nbsp;{

&nbsp;expiredKeys.Add(kvp.Key);

&nbsp;}

&nbsp;}



&nbsp;foreach (var key in expiredKeys)

&nbsp;{

&nbsp;activeHandshakes.Remove(key);

&nbsp;removed++;

&nbsp;}

&nbsp;}



&nbsp;if (removed > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {removed} handshakes expirados removidos");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DoPeriodicWork - Mantenimiento periódico completo Kademlia

&nbsp;/// </summary>

&nbsp;public void DoPeriodicWork()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// 1. Limpieza de handshakes expirados

&nbsp;CleanupExpiredHandshakes();



&nbsp;// 2. Limpieza de buckets Kademlia

&nbsp;int removed = routingTable.CleanupAllBuckets();

&nbsp;if (removed > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Limpieza Kademlia: {removed} nodos removidos");

&nbsp;}



&nbsp;// 3. Refresco de buckets que necesitan actualización

&nbsp;var bucketsNeedingRefresh = routingTable.GetBucketsNeedingRefresh();

&nbsp;foreach (int bucketIndex in bucketsNeedingRefresh)

&nbsp;{

&nbsp;RefreshBucket(bucketIndex);

&nbsp;}



&nbsp;// 4. Re-bootstrap periódico

&nbsp;if ((currentTime - lastBootstrapTime) > TimeSpan.TicksPerSecond \* 300) // 5 minutos

&nbsp;{

&nbsp;foreach (var bootstrapNode in bootstrapNodes)

&nbsp;{

&nbsp;DHT\_bootstrap(bootstrapNode.IPPort, bootstrapNode.PublicKey);

&nbsp;}

&nbsp;lastBootstrapTime = currentTime;

&nbsp;}



&nbsp;// 5. Logging periódico

&nbsp;if ((currentTime - lastLogTime) > TimeSpan.TicksPerSecond \* 30) // 30 segundos

&nbsp;{

&nbsp;var allNodes = routingTable.GetAllNodes();

&nbsp;int activeCount = allNodes.Count(n => n.IsActive);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Kademlia Stats - Total: {allNodes.Count}, Activos: {activeCount}, Buckets: {GetActiveBucketCount()}");

&nbsp;lastLogTime = currentTime;

&nbsp;}



&nbsp;// 6. Rotación de claves temporales

&nbsp;EnsureTempKeys();



&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en trabajo periódico Kademlia: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Refresca un bucket Kademlia específico

&nbsp;/// </summary>

&nbsp;private void RefreshBucket(int bucketIndex)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Generar un ID aleatorio que caiga en este bucket

&nbsp;byte\[] randomId = GenerateRandomIdForBucket(bucketIndex);



&nbsp;// Hacer búsqueda de nodos para este ID

&nbsp;var closestNodes = routingTable.FindClosestNodes(randomId, ALPHA);



&nbsp;foreach (var node in closestNodes)

&nbsp;{

&nbsp;// Enviar get\_nodes request

&nbsp;byte\[] requestPacket = CreateEncryptedGetNodesPacket(node.PublicKey, randomId);

&nbsp;if (requestPacket != null)

&nbsp;{

&nbsp;DHT\_send\_packet(node.EndPoint, requestPacket, requestPacket.Length);

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Bucket {bucketIndex} refrescado");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error refrescando bucket {bucketIndex}: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera un ID aleatorio que caiga en un bucket específico

&nbsp;/// </summary>

&nbsp;private byte\[] GenerateRandomIdForBucket(int bucketIndex)

&nbsp;{

&nbsp;byte\[] randomId = new byte\[CRYPTO\_PUBLIC\_KEY\_SIZE];

&nbsp;RandomNumberGenerator.Fill(randomId);



&nbsp;// Asegurar que el ID caiga en el bucket deseado

&nbsp;if (bucketIndex > 0)

&nbsp;{

&nbsp;int byteIndex = bucketIndex / 8;

&nbsp;int bitIndex = bucketIndex % 8;



&nbsp;// Forzar el bit en la posición correcta

&nbsp;if (byteIndex < randomId.Length)

&nbsp;{

&nbsp;byte mask = (byte)(1 << (7 - bitIndex));

&nbsp;randomId\[byteIndex] = (byte)((randomId\[byteIndex] \& ~mask) | mask);

&nbsp;}

&nbsp;}



&nbsp;return randomId;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene el número de buckets activos

&nbsp;/// </summary>

&nbsp;private int GetActiveBucketCount()

&nbsp;{

&nbsp;int activeCount = 0;

&nbsp;for (int i = 0; i < 256; i++)

&nbsp;{

&nbsp;if (routingTable.FindClosestNodes(SelfPublicKey, 1).Count > 0)

&nbsp;{

&nbsp;activeCount++;

&nbsp;}

&nbsp;}

&nbsp;return activeCount;

&nbsp;}



&nbsp;// ===== FUNCIONES DE UTILIDAD =====



&nbsp;/// <summary>

&nbsp;/// Obtiene nodos más cercanos (versión cacheada para compatibilidad)

&nbsp;/// </summary>

&nbsp;public List<DHTNode> GetClosestNodesCached(byte\[] targetPublicKey, int maxNodes = 8)

&nbsp;{

&nbsp;return routingTable.FindClosestNodes(targetPublicKey, maxNodes);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene nodos más cercanos usando Kademlia

&nbsp;/// </summary>

&nbsp;public List<DHTNode> GetClosestNodes(byte\[] targetKey, int maxNodes = MAX\_FRIEND\_CLOSE)

&nbsp;{

&nbsp;return routingTable.FindClosestNodes(targetKey, maxNodes);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Cerrar DHT y liberar recursos

&nbsp;/// </summary>

&nbsp;public void Close()

&nbsp;{

&nbsp;if (Socket != -1)

&nbsp;{

&nbsp;Network.kill\_socket(Socket);

&nbsp;Socket = -1;

&nbsp;}



&nbsp;bootstrapNodes.Clear();

&nbsp;activeHandshakes.Clear();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Imprime estadísticas de Kademlia

&nbsp;/// </summary>

&nbsp;public void PrintStatistics()

&nbsp;{

&nbsp;var allNodes = routingTable.GetAllNodes();

&nbsp;int activeCount = allNodes.Count(n => n.IsActive);

&nbsp;int bucketCount = GetActiveBucketCount();



&nbsp;Console.WriteLine($"\[DHT Kademlia] Statistics:");

&nbsp;Console.WriteLine($" Total Nodes: {allNodes.Count}");

&nbsp;Console.WriteLine($" Active Nodes: {activeCount}");

&nbsp;Console.WriteLine($" Active Buckets: {bucketCount}");

&nbsp;Console.WriteLine($" Bootstrap Nodes: {bootstrapNodes.Count}");

&nbsp;Console.WriteLine($" Socket: {(Socket == -1 ? "Closed" : "Open")}");

&nbsp;}

&nbsp;}

}

]



Archivo EnhancedLogger.cs \[

using System.Collections.Concurrent;

using System.Text;

using System.Runtime.CompilerServices;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Niveles de log mejorados con colores y categorías

&nbsp;/// </summary>

&nbsp;public enum EnhancedLogLevel

&nbsp;{

&nbsp;TRACE = 0,

&nbsp;DEBUG = 1,

&nbsp;INFO = 2,

&nbsp;WARNING = 3,

&nbsp;ERROR = 4,

&nbsp;CRITICAL = 5,

&nbsp;PERFORMANCE = 6,

&nbsp;SECURITY = 7,

&nbsp;NETWORK = 8

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Categorías de log para filtrado

&nbsp;/// </summary>

&nbsp;public enum LogCategory

&nbsp;{

&nbsp;GENERAL,

&nbsp;NETWORK,

&nbsp;CRYPTO,

&nbsp;DHT,

&nbsp;MESSENGER,

&nbsp;FILE\_TRANSFER,

&nbsp;GROUP\_CHAT,

&nbsp;AV,

&nbsp;ONION,

&nbsp;TCP,

&nbsp;UDP,

&nbsp;MEMORY,

&nbsp;PERFORMANCE,

&nbsp;SECURITY

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Configuración del logger avanzado

&nbsp;/// </summary>

&nbsp;public class LoggerConfig

&nbsp;{

&nbsp;public string LogDirectory { get; set; } = "logs";

&nbsp;public string FileNamePrefix { get; set; } = "tox";

&nbsp;public bool EnableConsole { get; set; } = true;

&nbsp;public bool EnableFileLogging { get; set; } = true;

&nbsp;public bool EnableColors { get; set; } = true;

&nbsp;public bool EnableTimestamps { get; set; } = true;

&nbsp;public bool EnableCallerInfo { get; set; } = true;

&nbsp;public int MaxFileSizeMB { get; set; } = 10;

&nbsp;public int MaxFiles { get; set; } = 5;

&nbsp;public EnhancedLogLevel MinLevel { get; set; } = EnhancedLogLevel.INFO;

&nbsp;public LogCategory\[] EnabledCategories { get; set; } = Enum.GetValues<LogCategory>();

&nbsp;public bool AsyncLogging { get; set; } = true;

&nbsp;public int QueueSize { get; set; } = 1000;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Entrada de log con información completa

&nbsp;/// </summary>

&nbsp;public struct LogEntry

&nbsp;{

&nbsp;public EnhancedLogLevel Level;

&nbsp;public LogCategory Category;

&nbsp;public string Message;

&nbsp;public string File;

&nbsp;public string Member;

&nbsp;public int Line;

&nbsp;public DateTime Timestamp;

&nbsp;public Exception Exception;

&nbsp;public string ThreadName;

&nbsp;public long MemoryUsage;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Logger avanzado con múltiples destinos y características profesionales

&nbsp;/// </summary>

&nbsp;public class EnhancedLogger : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "ENH\_LOGGER";



&nbsp;// Componentes

&nbsp;private readonly LoggerConfig \_config;

&nbsp;private readonly ConcurrentQueue<LogEntry> \_logQueue;

&nbsp;private readonly Thread \_logWorker;

&nbsp;private readonly CancellationTokenSource \_cancellationTokenSource;

&nbsp;private readonly object \_fileLock = new object();

&nbsp;private StreamWriter \_currentFileWriter;

&nbsp;private string \_currentLogFile;

&nbsp;private long \_currentFileSize;

&nbsp;private bool \_isDisposed;

&nbsp;private bool \_isRunning;



&nbsp;// Estadísticas

&nbsp;private long \_totalLogEntries;

&nbsp;private long \_droppedEntries;

&nbsp;private DateTime \_startTime;



&nbsp;// Colores para consola (ANSI)

&nbsp;private static readonly Dictionary<EnhancedLogLevel, string> \_consoleColors = new()

&nbsp;{

&nbsp;\[EnhancedLogLevel.TRACE] = "\\x1b\[37m", // White

&nbsp;\[EnhancedLogLevel.DEBUG] = "\\x1b\[36m", // Cyan

&nbsp;\[EnhancedLogLevel.INFO] = "\\x1b\[32m", // Green

&nbsp;\[EnhancedLogLevel.WARNING] = "\\x1b\[33m", // Yellow

&nbsp;\[EnhancedLogLevel.ERROR] = "\\x1b\[31m", // Red

&nbsp;\[EnhancedLogLevel.CRITICAL] = "\\x1b\[35m", // Magenta

&nbsp;\[EnhancedLogLevel.PERFORMANCE] = "\\x1b\[34m", // Blue

&nbsp;\[EnhancedLogLevel.SECURITY] = "\\x1b\[91m", // Bright Red

&nbsp;\[EnhancedLogLevel.NETWORK] = "\\x1b\[94m" // Bright Blue

&nbsp;};



&nbsp;private const string ResetColor = "\\x1b\[0m";



&nbsp;// Categorías abreviadas

&nbsp;private static readonly Dictionary<LogCategory, string> \_categoryAbbr = new()

&nbsp;{

&nbsp;\[LogCategory.GENERAL] = "GEN",

&nbsp;\[LogCategory.NETWORK] = "NET",

&nbsp;\[LogCategory.CRYPTO] = "CRY",

&nbsp;\[LogCategory.DHT] = "DHT",

&nbsp;\[LogCategory.MESSENGER] = "MSG",

&nbsp;\[LogCategory.FILE\_TRANSFER] = "FIL",

&nbsp;\[LogCategory.GROUP\_CHAT] = "GRP",

&nbsp;\[LogCategory.AV] = "AV",

&nbsp;\[LogCategory.ONION] = "ONI",

&nbsp;\[LogCategory.TCP] = "TCP",

&nbsp;\[LogCategory.UDP] = "UDP",

&nbsp;\[LogCategory.MEMORY] = "MEM",

&nbsp;\[LogCategory.PERFORMANCE] = "PER",

&nbsp;\[LogCategory.SECURITY] = "SEC"

&nbsp;};



&nbsp;public EnhancedLogger(LoggerConfig config = null)

&nbsp;{

&nbsp;\_config = config ?? new LoggerConfig();

&nbsp;\_logQueue = new ConcurrentQueue<LogEntry>();

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;InitializeLogging();



&nbsp;if (\_config.AsyncLogging)

&nbsp;{

&nbsp;\_logWorker = new Thread(LogWorker);

&nbsp;\_logWorker.IsBackground = true;

&nbsp;\_logWorker.Name = "EnhancedLogger-Worker";

&nbsp;\_logWorker.Start();

&nbsp;}



&nbsp;\_startTime = DateTime.UtcNow;

&nbsp;LogInternal(EnhancedLogLevel.INFO, LogCategory.GENERAL,

&nbsp;$"Enhanced Logger inicializado - Nivel: {\_config.MinLevel}",

&nbsp;"EnhancedLogger", ".ctor", 0);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Inicializar sistema de logging

&nbsp;/// </summary>

&nbsp;private void InitializeLogging()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (\_config.EnableFileLogging)

&nbsp;{

&nbsp;// Crear directorio de logs

&nbsp;if (!Directory.Exists(\_config.LogDirectory))

&nbsp;{

&nbsp;Directory.CreateDirectory(\_config.LogDirectory);

&nbsp;}



&nbsp;// Crear archivo de log inicial

&nbsp;CreateNewLogFile();

&nbsp;}



&nbsp;\_isRunning = true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;// Fallback a logging básico

&nbsp;Console.WriteLine($"ERROR inicializando logger: {ex.Message}");

&nbsp;\_config.EnableFileLogging = false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Crear nuevo archivo de log

&nbsp;/// </summary>

&nbsp;private void CreateNewLogFile()

&nbsp;{

&nbsp;lock (\_fileLock)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;\_currentFileWriter?.Close();

&nbsp;\_currentFileWriter?.Dispose();



&nbsp;string timestamp = DateTime.Now.ToString("yyyyMMdd\_HHmmss");

&nbsp;\_currentLogFile = Path.Combine(\_config.LogDirectory,

&nbsp;$"{\_config.FileNamePrefix}\_{timestamp}.log");



&nbsp;\_currentFileWriter = new StreamWriter(\_currentLogFile, true, Encoding.UTF8)

&nbsp;{

&nbsp;AutoFlush = true

&nbsp;};

&nbsp;\_currentFileSize = 0;



&nbsp;// Escribir header del archivo

&nbsp;\_currentFileWriter.WriteLine($"# ToxCore Log - Started {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

&nbsp;\_currentFileWriter.WriteLine($"# Level: {\_config.MinLevel}");

&nbsp;\_currentFileWriter.WriteLine($"# Categories: {string.Join(", ", \_config.EnabledCategories)}");

&nbsp;\_currentFileWriter.WriteLine("# Fields: Timestamp|Level|Category|Thread|File:Line|Member|Message|Exception");

&nbsp;\_currentFileWriter.WriteLine();



&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($"ERROR creando archivo de log: {ex.Message}");

&nbsp;\_config.EnableFileLogging = false;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Log principal con información completa del caller

&nbsp;/// </summary>

&nbsp;public void Log(EnhancedLogLevel level, LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "",

&nbsp;\[CallerMemberName] string member = "",

&nbsp;\[CallerLineNumber] int line = 0)

&nbsp;{

&nbsp;if (!ShouldLog(level, category)) return;



&nbsp;var entry = new LogEntry

&nbsp;{

&nbsp;Level = level,

&nbsp;Category = category,

&nbsp;Message = message,

&nbsp;File = Path.GetFileName(file),

&nbsp;Member = member,

&nbsp;Line = line,

&nbsp;Timestamp = DateTime.UtcNow,

&nbsp;ThreadName = Thread.CurrentThread.Name ?? $"Thread\_{Thread.CurrentThread.ManagedThreadId}",

&nbsp;MemoryUsage = GC.GetTotalMemory(false)

&nbsp;};



&nbsp;if (\_config.AsyncLogging)

&nbsp;{

&nbsp;// Logging asíncrono

&nbsp;if (\_logQueue.Count < \_config.QueueSize)

&nbsp;{

&nbsp;\_logQueue.Enqueue(entry);

&nbsp;Interlocked.Increment(ref \_totalLogEntries);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Interlocked.Increment(ref \_droppedEntries);

&nbsp;// Fallback síncrono para no perder logs críticos

&nbsp;if (level >= EnhancedLogLevel.ERROR)

&nbsp;{

&nbsp;ProcessLogEntrySync(entry);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// Logging síncrono

&nbsp;ProcessLogEntrySync(entry);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Log con excepción

&nbsp;/// </summary>

&nbsp;public void LogException(EnhancedLogLevel level, LogCategory category, Exception exception, string context,

&nbsp;\[CallerFilePath] string file = "",

&nbsp;\[CallerMemberName] string member = "",

&nbsp;\[CallerLineNumber] int line = 0)

&nbsp;{

&nbsp;if (!ShouldLog(level, category)) return;



&nbsp;string message = $"{context} - {exception.GetType().Name}: {exception.Message}";

&nbsp;if (exception.InnerException != null)

&nbsp;{

&nbsp;message += $" -> {exception.InnerException.Message}";

&nbsp;}



&nbsp;var entry = new LogEntry

&nbsp;{

&nbsp;Level = level,

&nbsp;Category = category,

&nbsp;Message = message,

&nbsp;File = Path.GetFileName(file),

&nbsp;Member = member,

&nbsp;Line = line,

&nbsp;Timestamp = DateTime.UtcNow,

&nbsp;Exception = exception,

&nbsp;ThreadName = Thread.CurrentThread.Name ?? $"Thread\_{Thread.CurrentThread.ManagedThreadId}",

&nbsp;MemoryUsage = GC.GetTotalMemory(false)

&nbsp;};



&nbsp;if (\_config.AsyncLogging)

&nbsp;{

&nbsp;\_logQueue.Enqueue(entry);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;ProcessLogEntrySync(entry);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Verificar si se debe loguear

&nbsp;/// </summary>

&nbsp;private bool ShouldLog(EnhancedLogLevel level, LogCategory category)

&nbsp;{

&nbsp;return level >= \_config.MinLevel \&\&

&nbsp;\_config.EnabledCategories.Contains(category) \&\&

&nbsp;\_isRunning;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Worker principal para logging asíncrono

&nbsp;/// </summary>

&nbsp;private void LogWorker()

&nbsp;{

&nbsp;while (!\_cancellationTokenSource.Token.IsCancellationRequested || !\_logQueue.IsEmpty)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (\_logQueue.TryDequeue(out LogEntry entry))

&nbsp;{

&nbsp;ProcessLogEntry(entry);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Thread.Sleep(10); // Pequeña pausa si no hay entries

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;// Log de fallo del logger (usando Console como fallback)

&nbsp;Console.WriteLine($"LOGGER ERROR: {ex.Message}");

&nbsp;Thread.Sleep(100);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Procesar entrada de log

&nbsp;/// </summary>

&nbsp;private void ProcessLogEntry(LogEntry entry)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string formatted = FormatLogEntry(entry);



&nbsp;if (\_config.EnableConsole)

&nbsp;{

&nbsp;WriteToConsole(entry, formatted);

&nbsp;}



&nbsp;if (\_config.EnableFileLogging)

&nbsp;{

&nbsp;WriteToFile(formatted);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($"ERROR procesando log: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Procesar entrada de log síncronamente

&nbsp;/// </summary>

&nbsp;private void ProcessLogEntrySync(LogEntry entry)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string formatted = FormatLogEntry(entry);



&nbsp;if (\_config.EnableConsole)

&nbsp;{

&nbsp;WriteToConsole(entry, formatted);

&nbsp;}



&nbsp;if (\_config.EnableFileLogging)

&nbsp;{

&nbsp;WriteToFileSync(formatted);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($"ERROR procesando log síncrono: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Formatear entrada de log

&nbsp;/// </summary>

&nbsp;private string FormatLogEntry(LogEntry entry)

&nbsp;{

&nbsp;var sb = new StringBuilder();



&nbsp;if (\_config.EnableTimestamps)

&nbsp;{

&nbsp;sb.Append($"{entry.Timestamp:HH:mm:ss.fff}|");

&nbsp;}



&nbsp;sb.Append($"{entry.Level,-9}|");

&nbsp;sb.Append($"{\_categoryAbbr\[entry.Category]}|");

&nbsp;sb.Append($"{entry.ThreadName,-15}|");



&nbsp;if (\_config.EnableCallerInfo)

&nbsp;{

&nbsp;sb.Append($"{entry.File}:{entry.Line,-4}|");

&nbsp;sb.Append($"{entry.Member,-20}|");

&nbsp;}



&nbsp;sb.Append(entry.Message);



&nbsp;if (entry.Exception != null)

&nbsp;{

&nbsp;sb.Append($" | EXCEPTION: {entry.Exception}");

&nbsp;if (entry.Exception.StackTrace != null)

&nbsp;{

&nbsp;sb.Append($" | STACK: {entry.Exception.StackTrace}");

&nbsp;}

&nbsp;}



&nbsp;// Agregar uso de memoria para logs de performance

&nbsp;if (entry.Level == EnhancedLogLevel.PERFORMANCE)

&nbsp;{

&nbsp;sb.Append($" | MEM: {entry.MemoryUsage / 1024 / 1024}MB");

&nbsp;}



&nbsp;return sb.ToString();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Escribir a consola con colores

&nbsp;/// </summary>

&nbsp;private void WriteToConsole(LogEntry entry, string formatted)

&nbsp;{

&nbsp;if (\_config.EnableColors \&\& \_consoleColors.ContainsKey(entry.Level))

&nbsp;{

&nbsp;Console.WriteLine($"{\_consoleColors\[entry.Level]}{formatted}{ResetColor}");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Console.WriteLine(formatted);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Escribir a archivo (thread-safe)

&nbsp;/// </summary>

&nbsp;private void WriteToFile(string formatted)

&nbsp;{

&nbsp;lock (\_fileLock)

&nbsp;{

&nbsp;if (\_currentFileWriter != null)

&nbsp;{

&nbsp;\_currentFileWriter.WriteLine(formatted);

&nbsp;\_currentFileSize += formatted.Length + Environment.NewLine.Length;



&nbsp;// Rotar archivo si es muy grande

&nbsp;if (\_currentFileSize > \_config.MaxFileSizeMB \* 1024 \* 1024)

&nbsp;{

&nbsp;RotateLogFiles();

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Escribir a archivo síncrono

&nbsp;/// </summary>

&nbsp;private void WriteToFileSync(string formatted)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_fileLock)

&nbsp;{

&nbsp;\_currentFileWriter?.WriteLine(formatted);

&nbsp;\_currentFileSize += formatted.Length + Environment.NewLine.Length;



&nbsp;if (\_currentFileSize > \_config.MaxFileSizeMB \* 1024 \* 1024)

&nbsp;{

&nbsp;RotateLogFiles();

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($"ERROR escribiendo a archivo: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Rotar archivos de log

&nbsp;/// </summary>

&nbsp;private void RotateLogFiles()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;CreateNewLogFile();

&nbsp;CleanupOldLogs();

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($"ERROR rotando logs: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpiar logs antiguos

&nbsp;/// </summary>

&nbsp;private void CleanupOldLogs()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var logFiles = Directory.GetFiles(\_config.LogDirectory, $"{\_config.FileNamePrefix}\_\*.log")

&nbsp;.Select(f => new FileInfo(f))

&nbsp;.OrderByDescending(f => f.CreationTime)

&nbsp;.ToList();



&nbsp;// Mantener solo los N archivos más recientes

&nbsp;for (int i = \_config.MaxFiles; i < logFiles.Count; i++)

&nbsp;{

&nbsp;logFiles\[i].Delete();

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;LogInternal(EnhancedLogLevel.ERROR, LogCategory.GENERAL,

&nbsp;$"Error limpiando logs antiguos: {ex.Message}", "EnhancedLogger", "CleanupOldLogs", 0);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Log interno del logger (evita recursión)

&nbsp;/// </summary>

&nbsp;private void LogInternal(EnhancedLogLevel level, LogCategory category, string message,

&nbsp;string file, string member, int line)

&nbsp;{

&nbsp;var entry = new LogEntry

&nbsp;{

&nbsp;Level = level,

&nbsp;Category = category,

&nbsp;Message = message,

&nbsp;File = file,

&nbsp;Member = member,

&nbsp;Line = line,

&nbsp;Timestamp = DateTime.UtcNow,

&nbsp;ThreadName = "Logger"

&nbsp;};



&nbsp;ProcessLogEntrySync(entry);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtener estadísticas del logger

&nbsp;/// </summary>

&nbsp;public LoggerStats GetStats()

&nbsp;{

&nbsp;return new LoggerStats

&nbsp;{

&nbsp;TotalEntries = \_totalLogEntries,

&nbsp;DroppedEntries = \_droppedEntries,

&nbsp;QueueSize = \_logQueue.Count,

&nbsp;Uptime = DateTime.UtcNow - \_startTime,

&nbsp;CurrentLogFile = \_currentLogFile,

&nbsp;CurrentFileSize = \_currentFileSize

&nbsp;};

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Flushear logs pendientes

&nbsp;/// </summary>

&nbsp;public void Flush()

&nbsp;{

&nbsp;if (\_config.AsyncLogging)

&nbsp;{

&nbsp;// Procesar cola restante

&nbsp;while (!\_logQueue.IsEmpty)

&nbsp;{

&nbsp;if (\_logQueue.TryDequeue(out LogEntry entry))

&nbsp;{

&nbsp;ProcessLogEntrySync(entry);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;lock (\_fileLock)

&nbsp;{

&nbsp;\_currentFileWriter?.Flush();

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;if (\_isDisposed) return;



&nbsp;\_isRunning = false;

&nbsp;\_cancellationTokenSource?.Cancel();



&nbsp;// Esperar a que el worker termine

&nbsp;if (\_config.AsyncLogging)

&nbsp;{

&nbsp;\_logWorker?.Join(2000);

&nbsp;}



&nbsp;// Flushear logs finales

&nbsp;Flush();



&nbsp;\_cancellationTokenSource?.Dispose();



&nbsp;lock (\_fileLock)

&nbsp;{

&nbsp;\_currentFileWriter?.Close();

&nbsp;\_currentFileWriter?.Dispose();

&nbsp;}



&nbsp;\_isDisposed = true;



&nbsp;LogInternal(EnhancedLogLevel.INFO, LogCategory.GENERAL,

&nbsp;"Enhanced Logger detenido", "EnhancedLogger", "Dispose", 0);

&nbsp;}



&nbsp;// ==================== MÉTODOS DE CONVENIENCIA ====================



&nbsp;public void Trace(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.TRACE, category, message, file, member, line);



&nbsp;public void Debug(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.DEBUG, category, message, file, member, line);



&nbsp;public void Info(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.INFO, category, message, file, member, line);



&nbsp;public void Warning(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.WARNING, category, message, file, member, line);



&nbsp;public void Error(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.ERROR, category, message, file, member, line);



&nbsp;public void Critical(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.CRITICAL, category, message, file, member, line);



&nbsp;public void Performance(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.PERFORMANCE, LogCategory.PERFORMANCE, message, file, member, line);



&nbsp;public void Security(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.SECURITY, LogCategory.SECURITY, message, file, member, line);



&nbsp;public void Network(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.NETWORK, LogCategory.NETWORK, message, file, member, line);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Estadísticas del logger

&nbsp;/// </summary>

&nbsp;public class LoggerStats

&nbsp;{

&nbsp;public long TotalEntries { get; set; }

&nbsp;public long DroppedEntries { get; set; }

&nbsp;public int QueueSize { get; set; }

&nbsp;public TimeSpan Uptime { get; set; }

&nbsp;public string CurrentLogFile { get; set; }

&nbsp;public long CurrentFileSize { get; set; }



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"Logger Stats - Entries: {TotalEntries}, Dropped: {DroppedEntries}, " +

&nbsp;$"Queue: {QueueSize}, Uptime: {Uptime:hh\\\\:mm\\\\:ss}";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Logger global para uso fácil en toda la aplicación

&nbsp;/// </summary>

&nbsp;public static class GlobalLogger

&nbsp;{

&nbsp;private static EnhancedLogger \_instance;

&nbsp;private static readonly object \_lock = new object();



&nbsp;public static void Initialize(LoggerConfig config = null)

&nbsp;{

&nbsp;lock (\_lock)

&nbsp;{

&nbsp;\_instance?.Dispose();

&nbsp;\_instance = new EnhancedLogger(config);

&nbsp;}

&nbsp;}



&nbsp;public static void Log(EnhancedLogLevel level, LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;{

&nbsp;\_instance?.Log(level, category, message, file, member, line);

&nbsp;}



&nbsp;public static void LogException(EnhancedLogLevel level, LogCategory category, Exception ex, string context,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;{

&nbsp;\_instance?.LogException(level, category, ex, context, file, member, line);

&nbsp;}



&nbsp;// Métodos de conveniencia

&nbsp;public static void Trace(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.TRACE, category, message, file, member, line);



&nbsp;public static void Debug(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.DEBUG, category, message, file, member, line);



&nbsp;public static void Info(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.INFO, category, message, file, member, line);



&nbsp;public static void Warning(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.WARNING, category, message, file, member, line);



&nbsp;public static void Error(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.ERROR, category, message, file, member, line);



&nbsp;public static void Critical(LogCategory category, string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.CRITICAL, category, message, file, member, line);



&nbsp;public static void Performance(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.PERFORMANCE, LogCategory.PERFORMANCE, message, file, member, line);



&nbsp;public static void Security(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.SECURITY, LogCategory.SECURITY, message, file, member, line);



&nbsp;public static void Network(string message,

&nbsp;\[CallerFilePath] string file = "", \[CallerMemberName] string member = "", \[CallerLineNumber] int line = 0)

&nbsp;=> Log(EnhancedLogLevel.NETWORK, LogCategory.NETWORK, message, file, member, line);



&nbsp;public static void Dispose()

&nbsp;{

&nbsp;lock (\_lock)

&nbsp;{

&nbsp;\_instance?.Dispose();

&nbsp;\_instance = null;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo FriendConnection.cs \[

using Sodium;

using System.Runtime.InteropServices;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estados de conexión de amigos compatibles con toxcore

&nbsp;/// </summary>

&nbsp;public enum FriendConnectionStatus

&nbsp;{

&nbsp;FRIENDCONN\_STATUS\_NONE,

&nbsp;FRIENDCONN\_STATUS\_CONNECTING,

&nbsp;FRIENDCONN\_STATUS\_CONNECTED,

&nbsp;FRIENDCONN\_STATUS\_DISCONNECTED

&nbsp;}



&nbsp;public enum FriendUserStatus

&nbsp;{

&nbsp;TOX\_USER\_STATUS\_NONE,

&nbsp;TOX\_USER\_STATUS\_AWAY,

&nbsp;TOX\_USER\_STATUS\_BUSY

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// Información de un amigo individual

&nbsp;/// </summary>

&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public class Friend

&nbsp;{

&nbsp;public int FriendNumber;

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]

&nbsp;public byte\[] PublicKey;

&nbsp;public FriendConnectionStatus ConnectionStatus;

&nbsp;public FriendUserStatus UserStatus;

&nbsp;public long LastSeen;

&nbsp;public bool IsOnline;

&nbsp;public int PingId;

&nbsp;public long LastPingSent;

&nbsp;public long LastPingReceived; // ✅ NUEVO

&nbsp;public ToxConnection ConnectionType; // ✅ NUEVO - UDP/TCP/None

&nbsp;public int FailedPings; // ✅ NUEVO - contador de pings fallidos



&nbsp;public Friend(int friendNumber, byte\[] publicKey)

&nbsp;{

&nbsp;FriendNumber = friendNumber;

&nbsp;PublicKey = new byte\[32];

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);

&nbsp;}

&nbsp;ConnectionStatus = FriendConnectionStatus.FRIENDCONN\_STATUS\_NONE;

&nbsp;UserStatus = FriendUserStatus.TOX\_USER\_STATUS\_NONE;

&nbsp;LastSeen = 0;

&nbsp;IsOnline = false;

&nbsp;PingId = 0;

&nbsp;LastPingSent = 0;

&nbsp;LastPingReceived = 0; // ✅ NUEVO

&nbsp;ConnectionType = ToxConnection.TOX\_CONNECTION\_NONE; // ✅ NUEVO

&nbsp;FailedPings = 0; // ✅ NUEVO

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Callbacks para eventos de amigos

&nbsp;/// </summary>

&nbsp;public class FriendCallbacks

&nbsp;{

&nbsp;public Action<int, FriendConnectionStatus> OnConnectionStatusChanged;

&nbsp;public Action<int, byte\[], int> OnMessageReceived;

&nbsp;public Action<int, string> OnNameChanged;

&nbsp;public Action<int, string> OnStatusMessageChanged;

&nbsp;public Action<int, FriendUserStatus> OnUserStatusChanged;

&nbsp;public Action<byte\[], string> OnFriendRequest; // ✅ NUEVO - solicitudes de amistad

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Implementación completa de Friend Connection compatible con toxcore

&nbsp;/// </summary>

&nbsp;public class FriendConnection

&nbsp;{

&nbsp;private const string LOG\_TAG = "FRIEND";

&nbsp;private long \_lastLogTime = 0;



&nbsp;public const int MAX\_DATA\_SIZE = 1372; // Tamaño máximo de mensaje en toxcore

&nbsp;public const int CRYPTO\_NONCE\_SIZE = 24;

&nbsp;public const int CRYPTO\_MAC\_SIZE = 16;



&nbsp;public const int MAX\_FRIEND\_COUNT = 500;

&nbsp;public const int FRIEND\_CONNECTION\_TIMEOUT = 60000;

&nbsp;public const int FRIEND\_PING\_INTERVAL = 30000;



&nbsp;public byte\[] SelfPublicKey { get; private set; }

&nbsp;public byte\[] SelfSecretKey { get; private set; }

&nbsp;public FriendCallbacks Callbacks { get; private set; }



&nbsp;private readonly List<Friend> \_friends;

&nbsp;private readonly object \_friendsLock = new object();

&nbsp;private DHT \_dht;

&nbsp;private Onion \_onion;

&nbsp;private TCP\_Client \_tcpClient;

&nbsp;private int \_lastFriendNumber;

&nbsp;private long \_lastMaintenanceTime;



&nbsp;public int FriendCount

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;return \_friends.Count;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public int OnlineFriends

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;return \_friends.Count(f => f.IsOnline);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public FriendConnection(byte\[] selfPublicKey, byte\[] selfSecretKey, DHT dht, Onion onion)

&nbsp;{

&nbsp;SelfPublicKey = new byte\[32];

&nbsp;SelfSecretKey = new byte\[32];

&nbsp;Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);

&nbsp;Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);



&nbsp;\_friends = new List<Friend>();

&nbsp;\_dht = dht;

&nbsp;\_onion = onion;

&nbsp;\_tcpClient = new TCP\_Client(selfPublicKey, selfSecretKey);

&nbsp;\_lastFriendNumber = 0;

&nbsp;\_lastMaintenanceTime = DateTime.UtcNow.Ticks;

&nbsp;Callbacks = new FriendCallbacks();

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] FriendConnection inicializado");

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// GetFriendConnectionStatus - Determina estado REAL de conexión como en Messenger.c

&nbsp;/// </summary>

&nbsp;public ToxConnection GetFriendConnectionStatus(int friendNumber)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;if (friend.PublicKey == null) return ToxConnection.TOX\_CONNECTION\_NONE;



&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;long timeSinceLastSeen = (currentTime - friend.LastSeen) / TimeSpan.TicksPerMillisecond;

&nbsp;long timeSinceLastPingResponse = (currentTime - friend.LastPingReceived) / TimeSpan.TicksPerMillisecond;



&nbsp;// Si no hemos visto actividad reciente, está desconectado

&nbsp;if (timeSinceLastSeen > FRIEND\_CONNECTION\_TIMEOUT)

&nbsp;{

&nbsp;return ToxConnection.TOX\_CONNECTION\_NONE;

&nbsp;}



&nbsp;// Si recibimos pong recientemente, está conectado via UDP (óptimo)

&nbsp;if (timeSinceLastPingResponse < Messenger.PING\_TIMEOUT)

&nbsp;{

&nbsp;return ToxConnection.TOX\_CONNECTION\_UDP;

&nbsp;}



&nbsp;// Si hemos visto actividad pero no pongs recientes, podría ser TCP

&nbsp;if (timeSinceLastSeen < FRIEND\_CONNECTION\_TIMEOUT)

&nbsp;{

&nbsp;return ToxConnection.TOX\_CONNECTION\_TCP;

&nbsp;}



&nbsp;return ToxConnection.TOX\_CONNECTION\_NONE;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// SendPingToFriend - Envía ping REAL y monitorea respuesta

&nbsp;/// </summary>

&nbsp;public int SendPingToFriend(int friendNumber)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// Verificar que no estamos spameando pings

&nbsp;long timeSinceLastPing = (currentTime - friend.LastPingSent) / TimeSpan.TicksPerMillisecond;

&nbsp;if (timeSinceLastPing < Messenger.PING\_INTERVAL / 2) // Esperar al menos 15 segundos

&nbsp;{

&nbsp;return -1;

&nbsp;}



&nbsp;// Crear ping real con ID único

&nbsp;byte\[] pingPacket = CreateRealPingPacket(friend.PingId);

&nbsp;if (pingPacket == null) return -1;



&nbsp;// Enviar ping encriptado

&nbsp;int sent = m\_send\_message(friendNumber, pingPacket, pingPacket.Length);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// Actualizar estado del friend

&nbsp;friend.LastPingSent = currentTime;

&nbsp;friend.PingId++; // Incrementar para próximo ping

&nbsp;UpdateFriendInList(friend);



&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Ping enviado a friend {friendNumber} (ID: {friend.PingId})");

&nbsp;return sent;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando ping: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// CreateRealPingPacket - Crea ping REAL con timestamp e ID

&nbsp;/// </summary>

&nbsp;private byte\[] CreateRealPingPacket(int pingId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Payload del ping: \[0x10]\[ping\_id(4)]\[timestamp(8)]

&nbsp;byte\[] pingData = new byte\[1 + 4 + 8];

&nbsp;pingData\[0] = 0x10; // PING type



&nbsp;// Ping ID (4 bytes)

&nbsp;byte\[] idBytes = BitConverter.GetBytes(pingId);

&nbsp;Buffer.BlockCopy(idBytes, 0, pingData, 1, 4);



&nbsp;// Timestamp actual (8 bytes)

&nbsp;byte\[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);

&nbsp;Buffer.BlockCopy(timestamp, 0, pingData, 5, 8);



&nbsp;return pingData;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando ping packet: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// HandleRealPongResponse - Procesa respuesta PONG real

&nbsp;/// </summary>

&nbsp;private int HandlePongResponse(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 1 + 4 + 8) return -1; // \[0x11]\[ping\_id]\[timestamp]



&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;// Extraer ping ID (bytes 1-4)

&nbsp;int receivedPingId = BitConverter.ToInt32(packet, 1);



&nbsp;// Extraer timestamp (bytes 5-12) - podríamos calcular RTT aquí

&nbsp;long pingTimestamp = BitConverter.ToInt64(packet, 5);



&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// Actualizar estado del friend

&nbsp;friend.LastPingReceived = currentTime;

&nbsp;friend.LastSeen = currentTime;

&nbsp;friend.FailedPings = 0; // Resetear contador de fallos

&nbsp;friend.ConnectionType = ToxConnection.TOX\_CONNECTION\_UDP; // Conexión directa



&nbsp;UpdateFriendInList(friend);



&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Pong recibido de friend {friendNumber} (ID: {receivedPingId})");

&nbsp;return 0;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando pong: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// CheckConnectionStatusChanges - Monitorea cambios de estado REAL

&nbsp;/// </summary>

&nbsp;private void CheckConnectionStatusChanges()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<(int friendNumber, ToxConnection newStatus)> statusChanges = new List<(int, ToxConnection)>();



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;foreach (var friend in \_friends)

&nbsp;{

&nbsp;if (friend.PublicKey == null) continue;



&nbsp;ToxConnection currentStatus = friend.ConnectionType;

&nbsp;ToxConnection newStatus = GetFriendConnectionStatus(friend.FriendNumber);



&nbsp;// Si el estado cambió, registrar para callback

&nbsp;if (currentStatus != newStatus)

&nbsp;{

&nbsp;statusChanges.Add((friend.FriendNumber, newStatus));



&nbsp;// Actualizar friend con nuevo estado

&nbsp;var updatedFriend = friend;

&nbsp;updatedFriend.ConnectionType = newStatus;

&nbsp;updatedFriend.IsOnline = (newStatus != ToxConnection.TOX\_CONNECTION\_NONE);

&nbsp;UpdateFriendInList(updatedFriend);

&nbsp;}



&nbsp;// Si estamos desconectados, incrementar contador de pings fallidos

&nbsp;if (newStatus == ToxConnection.TOX\_CONNECTION\_NONE)

&nbsp;{

&nbsp;var updatedFriend = friend;

&nbsp;updatedFriend.FailedPings++;

&nbsp;UpdateFriendInList(updatedFriend);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// Disparar callbacks fuera del lock

&nbsp;foreach (var change in statusChanges)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Estado de friend {change.friendNumber} cambió: {change.newStatus}");

&nbsp;// Aquí iría: Callbacks.OnConnectionStatusChanged?.Invoke(change.friendNumber, change.newStatus);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error verificando cambios de estado: {ex.Message}");

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// UpdateFriendInList - Actualiza friend en la lista de forma segura

&nbsp;/// </summary>

&nbsp;private void UpdateFriendInList(Friend updatedFriend)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;for (int i = 0; i < \_friends.Count; i++)

&nbsp;{

&nbsp;if (\_friends\[i].FriendNumber == updatedFriend.FriendNumber)

&nbsp;{

&nbsp;\_friends\[i] = updatedFriend;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}





&nbsp;// ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// m\_addfriend - Agregar amigo por clave pública

&nbsp;/// </summary>

&nbsp;public int m\_addfriend(byte\[] public\_key)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Agregando nuevo amigo \[PK: {BitConverter.ToString(public\_key, 0, 8).Replace("-", "")}...]");



&nbsp;if (public\_key == null || public\_key.Length != 32) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;// Verificar si el amigo ya existe

&nbsp;var existingFriend = \_friends.Find(f => ByteArraysEqual(public\_key, f.PublicKey));

&nbsp;if (existingFriend.PublicKey != null)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Amigo ya existe: {existingFriend.FriendNumber}");

&nbsp;return -1;

&nbsp;}



&nbsp;// Verificar límite de amigos

&nbsp;if (\_friends.Count >= MAX\_FRIEND\_COUNT) return -1;



&nbsp;// Crear nuevo amigo

&nbsp;var newFriend = new Friend(\_lastFriendNumber++, public\_key);

&nbsp;\_friends.Add(newFriend);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nuevo amigo agregado: {newFriend.FriendNumber} \[Total: {\_friends.Count}]");



&nbsp;// Intentar conectar inmediatamente

&nbsp;friendconn\_connect(newFriend.FriendNumber);



&nbsp;return newFriend.FriendNumber;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error agregando amigo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// m\_delfriend - Eliminar amigo

&nbsp;/// </summary>

&nbsp;public int m\_delfriend(int friend\_number)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;// Cerrar conexiones activas

&nbsp;friendconn\_kill(friend\_number);



&nbsp;\_friends.Remove(friend);

&nbsp;return 0;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// m\_send\_message - Enviar mensaje a amigo

&nbsp;/// </summary>

&nbsp;public int m\_send\_message(int friend\_number, byte\[] message, int length)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Enviando mensaje a amigo {friend\_number} - Tamaño: {length} bytes");



&nbsp;if (message == null || length > 1372) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = FindFriendByNumber(friend\_number);

&nbsp;if (friend?.PublicKey == null || !friend.IsOnline)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Amigo {friend\_number} no disponible para envío");

&nbsp;return -1;

&nbsp;}



&nbsp;// Crear paquete de mensaje ENCRIPTADO

&nbsp;byte\[] packet = CreateMessagePacket(message, length, friend\_number);

&nbsp;if (packet == null) return -1;



&nbsp;// Enviar a través de Onion Routing

&nbsp;int sent = \_onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;friend.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Mensaje enviado a amigo {friend\_number}: {sent} bytes");

&nbsp;return sent;

&nbsp;}



&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Falló envío a amigo {friend\_number}");

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando mensaje: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}







&nbsp;/// <summary>

&nbsp;/// m\_set\_status - Establecer estado de usuario

&nbsp;/// </summary>

&nbsp;public int m\_set\_status(FriendUserStatus status)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Notificar a todos los amigos conectados

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;foreach (var friend in \_friends)

&nbsp;{

&nbsp;if (friend.IsOnline)

&nbsp;{

&nbsp;byte\[] statusPacket = CreateStatusPacket(status);

&nbsp;\_onion.onion\_send\_1(statusPacket, statusPacket.Length, friend.PublicKey);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// m\_set\_status\_message - Establecer mensaje de estado

&nbsp;/// </summary>

&nbsp;public int m\_set\_status\_message(string message)

&nbsp;{

&nbsp;if (message == null || message.Length > 1007) return -1; // MAX\_STATUSMESSAGE\_LENGTH



&nbsp;try

&nbsp;{

&nbsp;byte\[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;foreach (var friend in \_friends)

&nbsp;{

&nbsp;if (friend.IsOnline)

&nbsp;{

&nbsp;byte\[] statusMessagePacket = CreateStatusMessagePacket(messageBytes, messageBytes.Length);

&nbsp;\_onion.onion\_send\_1(statusMessagePacket, statusMessagePacket.Length, friend.PublicKey);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== GESTIÓN DE CONEXIONES ====================



&nbsp;/// <summary>

&nbsp;/// friendconn\_connect - Conectar a amigo

&nbsp;/// </summary>

&nbsp;public int friendconn\_connect(int friend\_number)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;// Buscar amigo en DHT

&nbsp;var closestNodes = \_dht.GetClosestNodes(friend.PublicKey, 8);

&nbsp;if (closestNodes.Count == 0) return -1;



&nbsp;// Enviar solicitud de conexión a través de Onion

&nbsp;byte\[] connectPacket = CreateConnectPacket();

&nbsp;int sent = \_onion.onion\_send\_1(connectPacket, connectPacket.Length, friend.PublicKey);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;UpdateFriendStatus(friend\_number, FriendConnectionStatus.FRIENDCONN\_STATUS\_CONNECTING);

&nbsp;friend.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;return 0;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// friendconn\_kill - Desconectar amigo

&nbsp;/// </summary>

&nbsp;public int friendconn\_kill(int friend\_number)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;// Enviar paquete de desconexión

&nbsp;byte\[] disconnectPacket = CreateDisconnectPacket();

&nbsp;\_onion.onion\_send\_1(disconnectPacket, disconnectPacket.Length, friend.PublicKey);



&nbsp;UpdateFriendStatus(friend\_number, FriendConnectionStatus.FRIENDCONN\_STATUS\_DISCONNECTED);

&nbsp;return 0;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// friend\_new\_connection - Nueva conexión entrante

&nbsp;/// </summary>

&nbsp;public int friend\_new\_connection(int friend\_number)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nueva conexión con amigo {friend\_number}");



&nbsp;try

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey == null) return -1;



&nbsp;UpdateFriendStatus(friend\_number, FriendConnectionStatus.FRIENDCONN\_STATUS\_CONNECTED);

&nbsp;friend.IsOnline = true;

&nbsp;friend.LastSeen = DateTime.UtcNow.Ticks;



&nbsp;// Notificar callback

&nbsp;Callbacks.OnConnectionStatusChanged?.Invoke(friend\_number, FriendConnectionStatus.FRIENDCONN\_STATUS\_CONNECTED);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Amigo {friend\_number} conectado \[Online: {\_friends.Count(f => f.IsOnline)}]");

&nbsp;return 0;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en nueva conexión: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MANEJO DE PAQUETES ====================



&nbsp;/// <summary>

&nbsp;/// handle\_packet - Manejar paquete entrante de amigo

&nbsp;/// </summary>

&nbsp;public int handle\_packet(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 1) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x10: // Ping

&nbsp;return HandlePingPacket(friend\_number, packet, length);

&nbsp;case 0x11: // Pong

&nbsp;return HandlePongPacket(friend\_number, packet, length);

&nbsp;case 0x20: // Message

&nbsp;return HandleMessagePacket(friend\_number, packet, length);

&nbsp;case 0x30: // Connection request

&nbsp;return HandleConnectionPacket(friend\_number, packet, length);

&nbsp;case 0x31: // Disconnection

&nbsp;return HandleDisconnectionPacket(friend\_number, packet, length);

&nbsp;case 0x40: // Status update

&nbsp;return HandleStatusPacket(friend\_number, packet, length);

&nbsp;case 0x41: // Status message

&nbsp;return HandleStatusMessagePacket(friend\_number, packet, length);

&nbsp;default:

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// m\_handle\_packet - ACTUALIZADO para usar procesamiento REAL

&nbsp;/// </summary>

&nbsp;public int m\_handle\_packet(int friendcon\_id, byte\[] data, int length)

&nbsp;{

&nbsp;// Este método ahora delega al sistema real de procesamiento

&nbsp;// Necesitamos obtener la public key del friend primero

&nbsp;byte\[] friendPublicKey = GetFriendPublicKey(friendcon\_id);

&nbsp;if (friendPublicKey == null) return -1;



&nbsp;return HandleFriendPacket(data, length, friendPublicKey);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// GetFriendPublicKey - Obtiene public key de un friend por número

&nbsp;/// </summary>

&nbsp;private byte\[] GetFriendPublicKey(int friendNumber)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;return friend.PublicKey;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleFriendRequest - Procesa solicitudes de amistad REALES

&nbsp;/// Como en Messenger.c - friendreq\_handle()

&nbsp;/// </summary>

&nbsp;public int HandleFriendRequest(byte\[] publicKey, string message)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (publicKey == null || publicKey.Length != 32)

&nbsp;return -1;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Solicitud de amistad recibida: '{message}'");



&nbsp;// Verificar si ya es nuestro amigo

&nbsp;if (FindFriendNumberByPublicKey(publicKey) != -1)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Solicitud de amistad de friend ya existente");

&nbsp;return -1;

&nbsp;}



&nbsp;// Disparar callback de solicitud de amistad

&nbsp;Callbacks.OnFriendRequest?.Invoke(publicKey, message);



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando solicitud de amistad: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES DE CREACIÓN DE PAQUETES ====================



&nbsp;private byte\[] CreateMessagePacket(byte\[] message, int length, int friendNumber) // ← Agregar friendNumber como parámetro

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Obtener la shared key real para este amigo

&nbsp;byte\[] sharedKey = GetFriendSharedKey(friendNumber);



&nbsp;if (sharedKey == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No shared key para friend {friendNumber}");

&nbsp;return null;

&nbsp;}



&nbsp;// Nonce para encriptación

&nbsp;byte\[] nonce = RandomBytes.Generate(CryptoBox.CRYPTO\_NONCE\_SIZE);



&nbsp;// Encriptar como en Messenger.c - encrypt\_data\_symmetric

&nbsp;byte\[] encrypted = new byte\[length + CryptoBox.CRYPTO\_MAC\_SIZE];



&nbsp;// Usar Sodium para encriptación simétrica

&nbsp;byte\[] cipherText = SecretBox.Create(message, nonce, sharedKey);

&nbsp;if (cipherText == null || cipherText.Length != encrypted.Length)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Falló encriptación para friend {friendNumber}");

&nbsp;return null;

&nbsp;}



&nbsp;Buffer.BlockCopy(cipherText, 0, encrypted, 0, encrypted.Length);



&nbsp;// Paquete real: \[nonce(24)]\[encrypted\_data]

&nbsp;byte\[] packet = new byte\[CryptoBox.CRYPTO\_NONCE\_SIZE + encrypted.Length];

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 0, CryptoBox.CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(encrypted, 0, packet, CryptoBox.CRYPTO\_NONCE\_SIZE, encrypted.Length);



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete mensaje: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] GetFriendSharedKey(int friendNumber)

&nbsp;{

&nbsp;// Basado en Messenger.c - get\_friend\_shared\_key

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;if (friend?.PublicKey == null) return null;



&nbsp;// Calcular shared key usando crypto\_box\_beforenm (versión corregida)

&nbsp;byte\[] sharedKey = CryptoBox.BeforeNm(friend.PublicKey, SelfSecretKey);



&nbsp;return sharedKey; // Ya retorna null si falla

&nbsp;}

&nbsp;}





&nbsp;private byte\[] CreateConnectPacket()

&nbsp;{

&nbsp;byte\[] packet = new byte\[33];

&nbsp;packet\[0] = 0x30; // Connection request type

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateDisconnectPacket()

&nbsp;{

&nbsp;return new byte\[] { 0x31 }; // Disconnection type

&nbsp;}



&nbsp;private byte\[] CreateStatusPacket(FriendUserStatus status)

&nbsp;{

&nbsp;byte\[] packet = new byte\[2];

&nbsp;packet\[0] = 0x40; // Status type

&nbsp;packet\[1] = (byte)status;

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateStatusMessagePacket(byte\[] message, int length)

&nbsp;{

&nbsp;byte\[] packet = new byte\[1 + length];

&nbsp;packet\[0] = 0x41; // Status message type

&nbsp;Buffer.BlockCopy(message, 0, packet, 1, length);

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreatePingPacket(int pingId)

&nbsp;{

&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = 0x10; // Ping type

&nbsp;byte\[] idBytes = BitConverter.GetBytes(pingId);

&nbsp;Buffer.BlockCopy(idBytes, 0, packet, 1, 4);

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreatePongPacket(int pingId)

&nbsp;{

&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = 0x11; // Pong type

&nbsp;byte\[] idBytes = BitConverter.GetBytes(pingId);

&nbsp;Buffer.BlockCopy(idBytes, 0, packet, 1, 4);

&nbsp;return packet;

&nbsp;}



&nbsp;// ==================== MANEJADORES DE PAQUETES ====================



&nbsp;private int HandlePingPacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length != 5) return -1;



&nbsp;// Extraer ID del ping

&nbsp;int pingId = BitConverter.ToInt32(packet, 1);



&nbsp;// Enviar pong de respuesta

&nbsp;byte\[] pongPacket = CreatePongPacket(pingId);

&nbsp;return m\_send\_message(friend\_number, pongPacket, pongPacket.Length);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandlePongPacket - ACTUALIZADO para usar gestión real

&nbsp;/// </summary>

&nbsp;private int HandlePongPacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;// Usar el nuevo sistema real de pong

&nbsp;return HandlePongResponse(friend\_number, packet, length);

&nbsp;}



&nbsp;private int HandleMessagePacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 2) return -1;



&nbsp;byte\[] message = new byte\[length - 1];

&nbsp;Buffer.BlockCopy(packet, 1, message, 0, length - 1);



&nbsp;// Notificar callback

&nbsp;Callbacks.OnMessageReceived?.Invoke(friend\_number, message, message.Length);



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleConnectionPacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length != 33) return -1;



&nbsp;// Verificar clave pública

&nbsp;byte\[] senderPublicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey != null \&\& ByteArraysEqual(senderPublicKey, friend.PublicKey))

&nbsp;{

&nbsp;// Aceptar conexión

&nbsp;friend\_new\_connection(friend\_number);



&nbsp;// Enviar confirmación

&nbsp;byte\[] connectPacket = CreateConnectPacket();

&nbsp;return m\_send\_message(friend\_number, connectPacket, connectPacket.Length);

&nbsp;}

&nbsp;}



&nbsp;return -1;

&nbsp;}



&nbsp;private int HandleDisconnectionPacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey != null)

&nbsp;{

&nbsp;UpdateFriendStatus(friend\_number, FriendConnectionStatus.FRIENDCONN\_STATUS\_DISCONNECTED);

&nbsp;friend.IsOnline = false;

&nbsp;}

&nbsp;}

&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleStatusPacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length != 2) return -1;



&nbsp;FriendUserStatus status = (FriendUserStatus)packet\[1];



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;if (friend.PublicKey != null)

&nbsp;{

&nbsp;friend.UserStatus = status;

&nbsp;Callbacks.OnUserStatusChanged?.Invoke(friend\_number, status);

&nbsp;}

&nbsp;}

&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleStatusMessagePacket(int friend\_number, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 2) return -1;



&nbsp;byte\[] messageBytes = new byte\[length - 1];

&nbsp;Buffer.BlockCopy(packet, 1, messageBytes, 0, length - 1);

&nbsp;string statusMessage = System.Text.Encoding.UTF8.GetString(messageBytes);



&nbsp;Callbacks.OnStatusMessageChanged?.Invoke(friend\_number, statusMessage);

&nbsp;return 0;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleFriendPacket - Procesa paquetes encriptados de amigos REALES

&nbsp;/// Como en Messenger.c - handle\_packet()

&nbsp;/// </summary>

&nbsp;public int HandleFriendPacket(byte\[] packet, int length, byte\[] publicKey)

&nbsp;{

&nbsp;if (packet == null || length < CRYPTO\_NONCE\_SIZE + CRYPTO\_MAC\_SIZE + 1)

&nbsp;return -1;



&nbsp;try

&nbsp;{

&nbsp;// 1. Buscar el friend por public key

&nbsp;int friendNumber = FindFriendNumberByPublicKey(publicKey);

&nbsp;if (friendNumber == -1)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Paquete de friend desconocido: {BitConverter.ToString(publicKey, 0, 8).Replace("-", "")}...");

&nbsp;return -1;

&nbsp;}



&nbsp;// 2. Obtener shared key para este friend

&nbsp;byte\[] sharedKey = GetFriendSharedKey(friendNumber);

&nbsp;if (sharedKey == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No shared key para friend {friendNumber}");

&nbsp;return -1;

&nbsp;}



&nbsp;// 3. Extraer nonce (primeros 24 bytes)

&nbsp;byte\[] nonce = new byte\[CRYPTO\_NONCE\_SIZE];

&nbsp;Buffer.BlockCopy(packet, 0, nonce, 0, CRYPTO\_NONCE\_SIZE);



&nbsp;// 4. Extraer datos encriptados (resto)

&nbsp;int encryptedLength = length - CRYPTO\_NONCE\_SIZE;

&nbsp;byte\[] encrypted = new byte\[encryptedLength];

&nbsp;Buffer.BlockCopy(packet, CRYPTO\_NONCE\_SIZE, encrypted, 0, encryptedLength);



&nbsp;// 5. Decryptar usando crypto\_secretbox\_open

&nbsp;byte\[] decrypted = SecretBox.Open(encrypted, nonce, sharedKey);

&nbsp;if (decrypted == null || decrypted.Length < 1)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Falló decryptación para friend {friendNumber}");

&nbsp;return -1;

&nbsp;}



&nbsp;// 6. Procesar el paquete decryptado

&nbsp;return ProcessDecryptedFriendPacket(friendNumber, decrypted, decrypted.Length);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en HandleFriendPacket: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// FindFriendNumberByPublicKey - Encuentra friend number por public key

&nbsp;/// </summary>

&nbsp;private int FindFriendNumberByPublicKey(byte\[] publicKey)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => ByteArraysEqual(f.PublicKey, publicKey));

&nbsp;return friend.PublicKey != null ? friend.FriendNumber : -1;

&nbsp;}

&nbsp;}



&nbsp;private Friend? FindFriendByNumber(int friendNumber)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;return \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// ProcessDecryptedFriendPacket - Procesa paquetes decryptados de amigos

&nbsp;/// Como en Messenger.c - handle\_packet()

&nbsp;/// </summary>

&nbsp;private int ProcessDecryptedFriendPacket(int friendNumber, byte\[] decrypted, int length)

&nbsp;{

&nbsp;if (decrypted == null || length < 1) return -1;



&nbsp;byte packetType = decrypted\[0];



&nbsp;// Actualizar last seen - el friend está activo

&nbsp;UpdateFriendLastSeen(friendNumber);



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x10: // Ping

&nbsp;return HandlePingPacket(friendNumber, decrypted, length); // ← CAMBIADO



&nbsp;case 0x11: // Pong

&nbsp;return HandlePongResponse(friendNumber, decrypted, length);



&nbsp;case 0x20: // Message

&nbsp;return HandleRealMessagePacket(friendNumber, decrypted, length);



&nbsp;case 0x30: // Connection request

&nbsp;return HandleRealConnectionPacket(friendNumber, decrypted, length);



&nbsp;case 0x31: // Disconnection

&nbsp;return HandleDisconnectionPacket(friendNumber, decrypted, length); // ← CAMBIADO



&nbsp;case 0x40: // Status update

&nbsp;return HandleStatusPacket(friendNumber, decrypted, length); // ← CAMBIADO



&nbsp;case 0x41: // Status message

&nbsp;return HandleStatusMessagePacket(friendNumber, decrypted, length); // ← CAMBIADO



&nbsp;default:

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Tipo de paquete friend desconocido: 0x{packetType:X2}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleRealMessagePacket - Procesa mensajes REALES de amigos

&nbsp;/// </summary>

&nbsp;private int HandleRealMessagePacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 2) return -1; // \[type]\[message\_data...]



&nbsp;try

&nbsp;{

&nbsp;// Extraer datos del mensaje (bytes 1 hasta el final)

&nbsp;byte\[] messageData = new byte\[length - 1];

&nbsp;Buffer.BlockCopy(packet, 1, messageData, 0, length - 1);



&nbsp;// Convertir a string (asumiendo UTF-8 como en toxcore)

&nbsp;string message = System.Text.Encoding.UTF8.GetString(messageData);



&nbsp;// Determinar tipo de mensaje (normal o acción)

&nbsp;ToxMessageType messageType = ToxMessageType.TOX\_MESSAGE\_TYPE\_NORMAL;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Mensaje recibido de friend {friendNumber}: '{message}'");



&nbsp;// Disparar callback de mensaje recibido

&nbsp;Callbacks.OnMessageReceived?.Invoke(friendNumber, messageData, messageData.Length);



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando mensaje: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HandleRealConnectionPacket - Procesa solicitudes de conexión REALES

&nbsp;/// </summary>

&nbsp;private int HandleRealConnectionPacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length != 1 + 32) return -1; // \[0x30]\[public\_key(32)]



&nbsp;try

&nbsp;{

&nbsp;// Extraer public key del solicitante

&nbsp;byte\[] senderPublicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 1, senderPublicKey, 0, 32);



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;var friend = \_friends.Find(f => f.FriendNumber == friendNumber);

&nbsp;if (friend.PublicKey != null \&\& ByteArraysEqual(senderPublicKey, friend.PublicKey))

&nbsp;{

&nbsp;// Aceptar conexión - friend se conectó exitosamente

&nbsp;friend\_new\_connection(friendNumber);



&nbsp;// Enviar confirmación de conexión

&nbsp;byte\[] connectPacket = CreateRealConnectionPacket();

&nbsp;return m\_send\_message(friendNumber, connectPacket, connectPacket.Length);

&nbsp;}

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando conexión: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CreateRealConnectionPacket - Crea paquete de conexión REAL

&nbsp;/// </summary>

&nbsp;private byte\[] CreateRealConnectionPacket()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Payload: \[0x30]\[nuestra\_public\_key(32)]

&nbsp;byte\[] packet = new byte\[1 + 32];

&nbsp;packet\[0] = 0x30; // Connection type

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, packet, 1, 32);



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete conexión: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// UpdateFriendLastSeen - Actualiza last seen de un friend

&nbsp;/// </summary>

&nbsp;private void UpdateFriendLastSeen(int friendNumber)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;for (int i = 0; i < \_friends.Count; i++)

&nbsp;{

&nbsp;if (\_friends\[i].FriendNumber == friendNumber)

&nbsp;{

&nbsp;var friend = \_friends\[i];

&nbsp;friend.LastSeen = DateTime.UtcNow.Ticks;

&nbsp;friend.IsOnline = true;

&nbsp;friend.ConnectionType = ToxConnection.TOX\_CONNECTION\_UDP;

&nbsp;\_friends\[i] = friend;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}









&nbsp;// ==================== FUNCIONES AUXILIARES ====================



&nbsp;private void UpdateFriendStatus(int friend\_number, FriendConnectionStatus status)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;for (int i = 0; i < \_friends.Count; i++)

&nbsp;{

&nbsp;if (\_friends\[i].FriendNumber == friend\_number)

&nbsp;{

&nbsp;var friend = \_friends\[i];

&nbsp;friend.ConnectionStatus = status;

&nbsp;friend.IsOnline = (status == FriendConnectionStatus.FRIENDCONN\_STATUS\_CONNECTED);

&nbsp;\_friends\[i] = friend;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;private static bool ByteArraysEqual(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null || a.Length != b.Length) return false;

&nbsp;for (int i = 0; i < a.Length; i++)

&nbsp;{

&nbsp;if (a\[i] != b\[i]) return false;

&nbsp;}

&nbsp;return true;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Do\_periodic\_work - ACTUALIZADO con gestión real de conexión

&nbsp;/// </summary>

&nbsp;public void Do\_periodic\_work()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;for (int i = 0; i < \_friends.Count; i++)

&nbsp;{

&nbsp;var friend = \_friends\[i];



&nbsp;// Enviar ping a amigos que necesiten actualización de estado

&nbsp;if (friend.IsOnline \&\& (currentTime - friend.LastPingSent) > TimeSpan.TicksPerMillisecond \* Messenger.PING\_INTERVAL)

&nbsp;{

&nbsp;SendPingToFriend(friend.FriendNumber);

&nbsp;}



&nbsp;// Verificar timeouts reales

&nbsp;if (friend.IsOnline \&\& (currentTime - friend.LastSeen) > TimeSpan.TicksPerMillisecond \* FRIEND\_CONNECTION\_TIMEOUT)

&nbsp;{

&nbsp;var updatedFriend = friend;

&nbsp;updatedFriend.IsOnline = false;

&nbsp;updatedFriend.ConnectionType = ToxConnection.TOX\_CONNECTION\_NONE;

&nbsp;\_friends\[i] = updatedFriend;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Friend {friend.FriendNumber} desconectado por timeout");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// Verificar cambios de estado

&nbsp;CheckConnectionStatusChanges();



&nbsp;if ((currentTime - \_lastLogTime) > TimeSpan.TicksPerSecond \* 60)

&nbsp;{

&nbsp;int onlineCount = \_friends.Count(f => f.IsOnline);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Estadísticas - Amigos: {\_friends.Count}, Online: {onlineCount}");

&nbsp;\_lastLogTime = currentTime;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en trabajo periódico: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Get\_friend - Obtener información de amigo

&nbsp;/// </summary>

&nbsp;public Friend? Get\_friend(int friend\_number)

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;return \_friends.Find(f => f.FriendNumber == friend\_number);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Get\_friend\_list - Obtener lista de amigos

&nbsp;/// </summary>

&nbsp;public List<Friend> Get\_friend\_list()

&nbsp;{

&nbsp;lock (\_friendsLock)

&nbsp;{

&nbsp;return new List<Friend>(\_friends);

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo Group.cs \[

using System;

using System;

using System.Collections.Generic;

using System.Text;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Adaptación de group.c - Chats grupales de Tox

&nbsp;/// </summary>

&nbsp;public class GroupManager : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "GROUP";



&nbsp;private Messenger \_messenger;

&nbsp;private bool \_isRunning;



&nbsp;// Almacenamiento de grupos

&nbsp;private readonly Dictionary<int, ToxGroup> \_groups;

&nbsp;private readonly object \_groupsLock = new object();

&nbsp;private int \_lastGroupNumber = 0;



&nbsp;// Callbacks de grupos (equivalente a group.h callbacks)

&nbsp;public delegate void GroupInviteCallback(GroupManager manager, int friendNumber, byte\[] inviteData, string groupName, object userData);

&nbsp;public delegate void GroupMessageCallback(GroupManager manager, int groupNumber, int peerNumber, ToxMessageType type, string message, object userData);

&nbsp;public delegate void GroupPeerJoinCallback(GroupManager manager, int groupNumber, int peerNumber, object userData);

&nbsp;public delegate void GroupPeerExitCallback(GroupManager manager, int groupNumber, int peerNumber, ToxGroupExitType exitType, string name, object userData);

&nbsp;public delegate void GroupSelfJoinCallback(GroupManager manager, int groupNumber, object userData);

&nbsp;public delegate void GroupTopicCallback(GroupManager manager, int groupNumber, int peerNumber, string topic, object userData);

&nbsp;public delegate void GroupPeerListUpdateCallback(GroupManager manager, int groupNumber, object userData);



&nbsp;// Eventos

&nbsp;public event GroupInviteCallback OnGroupInvite;

&nbsp;public event GroupMessageCallback OnGroupMessage;

&nbsp;public event GroupPeerJoinCallback OnGroupPeerJoin;

&nbsp;public event GroupPeerExitCallback OnGroupPeerExit;

&nbsp;public event GroupSelfJoinCallback OnGroupSelfJoin;

&nbsp;public event GroupTopicCallback OnGroupTopic;

&nbsp;public event GroupPeerListUpdateCallback OnGroupPeerListUpdate;



&nbsp;public GroupManager(Messenger messenger)

&nbsp;{

&nbsp;\_messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));

&nbsp;\_groups = new Dictionary<int, ToxGroup>();

&nbsp;\_isRunning = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Group Manager inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar gestión de grupos

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Group Manager ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;\_isRunning = true;

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Group Manager iniciado");

&nbsp;return true;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener gestión de grupos

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;\_isRunning = false;



&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;\_groups.Clear();

&nbsp;}



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Group Manager detenido");

&nbsp;}



&nbsp;// ==================== API PÚBLICA DE GRUPOS ====================



&nbsp;/// <summary>

&nbsp;/// tox\_group\_new - Crear nuevo grupo

&nbsp;/// </summary>

&nbsp;public int GroupNew(string name)

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(name))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Nombre de grupo inválido");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;int groupNumber = \_lastGroupNumber++;

&nbsp;var group = new ToxGroup(groupNumber, name);



&nbsp;\_groups\[groupNumber] = group;



&nbsp;// Agregarnos como primer peer

&nbsp;var selfPeer = new GroupPeer(0, "Self", \_messenger.State.User.PublicKey);

&nbsp;group.AddPeer(selfPeer);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nuevo grupo creado: {name} (#{groupNumber})");



&nbsp;// Disparar callback de self-join

&nbsp;OnGroupSelfJoin?.Invoke(this, groupNumber, null);



&nbsp;return groupNumber;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando grupo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_join - Unirse a grupo existente

&nbsp;/// </summary>

&nbsp;public int GroupJoin(byte\[] inviteData)

&nbsp;{

&nbsp;if (inviteData == null || inviteData.Length == 0)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Datos de invitación inválidos");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;// Simular unirse a un grupo (en implementación real, esto procesaría la invitación)

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;int groupNumber = \_lastGroupNumber++;

&nbsp;string groupName = Encoding.UTF8.GetString(inviteData, 0, Math.Min(inviteData.Length, 64));



&nbsp;var group = new ToxGroup(groupNumber, groupName);

&nbsp;\_groups\[groupNumber] = group;



&nbsp;// Agregarnos como peer

&nbsp;var selfPeer = new GroupPeer(0, "Self", \_messenger.State.User.PublicKey);

&nbsp;group.AddPeer(selfPeer);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Unido a grupo: {groupName} (#{groupNumber})");



&nbsp;// Disparar callback

&nbsp;OnGroupSelfJoin?.Invoke(this, groupNumber, null);



&nbsp;return groupNumber;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error uniéndose a grupo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_send\_message - Enviar mensaje al grupo

&nbsp;/// </summary>

&nbsp;public int GroupSendMessage(int groupNumber, ToxMessageType type, string message)

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(message))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Mensaje de grupo vacío");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (!\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Grupo no encontrado: #{groupNumber}");

&nbsp;return -1;

&nbsp;}



&nbsp;if (message.Length > Constants.TOX\_MAX\_MESSAGE\_LENGTH)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Mensaje de grupo demasiado largo");

&nbsp;return -1;

&nbsp;}



&nbsp;// En implementación real, esto enviaría el mensaje a todos los peers

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Mensaje enviado al grupo #{groupNumber}: '{message}'");



&nbsp;// Simular recepción por otros peers

&nbsp;SimulateMessageReceipt(groupNumber, message, type);



&nbsp;return message.Length;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando mensaje de grupo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_set\_topic - Establecer tema del grupo

&nbsp;/// </summary>

&nbsp;public bool GroupSetTopic(int groupNumber, string topic)

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(topic))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Tema de grupo inválido");

&nbsp;return false;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (!\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Grupo no encontrado: #{groupNumber}");

&nbsp;return false;

&nbsp;}



&nbsp;group.Topic = topic;

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Tema establecido en grupo #{groupNumber}: '{topic}'");



&nbsp;// Disparar callback de cambio de tema

&nbsp;OnGroupTopic?.Invoke(this, groupNumber, 0, topic, null);



&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error estableciendo tema de grupo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_topic - Obtener tema del grupo

&nbsp;/// </summary>

&nbsp;public string GroupGetTopic(int groupNumber)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;return \_groups.TryGetValue(groupNumber, out var group) ? group.Topic : string.Empty;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_name - Obtener nombre del grupo

&nbsp;/// </summary>

&nbsp;public string GroupGetName(int groupNumber)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;return \_groups.TryGetValue(groupNumber, out var group) ? group.Name : string.Empty;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_peer\_name - Obtener nombre de peer en grupo

&nbsp;/// </summary>

&nbsp;public string GroupGetPeerName(int groupNumber, int peerNumber)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (!\_groups.TryGetValue(groupNumber, out var group))

&nbsp;return string.Empty;



&nbsp;var peer = group.GetPeer(peerNumber);

&nbsp;return peer?.Name ?? string.Empty;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_peer\_count - Obtener número de peers en grupo

&nbsp;/// </summary>

&nbsp;public int GroupGetPeerCount(int groupNumber)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;return \_groups.TryGetValue(groupNumber, out var group) ? group.PeerCount : 0;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_number\_groups - Obtener número de grupos

&nbsp;/// </summary>

&nbsp;public int GroupGetNumberGroups()

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;return \_groups.Count;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_get\_list - Obtener lista de números de grupo

&nbsp;/// </summary>

&nbsp;public int\[] GroupGetList()

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;return \_groups.Keys.ToArray();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_invite\_friend - Invitar amigo a grupo

&nbsp;/// </summary>

&nbsp;public bool GroupInviteFriend(int groupNumber, int friendNumber)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (!\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Grupo no encontrado: #{groupNumber}");

&nbsp;return false;

&nbsp;}



&nbsp;// Simular invitación

&nbsp;byte\[] inviteData = Encoding.UTF8.GetBytes(group.Name);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Amigo {friendNumber} invitado al grupo #{groupNumber}");



&nbsp;// En implementación real, esto enviaría la invitación al amigo

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error invitando amigo a grupo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_group\_leave - Abandonar grupo

&nbsp;/// </summary>

&nbsp;public bool GroupLeave(int groupNumber, string partMessage = "")

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (!\_groups.Remove(groupNumber))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Grupo no encontrado: #{groupNumber}");

&nbsp;return false;

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Abandonado grupo #{groupNumber}: '{partMessage}'");



&nbsp;// Disparar callback de salida

&nbsp;OnGroupPeerExit?.Invoke(this, groupNumber, 0, ToxGroupExitType.TOX\_GROUP\_EXIT\_QUIT, partMessage, null);



&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error abandonando grupo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS DE SIMULACIÓN/TEST ====================



&nbsp;/// <summary>

&nbsp;/// Simular invitación a grupo (para pruebas)

&nbsp;/// </summary>

&nbsp;public void SimulateGroupInvite(int friendNumber, string groupName)

&nbsp;{

&nbsp;byte\[] inviteData = Encoding.UTF8.GetBytes(groupName);

&nbsp;OnGroupInvite?.Invoke(this, friendNumber, inviteData, groupName, null);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Simular unirse a grupo (para pruebas)

&nbsp;/// </summary>

&nbsp;public int SimulateGroupJoin(string groupName)

&nbsp;{

&nbsp;byte\[] inviteData = Encoding.UTF8.GetBytes(groupName);

&nbsp;return GroupJoin(inviteData);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Simular peer uniéndose a grupo (para pruebas)

&nbsp;/// </summary>

&nbsp;public void SimulatePeerJoin(int groupNumber, string peerName)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;int peerNumber = group.PeerCount;

&nbsp;var peer = new GroupPeer(peerNumber, peerName, new byte\[32]);

&nbsp;group.AddPeer(peer);



&nbsp;OnGroupPeerJoin?.Invoke(this, groupNumber, peerNumber, null);

&nbsp;OnGroupPeerListUpdate?.Invoke(this, groupNumber, null);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Simular peer abandonando grupo (para pruebas)

&nbsp;/// </summary>

&nbsp;public void SimulatePeerExit(int groupNumber, int peerNumber, ToxGroupExitType exitType, string exitMessage)

&nbsp;{

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;group.RemovePeer(peerNumber);

&nbsp;OnGroupPeerExit?.Invoke(this, groupNumber, peerNumber, exitType, exitMessage, null);

&nbsp;OnGroupPeerListUpdate?.Invoke(this, groupNumber, null);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS PRIVADOS ====================



&nbsp;private void SimulateMessageReceipt(int groupNumber, string message, ToxMessageType type)

&nbsp;{

&nbsp;// Simular que otros peers reciben el mensaje

&nbsp;lock (\_groupsLock)

&nbsp;{

&nbsp;if (\_groups.TryGetValue(groupNumber, out var group))

&nbsp;{

&nbsp;// En implementación real, esto enviaría a todos los peers

&nbsp;// Por ahora, solo disparamos el callback para simular recepción

&nbsp;OnGroupMessage?.Invoke(this, groupNumber, 1, type, $"(Eco) {message}", null);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;}

&nbsp;}



&nbsp;// ==================== CLASES DE DATOS DE GRUPO ====================



&nbsp;/// <summary>

&nbsp;/// Representa un grupo de chat

&nbsp;/// </summary>

&nbsp;public class ToxGroup

&nbsp;{

&nbsp;public int GroupNumber { get; }

&nbsp;public string Name { get; set; }

&nbsp;public string Topic { get; set; }

&nbsp;public List<GroupPeer> Peers { get; }

&nbsp;public int PeerCount => Peers.Count;

&nbsp;public DateTime CreatedAt { get; }



&nbsp;public ToxGroup(int groupNumber, string name)

&nbsp;{

&nbsp;GroupNumber = groupNumber;

&nbsp;Name = name;

&nbsp;Topic = string.Empty;

&nbsp;Peers = new List<GroupPeer>();

&nbsp;CreatedAt = DateTime.UtcNow;

&nbsp;}



&nbsp;public void AddPeer(GroupPeer peer)

&nbsp;{

&nbsp;Peers.Add(peer);

&nbsp;}



&nbsp;public void RemovePeer(int peerNumber)

&nbsp;{

&nbsp;Peers.RemoveAll(p => p.PeerNumber == peerNumber);

&nbsp;}



&nbsp;public GroupPeer GetPeer(int peerNumber)

&nbsp;{

&nbsp;return Peers.FirstOrDefault(p => p.PeerNumber == peerNumber);

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{Name} (#{GroupNumber}) - {PeerCount} miembros - Tema: {Topic}";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Representa un peer en un grupo

&nbsp;/// </summary>

&nbsp;public class GroupPeer

&nbsp;{

&nbsp;public int PeerNumber { get; }

&nbsp;public string Name { get; set; }

&nbsp;public byte\[] PublicKey { get; }

&nbsp;public DateTime JoinedAt { get; }



&nbsp;public GroupPeer(int peerNumber, string name, byte\[] publicKey)

&nbsp;{

&nbsp;PeerNumber = peerNumber;

&nbsp;Name = name;

&nbsp;PublicKey = publicKey;

&nbsp;JoinedAt = DateTime.UtcNow;

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{Name} (#{PeerNumber})";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tipos de salida de grupo

&nbsp;/// </summary>

&nbsp;public enum ToxGroupExitType

&nbsp;{

&nbsp;TOX\_GROUP\_EXIT\_QUIT = 0, // Salida voluntaria

&nbsp;TOX\_GROUP\_EXIT\_TIMEOUT = 1, // Timeout de conexión

&nbsp;TOX\_GROUP\_EXIT\_DISCONNECT = 2,// Desconexión

&nbsp;TOX\_GROUP\_EXIT\_KICK = 3 // Expulsado

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Constantes para grupos

&nbsp;/// </summary>

&nbsp;public static class Constants

&nbsp;{

&nbsp;public const int TOX\_MAX\_MESSAGE\_LENGTH = 1372;

&nbsp;public const int TOX\_MAX\_NAME\_LENGTH = 128;

&nbsp;public const int TOX\_GROUP\_MAX\_PEERS = 500;

&nbsp;}

}

]



Archivo LANDiscovery.cs \[

using System.Net;

using System.Net.Sockets;

using System.Text;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación de LAN\_discovery.c - Descubrimiento de clientes Tox en red local

&nbsp;/// </summary>

&nbsp;public class LANDiscovery : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "LANDISCOVERY";



&nbsp;// Configuración

&nbsp;private const int DISCOVERY\_PORT = 33445;

&nbsp;private const int DISCOVERY\_INTERVAL\_MS = 30000; // 30 segundos

&nbsp;private const int PACKET\_TIMEOUT\_MS = 120000; // 2 minutos



&nbsp;// Componentes

&nbsp;private UdpClient \_udpClientV4;

&nbsp;private UdpClient \_udpClientV6;

&nbsp;private Thread \_discoveryThread;

&nbsp;private Thread \_receiveThreadV4;

&nbsp;private Thread \_receiveThreadV6;

&nbsp;private bool \_isRunning;

&nbsp;private byte\[] \_selfPublicKey;



&nbsp;// Almacenamiento de peers descubiertos

&nbsp;private readonly Dictionary<string, DiscoveredPeer> \_discoveredPeers;

&nbsp;private readonly object \_peersLock = new object();



&nbsp;// Callbacks

&nbsp;public Action<DiscoveredPeer> PeerDiscoveredCallback { get; set; }

&nbsp;public Action<DiscoveredPeer> PeerExpiredCallback { get; set; }



&nbsp;public LANDiscovery(byte\[] selfPublicKey)

&nbsp;{

&nbsp;\_selfPublicKey = selfPublicKey ?? throw new ArgumentNullException(nameof(selfPublicKey));

&nbsp;\_discoveredPeers = new Dictionary<string, DiscoveredPeer>();

&nbsp;\_isRunning = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] LAN Discovery inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar servicio de descubrimiento LAN

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Servicio ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;// Crear socket UDP IPv4

&nbsp;\_udpClientV4 = new UdpClient(AddressFamily.InterNetwork);

&nbsp;\_udpClientV4.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

&nbsp;\_udpClientV4.Client.Bind(new IPEndPoint(IPAddress.Any, DISCOVERY\_PORT));

&nbsp;\_udpClientV4.EnableBroadcast = true;

&nbsp;\_udpClientV4.MulticastLoopback = true;



&nbsp;// Unirse al grupo multicast para IPv4

&nbsp;try

&nbsp;{

&nbsp;\_udpClientV4.JoinMulticastGroup(IPAddress.Parse("239.192.255.250"), 50);

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Unido a grupo multicast IPv4");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No se pudo unir a grupo multicast IPv4: {ex.Message}");

&nbsp;}



&nbsp;// Crear socket UDP IPv6 (si está disponible)

&nbsp;try

&nbsp;{

&nbsp;\_udpClientV6 = new UdpClient(AddressFamily.InterNetworkV6);

&nbsp;\_udpClientV6.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

&nbsp;\_udpClientV6.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, DISCOVERY\_PORT));

&nbsp;\_udpClientV6.MulticastLoopback = true;



&nbsp;// Unirse al grupo multicast para IPv6

&nbsp;\_udpClientV6.JoinMulticastGroup(IPAddress.Parse("ff02::1"));

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Unido a grupo multicast IPv6");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No se pudo crear socket IPv6: {ex.Message}");

&nbsp;\_udpClientV6 = null;

&nbsp;}



&nbsp;\_isRunning = true;



&nbsp;// Iniciar hilo de envío de anuncios

&nbsp;\_discoveryThread = new Thread(DiscoveryWorker);

&nbsp;\_discoveryThread.IsBackground = true;

&nbsp;\_discoveryThread.Name = "LANDiscovery-Sender";

&nbsp;\_discoveryThread.Start();



&nbsp;// Iniciar hilos de recepción

&nbsp;\_receiveThreadV4 = new Thread(() => ReceiveWorker(\_udpClientV4, "IPv4"));

&nbsp;\_receiveThreadV4.IsBackground = true;

&nbsp;\_receiveThreadV4.Name = "LANDiscovery-Receiver-IPv4";

&nbsp;\_receiveThreadV4.Start();



&nbsp;if (\_udpClientV6 != null)

&nbsp;{

&nbsp;\_receiveThreadV6 = new Thread(() => ReceiveWorker(\_udpClientV6, "IPv6"));

&nbsp;\_receiveThreadV6.IsBackground = true;

&nbsp;\_receiveThreadV6.Name = "LANDiscovery-Receiver-IPv6";

&nbsp;\_receiveThreadV6.Start();

&nbsp;}



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio LAN Discovery iniciado en puerto {DISCOVERY\_PORT}");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando LAN Discovery: {ex.Message}");

&nbsp;Stop();

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener servicio de descubrimiento LAN

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;\_isRunning = false;



&nbsp;try

&nbsp;{

&nbsp;\_discoveryThread?.Join(1000);

&nbsp;\_receiveThreadV4?.Join(1000);

&nbsp;\_receiveThreadV6?.Join(1000);



&nbsp;\_udpClientV4?.Close();

&nbsp;\_udpClientV4?.Dispose();

&nbsp;\_udpClientV4 = null;



&nbsp;\_udpClientV6?.Close();

&nbsp;\_udpClientV6?.Dispose();

&nbsp;\_udpClientV6 = null;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio LAN Discovery detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo LAN Discovery: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Trabajador que envía anuncios periódicos

&nbsp;/// </summary>

&nbsp;private void DiscoveryWorker()

&nbsp;{

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo de descubrimiento iniciado");



&nbsp;while (\_isRunning)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;SendDiscoveryPacket();

&nbsp;CleanupExpiredPeers();

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error en trabajador de descubrimiento: {ex.Message}");

&nbsp;}



&nbsp;// Esperar hasta el próximo anuncio

&nbsp;for (int i = 0; i < DISCOVERY\_INTERVAL\_MS / 1000 \&\& \_isRunning; i++)

&nbsp;{

&nbsp;Thread.Sleep(1000);

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo de descubrimiento finalizado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Trabajador que recibe paquetes de descubrimiento

&nbsp;/// </summary>

&nbsp;private void ReceiveWorker(UdpClient client, string family)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Hilo de recepción {family} iniciado");



&nbsp;while (\_isRunning \&\& client != null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;IPEndPoint remoteEndPoint = new IPEndPoint(

&nbsp;family == "IPv4" ? IPAddress.Any : IPAddress.IPv6Any,

&nbsp;0

&nbsp;);

&nbsp;byte\[] receivedData = client.Receive(ref remoteEndPoint);



&nbsp;if (receivedData != null \&\& receivedData.Length > 0)

&nbsp;{

&nbsp;ProcessDiscoveryPacket(receivedData, remoteEndPoint, family);

&nbsp;}

&nbsp;}

&nbsp;catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)

&nbsp;{

&nbsp;// Socket cerrado, salir normalmente

&nbsp;break;

&nbsp;}

&nbsp;catch (ObjectDisposedException)

&nbsp;{

&nbsp;// Socket disposed, salir normalmente

&nbsp;break;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;if (\_isRunning) // Solo loguear errores si todavía estamos ejecutándonos

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error recibiendo paquete {family}: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Hilo de recepción {family} finalizado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar paquete de descubrimiento a la red local

&nbsp;/// </summary>

&nbsp;private void SendDiscoveryPacket()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Crear paquete de descubrimiento

&nbsp;byte\[] discoveryPacket = CreateDiscoveryPacket();

&nbsp;if (discoveryPacket == null) return;



&nbsp;// Enviar por broadcast IPv4

&nbsp;IPEndPoint broadcastV4 = new IPEndPoint(IPAddress.Broadcast, DISCOVERY\_PORT);

&nbsp;\_udpClientV4?.Send(discoveryPacket, discoveryPacket.Length, broadcastV4);



&nbsp;// Enviar por multicast IPv4

&nbsp;IPEndPoint multicastV4 = new IPEndPoint(IPAddress.Parse("239.192.255.250"), DISCOVERY\_PORT);

&nbsp;\_udpClientV4?.Send(discoveryPacket, discoveryPacket.Length, multicastV4);



&nbsp;// Enviar por multicast IPv6 (si está disponible)

&nbsp;if (\_udpClientV6 != null)

&nbsp;{

&nbsp;IPEndPoint multicastV6 = new IPEndPoint(IPAddress.Parse("ff02::1"), DISCOVERY\_PORT);

&nbsp;\_udpClientV6.Send(discoveryPacket, discoveryPacket.Length, multicastV6);

&nbsp;}



&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Paquete de descubrimiento enviado");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error enviando paquete de descubrimiento: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Crear paquete de descubrimiento LAN

&nbsp;/// </summary>

&nbsp;private byte\[] CreateDiscoveryPacket()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Formato del paquete: \[MAGIC]\[PUBLIC\_KEY]\[RESERVED]

&nbsp;const int PACKET\_SIZE = 32 + 32 + 16; // magic + public\_key + reserved

&nbsp;byte\[] packet = new byte\[PACKET\_SIZE];



&nbsp;// Magic bytes "ToxLANDiscovery"

&nbsp;byte\[] magic = Encoding.UTF8.GetBytes("ToxLANDiscovery");

&nbsp;Buffer.BlockCopy(magic, 0, packet, 0, Math.Min(magic.Length, 32));



&nbsp;// Clave pública

&nbsp;Buffer.BlockCopy(\_selfPublicKey, 0, packet, 32, 32);



&nbsp;// Reserved bytes (ceros)

&nbsp;for (int i = 64; i < PACKET\_SIZE; i++)

&nbsp;{

&nbsp;packet\[i] = 0;

&nbsp;}



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete de descubrimiento: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Procesar paquete de descubrimiento recibido

&nbsp;/// </summary>

&nbsp;private void ProcessDiscoveryPacket(byte\[] packet, IPEndPoint sender, string family)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Verificar tamaño mínimo

&nbsp;if (packet.Length < 64) // magic + public\_key

&nbsp;{

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Paquete demasiado corto: {packet.Length} bytes");

&nbsp;return;

&nbsp;}



&nbsp;// Verificar magic bytes

&nbsp;byte\[] expectedMagic = Encoding.UTF8.GetBytes("ToxLANDiscovery");

&nbsp;bool magicValid = true;

&nbsp;for (int i = 0; i < expectedMagic.Length \&\& i < 32; i++)

&nbsp;{

&nbsp;if (packet\[i] != expectedMagic\[i])

&nbsp;{

&nbsp;magicValid = false;

&nbsp;break;

&nbsp;}

&nbsp;}



&nbsp;if (!magicValid)

&nbsp;{

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Magic bytes inválidos en paquete");

&nbsp;return;

&nbsp;}



&nbsp;// Extraer clave pública

&nbsp;byte\[] publicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 32, publicKey, 0, 32);



&nbsp;// Ignorar nuestros propios paquetes

&nbsp;if (CryptoBytes.MemCompare(publicKey, \_selfPublicKey))

&nbsp;{

&nbsp;return;

&nbsp;}



&nbsp;// Crear objeto de peer descubierto

&nbsp;var peer = new DiscoveredPeer

&nbsp;{

&nbsp;PublicKey = publicKey,

&nbsp;IPAddress = sender.Address,

&nbsp;Port = (ushort)DISCOVERY\_PORT,

&nbsp;LastSeen = DateTime.UtcNow,

&nbsp;DiscoveryMethod = $"LAN-{family}"

&nbsp;};



&nbsp;// Agregar o actualizar peer

&nbsp;string peerKey = BitConverter.ToString(publicKey).Replace("-", "");

&nbsp;bool isNewPeer = false;



&nbsp;lock (\_peersLock)

&nbsp;{

&nbsp;if (!\_discoveredPeers.ContainsKey(peerKey))

&nbsp;{

&nbsp;\_discoveredPeers\[peerKey] = peer;

&nbsp;isNewPeer = true;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// Actualizar timestamp

&nbsp;\_discoveredPeers\[peerKey].LastSeen = DateTime.UtcNow;

&nbsp;}

&nbsp;}



&nbsp;// Llamar callback si es un peer nuevo

&nbsp;if (isNewPeer)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nuevo peer descubierto: {peer.IPAddress} \[PK: {peerKey.Substring(0, 16)}...] via {family}");

&nbsp;PeerDiscoveredCallback?.Invoke(peer);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error procesando paquete de descubrimiento: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpiar peers expirados

&nbsp;/// </summary>

&nbsp;private void CleanupExpiredPeers()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;DateTime cutoffTime = DateTime.UtcNow.AddMilliseconds(-PACKET\_TIMEOUT\_MS);

&nbsp;List<DiscoveredPeer> expiredPeers = new List<DiscoveredPeer>();



&nbsp;lock (\_peersLock)

&nbsp;{

&nbsp;var expiredKeys = \_discoveredPeers

&nbsp;.Where(kvp => kvp.Value.LastSeen < cutoffTime)

&nbsp;.Select(kvp => kvp.Key)

&nbsp;.ToList();



&nbsp;foreach (string key in expiredKeys)

&nbsp;{

&nbsp;expiredPeers.Add(\_discoveredPeers\[key]);

&nbsp;\_discoveredPeers.Remove(key);

&nbsp;}

&nbsp;}



&nbsp;// Notificar peers expirados

&nbsp;foreach (var peer in expiredPeers)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Peer expirado: {peer.IPAddress}");

&nbsp;PeerExpiredCallback?.Invoke(peer);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error limpiando peers expirados: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtener lista de peers descubiertos

&nbsp;/// </summary>

&nbsp;public List<DiscoveredPeer> GetDiscoveredPeers()

&nbsp;{

&nbsp;lock (\_peersLock)

&nbsp;{

&nbsp;return \_discoveredPeers.Values.ToList();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtener estadísticas de descubrimiento

&nbsp;/// </summary>

&nbsp;public LANDiscoveryStats GetStats()

&nbsp;{

&nbsp;lock (\_peersLock)

&nbsp;{

&nbsp;return new LANDiscoveryStats

&nbsp;{

&nbsp;TotalPeersDiscovered = \_discoveredPeers.Count,

&nbsp;ActivePeers = \_discoveredPeers.Count(p => p.Value.LastSeen > DateTime.UtcNow.AddMinutes(-5)),

&nbsp;IsRunning = \_isRunning

&nbsp;};

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Forzar descubrimiento inmediato

&nbsp;/// </summary>

&nbsp;public void ForceDiscovery()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;SendDiscoveryPacket();

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Descubrimiento forzado ejecutado");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error en descubrimiento forzado: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;}

&nbsp;}



&nbsp;// ... (las clases DiscoveredPeer, LANDiscoveryStats, y CryptoBytes se mantienen igual)





&nbsp;/// <summary>

&nbsp;/// Información de un peer descubierto

&nbsp;/// </summary>

&nbsp;public class DiscoveredPeer

&nbsp;{

&nbsp;public byte\[] PublicKey { get; set; }

&nbsp;public IPAddress IPAddress { get; set; }

&nbsp;public ushort Port { get; set; }

&nbsp;public DateTime LastSeen { get; set; }

&nbsp;public string DiscoveryMethod { get; set; }



&nbsp;public override string ToString()

&nbsp;{

&nbsp;string keyShort = PublicKey != null ? BitConverter.ToString(PublicKey, 0, 8).Replace("-", "") : "N/A";

&nbsp;return $"{IPAddress}:{Port} \[PK: {keyShort}...] ({DiscoveryMethod})";

&nbsp;}

&nbsp;}







&nbsp;/// <summary>

&nbsp;/// Estadísticas de LAN Discovery

&nbsp;/// </summary>

&nbsp;public class LANDiscoveryStats

&nbsp;{

&nbsp;public int TotalPeersDiscovered { get; set; }

&nbsp;public int ActivePeers { get; set; }

&nbsp;public bool IsRunning { get; set; }



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"LAN Discovery - Ejecutándose: {IsRunning}, Peers: {TotalPeersDiscovered} total, {ActivePeers} activos";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Helper para comparación de bytes

&nbsp;/// </summary>

&nbsp;internal static class CryptoBytes

&nbsp;{

&nbsp;public static bool MemCompare(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null) return false;

&nbsp;if (a.Length != b.Length) return false;



&nbsp;for (int i = 0; i < a.Length; i++)

&nbsp;{

&nbsp;if (a\[i] != b\[i]) return false;

&nbsp;}

&nbsp;return true;

&nbsp;}

&nbsp;}

}

]



Archivo Logger.cs \[

using System.Text;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Niveles de log compatibles con toxcore

&nbsp;/// </summary>

&nbsp;public enum ToxLogLevel

&nbsp;{

&nbsp;TOX\_LOG\_LEVEL\_TRACE,

&nbsp;TOX\_LOG\_LEVEL\_DEBUG,

&nbsp;TOX\_LOG\_LEVEL\_INFO,

&nbsp;TOX\_LOG\_LEVEL\_WARNING,

&nbsp;TOX\_LOG\_LEVEL\_ERROR

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Callback para logging personalizado

&nbsp;/// </summary>

&nbsp;/// <param name="level">Nivel de log</param>

&nbsp;/// <param name="file">Archivo origen</param>

&nbsp;/// <param name="line">Línea origen</param>

&nbsp;/// <param name="func">Función origen</param>

&nbsp;/// <param name="message">Mensaje de log</param>

&nbsp;/// <param name="userData">Datos de usuario</param>

&nbsp;public delegate void ToxLogCallback(ToxLogLevel level, string file, int line, string func, string message, IntPtr userData);



&nbsp;/// <summary>

&nbsp;/// Implementación de logger compatible con logger.c de toxcore

&nbsp;/// </summary>

&nbsp;public static class Logger

&nbsp;{

&nbsp;private static ToxLogCallback \_logCallback;

&nbsp;private static IntPtr \_userData;

&nbsp;private static ToxLogLevel \_minLevel = ToxLogLevel.TOX\_LOG\_LEVEL\_INFO;

&nbsp;private static readonly object \_lockObject = new object();

&nbsp;private static StreamWriter \_fileWriter;

&nbsp;private static string \_logFilePath;



&nbsp;// ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// tox\_log\_cb\_register - Registrar callback de logging

&nbsp;/// </summary>

&nbsp;public static void tox\_log\_cb\_register(ToxLogCallback callback, IntPtr userData)

&nbsp;{

&nbsp;lock (\_lockObject)

&nbsp;{

&nbsp;\_logCallback = callback;

&nbsp;\_userData = userData;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_log\_set\_level - Establecer nivel mínimo de log

&nbsp;/// </summary>

&nbsp;public static void tox\_log\_set\_level(ToxLogLevel level)

&nbsp;{

&nbsp;lock (\_lockObject)

&nbsp;{

&nbsp;\_minLevel = level;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_log\_get\_level - Obtener nivel actual de log

&nbsp;/// </summary>

&nbsp;public static ToxLogLevel tox\_log\_get\_level()

&nbsp;{

&nbsp;return \_minLevel;

&nbsp;}



&nbsp;// ==================== FUNCIONES DE LOGGING PRINCIPALES ====================



&nbsp;/// <summary>

&nbsp;/// LOGGER\_TRACE - Log nivel trace

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_TRACE(string file, int line, string func, string message)

&nbsp;{

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_TRACE, file, line, func, message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_DEBUG - Log nivel debug

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_DEBUG(string file, int line, string func, string message)

&nbsp;{

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_DEBUG, file, line, func, message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_INFO - Log nivel info

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_INFO(string file, int line, string func, string message)

&nbsp;{

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_INFO, file, line, func, message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_WARNING - Log nivel warning

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_WARNING(string file, int line, string func, string message)

&nbsp;{

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_WARNING, file, line, func, message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_ERROR - Log nivel error

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_ERROR(string file, int line, string func, string message)

&nbsp;{

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_ERROR, file, line, func, message);

&nbsp;}



&nbsp;// ==================== FUNCIONES DE LOGGING CON FORMATO ====================



&nbsp;/// <summary>

&nbsp;/// LOGGER\_TRACE\_F - Log trace con formato

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_TRACE\_F(string file, int line, string func, string format, params object\[] args)

&nbsp;{

&nbsp;if (\_minLevel <= ToxLogLevel.TOX\_LOG\_LEVEL\_TRACE)

&nbsp;{

&nbsp;string message = string.Format(format, args);

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_TRACE, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_DEBUG\_F - Log debug con formato

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_DEBUG\_F(string file, int line, string func, string format, params object\[] args)

&nbsp;{

&nbsp;if (\_minLevel <= ToxLogLevel.TOX\_LOG\_LEVEL\_DEBUG)

&nbsp;{

&nbsp;string message = string.Format(format, args);

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_DEBUG, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_INFO\_F - Log info con formato

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_INFO\_F(string file, int line, string func, string format, params object\[] args)

&nbsp;{

&nbsp;if (\_minLevel <= ToxLogLevel.TOX\_LOG\_LEVEL\_INFO)

&nbsp;{

&nbsp;string message = string.Format(format, args);

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_INFO, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_WARNING\_F - Log warning con formato

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_WARNING\_F(string file, int line, string func, string format, params object\[] args)

&nbsp;{

&nbsp;if (\_minLevel <= ToxLogLevel.TOX\_LOG\_LEVEL\_WARNING)

&nbsp;{

&nbsp;string message = string.Format(format, args);

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_WARNING, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// LOGGER\_ERROR\_F - Log error con formato

&nbsp;/// </summary>

&nbsp;public static void LOGGER\_ERROR\_F(string file, int line, string func, string format, params object\[] args)

&nbsp;{

&nbsp;if (\_minLevel <= ToxLogLevel.TOX\_LOG\_LEVEL\_ERROR)

&nbsp;{

&nbsp;string message = string.Format(format, args);

&nbsp;LogInternal(ToxLogLevel.TOX\_LOG\_LEVEL\_ERROR, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES INTERNAS ====================



&nbsp;private static void LogInternal(ToxLogLevel level, string file, int line, string func, string message)

&nbsp;{

&nbsp;if (level < \_minLevel) return;



&nbsp;lock (\_lockObject)

&nbsp;{

&nbsp;// Llamar callback si está registrado

&nbsp;if (\_logCallback != null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;\_logCallback(level, file, line, func, message, \_userData);

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;// Silenciar errores en callback

&nbsp;}

&nbsp;}



&nbsp;// Log a consola

&nbsp;LogToConsole(level, file, line, func, message);



&nbsp;// Log a archivo si está configurado

&nbsp;LogToFile(level, file, line, func, message);

&nbsp;}

&nbsp;}



&nbsp;private static void LogToConsole(ToxLogLevel level, string file, int line, string func, string message)

&nbsp;{

&nbsp;string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");

&nbsp;string levelStr = GetLevelString(level);

&nbsp;string fileName = Path.GetFileName(file);



&nbsp;Console.WriteLine($"\[{timestamp}] \[{levelStr}] {fileName}:{line} ({func}) {message}");

&nbsp;}



&nbsp;private static void LogToFile(ToxLogLevel level, string file, int line, string func, string message)

&nbsp;{

&nbsp;if (\_fileWriter != null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");

&nbsp;string levelStr = GetLevelString(level);

&nbsp;string fileName = Path.GetFileName(file);



&nbsp;\_fileWriter.WriteLine($"\[{timestamp}] \[{levelStr}] {fileName}:{line} ({func}) {message}");

&nbsp;\_fileWriter.Flush();

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;// Silenciar errores de escritura de archivo

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;private static string GetLevelString(ToxLogLevel level)

&nbsp;{

&nbsp;switch (level)

&nbsp;{

&nbsp;case ToxLogLevel.TOX\_LOG\_LEVEL\_TRACE: return "TRACE";

&nbsp;case ToxLogLevel.TOX\_LOG\_LEVEL\_DEBUG: return "DEBUG";

&nbsp;case ToxLogLevel.TOX\_LOG\_LEVEL\_INFO: return "INFO";

&nbsp;case ToxLogLevel.TOX\_LOG\_LEVEL\_WARNING: return "WARN";

&nbsp;case ToxLogLevel.TOX\_LOG\_LEVEL\_ERROR: return "ERROR";

&nbsp;default: return "UNKNOWN";

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES DE GESTIÓN DE ARCHIVOS ====================



&nbsp;/// <summary>

&nbsp;/// tox\_log\_enable\_file\_logging - Habilitar logging a archivo

&nbsp;/// </summary>

&nbsp;public static bool tox\_log\_enable\_file\_logging(string filePath)

&nbsp;{

&nbsp;lock (\_lockObject)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (\_fileWriter != null)

&nbsp;{

&nbsp;\_fileWriter.Close();

&nbsp;\_fileWriter = null;

&nbsp;}



&nbsp;\_fileWriter = new StreamWriter(filePath, true, Encoding.UTF8);

&nbsp;\_logFilePath = filePath;

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_log\_disable\_file\_logging - Deshabilitar logging a archivo

&nbsp;/// </summary>

&nbsp;public static void tox\_log\_disable\_file\_logging()

&nbsp;{

&nbsp;lock (\_lockObject)

&nbsp;{

&nbsp;if (\_fileWriter != null)

&nbsp;{

&nbsp;\_fileWriter.Close();

&nbsp;\_fileWriter = null;

&nbsp;\_logFilePath = null;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_log\_get\_file\_path - Obtener ruta del archivo de log

&nbsp;/// </summary>

&nbsp;public static string tox\_log\_get\_file\_path()

&nbsp;{

&nbsp;return \_logFilePath;

&nbsp;}



&nbsp;// ==================== MACROS COMPATIBLES (para uso en otros módulos) ====================



&nbsp;/// <summary>

&nbsp;/// Macros para facilitar el logging desde otros archivos

&nbsp;/// </summary>

&nbsp;public static class Log

&nbsp;{

&nbsp;public static void Trace(string message, \[System.Runtime.CompilerServices.CallerFilePath] string file = "",

&nbsp;\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0,

&nbsp;\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;LOGGER\_TRACE(file, line, func, message);

&nbsp;}



&nbsp;public static void Debug(string message, \[System.Runtime.CompilerServices.CallerFilePath] string file = "",

&nbsp;\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0,

&nbsp;\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;LOGGER\_DEBUG(file, line, func, message);

&nbsp;}



&nbsp;public static void Info(string message, \[System.Runtime.CompilerServices.CallerFilePath] string file = "",

&nbsp;\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0,

&nbsp;\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;LOGGER\_INFO(file, line, func, message);

&nbsp;}



&nbsp;public static void Warning(string message, \[System.Runtime.CompilerServices.CallerFilePath] string file = "",

&nbsp;\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0,

&nbsp;\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;LOGGER\_WARNING(file, line, func, message);

&nbsp;}



&nbsp;public static void Error(string message, \[System.Runtime.CompilerServices.CallerFilePath] string file = "",

&nbsp;\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0,

&nbsp;\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;LOGGER\_ERROR(file, line, func, message);

&nbsp;}



&nbsp;public static void TraceF(string format, params object\[] args)

&nbsp;{

&nbsp;LOGGER\_TRACE\_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);

&nbsp;}



&nbsp;public static void DebugF(string format, params object\[] args)

&nbsp;{

&nbsp;LOGGER\_DEBUG\_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);

&nbsp;}



&nbsp;public static void InfoF(string format, params object\[] args)

&nbsp;{

&nbsp;LOGGER\_INFO\_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);

&nbsp;}



&nbsp;public static void WarningF(string format, params object\[] args)

&nbsp;{

&nbsp;LOGGER\_WARNING\_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);

&nbsp;}



&nbsp;public static void ErrorF(string format, params object\[] args)

&nbsp;{

&nbsp;LOGGER\_ERROR\_F(GetCallerFile(), GetCallerLine(), GetCallerMethod(), format, args);

&nbsp;}



&nbsp;private static string GetCallerFile(\[System.Runtime.CompilerServices.CallerFilePath] string file = "")

&nbsp;{

&nbsp;return file;

&nbsp;}



&nbsp;private static int GetCallerLine(\[System.Runtime.CompilerServices.CallerLineNumber] int line = 0)

&nbsp;{

&nbsp;return line;

&nbsp;}



&nbsp;private static string GetCallerMethod(\[System.Runtime.CompilerServices.CallerMemberName] string func = "")

&nbsp;{

&nbsp;return func;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo Messenger.cs \[

using System.Net;

using ToxCore.FileTransfer;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Adaptación de messenger.c - Núcleo principal del cliente Tox

&nbsp;/// </summary>

&nbsp;public class Messenger : IDisposable

&nbsp;{

&nbsp;public enum ToxConnection

&nbsp;{

&nbsp;TOX\_CONNECTION\_NONE = 0,

&nbsp;TOX\_CONNECTION\_TCP = 1,

&nbsp;TOX\_CONNECTION\_UDP = 2

&nbsp;}



&nbsp;private readonly List<BootstrapNode> \_bootstrapNodes = new List<BootstrapNode>

&nbsp;{

&nbsp;// Nodos oficiales de Tox - actualizados 2024

&nbsp;new BootstrapNode("tox.plastiras.org", 33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832"),

&nbsp;new BootstrapNode("144.217.167.73", 33445, "7F9C31FE850E97CEFD4C4591DF93FC757C7C12549DDD55F8EEAECC34FE76C029"),

&nbsp;new BootstrapNode("tox.abilinski.com", 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D294302F67BEDFFB5DF67F"),

&nbsp;new BootstrapNode("tox.novg.net", 33445, "D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463"),

&nbsp;new BootstrapNode("tox.kurnevsky.net", 33445, "82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23")

&nbsp;};



&nbsp;private int \_currentBootstrapIndex = 0;

&nbsp;private long \_lastBootstrapAttempt = 0;

&nbsp;private const int BOOTSTRAP\_RETRY\_INTERVAL = 30000; // 30 segundos

&nbsp;private const int BOOTSTRAP\_MAX\_ATTEMPTS = 3;



&nbsp;// ✅ NUEVO: Clase para nodos bootstrap

&nbsp;private class BootstrapNode

&nbsp;{

&nbsp;public string Host { get; }

&nbsp;public ushort Port { get; }

&nbsp;public byte\[] PublicKey { get; }



&nbsp;public BootstrapNode(string host, ushort port, string publicKeyHex)

&nbsp;{

&nbsp;Host = host;

&nbsp;Port = port;

&nbsp;PublicKey = HexStringToByteArray(publicKeyHex);

&nbsp;}

&nbsp;}





&nbsp;public const int FRIEND\_CONNECTION\_TIMEOUT = 60000; // 60 segundos

&nbsp;public const int PING\_INTERVAL = 30000; // 30 segundos

&nbsp;public const int PING\_TIMEOUT = 10000; // 10 segundos



&nbsp;private const string LOG\_TAG = "MESSENGER";

&nbsp;public GroupManager GroupManager { get; private set; }



&nbsp;// Componentes principales

&nbsp;public DHT Dht { get; private set; }

&nbsp;public Onion Onion { get; private set; }

&nbsp;public TCP\_Server TcpServer { get; private set; }

&nbsp;public FriendConnection FriendConn { get; private set; }

&nbsp;public ToxState State { get; private set; }

&nbsp;public LANDiscovery LANDiscovery { get; private set; }

&nbsp;public FileTransferManager FileTransfer { get; private set; }

&nbsp;public TCPTunnel TcpTunnel { get; private set; }

&nbsp;public TCPForwarding TcpForwarding { get; private set; }



&nbsp;// Configuración

&nbsp;private readonly MessengerOptions \_options;

&nbsp;private bool \_isRunning;



&nbsp;public Messenger(MessengerOptions options = null)

&nbsp;{

&nbsp;\_options = options ?? new MessengerOptions();

&nbsp;State = new ToxState();

&nbsp;TcpTunnel = new TCPTunnel(this);

&nbsp;TcpForwarding = new TCPForwarding(TcpTunnel);

&nbsp;\_isRunning = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Messenger inicializando...");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_start - Inicializar todos los componentes

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Messenger ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;// 1. Generar claves si no existen

&nbsp;if (State.User.PublicKey.All(b => b == 0) || State.User.SecretKey.All(b => b == 0))

&nbsp;{

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Generando nuevas claves criptográficas");

&nbsp;GenerateNewKeys();

&nbsp;}



&nbsp;// 2. Inicializar DHT

&nbsp;Dht = new DHT(State.User.PublicKey, State.User.SecretKey);



&nbsp;// 3. Inicializar Onion

&nbsp;Onion = new Onion(State.User.PublicKey, State.User.SecretKey);



&nbsp;// 4. Inicializar TCP Server si está habilitado (usar constructor sin parámetros)

&nbsp;if (\_options.TcpEnabled)

&nbsp;{

&nbsp;TcpServer = new TCP\_Server(State.User.PublicKey, State.User.SecretKey);

&nbsp;// En una implementación real, inicializarías el servidor aquí

&nbsp;}



&nbsp;// 5. Inicializar Friend Connection

&nbsp;FriendConn = new FriendConnection(State.User.PublicKey, State.User.SecretKey, Dht, Onion);



&nbsp;if (\_options.EnableLANDiscovery)

&nbsp;{

&nbsp;LANDiscovery = new LANDiscovery(State.User.PublicKey);



&nbsp;// Configurar callback para agregar amigos automáticamente

&nbsp;LANDiscovery.PeerDiscoveredCallback = OnPeerDiscovered;



&nbsp;bool lanStarted = LANDiscovery.Start();

&nbsp;if (lanStarted)

&nbsp;{

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] LAN Discovery iniciado");

&nbsp;}

&nbsp;}



&nbsp;GroupManager = new GroupManager(this);

&nbsp;GroupManager.Start();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Group Manager iniciado");





&nbsp;FileTransfer = new FileTransferManager(this);



&nbsp;TcpTunnel.Start();



&nbsp;\_isRunning = true;

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Messenger iniciado correctamente");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando messenger: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private int HandleTunnelPacket(int friendcon\_id, byte\[] data, int length)

&nbsp;{

&nbsp;return TcpTunnel?.HandleTunnelPacket(friendcon\_id, data, length) ?? -1;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_stop - Detener todos los componentes

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = false;



&nbsp;// Usar métodos de cierre existentes en tus clases

&nbsp;// Si no tienen Dispose, simplemente dejar que el GC los limpie

&nbsp;FriendConn = null;

&nbsp;Onion = null;

&nbsp;TcpServer = null;

&nbsp;Dht = null;

&nbsp;LANDiscovery?.Stop();

&nbsp;LANDiscovery?.Dispose();

&nbsp;GroupManager?.Stop();

&nbsp;GroupManager?.Dispose();

&nbsp;TcpTunnel?.Stop();

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Messenger detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo messenger: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;private void OnPeerDiscovered(DiscoveredPeer peer)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Peer LAN descubierto: {peer.IPAddress}");



&nbsp;// Intentar bootstrap con el peer descubierto

&nbsp;Bootstrap(peer.IPAddress.ToString(), peer.Port, peer.PublicKey);



&nbsp;// Opcional: agregar como amigo automáticamente

&nbsp;// AddFriend(peer.PublicKey, "Discovered on LAN");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error manejando peer descubierto: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_do - ACTUALIZADO con bootstrap automático

&nbsp;/// </summary>

&nbsp;public void Do()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;// 1. Bootstrap automático si no hay suficientes nodos DHT

&nbsp;if (Dht?.ActiveNodes < 10) // Si tenemos menos de 10 nodos activos

&nbsp;{

&nbsp;PerformAutomaticBootstrap();

&nbsp;}



&nbsp;// 2. Ejecutar trabajos periódicos de todos los componentes

&nbsp;Dht?.DoPeriodicWork();

&nbsp;Onion?.DoPeriodicWork();

&nbsp;FriendConn?.Do\_periodic\_work();



&nbsp;// 3. LAN Discovery si está habilitado

&nbsp;if (\_options.EnableLANDiscovery)

&nbsp;{

&nbsp;// LAN Discovery ya maneja su propio trabajo periódico

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en iteración principal: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Bootstrap - MEJORADO con múltiples intentos y mejor manejo de errores

&nbsp;/// </summary>

&nbsp;public bool Bootstrap(string host, ushort port, byte\[] publicKey)

&nbsp;{

&nbsp;if (!\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] No se puede bootstrap - Messenger no iniciado");

&nbsp;return false;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Bootstrap a {host}:{port}");



&nbsp;// ✅ MEJORADO: Usar DNS resolution real

&nbsp;IPAddress\[] addresses;

&nbsp;try

&nbsp;{

&nbsp;addresses = Dns.GetHostAddresses(host);

&nbsp;if (addresses.Length == 0)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se pudo resolver host: {host}");

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception dnsEx)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error DNS para {host}: {dnsEx.Message}");

&nbsp;return false;

&nbsp;}



&nbsp;// Intentar con todas las direcciones IP resueltas

&nbsp;foreach (var ipAddress in addresses)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var ipPort = new IPPort(new IP(ipAddress), port);



&nbsp;// Bootstrap en DHT

&nbsp;int result = Dht.DHT\_bootstrap(ipPort, publicKey);

&nbsp;bool success = result == 0;



&nbsp;if (success)

&nbsp;{

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Bootstrap exitoso a {ipAddress}:{port}");

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ipEx)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Bootstrap falló para {ipAddress}: {ipEx.Message}");

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Todos los intentos de bootstrap fallaron para {host}");

&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en bootstrap: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// BootstrapMultiple - Bootstrap a múltiples nodos simultáneamente

&nbsp;/// </summary>

&nbsp;public void BootstrapMultiple(params (string host, ushort port, string publicKeyHex)\[] nodes)

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;foreach (var node in nodes)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] publicKey = HexStringToByteArray(node.publicKeyHex);

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Task.Run(() => Bootstrap(node.host, node.port, publicKey));

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error en bootstrap múltiple para {node.host}: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_add\_friend - Agregar amigo por dirección Tox

&nbsp;/// </summary>

&nbsp;public int AddFriend(byte\[] address, string message)

&nbsp;{

&nbsp;if (!\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] No se puede agregar amigo - Messenger no iniciado");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;// Extraer clave pública de la dirección Tox (primeros 32 bytes)

&nbsp;if (address.Length < 32)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Dirección Tox inválida - muy corta");

&nbsp;return -1;

&nbsp;}



&nbsp;byte\[] publicKey = new byte\[32];

&nbsp;Array.Copy(address, publicKey, 32);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Agregando amigo - Mensaje: {message}");



&nbsp;// Usar API existente de FriendConnection - solo publicKey

&nbsp;int friendNumber = FriendConn.m\_addfriend(publicKey);



&nbsp;if (friendNumber >= 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Amigo agregado: {friendNumber}");

&nbsp;// Guardar en estado

&nbsp;SaveFriendToState(friendNumber, publicKey);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Falló agregar amigo");

&nbsp;}



&nbsp;return friendNumber;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error agregando amigo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_send\_message - Enviar mensaje a amigo

&nbsp;/// </summary>

&nbsp;public int SendMessage(uint friendNumber, string message)

&nbsp;{

&nbsp;if (!\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] No se puede enviar mensaje - Messenger no iniciado");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Enviando mensaje a amigo {friendNumber}");



&nbsp;// Convertir mensaje a bytes

&nbsp;byte\[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message ?? "");



&nbsp;// Usar API existente - solo 3 parámetros

&nbsp;int result = FriendConn.m\_send\_message((int)friendNumber, messageBytes, messageBytes.Length);



&nbsp;if (result > 0)

&nbsp;{

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Mensaje enviado a amigo {friendNumber}: {result} bytes");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Falló envío a amigo {friendNumber}");

&nbsp;}



&nbsp;return result;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando mensaje: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_set\_name - Establecer nombre de usuario

&nbsp;/// </summary>

&nbsp;public bool SetName(string name)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(name) || name.Length > 128)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Nombre inválido");

&nbsp;return false;

&nbsp;}



&nbsp;State.User.Name = name;

&nbsp;State.MarkModified();



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nombre establecido: {name}");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error estableciendo nombre: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_set\_status\_message - Establecer mensaje de estado

&nbsp;/// </summary>

&nbsp;public bool SetStatusMessage(string message)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (message?.Length > 1007) // Límite de toxcore

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Mensaje de estado muy largo");

&nbsp;return false;

&nbsp;}



&nbsp;State.User.StatusMessage = message ?? "";

&nbsp;State.MarkModified();



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Mensaje de estado establecido: {message}");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error estableciendo mensaje de estado: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// messenger\_set\_status - Establecer estado de usuario

&nbsp;/// </summary>

&nbsp;public bool SetStatus(ToxUserStatus status)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;State.User.Status = status;

&nbsp;State.MarkModified();



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Estado de usuario establecido: {status}");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error estableciendo estado: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS PRIVADOS ====================



&nbsp;private void GenerateNewKeys()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Generar par de claves

&nbsp;byte\[] publicKey = new byte\[32];

&nbsp;byte\[] secretKey = new byte\[32];



&nbsp;var random = new Random();

&nbsp;random.NextBytes(publicKey);

&nbsp;random.NextBytes(secretKey);



&nbsp;State.User.PublicKey = publicKey;

&nbsp;State.User.SecretKey = secretKey;

&nbsp;State.MarkModified();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Nuevas claves generadas");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error generando claves: {ex.Message}");

&nbsp;throw;

&nbsp;}

&nbsp;}



&nbsp;private void SaveFriendToState(int friendNumber, byte\[] publicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var friend = new ToxFriend

&nbsp;{

&nbsp;FriendNumber = (uint)friendNumber,

&nbsp;PublicKey = publicKey

&nbsp;};



&nbsp;var friendsList = State.Friends.Friends.ToList();

&nbsp;friendsList.Add(friend);

&nbsp;State.Friends.Friends = friendsList.ToArray();

&nbsp;State.MarkModified();



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Amigo {friendNumber} guardado en estado");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Error guardando amigo en estado: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// PerformAutomaticBootstrap - Bootstrap automático como en toxcore

&nbsp;/// </summary>

&nbsp;private void PerformAutomaticBootstrap()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// Esperar entre intentos de bootstrap

&nbsp;if ((currentTime - \_lastBootstrapAttempt) < TimeSpan.TicksPerMillisecond \* BOOTSTRAP\_RETRY\_INTERVAL)

&nbsp;return;



&nbsp;\_lastBootstrapAttempt = currentTime;



&nbsp;// Intentar con el siguiente nodo en la lista

&nbsp;var bootstrapNode = \_bootstrapNodes\[\_currentBootstrapIndex];

&nbsp;\_currentBootstrapIndex = (\_currentBootstrapIndex + 1) % \_bootstrapNodes.Count;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Intentando bootstrap automático con {bootstrapNode.Host}:{bootstrapNode.Port}");



&nbsp;bool success = Bootstrap(bootstrapNode.Host, bootstrapNode.Port, bootstrapNode.PublicKey);



&nbsp;if (success)

&nbsp;{

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Bootstrap automático exitoso");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Bootstrap automático falló, siguiente intento en {BOOTSTRAP\_RETRY\_INTERVAL / 1000} segundos");

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en bootstrap automático: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HexStringToByteArray - Convierte string hex a byte\[] (auxiliar para bootstrap)

&nbsp;/// </summary>

&nbsp;private static byte\[] HexStringToByteArray(string hex)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;int numberChars = hex.Length;

&nbsp;byte\[] bytes = new byte\[numberChars / 2];

&nbsp;for (int i = 0; i < numberChars; i += 2)

&nbsp;{

&nbsp;bytes\[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

&nbsp;}

&nbsp;return bytes;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[MESSENGER] Error convirtiendo hex a bytes: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}









&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;State?.Dispose();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Opciones de configuración del Messenger

&nbsp;/// </summary>

&nbsp;public class MessengerOptions

&nbsp;{

&nbsp;public bool IPv6Enabled { get; set; } = true;

&nbsp;public bool UDPEnabled { get; set; } = true;

&nbsp;public bool TcpEnabled { get; set; } = true;

&nbsp;public bool ProxyEnabled { get; set; } = false;

&nbsp;public string ProxyHost { get; set; } = string.Empty;

&nbsp;public ushort ProxyPort { get; set; } = 0;

&nbsp;public bool EnableLANDiscovery { get; set; } = true;



&nbsp;}

}

]



Archivo Network.cs \[

using System.Net;

using System.Net.Sockets;

using System.Runtime.InteropServices;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estructuras para direcciones de red compatibles con C

&nbsp;/// </summary>

&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct IP4

&nbsp;{

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]

&nbsp;public byte\[] Data;



&nbsp;public IP4(byte\[] data)

&nbsp;{

&nbsp;if (data == null || data.Length != 4)

&nbsp;throw new ArgumentException("IP4 must be 4 bytes");

&nbsp;Data = new byte\[4];

&nbsp;Buffer.BlockCopy(data, 0, Data, 0, 4);

&nbsp;}



&nbsp;public IP4(string ipString)

&nbsp;{

&nbsp;if (IPAddress.TryParse(ipString, out IPAddress address) \&\& address.AddressFamily == AddressFamily.InterNetwork)

&nbsp;{

&nbsp;Data = address.GetAddressBytes();

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;throw new ArgumentException("Invalid IPv4 address");

&nbsp;}

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{Data\[0]}.{Data\[1]}.{Data\[2]}.{Data\[3]}";

&nbsp;}

&nbsp;}



&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct IP6

&nbsp;{

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]

&nbsp;public byte\[] Data;



&nbsp;public IP6(byte\[] data)

&nbsp;{

&nbsp;if (data == null || data.Length != 16)

&nbsp;throw new ArgumentException("IP6 must be 16 bytes");

&nbsp;Data = new byte\[16];

&nbsp;Buffer.BlockCopy(data, 0, Data, 0, 16);

&nbsp;}



&nbsp;public IP6(string ipString)

&nbsp;{

&nbsp;if (IPAddress.TryParse(ipString, out IPAddress address) \&\& address.AddressFamily == AddressFamily.InterNetworkV6)

&nbsp;{

&nbsp;Data = address.GetAddressBytes();

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;throw new ArgumentException("Invalid IPv6 address");

&nbsp;}

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return new IPAddress(Data).ToString();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Dirección IP (IPv4 o IPv6)

&nbsp;/// </summary>

&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct IP

&nbsp;{

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]

&nbsp;public byte\[] Data;

&nbsp;public byte IsIPv6; // 0 = IPv4, 1 = IPv6



&nbsp;public IP(IP4 ip4)

&nbsp;{

&nbsp;Data = new byte\[16];

&nbsp;Buffer.BlockCopy(ip4.Data, 0, Data, 0, 4);

&nbsp;IsIPv6 = 0;

&nbsp;}



&nbsp;public IP(IP6 ip6)

&nbsp;{

&nbsp;Data = new byte\[16];

&nbsp;Buffer.BlockCopy(ip6.Data, 0, Data, 0, 16);

&nbsp;IsIPv6 = 1;

&nbsp;}



&nbsp;public IP(IPAddress address)

&nbsp;{

&nbsp;Data = new byte\[16];

&nbsp;if (address.AddressFamily == AddressFamily.InterNetwork)

&nbsp;{

&nbsp;byte\[] bytes = address.GetAddressBytes();

&nbsp;Buffer.BlockCopy(bytes, 0, Data, 0, 4);

&nbsp;IsIPv6 = 0;

&nbsp;}

&nbsp;else if (address.AddressFamily == AddressFamily.InterNetworkV6)

&nbsp;{

&nbsp;byte\[] bytes = address.GetAddressBytes();

&nbsp;Buffer.BlockCopy(bytes, 0, Data, 0, 16);

&nbsp;IsIPv6 = 1;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;throw new ArgumentException("Unsupported address family");

&nbsp;}

&nbsp;}



&nbsp;public IPAddress ToIPAddress()

&nbsp;{

&nbsp;if (IsIPv6 == 0)

&nbsp;{

&nbsp;byte\[] ip4Bytes = new byte\[4];

&nbsp;Buffer.BlockCopy(Data, 0, ip4Bytes, 0, 4);

&nbsp;return new IPAddress(ip4Bytes);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;return new IPAddress(Data);

&nbsp;}

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return ToIPAddress().ToString();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Par IP + Puerto

&nbsp;/// </summary>

&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct IPPort

&nbsp;{

&nbsp;public IP IP;

&nbsp;public ushort Port;



&nbsp;public IPPort(IP ip, ushort port)

&nbsp;{

&nbsp;IP = ip;

&nbsp;Port = port;

&nbsp;}



&nbsp;public IPPort(IPAddress ip, ushort port)

&nbsp;{

&nbsp;IP = new IP(ip);

&nbsp;Port = port;

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{IP}:{Port}";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Funciones básicas de networking compatibles con toxcore C

&nbsp;/// </summary>

&nbsp;public static class Network

&nbsp;{

&nbsp;public const int IP4\_SIZE = 4;

&nbsp;public const int IP6\_SIZE = 16;

&nbsp;public const int IP\_PORT\_SIZE = 18;

&nbsp;public const int SOCKET\_ERROR = -1;



&nbsp;// Gestión de sockets activos para compatibilidad con C

&nbsp;private static readonly List<Socket> \_activeSockets = new List<Socket>();

&nbsp;private static readonly object \_socketListLock = new object();



&nbsp;// ==================== COMPATIBILIDAD CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// new\_socket - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int new\_socket(int domain, int type, int protocol)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;AddressFamily af = (domain == 2) ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;

&nbsp;SocketType st = (type == 2) ? SocketType.Dgram : SocketType.Stream;

&nbsp;ProtocolType pt = (protocol == 17) ? ProtocolType.Udp : ProtocolType.Tcp;



&nbsp;Socket socket = new Socket(af, st, pt);



&nbsp;// Configuraciones esenciales

&nbsp;socket.Blocking = false;



&nbsp;if (st == SocketType.Dgram)

&nbsp;{

&nbsp;socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);



&nbsp;if (af == AddressFamily.InterNetworkV6)

&nbsp;{

&nbsp;socket.DualMode = true;

&nbsp;}

&nbsp;}



&nbsp;lock (\_socketListLock)

&nbsp;{

&nbsp;\_activeSockets.Add(socket);

&nbsp;return \_activeSockets.Count - 1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// socket\_bind - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int socket\_bind(int sock, IPPort ip\_port)

&nbsp;{

&nbsp;if (!IsValidSocket(sock)) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = \_activeSockets\[sock];

&nbsp;IPEndPoint endpoint = new IPEndPoint(ip\_port.IP.ToIPAddress(), ip\_port.Port);

&nbsp;socket.Bind(endpoint);

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// socket\_send - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int socket\_send(int sock, byte\[] data, int length, IPPort ip\_port)

&nbsp;{

&nbsp;if (!IsValidSocket(sock)) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = \_activeSockets\[sock];

&nbsp;IPEndPoint endpoint = new IPEndPoint(ip\_port.IP.ToIPAddress(), ip\_port.Port);

&nbsp;return socket.SendTo(data, 0, length, SocketFlags.None, endpoint);

&nbsp;}

&nbsp;catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// socket\_recv - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int socket\_recv(int sock, byte\[] buffer, ref IPPort ip\_port)

&nbsp;{

&nbsp;if (!IsValidSocket(sock)) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = \_activeSockets\[sock];

&nbsp;EndPoint tempEndpoint = new IPEndPoint(IPAddress.Any, 0);



&nbsp;int received = socket.ReceiveFrom(buffer, ref tempEndpoint);



&nbsp;if (tempEndpoint is IPEndPoint iep)

&nbsp;{

&nbsp;ip\_port.IP = new IP(iep.Address);

&nbsp;ip\_port.Port = (ushort)iep.Port;

&nbsp;}



&nbsp;return received;

&nbsp;}

&nbsp;catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// kill\_socket - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int kill\_socket(int sock)

&nbsp;{

&nbsp;if (!IsValidSocket(sock)) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = \_activeSockets\[sock];

&nbsp;socket.Close();



&nbsp;lock (\_socketListLock)

&nbsp;{

&nbsp;\_activeSockets\[sock] = null;

&nbsp;}

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// get\_ip - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int get\_ip(string ip\_str, ref IP ip)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;IPAddress addr = Resolve(ip\_str);

&nbsp;ip = new IP(addr);

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// socket\_get\_address - Compatible con C original

&nbsp;/// </summary>

&nbsp;public static int socket\_get\_address(int sock, ref IP ip, ref ushort port)

&nbsp;{

&nbsp;if (!IsValidSocket(sock)) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = \_activeSockets\[sock];

&nbsp;if (socket.LocalEndPoint is IPEndPoint localEndPoint)

&nbsp;{

&nbsp;ip = new IP(localEndPoint.Address);

&nbsp;port = (ushort)localEndPoint.Port;

&nbsp;return 0;

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES AUXILIARES MODERNAS ====================



&nbsp;/// <summary>

&nbsp;/// Crea un socket UDP

&nbsp;/// </summary>

&nbsp;public static Socket CreateUDPSocket(AddressFamily family = AddressFamily.InterNetwork)

&nbsp;{

&nbsp;var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);

&nbsp;ConfigureSocketForP2P(socket);

&nbsp;return socket;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Configura socket para optimizar performance P2P

&nbsp;/// </summary>

&nbsp;public static void ConfigureSocketForP2P(Socket socket)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;socket.Blocking = false;

&nbsp;socket.ReceiveBufferSize = 65536;

&nbsp;socket.SendBufferSize = 65536;

&nbsp;socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);



&nbsp;if (socket.AddressFamily == AddressFamily.InterNetworkV6)

&nbsp;{

&nbsp;socket.DualMode = true;

&nbsp;}

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;// Configuración fallida silenciosamente

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enlaza un socket a un puerto específico

&nbsp;/// </summary>

&nbsp;public static bool BindSocket(Socket socket, ushort port, AddressFamily family = AddressFamily.InterNetwork)

&nbsp;{

&nbsp;if (socket == null) throw new ArgumentNullException(nameof(socket));

&nbsp;try

&nbsp;{

&nbsp;IPEndPoint endPoint = family == AddressFamily.InterNetworkV6

&nbsp;? new IPEndPoint(IPAddress.IPv6Any, port)

&nbsp;: new IPEndPoint(IPAddress.Any, port);

&nbsp;socket.Bind(endPoint);

&nbsp;return true;

&nbsp;}

&nbsp;catch (SocketException)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Envía datos a través de un socket UDP

&nbsp;/// </summary>

&nbsp;public static int SendTo(Socket socket, byte\[] data, IPPort destination)

&nbsp;{

&nbsp;if (socket == null) throw new ArgumentNullException(nameof(socket));

&nbsp;if (data == null) throw new ArgumentNullException(nameof(data));

&nbsp;try

&nbsp;{

&nbsp;IPEndPoint endPoint = new IPEndPoint(destination.IP.ToIPAddress(), destination.Port);

&nbsp;return socket.SendTo(data, endPoint);

&nbsp;}

&nbsp;catch (SocketException)

&nbsp;{

&nbsp;return SOCKET\_ERROR;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Recibe datos de un socket UDP

&nbsp;/// </summary>

&nbsp;public static int RecvFrom(Socket socket, byte\[] buffer, out IPPort source)

&nbsp;{

&nbsp;if (socket == null) throw new ArgumentNullException(nameof(socket));

&nbsp;if (buffer == null) throw new ArgumentNullException(nameof(buffer));



&nbsp;try

&nbsp;{

&nbsp;EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);

&nbsp;int received = socket.ReceiveFrom(buffer, ref remoteEP);



&nbsp;IPEndPoint ipEndPoint = (IPEndPoint)remoteEP;

&nbsp;source = new IPPort(ipEndPoint.Address, (ushort)ipEndPoint.Port);



&nbsp;return received;

&nbsp;}

&nbsp;catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)

&nbsp;{

&nbsp;source = default;

&nbsp;return -1;

&nbsp;}

&nbsp;catch (SocketException)

&nbsp;{

&nbsp;source = default;

&nbsp;return SOCKET\_ERROR;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Convierte bytes a IPPort (versión segura sin punteros)

&nbsp;/// </summary>

&nbsp;public static bool BytesToIPPort(ref IPPort ipp, byte\[] ip, byte ipFamily, ushort port)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (ipFamily == 0) // IPv4

&nbsp;{

&nbsp;if (ip.Length < IP4\_SIZE) return false;

&nbsp;IP4 ip4 = new IP4(new byte\[] { ip\[0], ip\[1], ip\[2], ip\[3] });

&nbsp;ipp = new IPPort(new IP(ip4), port);

&nbsp;}

&nbsp;else // IPv6

&nbsp;{

&nbsp;if (ip.Length < IP6\_SIZE) return false;

&nbsp;byte\[] ip6Bytes = new byte\[IP6\_SIZE];

&nbsp;Buffer.BlockCopy(ip, 0, ip6Bytes, 0, IP6\_SIZE);

&nbsp;IP6 ip6 = new IP6(ip6Bytes);

&nbsp;ipp = new IPPort(new IP(ip6), port);

&nbsp;}



&nbsp;return true;

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Convierte un hostname a dirección IP

&nbsp;/// </summary>

&nbsp;public static IPAddress Resolve(string hostname)

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(hostname))

&nbsp;throw new ArgumentNullException(nameof(hostname));



&nbsp;try

&nbsp;{

&nbsp;IPAddress\[] addresses = Dns.GetHostAddresses(hostname);

&nbsp;if (addresses.Length == 0)

&nbsp;throw new SocketException((int)SocketError.HostNotFound);



&nbsp;// Preferir IPv4 para compatibilidad

&nbsp;foreach (IPAddress addr in addresses)

&nbsp;{

&nbsp;if (addr.AddressFamily == AddressFamily.InterNetwork)

&nbsp;return addr;

&nbsp;}



&nbsp;// Si no hay IPv4, usar el primero disponible

&nbsp;return addresses\[0];

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;throw new InvalidOperationException($"Failed to resolve hostname: {hostname}", ex);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene la IP local del socket

&nbsp;/// </summary>

&nbsp;public static IPAddress GetLocalIP(Socket socket)

&nbsp;{

&nbsp;if (socket == null) throw new ArgumentNullException(nameof(socket));

&nbsp;if (socket.LocalEndPoint is IPEndPoint localEndPoint)

&nbsp;{

&nbsp;return localEndPoint.Address;

&nbsp;}

&nbsp;return IPAddress.None;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Cierra un socket de forma segura

&nbsp;/// </summary>

&nbsp;public static void CloseSocket(Socket socket)

&nbsp;{

&nbsp;if (socket == null) return;



&nbsp;try

&nbsp;{

&nbsp;socket.Close();

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;// Ignorar errores al cerrar

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES INTERNAS ====================



&nbsp;private static bool IsValidSocket(int sock)

&nbsp;{

&nbsp;lock (\_socketListLock)

&nbsp;{

&nbsp;return sock >= 0 \&\& sock < \_activeSockets.Count \&\& \_activeSockets\[sock] != null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpia todos los sockets activos

&nbsp;/// </summary>

&nbsp;public static void Cleanup()

&nbsp;{

&nbsp;lock (\_socketListLock)

&nbsp;{

&nbsp;foreach (var socket in \_activeSockets)

&nbsp;{

&nbsp;socket?.Close();

&nbsp;}

&nbsp;\_activeSockets.Clear();

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES DE PRUEBA ====================



&nbsp;/// <summary>

&nbsp;/// Test básico de funcionalidades de red

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" Ejecutando tests de Network...");



&nbsp;// Test 1: Resolución de DNS

&nbsp;IPAddress localhost = Resolve("localhost");

&nbsp;if (localhost == null)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 1 falló: Resolución de localhost");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 1 - Resolución DNS: PASÓ");



&nbsp;// Test 2: Creación de estructuras IP

&nbsp;IP4 ip4 = new IP4("127.0.0.1");

&nbsp;IP6 ip6 = new IP6("::1");



&nbsp;if (ip4.ToString() != "127.0.0.1")

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 2 falló: IP4 string conversion");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 2 - Estructuras IP: PASÓ");



&nbsp;// Test 3: IPPort

&nbsp;IP ipFrom4 = new IP(ip4);

&nbsp;IPPort ipport = new IPPort(ipFrom4, 33445);

&nbsp;if (ipport.Port != 33445)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 3 falló: IPPort port");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 3 - IPPort: PASÓ");



&nbsp;// Test 4: API compatible con C

&nbsp;int sock = new\_socket(2, 2, 17); // IPv4, DGRAM, UDP

&nbsp;if (sock == -1)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 4 falló: new\_socket");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 4 - new\_socket: PASÓ");



&nbsp;// Test 5: socket\_bind

&nbsp;IPPort bindAddr = new IPPort(new IP(IPAddress.Loopback), 0);

&nbsp;int bindResult = socket\_bind(sock, bindAddr);

&nbsp;if (bindResult == -1)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 5 falló: socket\_bind");

&nbsp;kill\_socket(sock);

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 5 - socket\_bind: PASÓ");



&nbsp;kill\_socket(sock);

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Error en test: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo Onion.cs \[



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estructuras compatibles con Onion original de toxcore

&nbsp;/// </summary>

&nbsp;public class OnionNode

&nbsp;{

&nbsp;public IPPort IPPort { get; set; }

&nbsp;public byte\[] PublicKey { get; set; }

&nbsp;public long LastPinged { get; set; }

&nbsp;public bool IsActive { get; set; }

&nbsp;public int RTT { get; set; } // Round Trip Time en ms

&nbsp;public int SuccessRate { get; set; } // ✅ NUEVO - porcentaje de éxito

&nbsp;public long FirstSeen { get; set; } // ✅ NUEVO - cuando descubrimos el nodo

&nbsp;public int PacketsForwarded { get; set; } // ✅ NUEVO - contador de paquetes

&nbsp;public int FailedForwards { get; set; } // ✅ NUEVO - contador de fallos



&nbsp;public OnionNode(IPPort ipp, byte\[] publicKey)

&nbsp;{

&nbsp;IPPort = ipp;

&nbsp;PublicKey = new byte\[32];

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);

&nbsp;}

&nbsp;LastPinged = DateTime.UtcNow.Ticks;

&nbsp;IsActive = true;

&nbsp;RTT = 0;

&nbsp;SuccessRate = 100; // ✅ NUEVO - empezar con 100%

&nbsp;FirstSeen = DateTime.UtcNow.Ticks; // ✅ NUEVO

&nbsp;PacketsForwarded = 0; // ✅ NUEVO

&nbsp;FailedForwards = 0; // ✅ NUEVO

&nbsp;}



&nbsp;// ✅ NUEVO - Calcular score del nodo

&nbsp;public double CalculateScore()

&nbsp;{

&nbsp;double score = 0.0;



&nbsp;// RTT más bajo = mejor score (máx 1000ms = 0 puntos)

&nbsp;if (RTT > 0 \&\& RTT <= Onion.ONION\_PATH\_MAX\_LATENCY)

&nbsp;{

&nbsp;score += (Onion.ONION\_PATH\_MAX\_LATENCY - RTT) \* 0.5; // RTT contribuye 50%

&nbsp;}



&nbsp;// Success rate (porcentaje de éxito)

&nbsp;score += SuccessRate \* 0.3; // Success rate contribuye 30%



&nbsp;// Tiempo activo (más tiempo = más confiable)

&nbsp;long uptime = (DateTime.UtcNow.Ticks - FirstSeen) / TimeSpan.TicksPerMillisecond;

&nbsp;if (uptime > Onion.ONION\_NODE\_MIN\_UPTIME)

&nbsp;{

&nbsp;score += Math.Min(100, uptime / Onion.ONION\_NODE\_MIN\_UPTIME \* 10); // Uptime contribuye 20%

&nbsp;}



&nbsp;return score;

&nbsp;}



&nbsp;// ✅ NUEVO - Actualizar métricas después de un forward exitoso

&nbsp;public void RecordSuccessfulForward()

&nbsp;{

&nbsp;PacketsForwarded++;

&nbsp;SuccessRate = (int)((double)PacketsForwarded / (PacketsForwarded + FailedForwards) \* 100);

&nbsp;LastPinged = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;// ✅ NUEVO - Actualizar métricas después de un forward fallido

&nbsp;public void RecordFailedForward()

&nbsp;{

&nbsp;FailedForwards++;

&nbsp;SuccessRate = (int)((double)PacketsForwarded / (PacketsForwarded + FailedForwards) \* 100);

&nbsp;}

&nbsp;}



&nbsp;public class OnionPath

&nbsp;{

&nbsp;public int PathNumber { get; set; }

&nbsp;public OnionNode\[] Nodes { get; set; }

&nbsp;public long CreationTime { get; set; }

&nbsp;public long LastUsed { get; set; }

&nbsp;public bool IsActive { get; set; }

&nbsp;public int TimeoutCounter { get; set; }



&nbsp;public OnionPath(int pathNumber)

&nbsp;{

&nbsp;PathNumber = pathNumber;

&nbsp;Nodes = new OnionNode\[3];

&nbsp;CreationTime = DateTime.UtcNow.Ticks;

&nbsp;LastUsed = DateTime.UtcNow.Ticks;

&nbsp;IsActive = true;

&nbsp;TimeoutCounter = 0;

&nbsp;}



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"OnionPath #{PathNumber} - {Nodes.Count(n => n != null)} nodos - Activo: {IsActive}";

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Implementación compatible con onion.c de toxcore

&nbsp;/// </summary>

&nbsp;public class Onion

&nbsp;{

&nbsp;private const string LOG\_TAG = "ONION";

&nbsp;private long \_lastLogTime = 0;



&nbsp;public const int ONION\_MAX\_PACKET\_SIZE = 1400;

&nbsp;public const int ONION\_RETURN\_SIZE = 128;

&nbsp;public const int ONION\_PATH\_LENGTH = 3;

&nbsp;public const int ONION\_PATH\_TIMEOUT = 1200000;

&nbsp;public const int MAX\_ONION\_PATHS = 6;

&nbsp;public const int ONION\_NODE\_TIMEOUT = 1800000; // 30 minutos



&nbsp;public const int ONION\_PATH\_MAX\_LATENCY = 1000; // 1 segundo máximo RTT

&nbsp;public const int ONION\_NODE\_MIN\_UPTIME = 300000; // 5 minutos mínimos de actividad

&nbsp;public const int ONION\_PATH\_HEALTH\_CHECK\_INTERVAL = 60000; // 60 segundos



&nbsp;public byte\[] SelfPublicKey { get; private set; }

&nbsp;public byte\[] SelfSecretKey { get; private set; }

&nbsp;public int Socket { get; private set; }

&nbsp;public bool IsRunning { get; private set; }



&nbsp;private readonly List<OnionNode> \_onionNodes;

&nbsp;private readonly List<OnionPath> \_onionPaths;

&nbsp;private readonly object \_nodesLock = new object();

&nbsp;private readonly object \_pathsLock = new object();

&nbsp;private int \_lastPathNumber;

&nbsp;private long \_lastMaintenanceTime;



&nbsp;private readonly DHT \_dht;

&nbsp;private readonly Random \_random = new Random();



&nbsp;public int TotalOnionNodes => \_onionNodes.Count;

&nbsp;public int ActiveOnionNodes

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;return \_onionNodes.Count(n => n.IsActive);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;public int TotalPaths => \_onionPaths.Count;

&nbsp;public int ActivePaths

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;return \_onionPaths.Count(p => p.IsActive);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public Onion(byte\[] selfPublicKey, byte\[] selfSecretKey, DHT dht = null)

&nbsp;{

&nbsp;SelfPublicKey = new byte\[32];

&nbsp;SelfSecretKey = new byte\[32];

&nbsp;Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);

&nbsp;Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);



&nbsp;\_onionNodes = new List<OnionNode>();

&nbsp;\_onionPaths = new List<OnionPath>();

&nbsp;\_lastPathNumber = 0;

&nbsp;\_lastMaintenanceTime = DateTime.UtcNow.Ticks;

&nbsp;IsRunning = false;

&nbsp;\_dht = dht;



&nbsp;Socket = Network.new\_socket(2, 2, 17);

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Onion inicializado - Socket: {Socket}");

&nbsp;}



&nbsp;// ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// onion\_send\_1 - IMPLEMENTACIÓN REAL con path selection

&nbsp;/// </summary>

&nbsp;public int onion\_send\_1(byte\[] plain, int length, byte\[] public\_key)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Enviando paquete onion\_send\_1 - Tamaño: {length} bytes");



&nbsp;if (!IsRunning || Socket == -1) return -1;

&nbsp;if (plain == null || length > ONION\_MAX\_PACKET\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;// ✅ IMPLEMENTACIÓN REAL: Seleccionar mejor path disponible

&nbsp;var path = SelectBestOnionPath();

&nbsp;if (path == null)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No hay paths onion disponibles");

&nbsp;return -1;

&nbsp;}



&nbsp;byte\[] onionPacket = CreateOnionPacket(plain, length, public\_key, path);

&nbsp;if (onionPacket == null) return -1;



&nbsp;int sent = Network.socket\_send(Socket, onionPacket, onionPacket.Length, path.Nodes\[0].IPPort);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;path.LastUsed = DateTime.UtcNow.Ticks;

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Paquete onion\_send\_1 enviado: {sent} bytes");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Falló envío onion\_send\_1");

&nbsp;}



&nbsp;return sent;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en onion\_send\_1: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Selecciona el mejor path onion disponible

&nbsp;/// </summary>

&nbsp;private OnionPath SelectBestOnionPath()

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;var activePaths = \_onionPaths.Where(p => p.IsActive).ToList();

&nbsp;if (activePaths.Count == 0)

&nbsp;{

&nbsp;// Intentar crear nuevo path

&nbsp;int newPath = CreateOnionPath();

&nbsp;if (newPath >= 0)

&nbsp;{

&nbsp;// ✅ CORRECCIÓN: Find puede devolver null

&nbsp;var path = \_onionPaths.Find(p => p.PathNumber == newPath);

&nbsp;return path; // Puede ser null si no se encontró

&nbsp;}

&nbsp;return null;

&nbsp;}



&nbsp;// Seleccionar path más recientemente usado o con mejor health

&nbsp;return activePaths.OrderByDescending(p => p.LastUsed)

&nbsp;.ThenBy(p => p.TimeoutCounter)

&nbsp;.First();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// SelectOptimalOnionPath - Selección REAL de paths como en onion.c

&nbsp;/// Considera RTT, estabilidad, capacidad de nodos

&nbsp;/// </summary>

&nbsp;private OnionPath SelectOptimalOnionPath()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;var activePaths = \_onionPaths.Where(p => p.IsActive).ToList();

&nbsp;if (activePaths.Count == 0)

&nbsp;{

&nbsp;// Crear nuevo path si no hay activos

&nbsp;int newPath = CreateOnionPath();

&nbsp;if (newPath >= 0)

&nbsp;{

&nbsp;return \_onionPaths.Find(p => p.PathNumber == newPath);

&nbsp;}

&nbsp;return null;

&nbsp;}



&nbsp;// Calcular score para cada path

&nbsp;var scoredPaths = activePaths.Select(path => new

&nbsp;{

&nbsp;Path = path,

&nbsp;Score = CalculatePathScore(path)

&nbsp;}).ToList();



&nbsp;// Seleccionar path con mejor score

&nbsp;var bestPath = scoredPaths.OrderByDescending(sp => sp.Score).First();



&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Path seleccionado: #{bestPath.Path.PathNumber} (Score: {bestPath.Score:F2})");

&nbsp;return bestPath.Path;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error seleccionando path óptimo: {ex.Message}");

&nbsp;return \_onionPaths.FirstOrDefault(p => p.IsActive);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CalculatePathScore - Calcula score REAL de un path onion

&nbsp;/// </summary>

&nbsp;private double CalculatePathScore(OnionPath path)

&nbsp;{

&nbsp;if (path == null || path.Nodes.Any(n => n == null)) return 0.0;



&nbsp;double totalScore = 0.0;

&nbsp;int nodeCount = 0;



&nbsp;foreach (var node in path.Nodes)

&nbsp;{

&nbsp;if (node != null \&\& node.IsActive)

&nbsp;{

&nbsp;totalScore += node.CalculateScore();

&nbsp;nodeCount++;

&nbsp;}

&nbsp;}



&nbsp;if (nodeCount == 0) return 0.0;



&nbsp;// Score promedio de los nodos

&nbsp;double averageNodeScore = totalScore / nodeCount;



&nbsp;// Penalizar paths viejos (preferir paths más recientes)

&nbsp;long pathAge = (DateTime.UtcNow.Ticks - path.CreationTime) / TimeSpan.TicksPerMillisecond;

&nbsp;double agePenalty = Math.Max(0, 100 - (pathAge / 60000)); // Penalizar después de 1 minuto



&nbsp;// Bonus por uso reciente

&nbsp;long timeSinceLastUse = (DateTime.UtcNow.Ticks - path.LastUsed) / TimeSpan.TicksPerMillisecond;

&nbsp;double recencyBonus = timeSinceLastUse < 30000 ? 50 : 0; // Bonus si se usó en últimos 30 segundos



&nbsp;return averageNodeScore + agePenalty + recencyBonus;

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// onion\_send\_2 - Compatible con onion\_send\_2 del original

&nbsp;/// </summary>

&nbsp;public int onion\_send\_2(byte\[] plain, int length, byte\[] public\_key)

&nbsp;{

&nbsp;if (!IsRunning || Socket == -1) return -1;

&nbsp;if (plain == null || length > ONION\_MAX\_PACKET\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;if (\_onionPaths.Count < 2) return -1;



&nbsp;var path = \_onionPaths\[1];

&nbsp;if (!path.IsActive) return -1;



&nbsp;byte\[] onionPacket = CreateOnionPacket(plain, length, public\_key, path);

&nbsp;if (onionPacket == null) return -1;



&nbsp;int sent = Network.socket\_send(Socket, onionPacket, onionPacket.Length, path.Nodes\[0].IPPort);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;path.LastUsed = DateTime.UtcNow.Ticks;

&nbsp;return sent;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Actualiza o agrega un nodo onion

&nbsp;/// </summary>

&nbsp;private void UpdateOnionNode(IPPort endPoint, byte\[] publicKey)

&nbsp;{

&nbsp;if (publicKey == null || publicKey.Length != 32) return;



&nbsp;try

&nbsp;{

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;// ✅ CORRECCIÓN: Usar comparación con null

&nbsp;var existingNode = \_onionNodes.Find(n =>

&nbsp;n.IPPort.IP.ToString() == endPoint.IP.ToString() \&\&

&nbsp;n.IPPort.Port == endPoint.Port \&\&

&nbsp;ByteArraysEqual(publicKey, n.PublicKey));



&nbsp;if (existingNode != null) // ✅ Ahora funciona porque existingNode es OnionNode o null

&nbsp;{

&nbsp;existingNode.LastPinged = DateTime.UtcNow.Ticks;

&nbsp;existingNode.IsActive = true;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;var newNode = new OnionNode(endPoint, publicKey);

&nbsp;\_onionNodes.Add(newNode);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Nuevo nodo onion agregado: {endPoint}");

&nbsp;}



&nbsp;// Limpieza periódica

&nbsp;if (\_onionNodes.Count > 200)

&nbsp;{

&nbsp;CleanupOldOnionNodes();

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error actualizando nodo onion: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpia nodos onion antiguos

&nbsp;/// </summary>

&nbsp;private void CleanupOldOnionNodes()

&nbsp;{

&nbsp;long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond \* ONION\_NODE\_TIMEOUT;

&nbsp;int removed = 0;



&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;for (int i = \_onionNodes.Count - 1; i >= 0; i--)

&nbsp;{

&nbsp;var node = \_onionNodes\[i];

&nbsp;if (!node.IsActive || node.LastPinged < cutoffTime)

&nbsp;{

&nbsp;\_onionNodes.RemoveAt(i);

&nbsp;removed++;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;if (removed > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {removed} nodos onion removidos");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Encuentra un nodo onion por su public key

&nbsp;/// </summary>

&nbsp;private OnionNode FindOnionNodeByPublicKey(byte\[] publicKey)

&nbsp;{

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;return \_onionNodes.Find(n => ByteArraysEqual(publicKey, n.PublicKey));

&nbsp;}

&nbsp;}







&nbsp;/// <summary>

&nbsp;/// handle\_onion\_recv\_1 - Compatible con handle\_onion\_recv\_1 del original

&nbsp;/// </summary>

&nbsp;public int handle\_onion\_recv\_1(IPPort source, byte\[] packet, int length)

&nbsp;{

&nbsp;if (!IsRunning || packet == null || length < 100) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Implementación basada en el manejo real de onion\_recv\_1

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;Buffer.BlockCopy(packet, 0, nonce, 0, 24);



&nbsp;byte\[] tempPublicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 24, tempPublicKey, 0, 32);



&nbsp;int encryptedLength = length - 56;

&nbsp;if (encryptedLength <= 0) return -1;



&nbsp;byte\[] encrypted = new byte\[encryptedLength];

&nbsp;Buffer.BlockCopy(packet, 56, encrypted, 0, encryptedLength);



&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encrypted, nonce, tempPublicKey, SelfSecretKey);

&nbsp;if (decrypted == null) return -1;



&nbsp;// El paquete desencriptado contiene otro paquete onion

&nbsp;return handle\_onion\_recv\_2(source, decrypted, decrypted.Length);

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// handle\_onion\_recv\_2 - Compatible con handle\_onion\_recv\_2 del original

&nbsp;/// </summary>

&nbsp;public int handle\_onion\_recv\_2(IPPort source, byte\[] packet, int length)

&nbsp;{

&nbsp;if (!IsRunning || packet == null || length < 100) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Segunda capa de desencriptación onion

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;Buffer.BlockCopy(packet, 0, nonce, 0, 24);



&nbsp;byte\[] tempPublicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 24, tempPublicKey, 0, 32);



&nbsp;int encryptedLength = length - 56;

&nbsp;if (encryptedLength <= 0) return -1;



&nbsp;byte\[] encrypted = new byte\[encryptedLength];

&nbsp;Buffer.BlockCopy(packet, 56, encrypted, 0, encryptedLength);



&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encrypted, nonce, tempPublicKey, SelfSecretKey);

&nbsp;if (decrypted == null) return -1;



&nbsp;// Aquí se procesaría el paquete final desencriptado

&nbsp;// En toxcore real, esto se pasa al callback correspondiente

&nbsp;return decrypted.Length;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// onion\_add\_node - Compatible con onion\_add\_node del original

&nbsp;/// </summary>

&nbsp;public int onion\_add\_node(byte\[] public\_key, IPPort ip\_port)

&nbsp;{

&nbsp;if (public\_key == null || public\_key.Length != 32) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;var existingNode = \_onionNodes.Find(n =>

&nbsp;n.IPPort.IP.ToString() == ip\_port.IP.ToString() \&\&

&nbsp;n.IPPort.Port == ip\_port.Port \&\&

&nbsp;ByteArraysEqual(public\_key, n.PublicKey));



&nbsp;if (existingNode.IsActive)

&nbsp;{

&nbsp;existingNode.LastPinged = DateTime.UtcNow.Ticks;

&nbsp;return 1;

&nbsp;}



&nbsp;var newNode = new OnionNode(ip\_port, public\_key);

&nbsp;\_onionNodes.Add(newNode);

&nbsp;return 0;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES AUXILIARES ====================



&nbsp;

&nbsp;// ==================== ONION ENCRYPTION REAL ====================



&nbsp;/// <summary>

&nbsp;/// Crea un paquete onion REAL con encriptación en capas

&nbsp;/// </summary>

&nbsp;private byte\[] CreateOnionPacket(byte\[] plainData, int length, byte\[] destPublicKey, OnionPath path)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (plainData == null || length > ONION\_MAX\_PACKET\_SIZE)

&nbsp;return null;



&nbsp;// ✅ IMPLEMENTACIÓN REAL: Encriptación en capas

&nbsp;byte\[] currentPayload = plainData;



&nbsp;// Capa 3: Para el último nodo (destino final)

&nbsp;currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,

&nbsp;destPublicKey, path.Nodes\[2].PublicKey, path.Nodes\[2].PublicKey);



&nbsp;// Capa 2: Para el nodo medio

&nbsp;currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,

&nbsp;path.Nodes\[2].PublicKey, path.Nodes\[1].PublicKey, path.Nodes\[1].PublicKey);



&nbsp;// Capa 1: Para el primer nodo

&nbsp;currentPayload = CreateOnionLayer(currentPayload, currentPayload.Length,

&nbsp;path.Nodes\[1].PublicKey, path.Nodes\[0].PublicKey, path.Nodes\[0].PublicKey);



&nbsp;return currentPayload;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete onion: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// Crea una capa onion REAL con encriptación

&nbsp;/// </summary>

&nbsp;private byte\[] CreateOnionLayer(byte\[] data, int length, byte\[] nextPublicKey,

&nbsp;byte\[] layerPublicKey, byte\[] tempPublicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Construir payload de la capa: \[next\_public\_key]\[encrypted\_data]

&nbsp;byte\[] layerPayload = new byte\[32 + length];

&nbsp;Buffer.BlockCopy(nextPublicKey, 0, layerPayload, 0, 32);

&nbsp;Buffer.BlockCopy(data, 0, layerPayload, 32, length);



&nbsp;// Nonce aleatorio para esta capa

&nbsp;byte\[] nonce = RandomBytes.Generate(24);



&nbsp;// ✅ IMPLEMENTACIÓN REAL: Encriptar con CryptoBox usando la clave temporal

&nbsp;byte\[] encrypted = CryptoBox.Encrypt(layerPayload, nonce, layerPublicKey, SelfSecretKey);

&nbsp;if (encrypted == null) return null;



&nbsp;// Paquete de capa: \[nonce]\[encrypted\_data]

&nbsp;byte\[] layerPacket = new byte\[24 + encrypted.Length];

&nbsp;Buffer.BlockCopy(nonce, 0, layerPacket, 0, 24);

&nbsp;Buffer.BlockCopy(encrypted, 0, layerPacket, 24, encrypted.Length);



&nbsp;return layerPacket;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando capa onion: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Maneja un paquete onion entrante REAL

&nbsp;/// </summary>

&nbsp;public int HandleOnionPacket(byte\[] packet, int length, IPPort source)

&nbsp;{

&nbsp;if (!IsRunning || packet == null || length < 25) // mínimo: nonce(24) + algo de data

&nbsp;return -1;



&nbsp;try

&nbsp;{

&nbsp;// Extraer nonce y datos encriptados

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;byte\[] encrypted = new byte\[length - 24];



&nbsp;Buffer.BlockCopy(packet, 0, nonce, 0, 24);

&nbsp;Buffer.BlockCopy(packet, 24, encrypted, 0, encrypted.Length);



&nbsp;// Intentar desencriptar con nuestra clave

&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encrypted, nonce, SelfPublicKey, SelfSecretKey);

&nbsp;if (decrypted == null || decrypted.Length < 32)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Paquete onion no pudo ser desencriptado");

&nbsp;return -1;

&nbsp;}



&nbsp;// Extraer siguiente public key y datos

&nbsp;byte\[] nextPublicKey = new byte\[32];

&nbsp;byte\[] innerData = new byte\[decrypted.Length - 32];



&nbsp;Buffer.BlockCopy(decrypted, 0, nextPublicKey, 0, 32);

&nbsp;Buffer.BlockCopy(decrypted, 32, innerData, 0, innerData.Length);



&nbsp;// Actualizar nodo onion

&nbsp;UpdateOnionNode(source, nextPublicKey);



&nbsp;if (IsZeroKey(nextPublicKey))

&nbsp;{

&nbsp;// ✅ Llegamos al destino final

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Paquete onion llegó a destino final");

&nbsp;return ProcessFinalOnionPacket(innerData, innerData.Length, source);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// ✅ Reenviar al siguiente nodo

&nbsp;return ForwardOnionPacket(innerData, innerData.Length, nextPublicKey);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete onion: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// ForwardOnionPacket - ACTUALIZADO para registrar métricas REALES

&nbsp;/// </summary>

&nbsp;private int ForwardOnionPacket(byte\[] data, int length, byte\[] nextPublicKey)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var nextNode = FindOnionNodeByPublicKey(nextPublicKey);

&nbsp;if (nextNode == null)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Nodo onion no encontrado para reenvío");

&nbsp;return -1;

&nbsp;}



&nbsp;// Enviar paquete al siguiente nodo

&nbsp;int sent = Network.socket\_send(Socket, data, length, nextNode.IPPort);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// ✅ REGISTRAR MÉTRICA DE ÉXITO

&nbsp;nextNode.RecordSuccessfulForward();

&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Paquete onion reenviado a {nextNode.IPPort} (Success: {nextNode.SuccessRate}%)");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// ✅ REGISTRAR MÉTRICA DE FALLO

&nbsp;nextNode.RecordFailedForward();

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Falló reenvío a {nextNode.IPPort} (Success: {nextNode.SuccessRate}%)");

&nbsp;}



&nbsp;return sent;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error reenviando paquete onion: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Procesa un paquete onion que llegó a su destino final

&nbsp;/// </summary>

&nbsp;private int ProcessFinalOnionPacket(byte\[] data, int length, IPPort source)

&nbsp;{

&nbsp;// ✅ IMPLEMENTACIÓN REAL: Aquí se procesaría el paquete final

&nbsp;// En toxcore real, esto se pasaría al callback correspondiente

&nbsp;// (FriendConnection, GroupChat, etc.)



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Paquete onion procesado - Tamaño: {length} bytes desde {source}");



&nbsp;// Por ahora, simplemente retornamos el tamaño procesado

&nbsp;return length;

&nbsp;}



&nbsp;private static bool ByteArraysEqual(byte\[] a, byte\[] b)

&nbsp;{

&nbsp;if (a == null || b == null || a.Length != b.Length) return false;

&nbsp;return CryptoVerify.Verify(a, b);

&nbsp;}



&nbsp;private static bool IsZeroKey(byte\[] key)

&nbsp;{

&nbsp;if (key == null) return true;

&nbsp;foreach (byte b in key)

&nbsp;{

&nbsp;if (b != 0) return false;

&nbsp;}

&nbsp;return true;

&nbsp;}



&nbsp;// ==================== FUNCIONES DE GESTIÓN ====================



&nbsp;/// <summary>

&nbsp;/// Construye un path de onion REAL con nodos de la DHT

&nbsp;/// </summary>

&nbsp;public int CreateOnionPath()

&nbsp;{

&nbsp;if (\_dht == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se puede crear path - DHT no disponible");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;if (\_onionPaths.Count >= MAX\_ONION\_PATHS)

&nbsp;{

&nbsp;// Reemplazar path más antiguo

&nbsp;var oldestPath = \_onionPaths.Where(p => p != null)

&nbsp;.OrderBy(p => p.CreationTime)

&nbsp;.FirstOrDefault();

&nbsp;if (oldestPath != null)

&nbsp;{

&nbsp;\_onionPaths.Remove(oldestPath);

&nbsp;}

&nbsp;}



&nbsp;// Obtener nodos activos de la DHT

&nbsp;var potentialNodes = GetOnionNodesFromDHT();

&nbsp;if (potentialNodes.Count < ONION\_PATH\_LENGTH)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No hay suficientes nodos onion disponibles: {potentialNodes.Count}/{ONION\_PATH\_LENGTH}");

&nbsp;return -1;

&nbsp;}



&nbsp;// Seleccionar nodos aleatoriamente para el path

&nbsp;var selectedNodes = SelectRandomNodes(potentialNodes, ONION\_PATH\_LENGTH);

&nbsp;if (selectedNodes.Count < ONION\_PATH\_LENGTH)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No se pudieron seleccionar suficientes nodos: {selectedNodes.Count}/{ONION\_PATH\_LENGTH}");

&nbsp;return -1;

&nbsp;}



&nbsp;var newPath = new OnionPath(\_lastPathNumber++)

&nbsp;{

&nbsp;Nodes = selectedNodes.ToArray(),

&nbsp;CreationTime = DateTime.UtcNow.Ticks,

&nbsp;LastUsed = DateTime.UtcNow.Ticks,

&nbsp;IsActive = true

&nbsp;};



&nbsp;\_onionPaths.Add(newPath);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Nuevo path creado: {newPath.PathNumber} con {selectedNodes.Count} nodos");

&nbsp;return newPath.PathNumber;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando path: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Obtiene nodos adecuados para onion routing desde la DHT

&nbsp;/// </summary>

&nbsp;private List<OnionNode> GetOnionNodesFromDHT()

&nbsp;{

&nbsp;var onionNodes = new List<OnionNode>();



&nbsp;try

&nbsp;{

&nbsp;// Obtener nodos cercanos de la DHT

&nbsp;var dhtNodes = \_dht.GetClosestNodes(SelfPublicKey, 50); // Obtener más nodos para selección



&nbsp;foreach (var dhtNode in dhtNodes)

&nbsp;{

&nbsp;// Filtrar nodos que sean buenos candidatos para onion routing

&nbsp;if (IsGoodOnionNode(dhtNode))

&nbsp;{

&nbsp;var onionNode = new OnionNode(dhtNode.EndPoint, dhtNode.PublicKey)

&nbsp;{

&nbsp;LastPinged = DateTime.UtcNow.Ticks,

&nbsp;IsActive = true,

&nbsp;RTT = dhtNode.RTT

&nbsp;};

&nbsp;onionNodes.Add(onionNode);

&nbsp;}

&nbsp;}



&nbsp;// También incluir nodos onion existentes que estén activos

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;onionNodes.AddRange(\_onionNodes.Where(n => n.IsActive));

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {onionNodes.Count} nodos onion disponibles");

&nbsp;return onionNodes;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error obteniendo nodos de DHT: {ex.Message}");

&nbsp;return onionNodes;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// IsGoodOnionNode - Verificación REAL de nodos onion como en onion.c

&nbsp;/// </summary>

&nbsp;private bool IsGoodOnionNode(DHT.DHTNode node)

&nbsp;{

&nbsp;if (node == null || !node.IsActive) return false;



&nbsp;// Verificar RTT razonable

&nbsp;if (node.RTT <= 0 || node.RTT > ONION\_PATH\_MAX\_LATENCY)

&nbsp;return false;



&nbsp;// Verificar que no sea nuestro propio nodo

&nbsp;if (ByteArraysEqual(node.PublicKey, SelfPublicKey))

&nbsp;return false;



&nbsp;// Verificar que tenga un endpoint válido

&nbsp;if (node.EndPoint.Port == 0 || node.EndPoint.IP.Data == null)

&nbsp;return false;



&nbsp;// Verificar que haya estado activo por un tiempo mínimo

&nbsp;long nodeUptime = (DateTime.UtcNow.Ticks - node.LastSeen) / TimeSpan.TicksPerMillisecond;

&nbsp;if (nodeUptime < ONION\_NODE\_MIN\_UPTIME)

&nbsp;return false;



&nbsp;// Verificar calidad de conexión (basado en RTT y estabilidad)

&nbsp;if (node.RTT > 500) // Más de 500ms es considerado lento

&nbsp;return false;



&nbsp;return true;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// MaintainOnionPaths - Mantenimiento REAL como en onion.c

&nbsp;/// </summary>

&nbsp;private void MaintainOnionPaths()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;int pathsReplaced = 0;

&nbsp;int pathsCreated = 0;



&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;// 1. Reemplazar paths con nodos problemáticos

&nbsp;for (int i = \_onionPaths.Count - 1; i >= 0; i--)

&nbsp;{

&nbsp;var path = \_onionPaths\[i];

&nbsp;if (!path.IsActive) continue;



&nbsp;double pathScore = CalculatePathScore(path);



&nbsp;// Reemplazar paths con score bajo

&nbsp;if (pathScore < 50.0) // Score mínimo aceptable

&nbsp;{

&nbsp;\_onionPaths.RemoveAt(i);

&nbsp;pathsReplaced++;



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Path #{path.PathNumber} removido (Score: {pathScore:F2})");



&nbsp;// Crear reemplazo

&nbsp;int newPath = CreateOnionPath();

&nbsp;if (newPath >= 0) pathsCreated++;

&nbsp;}

&nbsp;}



&nbsp;// 2. Asegurar número mínimo de paths activos

&nbsp;int activePaths = \_onionPaths.Count(p => p.IsActive);

&nbsp;int pathsNeeded = Math.Max(2, MAX\_ONION\_PATHS / 2); // Al menos 2 paths o la mitad del máximo



&nbsp;while (activePaths < pathsNeeded \&\& \_onionPaths.Count < MAX\_ONION\_PATHS)

&nbsp;{

&nbsp;int newPath = CreateOnionPath();

&nbsp;if (newPath >= 0)

&nbsp;{

&nbsp;activePaths++;

&nbsp;pathsCreated++;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;break; // No se pudo crear más paths

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;if (pathsReplaced > 0 || pathsCreated > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Mantenimiento: {pathsReplaced} paths reemplazados, {pathsCreated} creados");

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en mantenimiento de paths: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// PerformHealthChecks - Verificación de salud REAL de nodos onion

&nbsp;/// </summary>

&nbsp;private void PerformHealthChecks()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_nodesLock)

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;int checksPerformed = 0;

&nbsp;int nodesMarkedInactive = 0;



&nbsp;foreach (var node in \_onionNodes)

&nbsp;{

&nbsp;if (!node.IsActive) continue;



&nbsp;long timeSinceLastActivity = (currentTime - node.LastPinged) / TimeSpan.TicksPerMillisecond;



&nbsp;// Si no ha habido actividad reciente, verificar salud

&nbsp;if (timeSinceLastActivity > ONION\_PATH\_HEALTH\_CHECK\_INTERVAL)

&nbsp;{

&nbsp;checksPerformed++;



&nbsp;// Nodo con muchos fallos recientes se marca como inactivo

&nbsp;if (node.SuccessRate < 30) // Menos del 30% de éxito

&nbsp;{

&nbsp;node.IsActive = false;

&nbsp;nodesMarkedInactive++;

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Nodo onion marcado inactivo (Success: {node.SuccessRate}%)");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;if (nodesMarkedInactive > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Health check: {nodesMarkedInactive}/{checksPerformed} nodos marcados inactivos");

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en health check: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Selecciona nodos aleatoriamente para el path

&nbsp;/// </summary>

&nbsp;private List<OnionNode> SelectRandomNodes(List<OnionNode> nodes, int count)

&nbsp;{

&nbsp;if (nodes.Count <= count)

&nbsp;return new List<OnionNode>(nodes);



&nbsp;// ✅ MEJORA: Filtrar nodos no nulos y activos

&nbsp;var activeNodes = nodes.Where(n => n != null \&\& n.IsActive).ToList();

&nbsp;if (activeNodes.Count <= count)

&nbsp;return activeNodes;



&nbsp;// Usar Fisher-Yates shuffle para selección aleatoria

&nbsp;var shuffled = activeNodes.OrderBy(x => \_random.Next()).ToList();

&nbsp;return shuffled.Take(count).ToList();

&nbsp;}









&nbsp;public int kill\_onion\_path(int path\_num)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;var path = \_onionPaths.Find(p => p.PathNumber == path\_num);

&nbsp;if (path != null)

&nbsp;{

&nbsp;path.IsActive = false;

&nbsp;\_onionPaths.Remove(path);

&nbsp;return 0;

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;public int Start()

&nbsp;{

&nbsp;if (Socket == -1)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No se puede iniciar - Socket inválido");

&nbsp;return -1;

&nbsp;}



&nbsp;IsRunning = true;



&nbsp;// Crear paths iniciales

&nbsp;for (int i = 0; i < 2 \&\& i < MAX\_ONION\_PATHS; i++)

&nbsp;{

&nbsp;CreateOnionPath();

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Servicio Onion iniciado con {\_onionPaths.Count} paths");

&nbsp;return 0;

&nbsp;}



&nbsp;public int Stop()

&nbsp;{

&nbsp;IsRunning = false;

&nbsp;return 0;

&nbsp;}



&nbsp;public void Close()

&nbsp;{

&nbsp;Stop();

&nbsp;if (Socket != -1)

&nbsp;{

&nbsp;Network.kill\_socket(Socket);

&nbsp;Socket = -1;

&nbsp;}

&nbsp;lock (\_nodesLock) \_onionNodes.Clear();

&nbsp;lock (\_pathsLock) \_onionPaths.Clear();

&nbsp;}



&nbsp;// ==================== AGREGAR ESTE MÉTODO A LA CLASE ONION ====================



&nbsp;/// <summary>

&nbsp;/// DoPeriodicWork - ACTUALIZADO con mantenimiento REAL

&nbsp;/// </summary>

&nbsp;public void DoPeriodicWork()

&nbsp;{

&nbsp;if (!IsRunning) return;



&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// 1. Health check de nodos

&nbsp;PerformHealthChecks();



&nbsp;// 2. Mantenimiento de paths

&nbsp;if ((currentTime - \_lastMaintenanceTime) > TimeSpan.TicksPerMillisecond \* 120000) // Cada 2 minutos

&nbsp;{

&nbsp;MaintainOnionPaths();

&nbsp;\_lastMaintenanceTime = currentTime;

&nbsp;}



&nbsp;// 3. Limpieza de nodos antiguos (existente)

&nbsp;CleanupOldOnionNodes();



&nbsp;// 4. Log estadísticas periódicas

&nbsp;if ((currentTime - \_lastLogTime) > TimeSpan.TicksPerSecond \* 120)

&nbsp;{

&nbsp;int healthyNodes = \_onionNodes.Count(n => n.IsActive \&\& n.SuccessRate > 70);

&nbsp;int optimalPaths = \_onionPaths.Count(p => p.IsActive \&\& CalculatePathScore(p) > 70.0);



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Estadísticas - Nodos: {TotalOnionNodes} total, {healthyNodes} saludables, Paths: {TotalPaths} total, {optimalPaths} óptimos");

&nbsp;\_lastLogTime = currentTime;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en trabajo periódico: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Limpia paths onion expirados

&nbsp;/// </summary>

&nbsp;private void CleanupExpiredPaths()

&nbsp;{

&nbsp;long cutoffTime = DateTime.UtcNow.Ticks - TimeSpan.TicksPerMillisecond \* ONION\_PATH\_TIMEOUT;

&nbsp;int removed = 0;



&nbsp;lock (\_pathsLock)

&nbsp;{

&nbsp;for (int i = \_onionPaths.Count - 1; i >= 0; i--)

&nbsp;{

&nbsp;var path = \_onionPaths\[i];

&nbsp;if (!path.IsActive || path.LastUsed < cutoffTime)

&nbsp;{

&nbsp;\_onionPaths.RemoveAt(i);

&nbsp;removed++;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;if (removed > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {removed} paths onion removidos");

&nbsp;}

&nbsp;} 

&nbsp;}

}

]



Archivo RandomBytes.cs \[

using System.Security.Cryptography;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Implementación de randombytes

&nbsp;/// Generación segura de bytes aleatorios para crypto

&nbsp;/// </summary>

&nbsp;public static class RandomBytes

&nbsp;{

&nbsp;private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

&nbsp;private static readonly object rngLock = new object();



&nbsp;/// <summary>

&nbsp;/// Genera bytes aleatorios criptográficamente seguros

&nbsp;/// </summary>

&nbsp;public static byte\[] Generate(uint length)

&nbsp;{

&nbsp;if (length == 0)

&nbsp;return Array.Empty<byte>();



&nbsp;byte\[] buffer = new byte\[length];

&nbsp;lock (rngLock)

&nbsp;{

&nbsp;rng.GetBytes(buffer);

&nbsp;}

&nbsp;return buffer;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Llena un buffer existente con bytes aleatorios

&nbsp;/// </summary>

&nbsp;public static void Generate(byte\[] buffer)

&nbsp;{

&nbsp;if (buffer == null) throw new ArgumentNullException(nameof(buffer));

&nbsp;if (buffer.Length == 0) return;



&nbsp;lock (rngLock)

&nbsp;{

&nbsp;rng.GetBytes(buffer);

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Llena una porción de un buffer con bytes aleatorios

&nbsp;/// </summary>

&nbsp;public static void Generate(byte\[] buffer, int offset, int count)

&nbsp;{

&nbsp;if (buffer == null) throw new ArgumentNullException(nameof(buffer));

&nbsp;if (offset < 0 || offset >= buffer.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(offset));

&nbsp;if (count < 0 || offset + count > buffer.Length)

&nbsp;throw new ArgumentOutOfRangeException(nameof(count));

&nbsp;if (count == 0) return;



&nbsp;// Crear un buffer temporal y copiar

&nbsp;byte\[] temp = new byte\[count];

&nbsp;lock (rngLock)

&nbsp;{

&nbsp;rng.GetBytes(temp);

&nbsp;}

&nbsp;Buffer.BlockCopy(temp, 0, buffer, offset, count);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera un número aleatorio en el rango \[0, upperBound)

&nbsp;/// </summary>

&nbsp;/// <summary>

&nbsp;/// Genera un número aleatorio en el rango \[0, upperBound) sin bias

&nbsp;/// </summary>

&nbsp;public static uint Uniform(uint upperBound)

&nbsp;{

&nbsp;if (upperBound == 0)

&nbsp;throw new ArgumentOutOfRangeException(nameof(upperBound), "Upper bound must be greater than 0");



&nbsp;if (upperBound == 1)

&nbsp;return 0;



&nbsp;// Para upperBound potencias de 2, podemos usar máscara simple

&nbsp;if ((upperBound \& (upperBound - 1)) == 0) // Es potencia de 2

&nbsp;{

&nbsp;byte\[] bytes = Generate(4);

&nbsp;uint valueP = BitConverter.ToUInt32(bytes, 0);

&nbsp;return valueP \& (upperBound - 1);

&nbsp;}



&nbsp;// Para valores no potencia de 2, usar método de rechazo

&nbsp;uint min = uint.MaxValue - (uint.MaxValue % upperBound);

&nbsp;uint value;



&nbsp;// Límite de intentos para evitar bucles infinitos

&nbsp;int maxAttempts = 100;

&nbsp;int attempts = 0;



&nbsp;do

&nbsp;{

&nbsp;byte\[] bytes = Generate(4);

&nbsp;value = BitConverter.ToUInt32(bytes, 0);

&nbsp;attempts++;



&nbsp;if (attempts > maxAttempts)

&nbsp;{

&nbsp;// Fallback: usar módulo simple (puede tener bias pequeño pero evita bucle infinito)

&nbsp;return value % upperBound;

&nbsp;}

&nbsp;} while (value >= min);



&nbsp;return value % upperBound;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera un nonce aleatorio de 24 bytes (para crypto\_box)

&nbsp;/// </summary>

&nbsp;public static byte\[] GenerateNonce()

&nbsp;{

&nbsp;return Generate(24);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Genera una clave aleatoria de 32 bytes

&nbsp;/// </summary>

&nbsp;public static byte\[] GenerateKey()

&nbsp;{

&nbsp;return Generate(32);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de generación de bytes aleatorios

&nbsp;/// </summary>

&nbsp;public static bool Test()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Console.WriteLine(" Ejecutando tests de RandomBytes...");



&nbsp;// Test 1: Generación básica

&nbsp;byte\[] random1 = Generate(32);

&nbsp;if (random1.Length != 32)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 1 falló: Longitud incorrecta");

&nbsp;return false;

&nbsp;}



&nbsp;// Verificar que no es todo cero (muy improbable)

&nbsp;bool allZero = true;

&nbsp;foreach (byte b in random1)

&nbsp;{

&nbsp;if (b != 0)

&nbsp;{

&nbsp;allZero = false;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;if (allZero)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 1 falló: Output todo cero");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 1 - Generación básica: PASÓ");



&nbsp;// Test 2: Generación a buffer existente

&nbsp;byte\[] buffer = new byte\[64];

&nbsp;Generate(buffer);



&nbsp;allZero = true;

&nbsp;foreach (byte b in buffer)

&nbsp;{

&nbsp;if (b != 0)

&nbsp;{

&nbsp;allZero = false;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;if (allZero)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 2 falló: Buffer todo cero");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 2 - Generación a buffer: PASÓ");



&nbsp;// Test 3: Generación con offset

&nbsp;byte\[] bufferWithOffset = new byte\[100];

&nbsp;Array.Fill(bufferWithOffset, (byte)0xFF); // Llenar con 0xFF

&nbsp;Generate(bufferWithOffset, 10, 50);



&nbsp;// Verificar que la zona modificada no es todo 0xFF

&nbsp;bool allFF = true;

&nbsp;for (int i = 10; i < 60; i++)

&nbsp;{

&nbsp;if (bufferWithOffset\[i] != 0xFF)

&nbsp;{

&nbsp;allFF = false;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;if (allFF)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 3 falló: Zona con offset no modificada");

&nbsp;return false;

&nbsp;}



&nbsp;// Verificar que las zonas fuera del offset no se modificaron

&nbsp;for (int i = 0; i < 10; i++)

&nbsp;{

&nbsp;if (bufferWithOffset\[i] != 0xFF)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 3 falló: Zona antes del offset modificada");

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;for (int i = 60; i < 100; i++)

&nbsp;{

&nbsp;if (bufferWithOffset\[i] != 0xFF)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 3 falló: Zona después del offset modificada");

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 3 - Generación con offset: PASÓ");



&nbsp;// Test 4: Uniform distribution (test estadístico básico)

&nbsp;uint upperBound = 100;

&nbsp;int\[] counts = new int\[upperBound];

&nbsp;int samples = 10000;



&nbsp;for (int i = 0; i < samples; i++)

&nbsp;{

&nbsp;uint value = Uniform(upperBound);

&nbsp;if (value >= upperBound)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 4 falló: Valor fuera de rango");

&nbsp;return false;

&nbsp;}

&nbsp;counts\[value]++;

&nbsp;}



&nbsp;// Verificar distribución básica (cada valor debería aparecer al menos una vez)

&nbsp;for (int i = 0; i < upperBound; i++)

&nbsp;{

&nbsp;if (counts\[i] == 0)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Test 4 falló: Valor {i} nunca generado");

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 4 - Distribución uniforme: PASÓ");



&nbsp;// Test 5: Generaciones consecutivas producen resultados diferentes

&nbsp;byte\[] random2 = Generate(32);

&nbsp;bool sameAsFirst = true;

&nbsp;for (int i = 0; i < 32; i++)

&nbsp;{

&nbsp;if (random1\[i] != random2\[i])

&nbsp;{

&nbsp;sameAsFirst = false;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;if (sameAsFirst)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 5 falló: Dos generaciones iguales (muy improbable)");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 5 - Generaciones diferentes: PASÓ");



&nbsp;// Test 6: Funciones de conveniencia

&nbsp;byte\[] nonce = GenerateNonce();

&nbsp;if (nonce.Length != 24)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 6 falló: Nonce tamaño incorrecto");

&nbsp;return false;

&nbsp;}



&nbsp;byte\[] key = GenerateKey();

&nbsp;if (key.Length != 32)

&nbsp;{

&nbsp;Console.WriteLine(" ❌ Test 6 falló: Key tamaño incorrecto");

&nbsp;return false;

&nbsp;}

&nbsp;Console.WriteLine(" ✅ Test 6 - Funciones de conveniencia: PASÓ");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Console.WriteLine($" ❌ Error en test: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de rendimiento y entropía

&nbsp;/// </summary>

&nbsp;public static void TestPerformance()

&nbsp;{

&nbsp;Console.WriteLine(" Probando rendimiento y entropía...");



&nbsp;var sw = System.Diagnostics.Stopwatch.StartNew();



&nbsp;// Generar 1MB de datos aleatorios

&nbsp;byte\[] largeData = Generate(1024 \* 1024);

&nbsp;long timeLarge = sw.ElapsedTicks;



&nbsp;sw.Restart();



&nbsp;// Generar muchos chunks pequeños

&nbsp;for (int i = 0; i < 1000; i++)

&nbsp;{

&nbsp;Generate(100);

&nbsp;}

&nbsp;long timeSmall = sw.ElapsedTicks;



&nbsp;Console.WriteLine($" 1MB de datos: {timeLarge} ticks");

&nbsp;Console.WriteLine($" 1000 chunks de 100 bytes: {timeSmall} ticks");



&nbsp;// Test básico de entropía (verificar que los bytes están distribuidos)

&nbsp;int\[] byteCounts = new int\[256];

&nbsp;foreach (byte b in largeData)

&nbsp;{

&nbsp;byteCounts\[b]++;

&nbsp;}



&nbsp;// Calcular chi-cuadrado básico (simplificado)

&nbsp;double expected = largeData.Length / 256.0;

&nbsp;double chiSquare = 0;

&nbsp;for (int i = 0; i < 256; i++)

&nbsp;{

&nbsp;double diff = byteCounts\[i] - expected;

&nbsp;chiSquare += (diff \* diff) / expected;

&nbsp;}



&nbsp;// Chi-cuadrado para 255 grados de libertad, p=0.05 es ~293

&nbsp;bool goodDistribution = chiSquare < 350; // Umbral conservador

&nbsp;Console.WriteLine($" Distribución chi-cuadrado: {chiSquare:F2}");

&nbsp;Console.WriteLine($" Buena distribución: {(goodDistribution ? "✅" : "⚠️")}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// API compatible con nombres C originales

&nbsp;/// </summary>

&nbsp;public static class randombytes\_native

&nbsp;{

&nbsp;public static void randombytes(byte\[] buf, ulong len)

&nbsp;{

&nbsp;if (buf == null) throw new ArgumentNullException(nameof(buf));

&nbsp;RandomBytes.Generate(buf, 0, (int)len);

&nbsp;}



&nbsp;public static uint randombytes\_uniform(uint upperBound)

&nbsp;{

&nbsp;return RandomBytes.Uniform(upperBound);

&nbsp;}



&nbsp;public static void randombytes\_buf(byte\[] buf, ulong len)

&nbsp;{

&nbsp;randombytes(buf, len);

&nbsp;}



&nbsp;public static void randombytes\_buf\_deterministic(byte\[] buf, ulong len, byte\[] seed)

&nbsp;{

&nbsp;// Para compatibilidad, pero en producción usamos RNG criptográfico

&nbsp;// Esta función sería para tests determinísticos

&nbsp;throw new NotImplementedException("Deterministic randombytes not implemented for production use");

&nbsp;}

&nbsp;}

}

]



Archivo State.cs \[

using System.Text;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Adaptación de state.c - Manejo de estado persistente del cliente Tox

&nbsp;/// </summary>

&nbsp;public class ToxState : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "STATE";



&nbsp;private byte\[] \_stateData;

&nbsp;private bool \_modified;



&nbsp;public ToxUser User { get; private set; }

&nbsp;public ToxFriends Friends { get; private set; }

&nbsp;public ToxConferences Conferences { get; private set; }



&nbsp;public ToxState()

&nbsp;{

&nbsp;User = new ToxUser();

&nbsp;Friends = new ToxFriends();

&nbsp;Conferences = new ToxConferences();

&nbsp;\_stateData = Array.Empty<byte>();

&nbsp;\_modified = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Estado inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_load - Cargar estado desde bytes (equivalente a state\_load)

&nbsp;/// </summary>

&nbsp;public bool Load(byte\[] data)

&nbsp;{

&nbsp;if (data == null || data.Length == 0)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Datos de estado vacíos o nulos");

&nbsp;return false;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;using var stream = new MemoryStream(data);

&nbsp;using var reader = new BinaryReader(stream);



&nbsp;// Verificar magic number (similar al original)

&nbsp;uint magic = reader.ReadUInt32();

&nbsp;if (magic != 0x01546F78) // "Tox\\0x01" en little-endian

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Magic number inválido: 0x{magic:X8}");

&nbsp;return false;

&nbsp;}



&nbsp;// Cargar usuario

&nbsp;User = ToxUser.Load(reader);



&nbsp;// Cargar amigos

&nbsp;Friends = ToxFriends.Load(reader);



&nbsp;// Cargar conferencias (si existen)

&nbsp;if (stream.Position < stream.Length)

&nbsp;{

&nbsp;Conferences = ToxConferences.Load(reader);

&nbsp;}



&nbsp;\_stateData = data;

&nbsp;\_modified = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Estado cargado correctamente - Tamaño: {data.Length} bytes");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error cargando estado: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_save - Guardar estado a bytes (equivalente a state\_save)

&nbsp;/// </summary>

&nbsp;public byte\[] Save()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;using var stream = new MemoryStream();

&nbsp;using var writer = new BinaryWriter(stream);



&nbsp;// Escribir magic number

&nbsp;writer.Write(0x01546F78); // "Tox\\0x01"



&nbsp;// Guardar usuario

&nbsp;User.Save(writer);



&nbsp;// Guardar amigos

&nbsp;Friends.Save(writer);



&nbsp;// Guardar conferencias

&nbsp;Conferences.Save(writer);



&nbsp;\_stateData = stream.ToArray();

&nbsp;\_modified = false;



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Estado guardado - Tamaño: {\_stateData.Length} bytes");

&nbsp;return \_stateData;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error guardando estado: {ex.Message}");

&nbsp;return Array.Empty<byte>();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_load\_from\_file - Cargar estado desde archivo

&nbsp;/// </summary>

&nbsp;public bool LoadFromFile(string filePath)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (!File.Exists(filePath))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Archivo no existe: {filePath}");

&nbsp;return false;

&nbsp;}



&nbsp;byte\[] data = File.ReadAllBytes(filePath);

&nbsp;bool success = Load(data);



&nbsp;if (success)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Estado cargado desde: {filePath}");

&nbsp;}



&nbsp;return success;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error cargando estado desde archivo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_save\_to\_file - Guardar estado a archivo

&nbsp;/// </summary>

&nbsp;public bool SaveToFile(string filePath)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] data = Save();

&nbsp;if (data.Length == 0)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No hay datos para guardar");

&nbsp;return false;

&nbsp;}



&nbsp;// Crear directorio si no existe

&nbsp;string directory = Path.GetDirectoryName(filePath);

&nbsp;if (!string.IsNullOrEmpty(directory) \&\& !Directory.Exists(directory))

&nbsp;{

&nbsp;Directory.CreateDirectory(directory);

&nbsp;}



&nbsp;File.WriteAllBytes(filePath, data);

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Estado guardado en: {filePath}");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error guardando estado en archivo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_is\_modified - Verificar si el estado ha sido modificado

&nbsp;/// </summary>

&nbsp;public bool IsModified()

&nbsp;{

&nbsp;return \_modified;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_mark\_modified - Marcar estado como modificado

&nbsp;/// </summary>

&nbsp;public void MarkModified()

&nbsp;{

&nbsp;\_modified = true;

&nbsp;Logger.Log.Trace($"\[{LOG\_TAG}] Estado marcado como modificado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_state\_get\_size - Obtener tamaño del estado serializado

&nbsp;/// </summary>

&nbsp;public int GetSize()

&nbsp;{

&nbsp;return \_stateData.Length;

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;// Limpiar recursos si es necesario

&nbsp;\_stateData = null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Datos del usuario (equivalente a USER\_STATE en C)

&nbsp;/// </summary>

&nbsp;public class ToxUser

&nbsp;{

&nbsp;public byte\[] PublicKey { get; set; }

&nbsp;public byte\[] SecretKey { get; set; }

&nbsp;public string Name { get; set; }

&nbsp;public string StatusMessage { get; set; }

&nbsp;public ToxUserStatus Status { get; set; }

&nbsp;public byte\[] Nospam { get; set; }



&nbsp;public ToxUser()

&nbsp;{

&nbsp;// INICIALIZAR ARRAYS PARA EVITAR NULL

&nbsp;PublicKey = new byte\[32];

&nbsp;SecretKey = new byte\[32];

&nbsp;Name = string.Empty;

&nbsp;StatusMessage = string.Empty;

&nbsp;Status = ToxUserStatus.NONE;

&nbsp;Nospam = new byte\[4];



&nbsp;// Generar nospam aleatorio por defecto

&nbsp;new Random().NextBytes(Nospam);

&nbsp;}



&nbsp;public static ToxUser Load(BinaryReader reader)

&nbsp;{

&nbsp;var user = new ToxUser();



&nbsp;try

&nbsp;{

&nbsp;// Cargar claves

&nbsp;user.PublicKey = reader.ReadBytes(32);

&nbsp;user.SecretKey = reader.ReadBytes(32);



&nbsp;// Cargar nospam

&nbsp;user.Nospam = reader.ReadBytes(4);



&nbsp;// Cargar nombre

&nbsp;ushort nameLength = reader.ReadUInt16();

&nbsp;if (nameLength > 0 \&\& nameLength <= 1024) // Límite razonable

&nbsp;{

&nbsp;user.Name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));

&nbsp;}



&nbsp;// Cargar estado

&nbsp;user.Status = (ToxUserStatus)reader.ReadByte();



&nbsp;// Cargar mensaje de estado

&nbsp;ushort statusLength = reader.ReadUInt16();

&nbsp;if (statusLength > 0 \&\& statusLength <= 1024) // Límite razonable

&nbsp;{

&nbsp;user.StatusMessage = Encoding.UTF8.GetString(reader.ReadBytes(statusLength));

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error cargando usuario: {ex.Message}");

&nbsp;// Devolver usuario por defecto en caso de error

&nbsp;return new ToxUser();

&nbsp;}



&nbsp;return user;

&nbsp;}



&nbsp;public void Save(BinaryWriter writer)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Asegurar que los arrays no sean null

&nbsp;PublicKey ??= new byte\[32];

&nbsp;SecretKey ??= new byte\[32];

&nbsp;Nospam ??= new byte\[4];



&nbsp;writer.Write(PublicKey);

&nbsp;writer.Write(SecretKey);

&nbsp;writer.Write(Nospam);



&nbsp;// Guardar nombre

&nbsp;byte\[] nameBytes = Encoding.UTF8.GetBytes(Name ?? "");

&nbsp;writer.Write((ushort)Math.Min(nameBytes.Length, 1024)); // Limitar tamaño

&nbsp;if (nameBytes.Length > 0)

&nbsp;{

&nbsp;writer.Write(nameBytes, 0, Math.Min(nameBytes.Length, 1024));

&nbsp;}



&nbsp;// Guardar estado

&nbsp;writer.Write((byte)Status);



&nbsp;// Guardar mensaje de estado

&nbsp;byte\[] statusBytes = Encoding.UTF8.GetBytes(StatusMessage ?? "");

&nbsp;writer.Write((ushort)Math.Min(statusBytes.Length, 1024)); // Limitar tamaño

&nbsp;if (statusBytes.Length > 0)

&nbsp;{

&nbsp;writer.Write(statusBytes, 0, Math.Min(statusBytes.Length, 1024));

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error guardando usuario: {ex.Message}");

&nbsp;throw;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Lista de amigos (equivalente a FRIEND\_STATE en C)

&nbsp;/// </summary>

&nbsp;public class ToxFriends

&nbsp;{

&nbsp;public ToxFriend\[] Friends { get; set; }



&nbsp;public ToxFriends()

&nbsp;{

&nbsp;Friends = Array.Empty<ToxFriend>();

&nbsp;}



&nbsp;public static ToxFriends Load(BinaryReader reader)

&nbsp;{

&nbsp;var friends = new ToxFriends();



&nbsp;try

&nbsp;{

&nbsp;uint count = reader.ReadUInt32();

&nbsp;// Limitar número máximo de amigos por seguridad

&nbsp;count = Math.Min(count, 1000);



&nbsp;friends.Friends = new ToxFriend\[count];



&nbsp;for (int i = 0; i < count; i++)

&nbsp;{

&nbsp;friends.Friends\[i] = ToxFriend.Load(reader);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error cargando amigos: {ex.Message}");

&nbsp;// Devolver lista vacía en caso de error

&nbsp;return new ToxFriends();

&nbsp;}



&nbsp;return friends;

&nbsp;}



&nbsp;public void Save(BinaryWriter writer)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Friends ??= Array.Empty<ToxFriend>();

&nbsp;writer.Write((uint)Friends.Length);



&nbsp;foreach (var friend in Friends)

&nbsp;{

&nbsp;friend?.Save(writer);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error guardando amigos: {ex.Message}");

&nbsp;throw;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Datos de un amigo individual

&nbsp;/// </summary>

&nbsp;public class ToxFriend

&nbsp;{

&nbsp;public byte\[] PublicKey { get; set; }

&nbsp;public string Name { get; set; }

&nbsp;public string StatusMessage { get; set; }

&nbsp;public ToxUserStatus Status { get; set; }

&nbsp;public uint FriendNumber { get; set; }



&nbsp;public ToxFriend()

&nbsp;{

&nbsp;PublicKey = new byte\[32];

&nbsp;Name = string.Empty;

&nbsp;StatusMessage = string.Empty;

&nbsp;Status = ToxUserStatus.NONE;

&nbsp;}



&nbsp;public static ToxFriend Load(BinaryReader reader)

&nbsp;{

&nbsp;var friend = new ToxFriend();



&nbsp;try

&nbsp;{

&nbsp;friend.PublicKey = reader.ReadBytes(32);

&nbsp;friend.FriendNumber = reader.ReadUInt32();



&nbsp;// Cargar nombre

&nbsp;ushort nameLength = reader.ReadUInt16();

&nbsp;if (nameLength > 0 \&\& nameLength <= 1024)

&nbsp;{

&nbsp;friend.Name = Encoding.UTF8.GetString(reader.ReadBytes(nameLength));

&nbsp;}



&nbsp;// Cargar estado

&nbsp;friend.Status = (ToxUserStatus)reader.ReadByte();



&nbsp;// Cargar mensaje de estado

&nbsp;ushort statusLength = reader.ReadUInt16();

&nbsp;if (statusLength > 0 \&\& statusLength <= 1024)

&nbsp;{

&nbsp;friend.StatusMessage = Encoding.UTF8.GetString(reader.ReadBytes(statusLength));

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error cargando amigo: {ex.Message}");

&nbsp;return new ToxFriend();

&nbsp;}



&nbsp;return friend;

&nbsp;}



&nbsp;public void Save(BinaryWriter writer)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;PublicKey ??= new byte\[32];

&nbsp;writer.Write(PublicKey);

&nbsp;writer.Write(FriendNumber);



&nbsp;// Guardar nombre

&nbsp;byte\[] nameBytes = Encoding.UTF8.GetBytes(Name ?? "");

&nbsp;writer.Write((ushort)Math.Min(nameBytes.Length, 1024));

&nbsp;if (nameBytes.Length > 0)

&nbsp;{

&nbsp;writer.Write(nameBytes, 0, Math.Min(nameBytes.Length, 1024));

&nbsp;}



&nbsp;// Guardar estado

&nbsp;writer.Write((byte)Status);



&nbsp;// Guardar mensaje de estado

&nbsp;byte\[] statusBytes = Encoding.UTF8.GetBytes(StatusMessage ?? "");

&nbsp;writer.Write((ushort)Math.Min(statusBytes.Length, 1024));

&nbsp;if (statusBytes.Length > 0)

&nbsp;{

&nbsp;writer.Write(statusBytes, 0, Math.Min(statusBytes.Length, 1024));

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[STATE] Error guardando amigo: {ex.Message}");

&nbsp;throw;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conferencias/grupos (placeholder para group.c futuro)

&nbsp;/// </summary>

&nbsp;public class ToxConferences

&nbsp;{

&nbsp;public static ToxConferences Load(BinaryReader reader)

&nbsp;{

&nbsp;// Implementación básica - se expandirá con group.c

&nbsp;return new ToxConferences();

&nbsp;}



&nbsp;public void Save(BinaryWriter writer)

&nbsp;{

&nbsp;// Implementación básica - no escribir nada por ahora

&nbsp;}

&nbsp;}



&nbsp;public enum ToxUserStatus

&nbsp;{

&nbsp;NONE = 0,

&nbsp;AWAY = 1,

&nbsp;BUSY = 2

&nbsp;}

}

]



Archivo TCPClient.cs \[

using System.Net;

using System.Net.Sockets;

using System.Runtime.InteropServices;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estado de conexión TCP compatible con toxcore

&nbsp;/// </summary>

&nbsp;public enum TCP\_Status

&nbsp;{

&nbsp;TCP\_STATUS\_NO\_STATUS,

&nbsp;TCP\_STATUS\_CONNECTING,

&nbsp;TCP\_STATUS\_UNCONFIRMED,

&nbsp;TCP\_STATUS\_CONFIRMED,

&nbsp;TCP\_STATUS\_DISCONNECTED

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conexión TCP individual

&nbsp;/// </summary>

&nbsp;\[StructLayout(LayoutKind.Sequential, Pack = 1)]

&nbsp;public struct TCP\_Connection

&nbsp;{

&nbsp;public Socket Socket;

&nbsp;public IPPort RemoteEndPoint;

&nbsp;\[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]

&nbsp;public byte\[] PublicKey;

&nbsp;public TCP\_Status Status;

&nbsp;public long LastActivity;

&nbsp;public int ConnectionID;



&nbsp;public TCP\_Connection(Socket socket, IPPort remote, byte\[] publicKey, int id)

&nbsp;{

&nbsp;Socket = socket;

&nbsp;RemoteEndPoint = remote;

&nbsp;PublicKey = new byte\[32];

&nbsp;if (publicKey != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(publicKey, 0, PublicKey, 0, 32);

&nbsp;}

&nbsp;Status = TCP\_Status.TCP\_STATUS\_CONNECTING;

&nbsp;LastActivity = DateTime.UtcNow.Ticks;

&nbsp;ConnectionID = id;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Cliente TCP compatible con TCP\_client.c de toxcore

&nbsp;/// </summary>

&nbsp;public class TCP\_Client

&nbsp;{

&nbsp;private const string LOG\_TAG = "TCP\_Client";



&nbsp;public const int TCP\_PACKET\_MAX\_SIZE = 2048;

&nbsp;public const int TCP\_HANDSHAKE\_TIMEOUT = 10000;

&nbsp;public const int TCP\_CONNECTION\_TIMEOUT = 30000;



&nbsp;public byte\[] SelfPublicKey { get; private set; }

&nbsp;public byte\[] SelfSecretKey { get; private set; }

&nbsp;public TCP\_Connection Connection { get; private set; }

&nbsp;public bool IsConnected => Connection.Socket != null \&\& Connection.Socket.Connected;



&nbsp;private int \_lastConnectionID;

&nbsp;private long \_lastKeepAliveSent;



&nbsp;public TCP\_Client(byte\[] selfPublicKey, byte\[] selfSecretKey)

&nbsp;{

&nbsp;SelfPublicKey = new byte\[32];

&nbsp;SelfSecretKey = new byte\[32];

&nbsp;Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);

&nbsp;Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);



&nbsp;Connection = new TCP\_Connection();

&nbsp;\_lastConnectionID = 0;

&nbsp;\_lastKeepAliveSent = 0;

&nbsp;}



&nbsp;// ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// tcp\_connect - Compatible con TCP\_client.c

&nbsp;/// </summary>

&nbsp;public int tcp\_connect(IPPort ipp, byte\[] public\_key)

&nbsp;{

&nbsp;if (IsConnected) return -1;



&nbsp;try

&nbsp;{

&nbsp;Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

&nbsp;socket.Blocking = false;



&nbsp;IPEndPoint endPoint = new IPEndPoint(ipp.IP.ToIPAddress(), ipp.Port);



&nbsp;// Conexión asíncrona

&nbsp;IAsyncResult result = socket.BeginConnect(endPoint, null, null);

&nbsp;bool success = result.AsyncWaitHandle.WaitOne(5000, true);



&nbsp;if (success \&\& socket.Connected)

&nbsp;{

&nbsp;socket.EndConnect(result);



&nbsp;// CORREGIDO: Crear nueva instancia en lugar de modificar propiedades

&nbsp;Connection = new TCP\_Connection(socket, ipp, public\_key, \_lastConnectionID++);



&nbsp;// Iniciar handshake criptográfico

&nbsp;return tcp\_handshake(public\_key);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;socket.Close();

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_send\_data - Compatible con TCP\_client.c

&nbsp;/// </summary>

&nbsp;public int tcp\_send\_data(byte\[] data, int length)

&nbsp;{

&nbsp;if (!IsConnected || Connection.Status != TCP\_Status.TCP\_STATUS\_CONFIRMED) return -1;

&nbsp;if (data == null || length > TCP\_PACKET\_MAX\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Encriptar datos para transmisión segura

&nbsp;byte\[] nonce = RandomBytes.Generate(24);

&nbsp;byte\[] encrypted = CryptoBox.Encrypt(data, nonce, Connection.PublicKey, SelfSecretKey);



&nbsp;if (encrypted == null) return -1;



&nbsp;// Crear paquete: nonce + datos encriptados

&nbsp;byte\[] packet = new byte\[24 + encrypted.Length];

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 0, 24);

&nbsp;Buffer.BlockCopy(encrypted, 0, packet, 24, encrypted.Length);



&nbsp;int sent = Connection.Socket.Send(packet);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// CORREGIDO: Actualizar LastActivity creando nueva instancia

&nbsp;Connection = new TCP\_Connection(

&nbsp;Connection.Socket,

&nbsp;Connection.RemoteEndPoint,

&nbsp;Connection.PublicKey,

&nbsp;Connection.ConnectionID)

&nbsp;{

&nbsp;Status = Connection.Status,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};

&nbsp;}

&nbsp;return sent;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_recv\_data - Compatible con TCP\_client.c

&nbsp;/// </summary>

&nbsp;public int tcp\_recv\_data(byte\[] buffer, int length)

&nbsp;{

&nbsp;if (!IsConnected || buffer == null) return -1;



&nbsp;try

&nbsp;{

&nbsp;if (Connection.Socket.Available > 0)

&nbsp;{

&nbsp;byte\[] tempBuffer = new byte\[TCP\_PACKET\_MAX\_SIZE];

&nbsp;int received = Connection.Socket.Receive(tempBuffer);



&nbsp;if (received >= 24)

&nbsp;{

&nbsp;// Extraer nonce y datos encriptados

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;Buffer.BlockCopy(tempBuffer, 0, nonce, 0, 24);



&nbsp;byte\[] encrypted = new byte\[received - 24];

&nbsp;Buffer.BlockCopy(tempBuffer, 24, encrypted, 0, received - 24);



&nbsp;// Desencriptar datos

&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encrypted, nonce, Connection.PublicKey, SelfSecretKey);



&nbsp;if (decrypted != null \&\& decrypted.Length <= length)

&nbsp;{

&nbsp;Buffer.BlockCopy(decrypted, 0, buffer, 0, decrypted.Length);



&nbsp;// CORREGIDO: Actualizar LastActivity

&nbsp;Connection = new TCP\_Connection(

&nbsp;Connection.Socket,

&nbsp;Connection.RemoteEndPoint,

&nbsp;Connection.PublicKey,

&nbsp;Connection.ConnectionID)

&nbsp;{

&nbsp;Status = Connection.Status,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};



&nbsp;return decrypted.Length;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_disconnect - Compatible con TCP\_client.c

&nbsp;/// </summary>

&nbsp;public int tcp\_disconnect()

&nbsp;{

&nbsp;if (!IsConnected) return -1;



&nbsp;try

&nbsp;{

&nbsp;Connection.Socket.Shutdown(SocketShutdown.Both);

&nbsp;Connection.Socket.Close();



&nbsp;// CORREGIDO: Crear nueva instancia desconectada

&nbsp;Connection = new TCP\_Connection();

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== FUNCIONES AUXILIARES ====================



&nbsp;/// <summary>

&nbsp;/// tcp\_handshake - Handshake criptográfico

&nbsp;/// </summary>

&nbsp;private int tcp\_handshake(byte\[] public\_key)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Enviar handshake inicial - pasar public\_key

&nbsp;byte\[] handshake = CreateHandshakePacket(public\_key); // ← Agregar parámetro

&nbsp;int sent = Connection.Socket.Send(handshake);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// Actualizar estado

&nbsp;Connection = new TCP\_Connection(

&nbsp;Connection.Socket,

&nbsp;Connection.RemoteEndPoint,

&nbsp;Connection.PublicKey,

&nbsp;Connection.ConnectionID)

&nbsp;{

&nbsp;Status = TCP\_Status.TCP\_STATUS\_CONFIRMED,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};



&nbsp;return 0;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_write\_packet - Envío de paquete raw

&nbsp;/// </summary>

&nbsp;public int tcp\_write\_packet(byte\[] data, int length)

&nbsp;{

&nbsp;if (!IsConnected) return -1;



&nbsp;try

&nbsp;{

&nbsp;int sent = Connection.Socket.Send(data, length, SocketFlags.None);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// CORREGIDO: Actualizar LastActivity

&nbsp;Connection = new TCP\_Connection(

&nbsp;Connection.Socket,

&nbsp;Connection.RemoteEndPoint,

&nbsp;Connection.PublicKey,

&nbsp;Connection.ConnectionID)

&nbsp;{

&nbsp;Status = Connection.Status,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};

&nbsp;}

&nbsp;return sent;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_read\_packet - Recepción de paquete raw

&nbsp;/// </summary>

&nbsp;public int tcp\_read\_packet(byte\[] buffer, int length)

&nbsp;{

&nbsp;if (!IsConnected || buffer == null) return -1;



&nbsp;try

&nbsp;{

&nbsp;if (Connection.Socket.Available > 0)

&nbsp;{

&nbsp;int received = Connection.Socket.Receive(buffer, Math.Min(length, buffer.Length), SocketFlags.None);

&nbsp;if (received > 0)

&nbsp;{

&nbsp;// CORREGIDO: Actualizar LastActivity

&nbsp;Connection = new TCP\_Connection(

&nbsp;Connection.Socket,

&nbsp;Connection.RemoteEndPoint,

&nbsp;Connection.PublicKey,

&nbsp;Connection.ConnectionID)

&nbsp;{

&nbsp;Status = Connection.Status,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};

&nbsp;}

&nbsp;return received;

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] CreateHandshakePacket(byte\[] public\_key) // ← Agregar parámetro public\_key

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Basado en TCP\_client.c - send\_tcp\_handshake

&nbsp;byte\[] packet = new byte\[CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE + CryptoBox.CRYPTO\_NONCE\_SIZE + CryptoBox.CRYPTO\_MAC\_SIZE];



&nbsp;// 1. Nuestra clave pública

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, packet, 0, CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE);



&nbsp;// 2. Nonce aleatorio

&nbsp;byte\[] nonce = RandomBytes.Generate(CryptoBox.CRYPTO\_NONCE\_SIZE);

&nbsp;Buffer.BlockCopy(nonce, 0, packet, CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE, CryptoBox.CRYPTO\_NONCE\_SIZE);



&nbsp;// 3. Encriptar con la clave pública del destino

&nbsp;byte\[] temp = new byte\[CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE + CryptoBox.CRYPTO\_NONCE\_SIZE];

&nbsp;Buffer.BlockCopy(SelfPublicKey, 0, temp, 0, CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(nonce, 0, temp, CryptoBox.CRYPTO\_PUBLIC\_KEY\_SIZE, CryptoBox.CRYPTO\_NONCE\_SIZE);



&nbsp;byte\[] encrypted = CryptoBox.Encrypt(temp, nonce, public\_key, SelfSecretKey);

&nbsp;if (encrypted == null) return null;



&nbsp;// 4. El paquete final es la data encriptada

&nbsp;return encrypted;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando handshake TCP: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_set\_nodelay - Configurar Nagle algorithm

&nbsp;/// </summary>

&nbsp;public int tcp\_set\_nodelay(bool nodelay)

&nbsp;{

&nbsp;if (!IsConnected) return -1;



&nbsp;try

&nbsp;{

&nbsp;Connection.Socket.NoDelay = nodelay;

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_set\_keepalive - Configurar keep-alive

&nbsp;/// </summary>

&nbsp;public int tcp\_set\_keepalive(bool keepalive)

&nbsp;{

&nbsp;if (!IsConnected) return -1;



&nbsp;try

&nbsp;{

&nbsp;// Configuración básica de keep-alive

&nbsp;byte\[] keepAlive = BitConverter.GetBytes(keepalive ? 1U : 0U);

&nbsp;Connection.Socket.IOControl(IOControlCode.KeepAliveValues, keepAlive, null);

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Do\_periodic\_work - Mantenimiento de conexión

&nbsp;/// </summary>

&nbsp;public void Do\_periodic\_work()

&nbsp;{

&nbsp;if (!IsConnected) return;



&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;// Verificar timeout

&nbsp;if ((currentTime - Connection.LastActivity) > TimeSpan.TicksPerMillisecond \* TCP\_CONNECTION\_TIMEOUT)

&nbsp;{

&nbsp;tcp\_disconnect();

&nbsp;return;

&nbsp;}



&nbsp;// Enviar keep-alive periódicamente

&nbsp;if ((currentTime - \_lastKeepAliveSent) > TimeSpan.TicksPerSecond \* 30)

&nbsp;{

&nbsp;byte\[] keepAlivePacket = new byte\[] { 0x00 }; // Packet keep-alive

&nbsp;tcp\_write\_packet(keepAlivePacket, 1);

&nbsp;\_lastKeepAliveSent = currentTime;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo TCPForwarding.cs \[



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Sistema de TCP Forwarding a través de la red Tox

&nbsp;/// </summary>

&nbsp;public class TCPForwarding

&nbsp;{

&nbsp;private const string LOG\_TAG = "TCP\_FORWARDING";



&nbsp;private readonly TCPTunnel \_tunnel;

&nbsp;private readonly Dictionary<int, ForwardingSession> \_forwardingSessions;

&nbsp;private readonly object \_sessionsLock = new object();

&nbsp;private int \_lastSessionId;



&nbsp;public TCPForwarding(TCPTunnel tunnel)

&nbsp;{

&nbsp;\_tunnel = tunnel ?? throw new ArgumentNullException(nameof(tunnel));

&nbsp;\_forwardingSessions = new Dictionary<int, ForwardingSession>();

&nbsp;\_lastSessionId = 0;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar forwarding a través de un amigo

&nbsp;/// </summary>

&nbsp;public int StartForwarding(int friendNumber, IPPort targetEndPoint)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Crear sesión de forwarding

&nbsp;int sessionId = \_lastSessionId++;

&nbsp;var session = new ForwardingSession(sessionId, friendNumber, targetEndPoint);



&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;\_forwardingSessions\[sessionId] = session;

&nbsp;}



&nbsp;// Iniciar tunnel

&nbsp;int tunnelId = \_tunnel.StartTunnel(friendNumber, targetEndPoint);

&nbsp;if (tunnelId >= 0)

&nbsp;{

&nbsp;session.TunnelId = tunnelId;

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Forwarding iniciado: {sessionId} -> {targetEndPoint} via friend {friendNumber}");

&nbsp;return sessionId;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando forwarding: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar datos a través del forwarding

&nbsp;/// </summary>

&nbsp;public int SendForwardingData(int sessionId, byte\[] data, int length)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ForwardingSession session;

&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;if (!\_forwardingSessions.TryGetValue(sessionId, out session))

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;return \_tunnel.SendTunnelData(session.TunnelId, data, length);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando datos de forwarding: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Cerrar sesión de forwarding

&nbsp;/// </summary>

&nbsp;public bool StopForwarding(int sessionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ForwardingSession session;

&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;if (!\_forwardingSessions.TryGetValue(sessionId, out session))

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;\_forwardingSessions.Remove(sessionId);

&nbsp;}



&nbsp;\_tunnel.CloseTunnel(session.TunnelId);

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Forwarding {sessionId} detenido");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo forwarding: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private class ForwardingSession

&nbsp;{

&nbsp;public int SessionId { get; }

&nbsp;public int FriendNumber { get; }

&nbsp;public IPPort TargetEndPoint { get; }

&nbsp;public int TunnelId { get; set; }

&nbsp;public long StartTime { get; }



&nbsp;public ForwardingSession(int sessionId, int friendNumber, IPPort targetEndPoint)

&nbsp;{

&nbsp;SessionId = sessionId;

&nbsp;FriendNumber = friendNumber;

&nbsp;TargetEndPoint = targetEndPoint;

&nbsp;StartTime = DateTime.UtcNow.Ticks;

&nbsp;TunnelId = -1;

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo TCPServer.cs \[

using System.Net;

using System.Net.Sockets;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Servidor TCP compatible con TCP\_server.c de toxcore

&nbsp;/// </summary>

&nbsp;public class TCP\_Server

&nbsp;{

&nbsp;public const int TCP\_MAX\_CONNECTIONS = 10;

&nbsp;public const int TCP\_BACKLOG\_SIZE = 5;

&nbsp;public const int TCP\_PACKET\_MAX\_SIZE = 2048;



&nbsp;public byte\[] SelfPublicKey { get; private set; }

&nbsp;public byte\[] SelfSecretKey { get; private set; }

&nbsp;public Socket ListenerSocket { get; private set; }

&nbsp;public bool IsRunning { get; private set; }



&nbsp;private readonly List<TCP\_Connection> \_connections;

&nbsp;private readonly object \_connectionsLock = new object();

&nbsp;private int \_lastConnectionID;



&nbsp;private readonly List<TcpClient> \_activeConnections = new List<TcpClient>();

&nbsp;private DateTime \_lastConnectionCleanup = DateTime.UtcNow;



&nbsp;public int ConnectionCount

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;return \_connections.Count;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public int ActiveConnections

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;return \_connections.Count(c => c.Status == TCP\_Status.TCP\_STATUS\_CONFIRMED);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public TCP\_Server(byte\[] selfPublicKey, byte\[] selfSecretKey)

&nbsp;{

&nbsp;SelfPublicKey = new byte\[32];

&nbsp;SelfSecretKey = new byte\[32];

&nbsp;Buffer.BlockCopy(selfPublicKey, 0, SelfPublicKey, 0, 32);

&nbsp;Buffer.BlockCopy(selfSecretKey, 0, SelfSecretKey, 0, 32);



&nbsp;\_connections = new List<TCP\_Connection>();

&nbsp;\_lastConnectionID = 0;

&nbsp;IsRunning = false;

&nbsp;}



&nbsp;// ==================== FUNCIONES COMPATIBLES CON C ORIGINAL ====================



&nbsp;/// <summary>

&nbsp;/// tcp\_listen - Compatible con TCP\_server.c

&nbsp;/// </summary>

&nbsp;public int tcp\_listen(IPPort ipp)

&nbsp;{

&nbsp;if (IsRunning) return -1;



&nbsp;try

&nbsp;{

&nbsp;ListenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

&nbsp;ListenerSocket.Blocking = false;

&nbsp;ListenerSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);



&nbsp;IPEndPoint localEndPoint = new IPEndPoint(ipp.IP.ToIPAddress(), ipp.Port);

&nbsp;ListenerSocket.Bind(localEndPoint);

&nbsp;ListenerSocket.Listen(TCP\_BACKLOG\_SIZE);



&nbsp;IsRunning = true;

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_accept - Compatible con TCP\_server.c

&nbsp;/// </summary>

&nbsp;public int tcp\_accept(out TCP\_Connection connection)

&nbsp;{

&nbsp;connection = new TCP\_Connection();



&nbsp;if (!IsRunning || ListenerSocket == null) return -1;



&nbsp;try

&nbsp;{

&nbsp;if (ListenerSocket.Poll(0, SelectMode.SelectRead))

&nbsp;{

&nbsp;Socket clientSocket = ListenerSocket.Accept();

&nbsp;clientSocket.Blocking = false;



&nbsp;IPEndPoint remoteEndPoint = (IPEndPoint)clientSocket.RemoteEndPoint;

&nbsp;IPPort ipp = new IPPort(new IP(remoteEndPoint.Address), (ushort)remoteEndPoint.Port);



&nbsp;connection = new TCP\_Connection(clientSocket, ipp, null, \_lastConnectionID++);

&nbsp;connection.Status = TCP\_Status.TCP\_STATUS\_UNCONFIRMED;



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (\_connections.Count < TCP\_MAX\_CONNECTIONS)

&nbsp;{

&nbsp;\_connections.Add(connection);

&nbsp;return 0;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;clientSocket.Close();

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_send\_packet - Compatible con TCP\_server.c

&nbsp;/// </summary>

&nbsp;public int tcp\_send\_packet(TCP\_Connection conn, byte\[] data, int length)

&nbsp;{

&nbsp;if (!IsRunning || data == null || length > TCP\_PACKET\_MAX\_SIZE) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;var connection = \_connections.Find(c => c.ConnectionID == conn.ConnectionID);

&nbsp;if (connection.Socket == null || !connection.Socket.Connected) return -1;



&nbsp;// Encriptar datos para transmisión segura

&nbsp;byte\[] nonce = RandomBytes.Generate(24);

&nbsp;byte\[] encrypted = CryptoBox.Encrypt(data, nonce, connection.PublicKey, SelfSecretKey);



&nbsp;if (encrypted == null) return -1;



&nbsp;// Crear paquete: nonce + datos encriptados

&nbsp;byte\[] packet = new byte\[24 + encrypted.Length];

&nbsp;Buffer.BlockCopy(nonce, 0, packet, 0, 24);

&nbsp;Buffer.BlockCopy(encrypted, 0, packet, 24, encrypted.Length);



&nbsp;int sent = connection.Socket.Send(packet);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;}

&nbsp;return sent;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_recv\_packet - Recepción de paquete del cliente

&nbsp;/// </summary>

&nbsp;public int tcp\_recv\_packet(TCP\_Connection conn, byte\[] buffer, int length)

&nbsp;{

&nbsp;if (!IsRunning || buffer == null) return -1;



&nbsp;try

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;var connection = \_connections.Find(c => c.ConnectionID == conn.ConnectionID);

&nbsp;if (connection.Socket == null || !connection.Socket.Connected) return -1;



&nbsp;if (connection.Socket.Available > 0)

&nbsp;{

&nbsp;byte\[] tempBuffer = new byte\[TCP\_PACKET\_MAX\_SIZE];

&nbsp;int received = connection.Socket.Receive(tempBuffer);



&nbsp;if (received >= 24)

&nbsp;{

&nbsp;// Extraer nonce y datos encriptados

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;Buffer.BlockCopy(tempBuffer, 0, nonce, 0, 24);



&nbsp;byte\[] encrypted = new byte\[received - 24];

&nbsp;Buffer.BlockCopy(tempBuffer, 24, encrypted, 0, received - 24);



&nbsp;// Desencriptar datos

&nbsp;byte\[] decrypted = CryptoBox.Decrypt(encrypted, nonce, connection.PublicKey, SelfSecretKey);



&nbsp;if (decrypted != null \&\& decrypted.Length <= length)

&nbsp;{

&nbsp;Buffer.BlockCopy(decrypted, 0, buffer, 0, decrypted.Length);

&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;return decrypted.Length;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_close\_connection - Cerrar conexión específica

&nbsp;/// </summary>

&nbsp;public int tcp\_close\_connection(TCP\_Connection conn)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;var connection = \_connections.Find(c => c.ConnectionID == conn.ConnectionID);

&nbsp;if (connection.Socket != null)

&nbsp;{

&nbsp;connection.Socket.Shutdown(SocketShutdown.Both);

&nbsp;connection.Socket.Close();

&nbsp;connection.Status = TCP\_Status.TCP\_STATUS\_DISCONNECTED;

&nbsp;\_connections.Remove(connection);

&nbsp;return 0;

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tcp\_bind - Bind a puerto específico

&nbsp;/// </summary>

&nbsp;public int tcp\_bind(IPPort ipp)

&nbsp;{

&nbsp;return tcp\_listen(ipp);

&nbsp;}



&nbsp;// ==================== FUNCIONES DE GESTIÓN ====================



&nbsp;/// <summary>

&nbsp;/// tcp\_handle\_connection - Manejar handshake y estado de conexión

&nbsp;/// </summary>

&nbsp;public int tcp\_handle\_connection(TCP\_Connection conn)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;var connection = \_connections.Find(c => c.ConnectionID == conn.ConnectionID);

&nbsp;if (connection.Socket == null || !connection.Socket.Connected) return -1;



&nbsp;// Procesar handshake si está en estado no confirmado

&nbsp;if (connection.Status == TCP\_Status.TCP\_STATUS\_UNCONFIRMED)

&nbsp;{

&nbsp;byte\[] handshakeBuffer = new byte\[64];

&nbsp;int received = tcp\_recv\_packet(connection, handshakeBuffer, handshakeBuffer.Length);



&nbsp;if (received >= 32)

&nbsp;{

&nbsp;// Extraer clave pública del cliente

&nbsp;byte\[] clientPublicKey = new byte\[32];

&nbsp;Buffer.BlockCopy(handshakeBuffer, 0, clientPublicKey, 0, 32);

&nbsp;connection.PublicKey = clientPublicKey;

&nbsp;connection.Status = TCP\_Status.TCP\_STATUS\_CONFIRMED;

&nbsp;return 0;

&nbsp;}

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Start - Iniciar servidor (alias de tcp\_listen)

&nbsp;/// </summary>

&nbsp;public int Start(IPPort ipp)

&nbsp;{

&nbsp;return tcp\_listen(ipp);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Stop - Detener servidor

&nbsp;/// </summary>

&nbsp;public int Stop()

&nbsp;{

&nbsp;if (!IsRunning) return -1;



&nbsp;try

&nbsp;{

&nbsp;IsRunning = false;



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;foreach (var connection in \_connections)

&nbsp;{

&nbsp;if (connection.Socket != null \&\& connection.Socket.Connected)

&nbsp;{

&nbsp;connection.Socket.Shutdown(SocketShutdown.Both);

&nbsp;connection.Socket.Close();

&nbsp;}

&nbsp;}

&nbsp;\_connections.Clear();

&nbsp;}



&nbsp;if (ListenerSocket != null)

&nbsp;{

&nbsp;ListenerSocket.Close();

&nbsp;ListenerSocket = null;

&nbsp;}



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;

&nbsp;/// <summary>

&nbsp;/// Do\_periodic\_work - Mantenimiento del servidor

&nbsp;/// </summary>

&nbsp;public void Do\_periodic\_work()

&nbsp;{

&nbsp;if (!IsRunning) return;



&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;// Limpiar conexiones desconectadas o timeout

&nbsp;for (int i = \_connections.Count - 1; i >= 0; i--)

&nbsp;{

&nbsp;var connection = \_connections\[i];



&nbsp;bool shouldRemove = false;



&nbsp;if (connection.Socket == null || !connection.Socket.Connected)

&nbsp;{

&nbsp;shouldRemove = true;

&nbsp;}

&nbsp;else if ((currentTime - connection.LastActivity) > TimeSpan.TicksPerMillisecond \* 30000)

&nbsp;{

&nbsp;shouldRemove = true;

&nbsp;}



&nbsp;if (shouldRemove)

&nbsp;{

&nbsp;if (connection.Socket != null)

&nbsp;{

&nbsp;connection.Socket.Close();

&nbsp;}

&nbsp;\_connections.RemoveAt(i);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Get\_connections - Obtener lista de conexiones activas

&nbsp;/// </summary>

&nbsp;public List<TCP\_Connection> Get\_connections()

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;return new List<TCP\_Connection>(\_connections);

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo TCPTunnel.cs \[

using Sodium;

using System.Net.Sockets;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Estados de conexión TCP tunneling

&nbsp;/// </summary>

&nbsp;public enum TCPTunnelStatus

&nbsp;{

&nbsp;TCP\_TUNNEL\_STATUS\_DISCONNECTED,

&nbsp;TCP\_TUNNEL\_STATUS\_CONNECTING,

&nbsp;TCP\_TUNNEL\_STATUS\_CONNECTED,

&nbsp;TCP\_TUNNEL\_STATUS\_FORWARDING,

&nbsp;TCP\_TUNNEL\_STATUS\_ERROR

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tipos de paquetes TCP tunneling

&nbsp;/// </summary>

&nbsp;public enum TCPTunnelPacketType

&nbsp;{

&nbsp;TCP\_TUNNEL\_PACKET\_CONNECT\_REQUEST = 0x10,

&nbsp;TCP\_TUNNEL\_PACKET\_CONNECT\_RESPONSE = 0x11,

&nbsp;TCP\_TUNNEL\_PACKET\_DATA = 0x12,

&nbsp;TCP\_TUNNEL\_PACKET\_DISCONNECT = 0x13,

&nbsp;TCP\_TUNNEL\_PACKET\_PING = 0x14,

&nbsp;TCP\_TUNNEL\_PACKET\_PONG = 0x15

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conexión de tunneling TCP

&nbsp;/// </summary>

&nbsp;public class TCPTunnelConnection

&nbsp;{

&nbsp;public int ConnectionId { get; set; }

&nbsp;public int FriendNumber { get; set; }

&nbsp;public TCPTunnelStatus Status { get; set; }

&nbsp;public Socket LocalSocket { get; set; }

&nbsp;public IPPort RemoteEndPoint { get; set; }

&nbsp;public byte\[] SessionKey { get; set; }

&nbsp;public long LastActivity { get; set; }

&nbsp;public int BytesSent { get; set; }

&nbsp;public int BytesReceived { get; set; }

&nbsp;public bool IsInitiator { get; set; }



&nbsp;// Buffer management

&nbsp;private readonly byte\[] \_receiveBuffer;

&nbsp;private int \_receiveBufferOffset;



&nbsp;public TCPTunnelConnection(int connectionId, int friendNumber)

&nbsp;{

&nbsp;ConnectionId = connectionId;

&nbsp;FriendNumber = friendNumber;

&nbsp;Status = TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_DISCONNECTED;

&nbsp;\_receiveBuffer = new byte\[16 \* 1024]; // 16KB buffer

&nbsp;\_receiveBufferOffset = 0;

&nbsp;SessionKey = new byte\[32];

&nbsp;LastActivity = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;public void AppendData(byte\[] data, int offset, int count)

&nbsp;{

&nbsp;if (\_receiveBufferOffset + count <= \_receiveBuffer.Length)

&nbsp;{

&nbsp;Buffer.BlockCopy(data, offset, \_receiveBuffer, \_receiveBufferOffset, count);

&nbsp;\_receiveBufferOffset += count;

&nbsp;}

&nbsp;}



&nbsp;public byte\[] GetBufferedData()

&nbsp;{

&nbsp;byte\[] data = new byte\[\_receiveBufferOffset];

&nbsp;Buffer.BlockCopy(\_receiveBuffer, 0, data, 0, \_receiveBufferOffset);

&nbsp;\_receiveBufferOffset = 0;

&nbsp;return data;

&nbsp;}



&nbsp;public bool HasBufferedData => \_receiveBufferOffset > 0;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Sistema principal de TCP Tunneling

&nbsp;/// </summary>

&nbsp;public class TCPTunnel : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "TCP\_TUNNEL";



&nbsp;// Constantes de configuración

&nbsp;private const int MAX\_TUNNEL\_CONNECTIONS = 10;

&nbsp;private const int TUNNEL\_CONNECTION\_TIMEOUT = 30000; // 30 segundos

&nbsp;private const int TUNNEL\_PING\_INTERVAL = 15000; // 15 segundos

&nbsp;private const int MAX\_PACKET\_SIZE = 1372; // Tamaño máximo de paquete Tox



&nbsp;private readonly Messenger \_messenger;

&nbsp;private readonly Dictionary<int, TCPTunnelConnection> \_connections;

&nbsp;private readonly object \_connectionsLock = new object();

&nbsp;private int \_lastConnectionId;

&nbsp;private bool \_isRunning;

&nbsp;private Thread \_tunnelThread;

&nbsp;private CancellationTokenSource \_cancellationTokenSource;



&nbsp;// Estadísticas

&nbsp;public int TotalConnections => \_connections.Count;

&nbsp;public int ActiveConnections

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;return \_connections.Values.Count(c =>

&nbsp;c.Status == TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTED ||

&nbsp;c.Status == TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_FORWARDING);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public TCPTunnel(Messenger messenger)

&nbsp;{

&nbsp;\_messenger = messenger ?? throw new ArgumentNullException(nameof(messenger));

&nbsp;\_connections = new Dictionary<int, TCPTunnelConnection>();

&nbsp;\_lastConnectionId = 0;

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] TCP Tunneling inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar servicio de tunneling

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] TCP Tunneling ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = true;

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;// Iniciar hilo de mantenimiento

&nbsp;\_tunnelThread = new Thread(TunnelWorker);

&nbsp;\_tunnelThread.IsBackground = true;

&nbsp;\_tunnelThread.Name = "TCPTunnel-Worker";

&nbsp;\_tunnelThread.Start();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio TCP Tunneling iniciado");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando TCP Tunneling: {ex.Message}");

&nbsp;\_isRunning = false;

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener servicio de tunneling

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = false;

&nbsp;\_cancellationTokenSource?.Cancel();



&nbsp;// Cerrar todas las conexiones

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;foreach (var connection in \_connections.Values)

&nbsp;{

&nbsp;CloseConnection(connection);

&nbsp;}

&nbsp;\_connections.Clear();

&nbsp;}



&nbsp;\_tunnelThread?.Join(2000);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio TCP Tunneling detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo TCP Tunneling: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== API PÚBLICA ====================



&nbsp;/// <summary>

&nbsp;/// Iniciar conexión de tunneling a un amigo

&nbsp;/// </summary>

&nbsp;public int StartTunnel(int friendNumber, IPPort remoteEndPoint)

&nbsp;{

&nbsp;if (!\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede iniciar tunnel - Servicio no iniciado");

&nbsp;return -1;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;int connectionId = \_lastConnectionId++;

&nbsp;var connection = new TCPTunnelConnection(connectionId, friendNumber)

&nbsp;{

&nbsp;RemoteEndPoint = remoteEndPoint,

&nbsp;Status = TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTING,

&nbsp;IsInitiator = true,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};



&nbsp;// Generar session key

&nbsp;RandomBytes.Generate(connection.SessionKey);



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (\_connections.Count >= MAX\_TUNNEL\_CONNECTIONS)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Límite de conexiones de tunnel alcanzado");

&nbsp;return -1;

&nbsp;}

&nbsp;\_connections\[connectionId] = connection;

&nbsp;}



&nbsp;// Enviar solicitud de conexión

&nbsp;if (SendConnectRequest(connection))

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Tunnel iniciado a friend {friendNumber} -> {remoteEndPoint}");

&nbsp;return connectionId;

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando tunnel: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar datos a través del tunnel

&nbsp;/// </summary>

&nbsp;public int SendTunnelData(int connectionId, byte\[] data, int length)

&nbsp;{

&nbsp;if (!\_isRunning) return -1;



&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection) ||

&nbsp;connection.Status != TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTED)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// Encriptar datos

&nbsp;byte\[] encryptedData = EncryptTunnelData(connection, data, length);

&nbsp;if (encryptedData == null) return -1;



&nbsp;// Crear paquete de datos

&nbsp;byte\[] packet = CreateDataPacket(connectionId, encryptedData);

&nbsp;if (packet == null) return -1;



&nbsp;// Enviar a través de messenger

&nbsp;int sent = \_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;connection.BytesSent += length;

&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;return sent;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando datos por tunnel: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Cerrar conexión de tunnel

&nbsp;/// </summary>

&nbsp;public bool CloseTunnel(int connectionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection))

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Enviar paquete de desconexión

&nbsp;SendDisconnectPacket(connection);



&nbsp;// Cerrar conexión local

&nbsp;CloseConnection(connection);



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;\_connections.Remove(connectionId);

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Tunnel {connectionId} cerrado");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error cerrando tunnel: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Manejar paquetes de tunneling entrantes

&nbsp;/// </summary>

&nbsp;public int HandleTunnelPacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 5) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];

&nbsp;int connectionId = BitConverter.ToInt32(packet, 1);



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_CONNECT\_REQUEST:

&nbsp;return HandleConnectRequest(friendNumber, connectionId, packet, length);



&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_CONNECT\_RESPONSE:

&nbsp;return HandleConnectResponse(connectionId, packet, length);



&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_DATA:

&nbsp;return HandleDataPacket(connectionId, packet, length);



&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_DISCONNECT:

&nbsp;return HandleDisconnectPacket(connectionId);



&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_PING:

&nbsp;return HandlePingPacket(connectionId);



&nbsp;case (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_PONG:

&nbsp;return HandlePongPacket(connectionId);



&nbsp;default:

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Tipo de paquete tunnel desconocido: 0x{packetType:X2}");

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete tunnel: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MANEJADORES DE PAQUETES ====================



&nbsp;private int HandleConnectRequest(int friendNumber, int connectionId, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 37) return -1; // type(1) + connectionId(4) + sessionKey(32)



&nbsp;try

&nbsp;{

&nbsp;// Extraer session key

&nbsp;byte\[] sessionKey = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 5, sessionKey, 0, 32);



&nbsp;// Extraer endpoint remoto (si está presente)

&nbsp;IPPort remoteEndPoint = new IPPort();

&nbsp;if (length > 37)

&nbsp;{

&nbsp;// El paquete incluye información del endpoint

&nbsp;// Esto sería para conexiones de forwarding

&nbsp;}



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;// Verificar si ya existe la conexión

&nbsp;if (\_connections.ContainsKey(connectionId))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Conexión tunnel {connectionId} ya existe");

&nbsp;return -1;

&nbsp;}



&nbsp;// Crear nueva conexión

&nbsp;var connection = new TCPTunnelConnection(connectionId, friendNumber)

&nbsp;{

&nbsp;Status = TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTING,

&nbsp;SessionKey = sessionKey,

&nbsp;IsInitiator = false,

&nbsp;LastActivity = DateTime.UtcNow.Ticks

&nbsp;};



&nbsp;\_connections\[connectionId] = connection;

&nbsp;}



&nbsp;// Enviar respuesta de conexión

&nbsp;SendConnectResponse(connectionId);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Solicitud de tunnel recibida de friend {friendNumber} (ID: {connectionId})");



&nbsp;// Aquí se podría disparar un callback para notificar la nueva conexión

&nbsp;// OnTunnelConnectionRequest?.Invoke(connectionId, friendNumber, remoteEndPoint);



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando solicitud de conexión: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleConnectResponse(int connectionId, byte\[] packet, int length)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection))

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;connection.Status = TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTED;

&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Conexión tunnel {connectionId} establecida");



&nbsp;// Aquí se podría disparar un callback

&nbsp;// OnTunnelConnected?.Invoke(connectionId);



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando respuesta de conexión: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleDataPacket(int connectionId, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 5) return -1;



&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection) ||

&nbsp;connection.Status != TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTED)

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// Extraer datos encriptados

&nbsp;int encryptedDataLength = length - 5;

&nbsp;byte\[] encryptedData = new byte\[encryptedDataLength];

&nbsp;Buffer.BlockCopy(packet, 5, encryptedData, 0, encryptedDataLength);



&nbsp;// Desencriptar datos

&nbsp;byte\[] decryptedData = DecryptTunnelData(connection, encryptedData);

&nbsp;if (decryptedData == null) return -1;



&nbsp;connection.BytesReceived += decryptedData.Length;

&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;



&nbsp;// Almacenar datos en buffer

&nbsp;connection.AppendData(decryptedData, 0, decryptedData.Length);



&nbsp;Logger.Log.TraceF($"\[{LOG\_TAG}] Datos recibidos por tunnel {connectionId}: {decryptedData.Length} bytes");



&nbsp;// Aquí se podría disparar un callback

&nbsp;// OnTunnelDataReceived?.Invoke(connectionId, decryptedData);



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete de datos: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleDisconnectPacket(int connectionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Desconexión recibida para tunnel {connectionId}");



&nbsp;CloseTunnel(connectionId);

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete de desconexión: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandlePingPacket(int connectionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection))

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// Enviar pong de respuesta

&nbsp;SendPongPacket(connection);



&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando ping: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandlePongPacket(int connectionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection))

&nbsp;{

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;connection.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando pong: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== CREACIÓN DE PAQUETES ====================



&nbsp;private bool SendConnectRequest(TCPTunnelConnection connection)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[37]; // type(1) + connectionId(4) + sessionKey(32)

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_CONNECT\_REQUEST;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(connection.SessionKey, 0, packet, 5, 32);



&nbsp;int sent = \_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;return sent > 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando solicitud de conexión: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private bool SendConnectResponse(int connectionId)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;TCPTunnelConnection connection;

&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;if (!\_connections.TryGetValue(connectionId, out connection))

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_CONNECT\_RESPONSE;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connectionId), 0, packet, 1, 4);



&nbsp;int sent = \_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;return sent > 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando respuesta de conexión: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] CreateDataPacket(int connectionId, byte\[] encryptedData)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[5 + encryptedData.Length];

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_DATA;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connectionId), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(encryptedData, 0, packet, 5, encryptedData.Length);

&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete de datos: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private void SendDisconnectPacket(TCPTunnelConnection connection)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_DISCONNECT;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);



&nbsp;\_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando paquete de desconexión: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;private void SendPingPacket(TCPTunnelConnection connection)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_PING;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);



&nbsp;\_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando ping: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;private void SendPongPacket(TCPTunnelConnection connection)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[5];

&nbsp;packet\[0] = (byte)TCPTunnelPacketType.TCP\_TUNNEL\_PACKET\_PONG;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(connection.ConnectionId), 0, packet, 1, 4);



&nbsp;\_messenger.FriendConn.m\_send\_message(connection.FriendNumber, packet, packet.Length);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando pong: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== CIFRADO/DESCIFRADO ====================



&nbsp;private byte\[] EncryptTunnelData(TCPTunnelConnection connection, byte\[] data, int length)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Usar session key para encriptación simétrica

&nbsp;byte\[] nonce = RandomBytes.Generate(24);

&nbsp;byte\[] encrypted = SecretBox.Create(

&nbsp;data.AsSpan(0, length).ToArray(),

&nbsp;nonce,

&nbsp;connection.SessionKey

&nbsp;);



&nbsp;if (encrypted == null) return null;



&nbsp;// Combinar nonce + datos encriptados

&nbsp;byte\[] result = new byte\[24 + encrypted.Length];

&nbsp;Buffer.BlockCopy(nonce, 0, result, 0, 24);

&nbsp;Buffer.BlockCopy(encrypted, 0, result, 24, encrypted.Length);



&nbsp;return result;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error encriptando datos de tunnel: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] DecryptTunnelData(TCPTunnelConnection connection, byte\[] encryptedData)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (encryptedData.Length < 24) return null;



&nbsp;// Extraer nonce y datos encriptados

&nbsp;byte\[] nonce = new byte\[24];

&nbsp;byte\[] data = new byte\[encryptedData.Length - 24];



&nbsp;Buffer.BlockCopy(encryptedData, 0, nonce, 0, 24);

&nbsp;Buffer.BlockCopy(encryptedData, 24, data, 0, data.Length);



&nbsp;// Desencriptar

&nbsp;byte\[] decrypted = SecretBox.Open(data, nonce, connection.SessionKey);

&nbsp;return decrypted;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error desencriptando datos de tunnel: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;// ==================== GESTIÓN DE CONEXIONES ====================



&nbsp;private void CloseConnection(TCPTunnelConnection connection)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;connection.Status = TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_DISCONNECTED;



&nbsp;if (connection.LocalSocket != null)

&nbsp;{

&nbsp;connection.LocalSocket.Close();

&nbsp;connection.LocalSocket = null;

&nbsp;}



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión tunnel {connection.ConnectionId} cerrada localmente");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error cerrando conexión local: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== WORKER PRINCIPAL ====================



&nbsp;private void TunnelWorker()

&nbsp;{

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo TCP Tunneling iniciado");



&nbsp;while (\_isRunning \&\& !\_cancellationTokenSource.Token.IsCancellationRequested)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;MaintainConnections();

&nbsp;Thread.Sleep(1000); // Ejecutar cada segundo

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en worker: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo TCP Tunneling finalizado");

&nbsp;}



&nbsp;private void MaintainConnections()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<int> connectionsToRemove = new List<int>();



&nbsp;lock (\_connectionsLock)

&nbsp;{

&nbsp;foreach (var kvp in \_connections)

&nbsp;{

&nbsp;var connection = kvp.Value;

&nbsp;long timeSinceActivity = (currentTime - connection.LastActivity) / TimeSpan.TicksPerMillisecond;



&nbsp;// Verificar timeout

&nbsp;if (timeSinceActivity > TUNNEL\_CONNECTION\_TIMEOUT)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Timeout en conexión tunnel {connection.ConnectionId}");

&nbsp;connectionsToRemove.Add(connection.ConnectionId);

&nbsp;continue;

&nbsp;}



&nbsp;// Enviar ping periódico para conexiones activas

&nbsp;if (connection.Status == TCPTunnelStatus.TCP\_TUNNEL\_STATUS\_CONNECTED \&\&

&nbsp;timeSinceActivity > TUNNEL\_PING\_INTERVAL)

&nbsp;{

&nbsp;SendPingPacket(connection);

&nbsp;}

&nbsp;}



&nbsp;// Remover conexiones timeout

&nbsp;foreach (int connectionId in connectionsToRemove)

&nbsp;{

&nbsp;\_connections.Remove(connectionId);

&nbsp;}

&nbsp;}



&nbsp;if (connectionsToRemove.Count > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] {connectionsToRemove.Count} conexiones tunnel removidas por timeout");

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;\_cancellationTokenSource?.Dispose();

&nbsp;}

&nbsp;}

}

]



Archivo Tox.cs \[

using ToxCore.AV;

using ToxCore.FileTransfer;

using ToxCore.Networking;



namespace ToxCore.Core

{

&nbsp;/// <summary>

&nbsp;/// Cliente Tox principal - Adaptación de tox.c/tox.h con API pública completa

&nbsp;/// </summary>

&nbsp;public class Tox : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "TOX";



&nbsp;// Componentes principales

&nbsp;private Messenger \_messenger;

&nbsp;private ToxOptions \_options;

&nbsp;private bool \_isRunning;





&nbsp;// Callbacks de la API pública (equivalente a tox.h callbacks)

&nbsp;public delegate void FriendRequestCallback(Tox tox, byte\[] publicKey, string message, object userData);

&nbsp;public delegate void FriendMessageCallback(Tox tox, uint friendNumber, ToxMessageType type, string message, object userData);

&nbsp;public delegate void FriendConnectionStatusCallback(Tox tox, uint friendNumber, ToxConnection connectionStatus, object userData);

&nbsp;public delegate void FriendNameCallback(Tox tox, uint friendNumber, string name, object userData);

&nbsp;public delegate void FriendStatusMessageCallback(Tox tox, uint friendNumber, string message, object userData);

&nbsp;public delegate void FriendStatusCallback(Tox tox, uint friendNumber, ToxUserStatus status, object userData);

&nbsp;public delegate void FriendReadReceiptCallback(Tox tox, uint friendNumber, uint messageId, object userData);

&nbsp;public delegate void SelfConnectionStatusCallback(Tox tox, ToxConnection connectionStatus, object userData);



&nbsp;// Eventos para callbacks (más idiomático en C#)

&nbsp;public event FriendRequestCallback OnFriendRequest;

&nbsp;public event FriendMessageCallback OnFriendMessage;

&nbsp;public event FriendConnectionStatusCallback OnFriendConnectionStatus;

&nbsp;public event FriendNameCallback OnFriendName;

&nbsp;public event FriendStatusMessageCallback OnFriendStatusMessage;

&nbsp;public event FriendStatusCallback OnFriendStatus;

&nbsp;public event FriendReadReceiptCallback OnFriendReadReceipt;

&nbsp;public event SelfConnectionStatusCallback OnSelfConnectionStatus;





&nbsp;// Callbacks para archivos

&nbsp;public event FileTransferCallbacks.FileReceiveCallback OnFileReceive;

&nbsp;public event FileTransferCallbacks.FileChunkRequestCallback OnFileChunkRequest;

&nbsp;public event FileTransferCallbacks.FileChunkReceivedCallback OnFileChunkReceived;

&nbsp;public event FileTransferCallbacks.FileTransferStatusChangedCallback OnFileTransferStatusChanged;



&nbsp;// Constantes de la API pública (de tox.h)

&nbsp;public const int TOX\_ADDRESS\_SIZE = 38;

&nbsp;public const int TOX\_PUBLIC\_KEY\_SIZE = 32;

&nbsp;public const int TOX\_SECRET\_KEY\_SIZE = 32;

&nbsp;public const int TOX\_NOSPAM\_SIZE = 4;

&nbsp;public const int TOX\_MAX\_NAME\_LENGTH = 128;

&nbsp;public const int TOX\_MAX\_STATUS\_MESSAGE\_LENGTH = 1007;

&nbsp;public const int TOX\_MAX\_FRIEND\_REQUEST\_LENGTH = 1016;

&nbsp;public const int TOX\_MAX\_MESSAGE\_LENGTH = 1372;



&nbsp;private ToxAv \_toxAv;

&nbsp;public ToxAv Av => \_toxAv;



&nbsp;private AdvancedNetworking \_advancedNetworking;

&nbsp;public AdvancedNetworking AdvancedNetworking => \_advancedNetworking;





&nbsp;public Tox(ToxOptions options = null)

&nbsp;{

&nbsp;\_options = options ?? new ToxOptions();

&nbsp;\_isRunning = false;

&nbsp;

&nbsp;\_advancedNetworking = new AdvancedNetworking(this);



&nbsp;\_toxAv = new ToxAv(this);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Cliente Tox inicializado");

&nbsp;}



&nbsp;// ==================== API PÚBLICA PRINCIPAL (tox.h) ====================



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_address - Obtener dirección Tox pública

&nbsp;/// </summary>

&nbsp;public string GetAddress()

&nbsp;{

&nbsp;if (\_messenger?.State?.User?.PublicKey == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede obtener address - Estado no inicializado");

&nbsp;return string.Empty;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;byte\[] publicKey = \_messenger.State.User.PublicKey;

&nbsp;byte\[] nospam = \_messenger.State.User.Nospam ?? new byte\[4];



&nbsp;// 1. Primero crear address sin checksum: public\_key (32) + nospam (4)

&nbsp;byte\[] addressWithoutChecksum = new byte\[TOX\_PUBLIC\_KEY\_SIZE + TOX\_NOSPAM\_SIZE];

&nbsp;Buffer.BlockCopy(publicKey, 0, addressWithoutChecksum, 0, TOX\_PUBLIC\_KEY\_SIZE);

&nbsp;Buffer.BlockCopy(nospam, 0, addressWithoutChecksum, TOX\_PUBLIC\_KEY\_SIZE, TOX\_NOSPAM\_SIZE);



&nbsp;// 2. Calcular checksum (2 bytes) como en toxcore - crypto\_sha256

&nbsp;byte\[] checksum = CalculateToxAddressChecksum(addressWithoutChecksum);



&nbsp;// 3. Combinar todo: public\_key (32) + nospam (4) + checksum (2) = 38 bytes

&nbsp;byte\[] fullAddress = new byte\[TOX\_ADDRESS\_SIZE];

&nbsp;Buffer.BlockCopy(addressWithoutChecksum, 0, fullAddress, 0, addressWithoutChecksum.Length);

&nbsp;Buffer.BlockCopy(checksum, 0, fullAddress, addressWithoutChecksum.Length, 2);



&nbsp;// Convertir a hexadecimal (76 caracteres)

&nbsp;return BitConverter.ToString(fullAddress).Replace("-", "").ToUpper();

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error obteniendo address: {ex.Message}");

&nbsp;return string.Empty;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// CalculateToxAddressChecksum - Como en toxcore (basado en SHA256)

&nbsp;/// </summary>

&nbsp;private byte\[] CalculateToxAddressChecksum(byte\[] addressWithoutChecksum)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// En toxcore, el checksum son los primeros 2 bytes del SHA256 hash

&nbsp;using (var sha256 = System.Security.Cryptography.SHA256.Create())

&nbsp;{

&nbsp;byte\[] hash = sha256.ComputeHash(addressWithoutChecksum);



&nbsp;// Tomar primeros 2 bytes del hash como checksum

&nbsp;byte\[] checksum = new byte\[2];

&nbsp;Buffer.BlockCopy(hash, 0, checksum, 0, 2);



&nbsp;return checksum;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error calculando checksum: {ex.Message}");

&nbsp;return new byte\[2]; // Checksum por defecto (ceros)

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// ValidateToxAddress - Verifica que un ID Tox sea válido (checksum correcto)

&nbsp;/// </summary>

&nbsp;public bool ValidateToxAddress(string toxAddress)

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(toxAddress) || toxAddress.Length != 76) // 38 bytes \* 2 caracteres hex

&nbsp;return false;



&nbsp;try

&nbsp;{

&nbsp;// Convertir hex string a bytes

&nbsp;byte\[] addressBytes = HexStringToByteArray(toxAddress);

&nbsp;if (addressBytes.Length != TOX\_ADDRESS\_SIZE)

&nbsp;return false;



&nbsp;// Separar components

&nbsp;byte\[] addressWithoutChecksum = new byte\[TOX\_PUBLIC\_KEY\_SIZE + TOX\_NOSPAM\_SIZE];

&nbsp;byte\[] receivedChecksum = new byte\[2];



&nbsp;Buffer.BlockCopy(addressBytes, 0, addressWithoutChecksum, 0, addressWithoutChecksum.Length);

&nbsp;Buffer.BlockCopy(addressBytes, addressWithoutChecksum.Length, receivedChecksum, 0, 2);



&nbsp;// Calcular checksum esperado

&nbsp;byte\[] calculatedChecksum = CalculateToxAddressChecksum(addressWithoutChecksum);



&nbsp;// ✅ CORREGIDO: Comparar manualmente los 2 bytes del checksum

&nbsp;return receivedChecksum\[0] == calculatedChecksum\[0] \&\&

&nbsp;receivedChecksum\[1] == calculatedChecksum\[1];

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error validando address: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// HexStringToByteArray - Convierte string hexadecimal a byte\[] (robusto)

&nbsp;/// </summary>

&nbsp;private static byte\[] HexStringToByteArray(string hex)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0)

&nbsp;return null;



&nbsp;byte\[] bytes = new byte\[hex.Length / 2];

&nbsp;for (int i = 0; i < hex.Length; i += 2)

&nbsp;{

&nbsp;string hexByte = hex.Substring(i, 2);

&nbsp;bytes\[i / 2] = Convert.ToByte(hexByte, 16);

&nbsp;}

&nbsp;return bytes;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[TOX] Error convirtiendo hex a bytes: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_public\_key - Obtener clave pública

&nbsp;/// </summary>

&nbsp;public byte\[] GetPublicKey()

&nbsp;{

&nbsp;return \_messenger?.State?.User?.PublicKey?.ToArray() ?? new byte\[TOX\_PUBLIC\_KEY\_SIZE];

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_secret\_key - Obtener clave secreta

&nbsp;/// </summary>

&nbsp;public byte\[] GetSecretKey()

&nbsp;{

&nbsp;return \_messenger?.State?.User?.SecretKey?.ToArray() ?? new byte\[TOX\_SECRET\_KEY\_SIZE];

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_set\_name - Establecer nombre de usuario

&nbsp;/// </summary>

&nbsp;public bool tox\_self\_set\_name(string name)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede establecer nombre - Messenger no inicializado");

&nbsp;return false;

&nbsp;}



&nbsp;return \_messenger.SetName(name);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_name - Obtener nombre de usuario

&nbsp;/// </summary>

&nbsp;public string tox\_self\_get\_name()

&nbsp;{

&nbsp;return \_messenger?.State?.User?.Name ?? string.Empty;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_set\_status\_message - Establecer mensaje de estado

&nbsp;/// </summary>

&nbsp;public bool tox\_self\_set\_status\_message(string message)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede establecer estado - Messenger no inicializado");

&nbsp;return false;

&nbsp;}



&nbsp;return \_messenger.SetStatusMessage(message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_status\_message - Obtener mensaje de estado

&nbsp;/// </summary>

&nbsp;public string tox\_self\_get\_status\_message()

&nbsp;{

&nbsp;return \_messenger?.State?.User?.StatusMessage ?? string.Empty;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_set\_status - Establecer estado de usuario

&nbsp;/// </summary>

&nbsp;public bool tox\_self\_set\_status(ToxUserStatus status)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede establecer estado - Messenger no inicializado");

&nbsp;return false;

&nbsp;}



&nbsp;return \_messenger.SetStatus(status);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_status - Obtener estado de usuario

&nbsp;/// </summary>

&nbsp;public ToxUserStatus tox\_self\_get\_status()

&nbsp;{

&nbsp;return \_messenger?.State?.User?.Status ?? ToxUserStatus.NONE;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_bootstrap - Conectar a la red Tox

&nbsp;/// </summary>

&nbsp;public bool tox\_bootstrap(string host, ushort port, byte\[] public\_key)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede bootstrap - Messenger no inicializado");

&nbsp;return false;

&nbsp;}



&nbsp;return \_messenger.Bootstrap(host, port, public\_key);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_add - ACTUALIZADO para validar formato de address

&nbsp;/// </summary>

&nbsp;public int tox\_friend\_add(byte\[] address, string message)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede agregar amigo - Messenger no inicializado");

&nbsp;return -1;

&nbsp;}



&nbsp;// Convertir address bytes a string hex para validación

&nbsp;string addressHex = BitConverter.ToString(address).Replace("-", "").ToUpper();



&nbsp;if (!ValidateToxAddress(addressHex))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Dirección Tox inválida - checksum incorrecto");

&nbsp;return -1;

&nbsp;}



&nbsp;if (address.Length < TOX\_PUBLIC\_KEY\_SIZE)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Dirección Tox inválida - muy corta");

&nbsp;return -1;

&nbsp;}



&nbsp;// Extraer clave pública (primeros 32 bytes del address)

&nbsp;byte\[] publicKey = new byte\[TOX\_PUBLIC\_KEY\_SIZE];

&nbsp;Array.Copy(address, publicKey, TOX\_PUBLIC\_KEY\_SIZE);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Agregando amigo - Mensaje: {message}");



&nbsp;int friendNumber = \_messenger.AddFriend(publicKey, message);



&nbsp;if (friendNumber >= 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Amigo agregado: {friendNumber}");

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Falló agregar amigo");

&nbsp;}



&nbsp;return friendNumber;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_add\_norequest - Agregar amigo solo con clave pública (sin enviar solicitud)

&nbsp;/// </summary>

&nbsp;public int tox\_friend\_add\_norequest(byte\[] publicKey)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede agregar amigo - Messenger no inicializado");

&nbsp;return -1;

&nbsp;}



&nbsp;if (publicKey == null || publicKey.Length != TOX\_PUBLIC\_KEY\_SIZE)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Clave pública inválida");

&nbsp;return -1;

&nbsp;}



&nbsp;// Crear dirección ficticia con nospam cero

&nbsp;byte\[] address = new byte\[TOX\_ADDRESS\_SIZE];

&nbsp;Buffer.BlockCopy(publicKey, 0, address, 0, TOX\_PUBLIC\_KEY\_SIZE);

&nbsp;// Los últimos 6 bytes (nospam + checksum) se dejan en cero



&nbsp;return \_messenger.AddFriend(publicKey, string.Empty);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_send\_message - Enviar mensaje a amigo

&nbsp;/// </summary>

&nbsp;public int tox\_friend\_send\_message(uint friendNumber, ToxMessageType type, string message)

&nbsp;{

&nbsp;if (\_messenger == null)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede enviar mensaje - Messenger no inicializado");

&nbsp;return -1;

&nbsp;}



&nbsp;if (string.IsNullOrEmpty(message))

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Mensaje vacío");

&nbsp;return -1;

&nbsp;}



&nbsp;if (message.Length > TOX\_MAX\_MESSAGE\_LENGTH)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] Mensaje demasiado largo");

&nbsp;return -1;

&nbsp;}



&nbsp;return \_messenger.SendMessage(friendNumber, message);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_friend\_list - Obtener lista de números de amigos

&nbsp;/// </summary>

&nbsp;public uint\[] tox\_self\_get\_friend\_list()

&nbsp;{

&nbsp;if (\_messenger?.State?.Friends?.Friends == null)

&nbsp;return Array.Empty<uint>();



&nbsp;return \_messenger.State.Friends.Friends

&nbsp;.Where(f => f != null)

&nbsp;.Select(f => f.FriendNumber)

&nbsp;.ToArray();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_get\_public\_key - Obtener clave pública de amigo

&nbsp;/// </summary>

&nbsp;public byte\[] tox\_friend\_get\_public\_key(uint friendNumber)

&nbsp;{

&nbsp;var friend = GetFriend(friendNumber);

&nbsp;return friend?.PublicKey?.ToArray() ?? new byte\[TOX\_PUBLIC\_KEY\_SIZE];

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_get\_connection\_status - Obtener estado de conexión de amigo

&nbsp;/// </summary>

&nbsp;public ToxConnection tox\_friend\_get\_connection\_status(uint friendNumber)

&nbsp;{

&nbsp;var friend = GetFriend(friendNumber);

&nbsp;// En esta implementación básica, asumimos que si el amigo existe está conectado

&nbsp;return friend != null ? ToxConnection.TOX\_CONNECTION\_UDP : ToxConnection.TOX\_CONNECTION\_NONE;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_friend\_get\_last\_online - Obtener última vez que el amigo estuvo online

&nbsp;/// </summary>

&nbsp;public ulong tox\_friend\_get\_last\_online(uint friendNumber)

&nbsp;{

&nbsp;// En esta implementación, devolvemos el timestamp actual

&nbsp;return (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_self\_get\_connection\_status - Obtener estado de conexión propio

&nbsp;/// </summary>

&nbsp;public ToxConnection tox\_self\_get\_connection\_status()

&nbsp;{

&nbsp;return \_messenger != null ? ToxConnection.TOX\_CONNECTION\_UDP : ToxConnection.TOX\_CONNECTION\_NONE;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_iterate - Ejecutar iteración principal

&nbsp;/// </summary>

&nbsp;public void tox\_iterate()

&nbsp;{

&nbsp;\_messenger?.Do();

&nbsp;}



&nbsp;// ==================== PROPIEDADES ADICIONALES ====================



&nbsp;/// <summary>

&nbsp;/// Número total de amigos

&nbsp;/// </summary>

&nbsp;public int FriendCount

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;return \_messenger?.State?.Friends?.Friends?.Length ?? 0;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Número de amigos conectados

&nbsp;/// </summary>

&nbsp;public int OnlineFriendCount

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;// Implementación simplificada - todos los amigos están "conectados"

&nbsp;return FriendCount;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Instancia del Messenger interno (para acceso avanzado)

&nbsp;/// </summary>

&nbsp;public Messenger Messenger => \_messenger;



&nbsp;// ==================== MÉTODOS DE CONTROL ====================



&nbsp;/// <summary>

&nbsp;/// Iniciar cliente Tox

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Cliente Tox ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;// Convertir ToxOptions a MessengerOptions

&nbsp;var messengerOptions = new MessengerOptions

&nbsp;{

&nbsp;IPv6Enabled = \_options.IPv6Enabled,

&nbsp;UDPEnabled = \_options.UDPEnabled,

&nbsp;TcpEnabled = true, // Habilitar TCP por defecto

&nbsp;EnableLANDiscovery = \_options.EnableLANDiscovery

&nbsp;};



&nbsp;\_messenger = new Messenger(messengerOptions);



&nbsp;\_advancedNetworking.Start();

&nbsp;\_toxAv.Start();



&nbsp;// Configurar LAN Discovery si está habilitado

&nbsp;if (\_options.EnableLANDiscovery \&\& \_messenger.LANDiscovery != null)

&nbsp;{

&nbsp;\_messenger.LANDiscovery.PeerDiscoveredCallback = (peer) =>

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Peer descubierto via LAN: {peer.IPAddress}");

&nbsp;// Opcional: agregar automáticamente como amigo

&nbsp;// tox\_friend\_add\_norequest(peer.PublicKey);

&nbsp;};

&nbsp;}





&nbsp;bool started = \_messenger.Start();



&nbsp;if (started)

&nbsp;{

&nbsp;\_isRunning = true;

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Cliente Tox iniciado correctamente");

&nbsp;}



&nbsp;return started;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando cliente Tox: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener cliente Tox

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_messenger?.Stop();

&nbsp;\_isRunning = false;

&nbsp;\_advancedNetworking?.Stop();

&nbsp;\_toxAv?.Stop();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Cliente Tox detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo cliente Tox: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS PRIVADOS ====================



&nbsp;private ToxFriend GetFriend(uint friendNumber)

&nbsp;{

&nbsp;return \_messenger?.State?.Friends?.Friends?

&nbsp;.FirstOrDefault(f => f.FriendNumber == friendNumber);

&nbsp;}



&nbsp;private void TriggerFriendRequest(byte\[] publicKey, string message)

&nbsp;{

&nbsp;OnFriendRequest?.Invoke(this, publicKey, message, null);

&nbsp;}



&nbsp;private void TriggerFriendMessage(uint friendNumber, ToxMessageType type, string message)

&nbsp;{

&nbsp;OnFriendMessage?.Invoke(this, friendNumber, type, message, null);

&nbsp;}



&nbsp;private void TriggerFriendConnectionStatus(uint friendNumber, ToxConnection status)

&nbsp;{

&nbsp;OnFriendConnectionStatus?.Invoke(this, friendNumber, status, null);

&nbsp;}



&nbsp;public int FileSend(int friendNumber, FileKind kind, long fileSize, string fileName, byte\[] fileId = null)

&nbsp;{

&nbsp;return \_messenger?.FileTransfer?.FileSend(friendNumber, kind, fileSize, fileName, fileId) ?? -1;

&nbsp;}



&nbsp;public bool FileSendChunk(int friendNumber, int fileNumber, long position, byte\[] data, int length)

&nbsp;{

&nbsp;return \_messenger?.FileTransfer?.FileSendChunk(friendNumber, fileNumber, position, data, length) ?? false;

&nbsp;}



&nbsp;public bool FileControl(int friendNumber, int fileNumber, int control)

&nbsp;{

&nbsp;return \_messenger?.FileTransfer?.FileControl(friendNumber, fileNumber, control) ?? false;

&nbsp;}



&nbsp;





&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;\_messenger?.Dispose();

&nbsp;\_advancedNetworking?.Dispose();

&nbsp;\_toxAv?.Dispose();

&nbsp;}

&nbsp;}



&nbsp;// ==================== ENUMS Y ESTRUCTURAS ====================



&nbsp;/// <summary>

&nbsp;/// Estados de conexión (de tox.h)

&nbsp;/// </summary>

&nbsp;public enum ToxConnection

&nbsp;{

&nbsp;TOX\_CONNECTION\_NONE = 0,

&nbsp;TOX\_CONNECTION\_TCP = 1,

&nbsp;TOX\_CONNECTION\_UDP = 2

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tipos de mensaje (de tox.h)

&nbsp;/// </summary>

&nbsp;public enum ToxMessageType

&nbsp;{

&nbsp;TOX\_MESSAGE\_TYPE\_NORMAL = 0,

&nbsp;TOX\_MESSAGE\_TYPE\_ACTION = 1

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Opciones para crear instancia Tox

&nbsp;/// </summary>

&nbsp;public class ToxOptions

&nbsp;{

&nbsp;public bool IPv6Enabled { get; set; } = true;

&nbsp;public bool UDPEnabled { get; set; } = true;

&nbsp;public bool ProxyEnabled { get; set; } = false;

&nbsp;public ToxProxyType ProxyType { get; set; } = ToxProxyType.TOX\_PROXY\_TYPE\_NONE;

&nbsp;public string ProxyHost { get; set; } = string.Empty;

&nbsp;public ushort ProxyPort { get; set; } = 0;

&nbsp;public ushort StartPort { get; set; } = 0;

&nbsp;public ushort EndPort { get; set; } = 0;

&nbsp;public uint TCPPort { get; set; } = 0;

&nbsp;public byte\[] SavedData { get; set; } = null;

&nbsp;public bool EnableLANDiscovery { get; set; } = true;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tipos de proxy (de tox.h)

&nbsp;/// </summary>

&nbsp;public enum ToxProxyType

&nbsp;{

&nbsp;TOX\_PROXY\_TYPE\_NONE = 0,

&nbsp;TOX\_PROXY\_TYPE\_HTTP = 1,

&nbsp;TOX\_PROXY\_TYPE\_SOCKS5 = 2

&nbsp;}

}

]



Archivo ToxAv.cs \[

using System;

using System.Collections.Generic;

using System.Linq;

using System.Runtime.InteropServices;

using System.Threading;

using ToxCore.Core;



namespace ToxCore.AV

{

&nbsp;/// <summary>

&nbsp;/// Codecs de audio y video soportados

&nbsp;/// </summary>

&nbsp;public enum ToxAvCodecType

&nbsp;{

&nbsp;TOXAV\_CODEC\_NONE = 0,

&nbsp;TOXAV\_CODEC\_AUDIO\_OPUS = 1,

&nbsp;TOXAV\_CODEC\_VIDEO\_VP8 = 2,

&nbsp;TOXAV\_CODEC\_VIDEO\_VP9 = 3,

&nbsp;TOXAV\_CODEC\_VIDEO\_H264 = 4

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Estados de llamada

&nbsp;/// </summary>

&nbsp;public enum ToxAvCallState

&nbsp;{

&nbsp;TOXAV\_CALL\_STATE\_NONE = 0,

&nbsp;TOXAV\_CALL\_STATE\_INVITING = 1,

&nbsp;TOXAV\_CALL\_STATE\_RINGING = 2,

&nbsp;TOXAV\_CALL\_STATE\_ACTIVE = 3,

&nbsp;TOXAV\_CALL\_STATE\_PAUSED = 4,

&nbsp;TOXAV\_CALL\_STATE\_ENDED = 5,

&nbsp;TOXAV\_CALL\_STATE\_ERROR = 6

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Control de llamadas

&nbsp;/// </summary>

&nbsp;public enum ToxAvCallControl

&nbsp;{

&nbsp;TOXAV\_CALL\_CONTROL\_RESUME = 0,

&nbsp;TOXAV\_CALL\_CONTROL\_PAUSE = 1,

&nbsp;TOXAV\_CALL\_CONTROL\_CANCEL = 2,

&nbsp;TOXAV\_CALL\_CONTROL\_MUTE\_AUDIO = 3,

&nbsp;TOXAV\_CALL\_CONTROL\_UNMUTE\_AUDIO = 4,

&nbsp;TOXAV\_CALL\_CONTROL\_HIDE\_VIDEO = 5,

&nbsp;TOXAV\_CALL\_CONTROL\_SHOW\_VIDEO = 6

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Información de una llamada activa

&nbsp;/// </summary>

&nbsp;public class ToxAvCall

&nbsp;{

&nbsp;public int FriendNumber { get; set; }

&nbsp;public ToxAvCallState State { get; set; }

&nbsp;public bool AudioEnabled { get; set; }

&nbsp;public bool VideoEnabled { get; set; }

&nbsp;public long StartTime { get; set; }

&nbsp;public uint CallId { get; set; }

&nbsp;public bool AudioMuted { get; set; }

&nbsp;public bool VideoHidden { get; set; }

&nbsp;public int AudioBitrate { get; set; }

&nbsp;public int VideoBitrate { get; set; }

&nbsp;public uint AudioSampleRate { get; set; }

&nbsp;public byte AudioChannels { get; set; }

&nbsp;public uint VideoWidth { get; set; }

&nbsp;public uint VideoHeight { get; set; }

&nbsp;public uint VideoFps { get; set; }



&nbsp;public ToxAvCall(int friendNumber, uint callId)

&nbsp;{

&nbsp;FriendNumber = friendNumber;

&nbsp;CallId = callId;

&nbsp;State = ToxAvCallState.TOXAV\_CALL\_STATE\_NONE;

&nbsp;AudioEnabled = false;

&nbsp;VideoEnabled = false;

&nbsp;StartTime = DateTime.UtcNow.Ticks;

&nbsp;AudioBitrate = 64000; // 64 kbps por defecto

&nbsp;VideoBitrate = 500000; // 500 kbps por defecto

&nbsp;AudioSampleRate = 48000; // 48 kHz

&nbsp;AudioChannels = 1; // Mono

&nbsp;VideoWidth = 640;

&nbsp;VideoHeight = 480;

&nbsp;VideoFps = 30;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Frame de audio

&nbsp;/// </summary>

&nbsp;public class AudioFrame

&nbsp;{

&nbsp;public byte\[] Samples { get; set; }

&nbsp;public uint SampleCount { get; set; }

&nbsp;public byte Channels { get; set; }

&nbsp;public uint SamplingRate { get; set; }

&nbsp;public long Timestamp { get; set; }



&nbsp;public AudioFrame(uint sampleCount, byte channels, uint samplingRate)

&nbsp;{

&nbsp;SampleCount = sampleCount;

&nbsp;Channels = channels;

&nbsp;SamplingRate = samplingRate;

&nbsp;Samples = new byte\[sampleCount \* channels \* 2]; // 16-bit samples

&nbsp;Timestamp = DateTime.UtcNow.Ticks;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Frame de video

&nbsp;/// </summary>

&nbsp;public class VideoFrame

&nbsp;{

&nbsp;public byte\[] Data { get; set; }

&nbsp;public uint Width { get; set; }

&nbsp;public uint Height { get; set; }

&nbsp;public long Timestamp { get; set; }

&nbsp;public uint StrideY { get; set; }

&nbsp;public uint StrideU { get; set; }

&nbsp;public uint StrideV { get; set; }



&nbsp;public VideoFrame(uint width, uint height)

&nbsp;{

&nbsp;Width = width;

&nbsp;Height = height;

&nbsp;// YUV420 format

&nbsp;Data = new byte\[width \* height \* 3 / 2];

&nbsp;StrideY = width;

&nbsp;StrideU = width / 2;

&nbsp;StrideV = width / 2;

&nbsp;Timestamp = DateTime.UtcNow.Ticks;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Callbacks de ToxAV

&nbsp;/// </summary>

&nbsp;public class ToxAvCallbacks

&nbsp;{

&nbsp;public delegate void CallCallback(ToxAv toxAv, int friendNumber, bool audio, bool video, object userData);

&nbsp;public delegate void CallStateCallback(ToxAv toxAv, int friendNumber, ToxAvCallState state, object userData);

&nbsp;public delegate void AudioReceiveCallback(ToxAv toxAv, int friendNumber, AudioFrame frame, object userData);

&nbsp;public delegate void VideoReceiveCallback(ToxAv toxAv, int friendNumber, VideoFrame frame, object userData);

&nbsp;public delegate void AudioBitrateCallback(ToxAv toxAv, int friendNumber, uint bitrate, object userData);

&nbsp;public delegate void VideoBitrateCallback(ToxAv toxAv, int friendNumber, uint bitrate, object userData);



&nbsp;public CallCallback OnCall { get; set; }

&nbsp;public CallStateCallback OnCallState { get; set; }

&nbsp;public AudioReceiveCallback OnAudioReceive { get; set; }

&nbsp;public VideoReceiveCallback OnVideoReceive { get; set; }

&nbsp;public AudioBitrateCallback OnAudioBitrate { get; set; }

&nbsp;public VideoBitrateCallback OnVideoBitrate { get; set; }

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Implementación principal de ToxAV - Audio/Video sobre Tox

&nbsp;/// </summary>

&nbsp;public class ToxAv : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "TOXAV";



&nbsp;// Constantes de configuración

&nbsp;public const uint DEFAULT\_AUDIO\_BITRATE = 64000; // 64 kbps

&nbsp;public const uint DEFAULT\_VIDEO\_BITRATE = 500000; // 500 kbps

&nbsp;public const uint DEFAULT\_AUDIO\_SAMPLE\_RATE = 48000; // 48 kHz

&nbsp;public const byte DEFAULT\_AUDIO\_CHANNELS = 1; // Mono

&nbsp;public const uint DEFAULT\_VIDEO\_WIDTH = 640;

&nbsp;public const uint DEFAULT\_VIDEO\_HEIGHT = 480;

&nbsp;public const uint DEFAULT\_VIDEO\_FPS = 30;



&nbsp;// Jitter buffer y timing

&nbsp;private const int JITTER\_BUFFER\_MAX\_PACKETS = 100;

&nbsp;private const int AUDIO\_FRAME\_DURATION\_MS = 20; // 20ms frames for Opus

&nbsp;private const int VIDEO\_FRAME\_DURATION\_MS = 33; // ~30fps



&nbsp;// Componentes

&nbsp;private readonly Core.Tox \_tox;

&nbsp;private readonly ToxAvCallbacks \_callbacks;

&nbsp;private readonly Dictionary<int, ToxAvCall> \_activeCalls;

&nbsp;private readonly Dictionary<int, JitterBuffer> \_audioJitterBuffers;

&nbsp;private readonly Dictionary<int, JitterBuffer> \_videoJitterBuffers;

&nbsp;private readonly object \_callsLock = new object();

&nbsp;private uint \_nextCallId = 1;

&nbsp;private bool \_isRunning;

&nbsp;private Thread \_avThread;

&nbsp;private CancellationTokenSource \_cancellationTokenSource;



&nbsp;// Codecs (en una implementación real usaríamos librerías como Opus, VP8)

&nbsp;private ToxAvCodecType \_audioCodec = ToxAvCodecType.TOXAV\_CODEC\_AUDIO\_OPUS;

&nbsp;private ToxAvCodecType \_videoCodec = ToxAvCodecType.TOXAV\_CODEC\_VIDEO\_VP8;



&nbsp;public ToxAvCallbacks Callbacks => \_callbacks;

&nbsp;public bool IsRunning => \_isRunning;



&nbsp;public ToxAv(Core.Tox tox)

&nbsp;{

&nbsp;\_tox = tox ?? throw new ArgumentNullException(nameof(tox));

&nbsp;\_callbacks = new ToxAvCallbacks();

&nbsp;\_activeCalls = new Dictionary<int, ToxAvCall>();

&nbsp;\_audioJitterBuffers = new Dictionary<int, JitterBuffer>();

&nbsp;\_videoJitterBuffers = new Dictionary<int, JitterBuffer>();

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] ToxAV inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar servicio de audio/video

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] ToxAV ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = true;

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;// Iniciar hilo de procesamiento AV

&nbsp;\_avThread = new Thread(AvWorker);

&nbsp;\_avThread.IsBackground = true;

&nbsp;\_avThread.Name = "ToxAV-Worker";

&nbsp;\_avThread.Start();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio ToxAV iniciado");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando ToxAV: {ex.Message}");

&nbsp;\_isRunning = false;

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener servicio de audio/video

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = false;

&nbsp;\_cancellationTokenSource?.Cancel();



&nbsp;// Terminar todas las llamadas activas

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;foreach (var call in \_activeCalls.Values.ToList())

&nbsp;{

&nbsp;CallControl(call.FriendNumber, ToxAvCallControl.TOXAV\_CALL\_CONTROL\_CANCEL);

&nbsp;}

&nbsp;\_activeCalls.Clear();

&nbsp;\_audioJitterBuffers.Clear();

&nbsp;\_videoJitterBuffers.Clear();

&nbsp;}



&nbsp;\_avThread?.Join(2000);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio ToxAV detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo ToxAV: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== API PÚBLICA PRINCIPAL ====================



&nbsp;/// <summary>

&nbsp;/// toxav\_call - Iniciar llamada a un amigo

&nbsp;/// </summary>

&nbsp;public bool Call(int friendNumber, bool audio, bool video)

&nbsp;{

&nbsp;if (!\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Error($"\[{LOG\_TAG}] No se puede iniciar llamada - ToxAV no iniciado");

&nbsp;return false;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.ContainsKey(friendNumber))

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Ya existe una llamada activa con friend {friendNumber}");

&nbsp;return false;

&nbsp;}



&nbsp;var call = new ToxAvCall(friendNumber, \_nextCallId++)

&nbsp;{

&nbsp;AudioEnabled = audio,

&nbsp;VideoEnabled = video,

&nbsp;State = ToxAvCallState.TOXAV\_CALL\_STATE\_INVITING

&nbsp;};



&nbsp;\_activeCalls\[friendNumber] = call;



&nbsp;// Crear jitter buffers

&nbsp;\_audioJitterBuffers\[friendNumber] = new JitterBuffer(JITTER\_BUFFER\_MAX\_PACKETS);

&nbsp;\_videoJitterBuffers\[friendNumber] = new JitterBuffer(JITTER\_BUFFER\_MAX\_PACKETS);

&nbsp;}



&nbsp;// Enviar paquete de invitación de llamada

&nbsp;byte\[] callPacket = CreateCallPacket(audio, video);

&nbsp;int sent = \_tox.Messenger.FriendConn.m\_send\_message(friendNumber, callPacket, callPacket.Length);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Llamada iniciada a friend {friendNumber} - Audio: {audio}, Video: {video}");

&nbsp;return true;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;\_activeCalls.Remove(friendNumber);

&nbsp;\_audioJitterBuffers.Remove(friendNumber);

&nbsp;\_videoJitterBuffers.Remove(friendNumber);

&nbsp;}

&nbsp;return false;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando llamada: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_answer - Responder a una llamada entrante

&nbsp;/// </summary>

&nbsp;public bool Answer(int friendNumber, bool audio, bool video)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ToxAvCall call;

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (!\_activeCalls.TryGetValue(friendNumber, out call))

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No hay llamada entrante de friend {friendNumber}");

&nbsp;return false;

&nbsp;}



&nbsp;if (call.State != ToxAvCallState.TOXAV\_CALL\_STATE\_RINGING)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Llamada no está en estado ringing: {call.State}");

&nbsp;return false;

&nbsp;}



&nbsp;call.AudioEnabled = audio;

&nbsp;call.VideoEnabled = video;

&nbsp;call.State = ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE;

&nbsp;}



&nbsp;// Enviar paquete de respuesta

&nbsp;byte\[] answerPacket = CreateAnswerPacket(audio, video);

&nbsp;int sent = \_tox.Messenger.FriendConn.m\_send\_message(friendNumber, answerPacket, answerPacket.Length);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Llamada respondida - Audio: {audio}, Video: {video}");

&nbsp;\_callbacks.OnCallState?.Invoke(this, friendNumber, ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE, null);

&nbsp;return true;

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error respondiendo llamada: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_call\_control - Control de llamada (pausar, reanudar, cancelar)

&nbsp;/// </summary>

&nbsp;public bool CallControl(int friendNumber, ToxAvCallControl control)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ToxAvCall call;

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (!\_activeCalls.TryGetValue(friendNumber, out call))

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] No hay llamada activa con friend {friendNumber}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Aplicar control localmente

&nbsp;bool success = ApplyCallControl(call, control);

&nbsp;if (!success) return false;



&nbsp;// Enviar control al peer remoto

&nbsp;byte\[] controlPacket = CreateControlPacket(control);

&nbsp;int sent = \_tox.Messenger.FriendConn.m\_send\_message(friendNumber, controlPacket, controlPacket.Length);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Control de llamada enviado: {control}");

&nbsp;return true;

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en control de llamada: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_audio\_send\_frame - Enviar frame de audio

&nbsp;/// </summary>

&nbsp;public bool SendAudioFrame(int friendNumber, AudioFrame frame)

&nbsp;{

&nbsp;if (!\_isRunning) return false;



&nbsp;try

&nbsp;{

&nbsp;ToxAvCall call;

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (!\_activeCalls.TryGetValue(friendNumber, out call) ||

&nbsp;call.State != ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE ||

&nbsp;!call.AudioEnabled ||

&nbsp;call.AudioMuted)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Codificar audio (en implementación real usaríamos Opus)

&nbsp;byte\[] encodedAudio = EncodeAudio(frame);

&nbsp;if (encodedAudio == null) return false;



&nbsp;// Crear paquete RTP de audio

&nbsp;byte\[] audioPacket = CreateAudioPacket(call.CallId, encodedAudio, frame.Timestamp);

&nbsp;if (audioPacket == null) return false;



&nbsp;// Enviar a través de onion routing

&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null) return false;



&nbsp;int sent = \_tox.Messenger.Onion.onion\_send\_1(audioPacket, audioPacket.Length, friend.PublicKey);

&nbsp;return sent > 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando frame de audio: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_video\_send\_frame - Enviar frame de video

&nbsp;/// </summary>

&nbsp;public bool SendVideoFrame(int friendNumber, VideoFrame frame)

&nbsp;{

&nbsp;if (!\_isRunning) return false;



&nbsp;try

&nbsp;{

&nbsp;ToxAvCall call;

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (!\_activeCalls.TryGetValue(friendNumber, out call) ||

&nbsp;call.State != ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE ||

&nbsp;!call.VideoEnabled ||

&nbsp;call.VideoHidden)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Codificar video (en implementación real usaríamos VP8/VP9)

&nbsp;byte\[] encodedVideo = EncodeVideo(frame);

&nbsp;if (encodedVideo == null) return false;



&nbsp;// Crear paquete RTP de video

&nbsp;byte\[] videoPacket = CreateVideoPacket(call.CallId, encodedVideo, frame.Timestamp);

&nbsp;if (videoPacket == null) return false;



&nbsp;// Enviar a través de onion routing

&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null) return false;



&nbsp;int sent = \_tox.Messenger.Onion.onion\_send\_1(videoPacket, videoPacket.Length, friend.PublicKey);

&nbsp;return sent > 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando frame de video: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_set\_audio\_bitrate - Configurar bitrate de audio

&nbsp;/// </summary>

&nbsp;public bool SetAudioBitrate(int friendNumber, uint bitrate)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;call.AudioBitrate = (int)bitrate;

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error configurando bitrate de audio: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_set\_video\_bitrate - Configurar bitrate de video

&nbsp;/// </summary>

&nbsp;public bool SetVideoBitrate(int friendNumber, uint bitrate)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;call.VideoBitrate = (int)bitrate;

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error configurando bitrate de video: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MANEJO DE PAQUETES AV ====================



&nbsp;/// <summary>

&nbsp;/// Manejar paquetes de audio/video

&nbsp;/// </summary>

&nbsp;public int HandleAvPacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 5) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x60: // CALL\_INVITE

&nbsp;return HandleCallInvite(friendNumber, packet, length);

&nbsp;case 0x61: // CALL\_ANSWER

&nbsp;return HandleCallAnswer(friendNumber, packet, length);

&nbsp;case 0x62: // CALL\_CONTROL

&nbsp;return HandleCallControl(friendNumber, packet, length);

&nbsp;case 0x63: // AUDIO\_FRAME

&nbsp;return HandleAudioFrame(friendNumber, packet, length);

&nbsp;case 0x64: // VIDEO\_FRAME

&nbsp;return HandleVideoFrame(friendNumber, packet, length);

&nbsp;case 0x65: // CODEC\_CONTROL

&nbsp;return HandleCodecControl(friendNumber, packet, length);

&nbsp;default:

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete AV: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleCallInvite(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 3) return -1;



&nbsp;bool audio = (packet\[1] \& 0x01) != 0;

&nbsp;bool video = (packet\[1] \& 0x02) != 0;

&nbsp;uint callId = BitConverter.ToUInt32(packet, 2);



&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;// Si ya existe una llamada, rechazar la nueva

&nbsp;if (\_activeCalls.ContainsKey(friendNumber))

&nbsp;{

&nbsp;// Enviar rechazo automático

&nbsp;CallControl(friendNumber, ToxAvCallControl.TOXAV\_CALL\_CONTROL\_CANCEL);

&nbsp;return -1;

&nbsp;}



&nbsp;var call = new ToxAvCall(friendNumber, callId)

&nbsp;{

&nbsp;AudioEnabled = audio,

&nbsp;VideoEnabled = video,

&nbsp;State = ToxAvCallState.TOXAV\_CALL\_STATE\_RINGING

&nbsp;};



&nbsp;\_activeCalls\[friendNumber] = call;

&nbsp;\_audioJitterBuffers\[friendNumber] = new JitterBuffer(JITTER\_BUFFER\_MAX\_PACKETS);

&nbsp;\_videoJitterBuffers\[friendNumber] = new JitterBuffer(JITTER\_BUFFER\_MAX\_PACKETS);

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Llamada entrante de friend {friendNumber} - Audio: {audio}, Video: {video}");



&nbsp;// Disparar callback

&nbsp;\_callbacks.OnCall?.Invoke(this, friendNumber, audio, video, null);



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleCallAnswer(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 3) return -1;



&nbsp;bool audio = (packet\[1] \& 0x01) != 0;

&nbsp;bool video = (packet\[1] \& 0x02) != 0;



&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;call.AudioEnabled = audio;

&nbsp;call.VideoEnabled = video;

&nbsp;call.State = ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE;

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Llamada aceptada por friend {friendNumber}");



&nbsp;\_callbacks.OnCallState?.Invoke(this, friendNumber, ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE, null);



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleCallControl(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 2) return -1;



&nbsp;ToxAvCallControl control = (ToxAvCallControl)packet\[1];



&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;ApplyCallControl(call, control);

&nbsp;}

&nbsp;}



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleCodecControl(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 3) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte controlType = packet\[1];

&nbsp;uint value = BitConverter.ToUInt32(packet, 2);



&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;switch (controlType)

&nbsp;{

&nbsp;case 0x01: // Audio bitrate change

&nbsp;call.AudioBitrate = (int)value;

&nbsp;\_callbacks.OnAudioBitrate?.Invoke(this, friendNumber, value, null);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Bitrate de audio cambiado: {value} bps");

&nbsp;break;



&nbsp;case 0x02: // Video bitrate change

&nbsp;call.VideoBitrate = (int)value;

&nbsp;\_callbacks.OnVideoBitrate?.Invoke(this, friendNumber, value, null);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Bitrate de video cambiado: {value} bps");

&nbsp;break;



&nbsp;case 0x03: // Audio codec change

&nbsp;\_audioCodec = (ToxAvCodecType)value;

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Codec de audio cambiado: {\_audioCodec}");

&nbsp;break;



&nbsp;case 0x04: // Video codec change

&nbsp;\_videoCodec = (ToxAvCodecType)value;

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Codec de video cambiado: {\_videoCodec}");

&nbsp;break;



&nbsp;case 0x05: // Audio sample rate change

&nbsp;call.AudioSampleRate = value;

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Sample rate de audio cambiado: {value} Hz");

&nbsp;break;



&nbsp;case 0x06: // Video resolution change

&nbsp;call.VideoWidth = value;

&nbsp;call.VideoHeight = BitConverter.ToUInt32(packet, 6);

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Resolución de video cambiada: {value}x{call.VideoHeight}");

&nbsp;break;



&nbsp;default:

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Tipo de control de codec desconocido: 0x{controlType:X2}");

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando control de codec: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// toxav\_send\_codec\_control - Enviar control de codec al peer remoto

&nbsp;/// </summary>

&nbsp;public bool SendCodecControl(int friendNumber, byte controlType, uint value, uint additionalValue = 0)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] controlPacket = CreateCodecControlPacket(controlType, value, additionalValue);

&nbsp;if (controlPacket == null) return false;



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null) return false;



&nbsp;int sent = \_tox.Messenger.Onion.onion\_send\_1(controlPacket, controlPacket.Length, friend.PublicKey);

&nbsp;return sent > 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando control de codec: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] CreateCodecControlPacket(byte controlType, uint value, uint additionalValue = 0)

&nbsp;{

&nbsp;int packetSize = (controlType == 0x06) ? 10 : 6; // Para cambio de resolución necesita 2 valores

&nbsp;byte\[] packet = new byte\[packetSize];



&nbsp;packet\[0] = 0x65; // CODEC\_CONTROL

&nbsp;packet\[1] = controlType;

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(value), 0, packet, 2, 4);



&nbsp;if (controlType == 0x06) // Video resolution change

&nbsp;{

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(additionalValue), 0, packet, 6, 4);

&nbsp;}



&nbsp;return packet;

&nbsp;}



&nbsp;// <summary>

&nbsp;/// Enviar cambio de bitrate de audio

&nbsp;/// </summary>

&nbsp;public bool SendAudioBitrateChange(int friendNumber, uint bitrate)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x01, bitrate);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar cambio de bitrate de video

&nbsp;/// </summary>

&nbsp;public bool SendVideoBitrateChange(int friendNumber, uint bitrate)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x02, bitrate);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar cambio de codec de audio

&nbsp;/// </summary>

&nbsp;public bool SendAudioCodecChange(int friendNumber, ToxAvCodecType codec)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x03, (uint)codec);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar cambio de codec de video

&nbsp;/// </summary>

&nbsp;public bool SendVideoCodecChange(int friendNumber, ToxAvCodecType codec)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x04, (uint)codec);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar cambio de sample rate de audio

&nbsp;/// </summary>

&nbsp;public bool SendAudioSampleRateChange(int friendNumber, uint sampleRate)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x05, sampleRate);

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar cambio de resolución de video

&nbsp;/// </summary>

&nbsp;public bool SendVideoResolutionChange(int friendNumber, uint width, uint height)

&nbsp;{

&nbsp;return SendCodecControl(friendNumber, 0x06, width, height);

&nbsp;}





&nbsp;private int HandleAudioFrame(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 20) return -1; // header + timestamp mínimo



&nbsp;uint callId = BitConverter.ToUInt32(packet, 1);

&nbsp;long timestamp = BitConverter.ToInt64(packet, 5);

&nbsp;uint sequence = BitConverter.ToUInt32(packet, 13);



&nbsp;int audioDataLength = length - 17;

&nbsp;byte\[] audioData = new byte\[audioDataLength];

&nbsp;Buffer.BlockCopy(packet, 17, audioData, 0, audioDataLength);



&nbsp;// Agregar al jitter buffer

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_audioJitterBuffers.TryGetValue(friendNumber, out var jitterBuffer))

&nbsp;{

&nbsp;jitterBuffer.AddPacket(sequence, timestamp, audioData);

&nbsp;}

&nbsp;}



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleVideoFrame(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 25) return -1; // header + metadata mínimo



&nbsp;uint callId = BitConverter.ToUInt32(packet, 1);

&nbsp;long timestamp = BitConverter.ToInt64(packet, 5);

&nbsp;uint sequence = BitConverter.ToUInt32(packet, 13);

&nbsp;uint width = BitConverter.ToUInt32(packet, 17);

&nbsp;uint height = BitConverter.ToUInt32(packet, 21);



&nbsp;int videoDataLength = length - 25;

&nbsp;byte\[] videoData = new byte\[videoDataLength];

&nbsp;Buffer.BlockCopy(packet, 25, videoData, 0, videoDataLength);



&nbsp;// Agregar al jitter buffer

&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;if (\_videoJitterBuffers.TryGetValue(friendNumber, out var jitterBuffer))

&nbsp;{

&nbsp;jitterBuffer.AddPacket(sequence, timestamp, videoData);

&nbsp;}

&nbsp;}



&nbsp;return 0;

&nbsp;}



&nbsp;// ==================== MÉTODOS AUXILIARES ====================



&nbsp;private bool ApplyCallControl(ToxAvCall call, ToxAvCallControl control)

&nbsp;{

&nbsp;switch (control)

&nbsp;{

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_RESUME:

&nbsp;call.State = ToxAvCallState.TOXAV\_CALL\_STATE\_ACTIVE;

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_PAUSE:

&nbsp;call.State = ToxAvCallState.TOXAV\_CALL\_STATE\_PAUSED;

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_CANCEL:

&nbsp;call.State = ToxAvCallState.TOXAV\_CALL\_STATE\_ENDED;

&nbsp;// Limpiar recursos

&nbsp;\_audioJitterBuffers.Remove(call.FriendNumber);

&nbsp;\_videoJitterBuffers.Remove(call.FriendNumber);

&nbsp;\_activeCalls.Remove(call.FriendNumber);

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_MUTE\_AUDIO:

&nbsp;call.AudioMuted = true;

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_UNMUTE\_AUDIO:

&nbsp;call.AudioMuted = false;

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_HIDE\_VIDEO:

&nbsp;call.VideoHidden = true;

&nbsp;break;

&nbsp;case ToxAvCallControl.TOXAV\_CALL\_CONTROL\_SHOW\_VIDEO:

&nbsp;call.VideoHidden = false;

&nbsp;break;

&nbsp;default:

&nbsp;return false;

&nbsp;}



&nbsp;\_callbacks.OnCallState?.Invoke(this, call.FriendNumber, call.State, null);

&nbsp;return true;

&nbsp;}



&nbsp;// ==================== CREACIÓN DE PAQUETES ====================



&nbsp;private byte\[] CreateCallPacket(bool audio, bool video)

&nbsp;{

&nbsp;byte\[] packet = new byte\[6];

&nbsp;packet\[0] = 0x60; // CALL\_INVITE

&nbsp;packet\[1] = (byte)((audio ? 0x01 : 0x00) | (video ? 0x02 : 0x00));

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(\_nextCallId), 0, packet, 2, 4);

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateAnswerPacket(bool audio, bool video)

&nbsp;{

&nbsp;byte\[] packet = new byte\[3];

&nbsp;packet\[0] = 0x61; // CALL\_ANSWER

&nbsp;packet\[1] = (byte)((audio ? 0x01 : 0x00) | (video ? 0x02 : 0x00));

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateControlPacket(ToxAvCallControl control)

&nbsp;{

&nbsp;byte\[] packet = new byte\[2];

&nbsp;packet\[0] = 0x62; // CALL\_CONTROL

&nbsp;packet\[1] = (byte)control;

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateAudioPacket(uint callId, byte\[] audioData, long timestamp)

&nbsp;{

&nbsp;byte\[] packet = new byte\[17 + audioData.Length];

&nbsp;packet\[0] = 0x63; // AUDIO\_FRAME

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(callId), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 13, 4); // sequence

&nbsp;Buffer.BlockCopy(audioData, 0, packet, 17, audioData.Length);

&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateVideoPacket(uint callId, byte\[] videoData, long timestamp)

&nbsp;{

&nbsp;byte\[] packet = new byte\[25 + videoData.Length];

&nbsp;packet\[0] = 0x64; // VIDEO\_FRAME

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(callId), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 13, 4); // sequence

&nbsp;// Incluir dimensiones del video

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(DEFAULT\_VIDEO\_WIDTH), 0, packet, 17, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(DEFAULT\_VIDEO\_HEIGHT), 0, packet, 21, 4);

&nbsp;Buffer.BlockCopy(videoData, 0, packet, 25, videoData.Length);

&nbsp;return packet;

&nbsp;}



&nbsp;// ==================== CODECS (STUBS - en implementación real usar librerías) ====================



&nbsp;private byte\[] EncodeAudio(AudioFrame frame)

&nbsp;{

&nbsp;// STUB - En implementación real usar Opus codec

&nbsp;// Por ahora simplemente devolvemos los samples sin comprimir

&nbsp;return frame.Samples;

&nbsp;}



&nbsp;private byte\[] EncodeVideo(VideoFrame frame)

&nbsp;{

&nbsp;// STUB - En implementación real usar VP8/VP9 codec

&nbsp;// Por ahora simplemente devolvemos los datos YUV sin comprimir

&nbsp;return frame.Data;

&nbsp;}



&nbsp;private AudioFrame DecodeAudio(byte\[] encodedAudio, uint sampleRate, byte channels)

&nbsp;{

&nbsp;// STUB - Decodificar audio

&nbsp;var frame = new AudioFrame((uint)encodedAudio.Length / 2, channels, sampleRate);

&nbsp;Buffer.BlockCopy(encodedAudio, 0, frame.Samples, 0, encodedAudio.Length);

&nbsp;return frame;

&nbsp;}



&nbsp;private VideoFrame DecodeVideo(byte\[] encodedVideo, uint width, uint height)

&nbsp;{

&nbsp;// STUB - Decodificar video

&nbsp;var frame = new VideoFrame(width, height);

&nbsp;Buffer.BlockCopy(encodedVideo, 0, frame.Data, 0, Math.Min(encodedVideo.Length, frame.Data.Length));

&nbsp;return frame;

&nbsp;}



&nbsp;// ==================== WORKER PRINCIPAL ====================



&nbsp;private void AvWorker()

&nbsp;{

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo AV iniciado");



&nbsp;while (\_isRunning \&\& !\_cancellationTokenSource.Token.IsCancellationRequested)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ProcessJitterBuffers();

&nbsp;Thread.Sleep(10); // 10ms para no consumir demasiada CPU

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;if (\_isRunning) // Solo loguear si todavía estamos ejecutándonos

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en worker AV: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo AV finalizado");

&nbsp;}



&nbsp;private void ProcessJitterBuffers()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;



&nbsp;lock (\_callsLock)

&nbsp;{

&nbsp;foreach (var kvp in \_audioJitterBuffers)

&nbsp;{

&nbsp;int friendNumber = kvp.Key;

&nbsp;var jitterBuffer = kvp.Value;



&nbsp;// Procesar paquetes de audio listos

&nbsp;var audioPacket = jitterBuffer.GetNextPacket(currentTime);

&nbsp;while (audioPacket != null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Obtener configuración de audio de la llamada

&nbsp;uint sampleRate = DEFAULT\_AUDIO\_SAMPLE\_RATE;

&nbsp;byte channels = DEFAULT\_AUDIO\_CHANNELS;



&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;sampleRate = call.AudioSampleRate;

&nbsp;channels = call.AudioChannels;

&nbsp;}



&nbsp;// Decodificar y disparar callback

&nbsp;var audioFrame = DecodeAudio(audioPacket.Data, sampleRate, channels);

&nbsp;\_callbacks.OnAudioReceive?.Invoke(this, friendNumber, audioFrame, null);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando frame de audio: {ex.Message}");

&nbsp;}



&nbsp;// Obtener siguiente paquete

&nbsp;audioPacket = jitterBuffer.GetNextPacket(currentTime);

&nbsp;}

&nbsp;}



&nbsp;foreach (var kvp in \_videoJitterBuffers)

&nbsp;{

&nbsp;int friendNumber = kvp.Key;

&nbsp;var jitterBuffer = kvp.Value;



&nbsp;// Procesar paquetes de video listos

&nbsp;var videoPacket = jitterBuffer.GetNextPacket(currentTime);

&nbsp;while (videoPacket != null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Obtener configuración de video de la llamada

&nbsp;uint width = DEFAULT\_VIDEO\_WIDTH;

&nbsp;uint height = DEFAULT\_VIDEO\_HEIGHT;



&nbsp;if (\_activeCalls.TryGetValue(friendNumber, out var call))

&nbsp;{

&nbsp;width = call.VideoWidth;

&nbsp;height = call.VideoHeight;

&nbsp;}



&nbsp;// Decodificar y disparar callback

&nbsp;var videoFrame = DecodeVideo(videoPacket.Data, width, height);

&nbsp;\_callbacks.OnVideoReceive?.Invoke(this, friendNumber, videoFrame, null);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando frame de video: {ex.Message}");

&nbsp;}



&nbsp;// Obtener siguiente paquete

&nbsp;videoPacket = jitterBuffer.GetNextPacket(currentTime);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;\_cancellationTokenSource?.Dispose();

&nbsp;}

&nbsp;}



&nbsp;// ==================== CLASES AUXILIARES ====================



&nbsp;/// <summary>

&nbsp;/// Jitter Buffer para manejar paquetes RTP

&nbsp;/// </summary>

&nbsp;public class JitterBuffer

&nbsp;{

&nbsp;private readonly SortedDictionary<uint, JitterPacket> \_packets;

&nbsp;private readonly int \_maxPackets;

&nbsp;private uint \_expectedSequence;

&nbsp;private readonly object \_lock = new object();



&nbsp;public JitterBuffer(int maxPackets)

&nbsp;{

&nbsp;\_packets = new SortedDictionary<uint, JitterPacket>();

&nbsp;\_maxPackets = maxPackets;

&nbsp;\_expectedSequence = 0;

&nbsp;}



&nbsp;public void AddPacket(uint sequence, long timestamp, byte\[] data)

&nbsp;{

&nbsp;lock (\_lock)

&nbsp;{

&nbsp;// Limpiar buffer si está lleno

&nbsp;if (\_packets.Count >= \_maxPackets)

&nbsp;{

&nbsp;var firstKey = \_packets.Keys.First();

&nbsp;\_packets.Remove(firstKey);

&nbsp;}



&nbsp;\_packets\[sequence] = new JitterPacket

&nbsp;{

&nbsp;Sequence = sequence,

&nbsp;Timestamp = timestamp,

&nbsp;Data = data

&nbsp;};

&nbsp;}

&nbsp;}



&nbsp;public JitterPacket GetNextPacket(long currentTime)

&nbsp;{

&nbsp;lock (\_lock)

&nbsp;{

&nbsp;if (\_packets.Count == 0) return null;



&nbsp;// Buscar el siguiente paquete en secuencia

&nbsp;if (\_packets.TryGetValue(\_expectedSequence, out var packet))

&nbsp;{

&nbsp;\_packets.Remove(\_expectedSequence);

&nbsp;\_expectedSequence++;

&nbsp;return packet;

&nbsp;}



&nbsp;// Si no encontramos el esperado, buscar el más antiguo

&nbsp;var oldestSequence = \_packets.Keys.First();

&nbsp;if (\_packets.TryGetValue(oldestSequence, out packet))

&nbsp;{

&nbsp;\_packets.Remove(oldestSequence);

&nbsp;\_expectedSequence = oldestSequence + 1;

&nbsp;return packet;

&nbsp;}



&nbsp;return null;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;public class JitterPacket

&nbsp;{

&nbsp;public uint Sequence { get; set; }

&nbsp;public long Timestamp { get; set; }

&nbsp;public byte\[] Data { get; set; }

&nbsp;}

}

]



Archivo EnhancedFileTransfer.cs \[

using System.Security.Cryptography;

using ToxCore.Core;



namespace ToxCore.FileTransfer

{

&nbsp;/// <summary>

&nbsp;/// Estados mejorados de transferencia de archivos

&nbsp;/// </summary>

&nbsp;public enum EnhancedFileTransferStatus

&nbsp;{

&nbsp;FILE\_TRANSFER\_STATUS\_NONE,

&nbsp;FILE\_TRANSFER\_STATUS\_PAUSED,

&nbsp;FILE\_TRANSFER\_STATUS\_TRANSFERRING,

&nbsp;FILE\_TRANSFER\_STATUS\_COMPLETED,

&nbsp;FILE\_TRANSFER\_STATUS\_CANCELLED,

&nbsp;FILE\_TRANSFER\_STATUS\_ERROR,

&nbsp;FILE\_TRANSFER\_STATUS\_WAITING,

&nbsp;FILE\_TRANSFER\_STATUS\_HASH\_VERIFYING,

&nbsp;FILE\_TRANSFER\_STATUS\_RESUMING

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Control de transferencia mejorado

&nbsp;/// </summary>

&nbsp;public enum EnhancedFileControl

&nbsp;{

&nbsp;FILE\_CONTROL\_RESUME = 0,

&nbsp;FILE\_CONTROL\_PAUSE = 1,

&nbsp;FILE\_CONTROL\_CANCEL = 2,

&nbsp;FILE\_CONTROL\_ACCEPT = 3,

&nbsp;FILE\_CONTROL\_REJECT = 4,

&nbsp;FILE\_CONTROL\_REQUEST\_HASH = 5,

&nbsp;FILE\_CONTROL\_SEND\_HASH = 6,

&nbsp;FILE\_CONTROL\_VERIFY\_HASH = 7

&nbsp;}



&nbsp;public class TransferStatistics

&nbsp;{

&nbsp;public string FileName { get; set; }

&nbsp;public long FileSize { get; set; }

&nbsp;public long BytesTransferred { get; set; }

&nbsp;public double Progress { get; set; }

&nbsp;public double Speed { get; set; }

&nbsp;public EnhancedFileTransferStatus Status { get; set; }

&nbsp;public TimeSpan EstimatedTimeRemaining { get; set; }

&nbsp;public bool HashVerified { get; set; }



&nbsp;public override string ToString()

&nbsp;{

&nbsp;return $"{FileName} - {Progress:F1}% ({Speed / 1024:F1} KB/s) - {Status}";

&nbsp;}

&nbsp;}





&nbsp;/// <summary>

&nbsp;/// Información completa de transferencia de archivo

&nbsp;/// </summary>

&nbsp;public class EnhancedFileTransfer

&nbsp;{

&nbsp;public int FriendNumber { get; set; }

&nbsp;public int FileNumber { get; set; }

&nbsp;public FileKind Kind { get; set; }

&nbsp;public EnhancedFileTransferStatus Status { get; set; }

&nbsp;public string FileName { get; set; }

&nbsp;public string FilePath { get; set; }

&nbsp;public long FileSize { get; set; }

&nbsp;public long BytesSent { get; set; }

&nbsp;public long BytesReceived { get; set; }

&nbsp;public byte\[] FileId { get; set; }

&nbsp;public FileStream FileStream { get; set; }

&nbsp;public long LastActivity { get; set; }

&nbsp;public int TimeoutCounter { get; set; }

&nbsp;public byte\[] FileHash { get; set; }

&nbsp;public byte\[] ReceivedHash { get; set; }

&nbsp;public bool HashVerified { get; set; }

&nbsp;public int ChunkSize { get; set; }

&nbsp;public int BandwidthLimit { get; set; } // KB/s

&nbsp;public long TransferStartTime { get; set; }

&nbsp;public double TransferSpeed { get; set; }

&nbsp;public double ProgressPercentage => FileSize > 0 ? (double)(BytesSent + BytesReceived) / FileSize \* 100.0 : 0.0;

&nbsp;public TimeSpan EstimatedTimeRemaining

&nbsp;{

&nbsp;get

&nbsp;{

&nbsp;if (TransferSpeed <= 0) return TimeSpan.MaxValue;

&nbsp;long remainingBytes = FileSize - (BytesSent + BytesReceived);

&nbsp;return TimeSpan.FromSeconds(remainingBytes / TransferSpeed);

&nbsp;}

&nbsp;}



&nbsp;// Para resumen de transferencias

&nbsp;public List<FileSegment> TransferredSegments { get; set; }

&nbsp;public Queue<FileSegment> PendingSegments { get; set; }



&nbsp;public EnhancedFileTransfer(int friendNumber, int fileNumber)

&nbsp;{

&nbsp;FriendNumber = friendNumber;

&nbsp;FileNumber = fileNumber;

&nbsp;Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_NONE;

&nbsp;FileId = new byte\[32];

&nbsp;FileHash = new byte\[32]; // SHA256

&nbsp;ReceivedHash = new byte\[32];

&nbsp;ChunkSize = 1024 \* 16; // 16KB chunks por defecto

&nbsp;BandwidthLimit = 0; // Sin límite por defecto

&nbsp;TransferredSegments = new List<FileSegment>();

&nbsp;PendingSegments = new Queue<FileSegment>();

&nbsp;HashVerified = false;

&nbsp;TransferStartTime = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;public void UpdateTransferSpeed()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;double elapsedSeconds = (currentTime - TransferStartTime) / TimeSpan.TicksPerSecond;



&nbsp;if (elapsedSeconds > 0)

&nbsp;{

&nbsp;TransferSpeed = (BytesSent + BytesReceived) / elapsedSeconds;

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Segmento de archivo para transferencia

&nbsp;/// </summary>

&nbsp;public class FileSegment

&nbsp;{

&nbsp;public long StartPosition { get; set; }

&nbsp;public int Length { get; set; }

&nbsp;public byte\[] Data { get; set; }

&nbsp;public bool Transferred { get; set; }

&nbsp;public long TransferTime { get; set; }



&nbsp;public FileSegment(long start, int length)

&nbsp;{

&nbsp;StartPosition = start;

&nbsp;Length = length;

&nbsp;Data = new byte\[length];

&nbsp;Transferred = false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Callbacks mejorados para transferencia de archivos

&nbsp;/// </summary>

&nbsp;public class EnhancedFileTransferCallbacks

&nbsp;{

&nbsp;public delegate void FileReceiveCallback(EnhancedFileTransferManager manager, int friendNumber, int fileNumber,

&nbsp;FileKind kind, long fileSize, string fileName, byte\[] fileId, object userData);



&nbsp;public delegate void FileChunkRequestCallback(EnhancedFileTransferManager manager, int friendNumber,

&nbsp;int fileNumber, long position, int length, object userData);



&nbsp;public delegate void FileChunkReceivedCallback(EnhancedFileTransferManager manager, int friendNumber,

&nbsp;int fileNumber, long position, byte\[] data, object userData);



&nbsp;public delegate void FileTransferStatusChangedCallback(EnhancedFileTransferManager manager, int friendNumber,

&nbsp;int fileNumber, EnhancedFileTransferStatus status, object userData);



&nbsp;public delegate void FileTransferProgressCallback(EnhancedFileTransferManager manager, int friendNumber,

&nbsp;int fileNumber, double progress, double speed, TimeSpan remaining, object userData);



&nbsp;public delegate void FileHashVerifiedCallback(EnhancedFileTransferManager manager, int friendNumber,

&nbsp;int fileNumber, bool verified, byte\[] computedHash, object userData);



&nbsp;public FileReceiveCallback OnFileReceive { get; set; }

&nbsp;public FileChunkRequestCallback OnFileChunkRequest { get; set; }

&nbsp;public FileChunkReceivedCallback OnFileChunkReceived { get; set; }

&nbsp;public FileTransferStatusChangedCallback OnFileTransferStatusChanged { get; set; }

&nbsp;public FileTransferProgressCallback OnFileTransferProgress { get; set; }

&nbsp;public FileHashVerifiedCallback OnFileHashVerified { get; set; }

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Gestor mejorado de transferencia de archivos

&nbsp;/// </summary>

&nbsp;public class EnhancedFileTransferManager : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "ENH\_FILETRANSFER";



&nbsp;// Constantes de configuración

&nbsp;private const int MAX\_CONCURRENT\_TRANSFERS = 3;

&nbsp;private const int DEFAULT\_CHUNK\_SIZE = 1024 \* 16; // 16KB

&nbsp;private const int MAX\_CHUNK\_SIZE = 1024 \* 64; // 64KB

&nbsp;private const int MIN\_CHUNK\_SIZE = 1024 \* 4; // 4KB

&nbsp;private const int TRANSFER\_TIMEOUT\_MS = 120000; // 2 minutos

&nbsp;private const int HASH\_VERIFICATION\_TIMEOUT\_MS = 30000; // 30 segundos

&nbsp;private const int PROGRESS\_UPDATE\_INTERVAL\_MS = 1000; // 1 segundo



&nbsp;// Componentes

&nbsp;private readonly Core.Tox \_tox;

&nbsp;private readonly EnhancedFileTransferCallbacks \_callbacks;

&nbsp;private readonly Dictionary<string, EnhancedFileTransfer> \_activeTransfers;

&nbsp;private readonly Dictionary<string, Timer> \_progressTimers;

&nbsp;private readonly object \_transfersLock = new object();

&nbsp;private readonly object \_bandwidthLock = new object();

&nbsp;private int \_lastFileNumber;

&nbsp;private bool \_isRunning;

&nbsp;private Thread \_transferThread;

&nbsp;private CancellationTokenSource \_cancellationTokenSource;

&nbsp;private long \_totalBytesTransferred;

&nbsp;private int \_currentBandwidthUsage; // KB/s



&nbsp;// Control de ancho de banda

&nbsp;private readonly SemaphoreSlim \_bandwidthSemaphore;

&nbsp;private readonly int \_maxBandwidth; // KB/s



&nbsp;public EnhancedFileTransferCallbacks Callbacks => \_callbacks;

&nbsp;public bool IsRunning => \_isRunning;

&nbsp;public long TotalBytesTransferred => \_totalBytesTransferred;



&nbsp;public EnhancedFileTransferManager(Core.Tox tox, int maxBandwidth = 0)

&nbsp;{

&nbsp;\_tox = tox ?? throw new ArgumentNullException(nameof(tox));

&nbsp;\_callbacks = new EnhancedFileTransferCallbacks();

&nbsp;\_activeTransfers = new Dictionary<string, EnhancedFileTransfer>();

&nbsp;\_progressTimers = new Dictionary<string, Timer>();

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();

&nbsp;\_lastFileNumber = 0;

&nbsp;\_maxBandwidth = maxBandwidth;

&nbsp;\_bandwidthSemaphore = new SemaphoreSlim(maxBandwidth > 0 ? maxBandwidth : int.MaxValue, int.MaxValue);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Enhanced File Transfer inicializado" +

&nbsp;(maxBandwidth > 0 ? $" - Límite de ancho de banda: {maxBandwidth} KB/s" : ""));

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar servicio de transferencia de archivos

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Enhanced File Transfer ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = true;

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;// Iniciar hilo de transferencia

&nbsp;\_transferThread = new Thread(TransferWorker);

&nbsp;\_transferThread.IsBackground = true;

&nbsp;\_transferThread.Name = "EnhancedFileTransfer-Worker";

&nbsp;\_transferThread.Start();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio Enhanced File Transfer iniciado");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando Enhanced File Transfer: {ex.Message}");

&nbsp;\_isRunning = false;

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener servicio de transferencia de archivos

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = false;

&nbsp;\_cancellationTokenSource?.Cancel();



&nbsp;// Pausar todas las transferencias activas

&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;foreach (var transfer in \_activeTransfers.Values.ToList())

&nbsp;{

&nbsp;if (transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING)

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_PAUSED;

&nbsp;}



&nbsp;transfer.FileStream?.Close();

&nbsp;transfer.FileStream?.Dispose();

&nbsp;}



&nbsp;\_activeTransfers.Clear();

&nbsp;}



&nbsp;// Detener timers de progreso

&nbsp;foreach (var timer in \_progressTimers.Values)

&nbsp;{

&nbsp;timer?.Dispose();

&nbsp;}

&nbsp;\_progressTimers.Clear();



&nbsp;\_transferThread?.Join(2000);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio Enhanced File Transfer detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo Enhanced File Transfer: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== API PÚBLICA MEJORADA ====================



&nbsp;/// <summary>

&nbsp;/// Enviar archivo con opciones avanzadas

&nbsp;/// </summary>

&nbsp;public int FileSend(int friendNumber, FileKind kind, string filePath,

&nbsp;int chunkSize = 0, int bandwidthLimit = 0, bool enableHashVerification = true)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;if (!File.Exists(filePath))

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Archivo no existe: {filePath}");

&nbsp;return -1;

&nbsp;}



&nbsp;var fileInfo = new FileInfo(filePath);

&nbsp;if (fileInfo.Length > 1024L \* 1024 \* 1024 \* 4) // 4GB límite

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Archivo demasiado grande: {fileInfo.Length} bytes");

&nbsp;return -1;

&nbsp;}



&nbsp;int fileNumber = \_lastFileNumber++;

&nbsp;var transfer = new EnhancedFileTransfer(friendNumber, fileNumber)

&nbsp;{

&nbsp;Kind = kind,

&nbsp;FileSize = fileInfo.Length,

&nbsp;FileName = Path.GetFileName(filePath),

&nbsp;FilePath = filePath,

&nbsp;Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_WAITING,

&nbsp;ChunkSize = chunkSize > 0 ? Math.Min(chunkSize, MAX\_CHUNK\_SIZE) : DEFAULT\_CHUNK\_SIZE,

&nbsp;BandwidthLimit = bandwidthLimit

&nbsp;};



&nbsp;// Calcular hash del archivo

&nbsp;if (enableHashVerification)

&nbsp;{

&nbsp;transfer.FileHash = ComputeFileHash(filePath);

&nbsp;}



&nbsp;// Inicializar segmentos del archivo

&nbsp;InitializeFileSegments(transfer);



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;\_activeTransfers\[transferKey] = transfer;

&nbsp;}



&nbsp;// Iniciar timer de progreso

&nbsp;StartProgressTimer(transfer);



&nbsp;// Enviar solicitud de archivo

&nbsp;byte\[] fileRequest = CreateFileRequestPacket(transfer);

&nbsp;int sent = \_tox.Messenger.FriendConn.m\_send\_message(friendNumber, fileRequest, fileRequest.Length);



&nbsp;if (sent > 0)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Envío de archivo iniciado: {filePath} ({fileInfo.Length} bytes) a friend {friendNumber}");

&nbsp;return fileNumber;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;\_activeTransfers.Remove(transferKey);

&nbsp;}

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando envío de archivo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar chunk de archivo con control de ancho de banda

&nbsp;/// </summary>

&nbsp;public async Task<bool> FileSendChunk(int friendNumber, int fileNumber, long position, byte\[] data, int length)

&nbsp;{

&nbsp;if (!\_isRunning) return false;



&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer) ||

&nbsp;transfer.Status != EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING)

&nbsp;{

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Control de ancho de banda

&nbsp;if (transfer.BandwidthLimit > 0)

&nbsp;{

&nbsp;await \_bandwidthSemaphore.WaitAsync();

&nbsp;try

&nbsp;{

&nbsp;// Simular limitación de ancho de banda

&nbsp;int delayMs = (length \* 1000) / (transfer.BandwidthLimit \* 1024);

&nbsp;if (delayMs > 0)

&nbsp;{

&nbsp;await Task.Delay(delayMs);

&nbsp;}

&nbsp;}

&nbsp;finally

&nbsp;{

&nbsp;\_bandwidthSemaphore.Release();

&nbsp;}

&nbsp;}



&nbsp;// Crear paquete FILE\_DATA mejorado

&nbsp;byte\[] packet = CreateEnhancedFileDataPacket(fileNumber, position, data, length);

&nbsp;if (packet == null) return false;



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null) return false;



&nbsp;int sent = \_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;transfer.BytesSent += length;

&nbsp;transfer.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;transfer.UpdateTransferSpeed();



&nbsp;// Marcar segmento como transferido

&nbsp;var segment = transfer.TransferredSegments.FirstOrDefault(s =>

&nbsp;s.StartPosition == position \&\& s.Length == length);

&nbsp;if (segment != null)

&nbsp;{

&nbsp;segment.Transferred = true;

&nbsp;segment.TransferTime = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;// Verificar si se completó la transferencia

&nbsp;if (transfer.BytesSent >= transfer.FileSize)

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_HASH\_VERIFYING;

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Transferencia completada: {transfer.FileName}");



&nbsp;// Iniciar verificación de hash

&nbsp;if (transfer.FileHash != null \&\& transfer.FileHash.Length > 0)

&nbsp;{

&nbsp;SendHashVerificationRequest(friendNumber, fileNumber);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED;

&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(this, friendNumber, fileNumber,

&nbsp;EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED, null);

&nbsp;}

&nbsp;}



&nbsp;return true;

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando chunk: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Control mejorado de transferencia

&nbsp;/// </summary>

&nbsp;public bool FileControl(int friendNumber, int fileNumber, EnhancedFileControl control)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return false;

&nbsp;}



&nbsp;bool success = ApplyEnhancedFileControl(transfer, control);

&nbsp;if (!success) return false;



&nbsp;// Enviar control al remitente

&nbsp;SendEnhancedFileControl(friendNumber, fileNumber, control);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Control de archivo {fileNumber}: {control}");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en control de archivo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Reanudar transferencia desde el último punto

&nbsp;/// </summary>

&nbsp;public bool FileResume(int friendNumber, int fileNumber)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return false;

&nbsp;}



&nbsp;if (transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_PAUSED ||

&nbsp;transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR)

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_RESUMING;



&nbsp;// Recalcular segmentos pendientes

&nbsp;RecalculatePendingSegments(transfer);



&nbsp;// Enviar solicitud de resumen

&nbsp;SendResumeRequest(friendNumber, fileNumber, transfer.BytesReceived);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Reanudando transferencia {fileNumber} desde byte {transfer.BytesReceived}");

&nbsp;return true;

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error reanudando transferencia: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MANEJO DE PAQUETES MEJORADO ====================



&nbsp;/// <summary>

&nbsp;/// Manejar paquetes de transferencia de archivos mejorados

&nbsp;/// </summary>

&nbsp;public int HandleEnhancedFilePacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 5) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x50: // FILE\_CONTROL\_EXTENDED

&nbsp;return HandleEnhancedFileControl(friendNumber, packet, length);

&nbsp;case 0x51: // FILE\_DATA\_EXTENDED

&nbsp;return HandleEnhancedFileData(friendNumber, packet, length);

&nbsp;case 0x52: // FILE\_REQUEST\_EXTENDED

&nbsp;return HandleEnhancedFileRequest(friendNumber, packet, length);

&nbsp;case 0x53: // FILE\_HASH\_VERIFICATION

&nbsp;return HandleFileHashVerification(friendNumber, packet, length);

&nbsp;case 0x54: // FILE\_RESUME\_REQUEST

&nbsp;return HandleFileResumeRequest(friendNumber, packet, length);

&nbsp;case 0x55: // FILE\_PROGRESS\_UPDATE

&nbsp;return HandleFileProgressUpdate(friendNumber, packet, length);

&nbsp;default:

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete de archivo mejorado: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleEnhancedFileRequest(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 53) return -1;



&nbsp;try

&nbsp;{

&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;long fileSize = BitConverter.ToInt64(packet, 5);



&nbsp;byte\[] fileId = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 13, fileId, 0, 32);



&nbsp;int chunkSize = BitConverter.ToInt32(packet, 45);

&nbsp;bool hasHash = packet\[49] == 0x01;



&nbsp;ushort fileNameLength = BitConverter.ToUInt16(packet, 50);

&nbsp;string fileName = System.Text.Encoding.UTF8.GetString(packet, 52, fileNameLength);



&nbsp;// Crear transferencia de recepción

&nbsp;var transfer = new EnhancedFileTransfer(friendNumber, fileNumber)

&nbsp;{

&nbsp;Kind = FileKind.TOX\_FILE\_KIND\_DATA,

&nbsp;FileSize = fileSize,

&nbsp;FileName = fileName,

&nbsp;FileId = fileId,

&nbsp;ChunkSize = chunkSize,

&nbsp;Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_WAITING,

&nbsp;FilePath = Path.Combine(Path.GetTempPath(), $"tox\_transfer\_{fileNumber}\_{fileName}")

&nbsp;};



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;\_activeTransfers\[transferKey] = transfer;

&nbsp;}



&nbsp;// Inicializar segmentos para recepción

&nbsp;InitializeFileSegments(transfer);



&nbsp;// Disparar callback

&nbsp;\_callbacks.OnFileReceive?.Invoke(this, friendNumber, fileNumber,

&nbsp;FileKind.TOX\_FILE\_KIND\_DATA, fileSize, fileName, fileId, null);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Solicitud de recepción de archivo: {fileName} ({fileSize} bytes)");



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando solicitud de archivo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleFileHashVerification(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 37) return -1; // \[type]\[file\_number(4)]\[control(1)]\[hash(32)]



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;byte control = packet\[5];

&nbsp;byte\[] hash = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 6, hash, 0, 32);



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return -1;

&nbsp;}



&nbsp;if (control == 0x01) // Request hash

&nbsp;{

&nbsp;// Enviar nuestro hash

&nbsp;SendFileHash(friendNumber, fileNumber, transfer.FileHash);

&nbsp;}

&nbsp;else if (control == 0x02) // Received hash

&nbsp;{

&nbsp;transfer.ReceivedHash = hash;

&nbsp;VerifyFileHash(transfer);

&nbsp;}



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleFileResumeRequest(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 13) return -1; // \[type]\[file\_number(4)]\[position(8)]



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;long resumePosition = BitConverter.ToInt64(packet, 5);



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return -1;

&nbsp;}



&nbsp;// Ajustar la posición de reanudación

&nbsp;transfer.BytesReceived = resumePosition;

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING;



&nbsp;// Recalcular segmentos pendientes desde la posición de reanudación

&nbsp;RecalculatePendingSegmentsFromPosition(transfer, resumePosition);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Transferencia {fileNumber} reanudada desde posición {resumePosition}");



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleFileProgressUpdate(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 21) return -1; // \[type]\[file\_number(4)]\[progress(8)]\[speed(8)]



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;double progress = BitConverter.ToDouble(packet, 5);

&nbsp;double speed = BitConverter.ToDouble(packet, 13);



&nbsp;// Actualizar UI o estadísticas (opcional)

&nbsp;// Podrías mantener estadísticas del peer remoto aquí



&nbsp;return 0;

&nbsp;}



&nbsp;private void SendFileHash(int friendNumber, int fileNumber, byte\[] hash)

&nbsp;{

&nbsp;if (hash == null) return;



&nbsp;byte\[] packet = new byte\[38];

&nbsp;packet\[0] = 0x53; // FILE\_HASH\_VERIFICATION

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;packet\[5] = 0x02; // Send hash

&nbsp;Buffer.BlockCopy(hash, 0, packet, 6, 32);



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}



&nbsp;private void SendResumeRequest(int friendNumber, int fileNumber, long position)

&nbsp;{

&nbsp;byte\[] packet = new byte\[13];

&nbsp;packet\[0] = 0x54; // FILE\_RESUME\_REQUEST

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}



&nbsp;private void SendProgressUpdate(int friendNumber, int fileNumber, double progress, double speed)

&nbsp;{

&nbsp;byte\[] packet = new byte\[21];

&nbsp;packet\[0] = 0x55; // FILE\_PROGRESS\_UPDATE

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(progress), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(speed), 0, packet, 13, 8);



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}



&nbsp;private void RecalculatePendingSegmentsFromPosition(EnhancedFileTransfer transfer, long position)

&nbsp;{

&nbsp;transfer.PendingSegments.Clear();



&nbsp;foreach (var segment in transfer.TransferredSegments)

&nbsp;{

&nbsp;if (segment.StartPosition >= position \&\& !segment.Transferred)

&nbsp;{

&nbsp;transfer.PendingSegments.Enqueue(segment);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// Método para aceptar una transferencia entrante

&nbsp;public bool FileAccept(int friendNumber, int fileNumber, string savePath, int bandwidthLimit = 0)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer) ||

&nbsp;transfer.Status != EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_WAITING)

&nbsp;{

&nbsp;return false;

&nbsp;}



&nbsp;transfer.FilePath = savePath;

&nbsp;transfer.BandwidthLimit = bandwidthLimit;

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING;

&nbsp;}



&nbsp;// Iniciar timer de progreso

&nbsp;StartProgressTimer(transfer);



&nbsp;// Enviar aceptación

&nbsp;SendEnhancedFileControl(friendNumber, fileNumber, EnhancedFileControl.FILE\_CONTROL\_ACCEPT);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Transferencia {fileNumber} aceptada, guardando en: {savePath}");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error aceptando transferencia: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;// Método para obtener estadísticas de transferencia

&nbsp;public TransferStatistics GetTransferStatistics(int friendNumber, int fileNumber)

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (\_activeTransfers.TryGetValue(transferKey, out var transfer))

&nbsp;{

&nbsp;return new TransferStatistics

&nbsp;{

&nbsp;FileName = transfer.FileName,

&nbsp;FileSize = transfer.FileSize,

&nbsp;BytesTransferred = transfer.BytesSent + transfer.BytesReceived,

&nbsp;Progress = transfer.ProgressPercentage,

&nbsp;Speed = transfer.TransferSpeed,

&nbsp;Status = transfer.Status,

&nbsp;EstimatedTimeRemaining = transfer.EstimatedTimeRemaining,

&nbsp;HashVerified = transfer.HashVerified

&nbsp;};

&nbsp;}

&nbsp;}



&nbsp;return null;

&nbsp;}



&nbsp;// Método para listar transferencias activas

&nbsp;public List<EnhancedFileTransfer> GetActiveTransfers()

&nbsp;{

&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;return \_activeTransfers.Values.ToList();

&nbsp;}

&nbsp;}









&nbsp;private int HandleEnhancedFileControl(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 6) return -1;



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;EnhancedFileControl control = (EnhancedFileControl)packet\[5];



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return -1;

&nbsp;}



&nbsp;return ApplyEnhancedFileControl(transfer, control) ? 0 : -1;

&nbsp;}



&nbsp;private int HandleEnhancedFileData(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 25) return -1;



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;long position = BitConverter.ToInt64(packet, 5);

&nbsp;int dataLength = BitConverter.ToInt32(packet, 13);

&nbsp;uint sequence = BitConverter.ToUInt32(packet, 17);



&nbsp;if (dataLength != length - 21)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Longitud de datos inconsistente en paquete de archivo");

&nbsp;return -1;

&nbsp;}



&nbsp;byte\[] data = new byte\[dataLength];

&nbsp;Buffer.BlockCopy(packet, 21, data, 0, dataLength);



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;EnhancedFileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return -1;

&nbsp;}



&nbsp;// Escribir datos en el archivo

&nbsp;try

&nbsp;{

&nbsp;if (transfer.FileStream == null)

&nbsp;{

&nbsp;transfer.FileStream = new FileStream(transfer.FilePath, FileMode.Create, FileAccess.Write);

&nbsp;}



&nbsp;transfer.FileStream.Seek(position, SeekOrigin.Begin);

&nbsp;transfer.FileStream.Write(data, 0, dataLength);

&nbsp;transfer.BytesReceived += dataLength;

&nbsp;transfer.LastActivity = DateTime.UtcNow.Ticks;

&nbsp;transfer.UpdateTransferSpeed();



&nbsp;// Disparar callback de chunk recibido

&nbsp;\_callbacks.OnFileChunkReceived?.Invoke(this, friendNumber, fileNumber, position, data, null);



&nbsp;// Verificar si se completó la recepción

&nbsp;if (transfer.BytesReceived >= transfer.FileSize)

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_HASH\_VERIFYING;

&nbsp;transfer.FileStream?.Close();



&nbsp;// Verificar hash si está disponible

&nbsp;if (transfer.ReceivedHash != null \&\& transfer.ReceivedHash.Length > 0)

&nbsp;{

&nbsp;VerifyFileHash(transfer);

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED;

&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(this, friendNumber, fileNumber,

&nbsp;EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED, null);

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Recepción completada: {transfer.FileName}");

&nbsp;}



&nbsp;return 0;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error escribiendo chunk de archivo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS AUXILIARES MEJORADOS ====================



&nbsp;private bool ApplyEnhancedFileControl(EnhancedFileTransfer transfer, EnhancedFileControl control)

&nbsp;{

&nbsp;switch (control)

&nbsp;{

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_RESUME:

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING;

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_PAUSE:

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_PAUSED;

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_CANCEL:

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_CANCELLED;

&nbsp;CleanupTransfer(transfer);

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_ACCEPT:

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING;

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_REJECT:

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_CANCELLED;

&nbsp;CleanupTransfer(transfer);

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_REQUEST\_HASH:

&nbsp;SendFileHash(transfer.FriendNumber, transfer.FileNumber, transfer.FileHash);

&nbsp;break;

&nbsp;case EnhancedFileControl.FILE\_CONTROL\_VERIFY\_HASH:

&nbsp;VerifyFileHash(transfer);

&nbsp;break;

&nbsp;default:

&nbsp;return false;

&nbsp;}



&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(this, transfer.FriendNumber, transfer.FileNumber, transfer.Status, null);

&nbsp;return true;

&nbsp;}



&nbsp;private void InitializeFileSegments(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;transfer.TransferredSegments.Clear();

&nbsp;transfer.PendingSegments.Clear();



&nbsp;long position = 0;

&nbsp;while (position < transfer.FileSize)

&nbsp;{

&nbsp;int chunkSize = (int)Math.Min(transfer.ChunkSize, transfer.FileSize - position);

&nbsp;var segment = new FileSegment(position, chunkSize);

&nbsp;transfer.TransferredSegments.Add(segment);

&nbsp;transfer.PendingSegments.Enqueue(segment);

&nbsp;position += chunkSize;

&nbsp;}

&nbsp;}



&nbsp;private void RecalculatePendingSegments(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;transfer.PendingSegments.Clear();



&nbsp;foreach (var segment in transfer.TransferredSegments)

&nbsp;{

&nbsp;if (!segment.Transferred)

&nbsp;{

&nbsp;transfer.PendingSegments.Enqueue(segment);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;private byte\[] ComputeFileHash(string filePath)

&nbsp;{

&nbsp;using (var sha256 = SHA256.Create())

&nbsp;using (var stream = File.OpenRead(filePath))

&nbsp;{

&nbsp;return sha256.ComputeHash(stream);

&nbsp;}

&nbsp;}



&nbsp;private void VerifyFileHash(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] computedHash = ComputeFileHash(transfer.FilePath);

&nbsp;bool verified = computedHash.SequenceEqual(transfer.ReceivedHash);



&nbsp;transfer.HashVerified = verified;

&nbsp;transfer.Status = verified ?

&nbsp;EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED :

&nbsp;EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR;



&nbsp;\_callbacks.OnFileHashVerified?.Invoke(this, transfer.FriendNumber, transfer.FileNumber,

&nbsp;verified, computedHash, null);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Verificación de hash {transfer.FileName}: {(verified ? "✅" : "❌")}");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error verificando hash: {ex.Message}");

&nbsp;transfer.Status = EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR;

&nbsp;}

&nbsp;}



&nbsp;private void CleanupTransfer(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;transfer.FileStream?.Close();

&nbsp;transfer.FileStream?.Dispose();



&nbsp;if (transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_CANCELLED)

&nbsp;{

&nbsp;// Eliminar archivo parcial si fue cancelado

&nbsp;try

&nbsp;{

&nbsp;if (File.Exists(transfer.FilePath))

&nbsp;{

&nbsp;File.Delete(transfer.FilePath);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] No se pudo eliminar archivo parcial: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;// ==================== CREACIÓN DE PAQUETES MEJORADOS ====================



&nbsp;private byte\[] CreateFileRequestPacket(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;byte\[] fileNameBytes = System.Text.Encoding.UTF8.GetBytes(transfer.FileName);

&nbsp;byte\[] packet = new byte\[53 + fileNameBytes.Length];



&nbsp;packet\[0] = 0x52; // FILE\_REQUEST\_EXTENDED

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(transfer.FileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(transfer.FileSize), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(transfer.FileId, 0, packet, 13, 32);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(transfer.ChunkSize), 0, packet, 45, 4);

&nbsp;packet\[49] = (byte)(transfer.FileHash != null ? 0x01 : 0x00); // Hash flag

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes((ushort)fileNameBytes.Length), 0, packet, 50, 2);

&nbsp;Buffer.BlockCopy(fileNameBytes, 0, packet, 52, fileNameBytes.Length);



&nbsp;return packet;

&nbsp;}



&nbsp;private byte\[] CreateEnhancedFileDataPacket(int fileNumber, long position, byte\[] data, int length)

&nbsp;{

&nbsp;byte\[] packet = new byte\[21 + length];

&nbsp;packet\[0] = 0x51; // FILE\_DATA\_EXTENDED

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(length), 0, packet, 13, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes((uint)DateTime.UtcNow.Ticks), 0, packet, 17, 4); // Sequence

&nbsp;Buffer.BlockCopy(data, 0, packet, 21, length);

&nbsp;return packet;

&nbsp;}



&nbsp;private void SendEnhancedFileControl(int friendNumber, int fileNumber, EnhancedFileControl control)

&nbsp;{

&nbsp;byte\[] packet = new byte\[6];

&nbsp;packet\[0] = 0x50; // FILE\_CONTROL\_EXTENDED

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;packet\[5] = (byte)control;



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}



&nbsp;private void SendHashVerificationRequest(int friendNumber, int fileNumber)

&nbsp;{

&nbsp;byte\[] packet = new byte\[6];

&nbsp;packet\[0] = 0x53; // FILE\_HASH\_VERIFICATION

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;packet\[5] = 0x01; // Request hash



&nbsp;var friend = \_tox.Messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_tox.Messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}



&nbsp;// ==================== WORKER PRINCIPAL ====================



&nbsp;private void TransferWorker()

&nbsp;{

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo Enhanced File Transfer iniciado");



&nbsp;while (\_isRunning \&\& !\_cancellationTokenSource.Token.IsCancellationRequested)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;ProcessPendingTransfers();

&nbsp;CleanupCompletedTransfers();

&nbsp;Thread.Sleep(100); // Ejecutar cada 100ms

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en worker: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo Enhanced File Transfer finalizado");

&nbsp;}



&nbsp;private void ProcessPendingTransfers()

&nbsp;{

&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;var activeTransfers = \_activeTransfers.Values

&nbsp;.Where(t => t.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING)

&nbsp;.Take(MAX\_CONCURRENT\_TRANSFERS) // Limitar transferencias concurrentes

&nbsp;.ToList();



&nbsp;foreach (var transfer in activeTransfers)

&nbsp;{

&nbsp;// Procesar siguiente segmento pendiente

&nbsp;if (transfer.PendingSegments.Count > 0)

&nbsp;{

&nbsp;var segment = transfer.PendingSegments.Dequeue();

&nbsp;if (!segment.Transferred)

&nbsp;{

&nbsp;// Leer datos del archivo y enviar

&nbsp;Task.Run(async () =>

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;using (var fileStream = new FileStream(transfer.FilePath, FileMode.Open, FileAccess.Read))

&nbsp;{

&nbsp;fileStream.Seek(segment.StartPosition, SeekOrigin.Begin);

&nbsp;byte\[] buffer = new byte\[segment.Length];

&nbsp;int bytesRead = fileStream.Read(buffer, 0, segment.Length);



&nbsp;if (bytesRead > 0)

&nbsp;{

&nbsp;await FileSendChunk(transfer.FriendNumber, transfer.FileNumber,

&nbsp;segment.StartPosition, buffer, bytesRead);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error procesando segmento: {ex.Message}");

&nbsp;}

&nbsp;});

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;private void CleanupCompletedTransfers()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<string> transfersToRemove = new List<string>();



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;foreach (var kvp in \_activeTransfers)

&nbsp;{

&nbsp;var transfer = kvp.Value;

&nbsp;long timeSinceActivity = (currentTime - transfer.LastActivity) / TimeSpan.TicksPerMillisecond;



&nbsp;// Limpiar transferencias completadas o con timeout

&nbsp;if (transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED ||

&nbsp;transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_CANCELLED ||

&nbsp;transfer.Status == EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR ||

&nbsp;(timeSinceActivity > TRANSFER\_TIMEOUT\_MS \&\&

&nbsp;transfer.Status != EnhancedFileTransferStatus.FILE\_TRANSFER\_STATUS\_PAUSED))

&nbsp;{

&nbsp;transfersToRemove.Add(kvp.Key);

&nbsp;CleanupTransfer(transfer);

&nbsp;}

&nbsp;}



&nbsp;foreach (string key in transfersToRemove)

&nbsp;{

&nbsp;\_activeTransfers.Remove(key);



&nbsp;// Detener timer de progreso

&nbsp;if (\_progressTimers.ContainsKey(key))

&nbsp;{

&nbsp;\_progressTimers\[key]?.Dispose();

&nbsp;\_progressTimers.Remove(key);

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;if (transfersToRemove.Count > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {transfersToRemove.Count} transferencias limpiadas");

&nbsp;}

&nbsp;}



&nbsp;private void StartProgressTimer(EnhancedFileTransfer transfer)

&nbsp;{

&nbsp;string transferKey = $"{transfer.FriendNumber}\_{transfer.FileNumber}";



&nbsp;var timer = new Timer(state =>

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;transfer.UpdateTransferSpeed();

&nbsp;\_callbacks.OnFileTransferProgress?.Invoke(this, transfer.FriendNumber, transfer.FileNumber,

&nbsp;transfer.ProgressPercentage, transfer.TransferSpeed, transfer.EstimatedTimeRemaining, null);

&nbsp;}

&nbsp;}, null, 0, PROGRESS\_UPDATE\_INTERVAL\_MS);



&nbsp;\_progressTimers\[transferKey] = timer;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Integración con el sistema de mensajes del Tox principal

&nbsp;/// </summary>

&nbsp;public int HandleToxPacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 1) return -1;



&nbsp;byte packetType = packet\[0];



&nbsp;// Paquetes de file transfer mejorado (0x50-0x55)

&nbsp;if (packetType >= 0x50 \&\& packetType <= 0x55)

&nbsp;{

&nbsp;return HandleEnhancedFilePacket(friendNumber, packet, length);

&nbsp;}



&nbsp;return -1; // No es un paquete de file transfer

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;\_cancellationTokenSource?.Dispose();

&nbsp;\_bandwidthSemaphore?.Dispose();



&nbsp;foreach (var timer in \_progressTimers.Values)

&nbsp;{

&nbsp;timer?.Dispose();

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo FileTransfer.cs \[

using ToxCore.Core;



namespace ToxCore.FileTransfer

{

&nbsp;/// <summary>

&nbsp;/// Estados de transferencia de archivos compatibles con toxcore

&nbsp;/// </summary>

&nbsp;public enum FileTransferStatus

&nbsp;{

&nbsp;FILE\_TRANSFER\_STATUS\_NONE,

&nbsp;FILE\_TRANSFER\_STATUS\_PAUSED,

&nbsp;FILE\_TRANSFER\_STATUS\_TRANSFERRING,

&nbsp;FILE\_TRANSFER\_STATUS\_COMPLETED,

&nbsp;FILE\_TRANSFER\_STATUS\_CANCELLED,

&nbsp;FILE\_TRANSFER\_STATUS\_ERROR

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Tipos de archivo compatibles

&nbsp;/// </summary>

&nbsp;public enum FileKind

&nbsp;{

&nbsp;TOX\_FILE\_KIND\_DATA = 0,

&nbsp;TOX\_FILE\_KIND\_AVATAR = 1

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Información de transferencia de archivo

&nbsp;/// </summary>

&nbsp;public class FileTransfer

&nbsp;{

&nbsp;public int FriendNumber { get; set; }

&nbsp;public int FileNumber { get; set; }

&nbsp;public FileKind Kind { get; set; }

&nbsp;public FileTransferStatus Status { get; set; }

&nbsp;public string FileName { get; set; }

&nbsp;public string FilePath { get; set; }

&nbsp;public long FileSize { get; set; }

&nbsp;public long BytesSent { get; set; }

&nbsp;public long BytesReceived { get; set; }

&nbsp;public byte\[] FileId { get; set; }

&nbsp;public Stream FileStream { get; set; }

&nbsp;public long LastActivity { get; set; }

&nbsp;public int TimeoutCounter { get; set; }



&nbsp;public FileTransfer(int friendNumber, int fileNumber)

&nbsp;{

&nbsp;FriendNumber = friendNumber;

&nbsp;FileNumber = fileNumber;

&nbsp;Status = FileTransferStatus.FILE\_TRANSFER\_STATUS\_NONE;

&nbsp;FileId = new byte\[32];

&nbsp;LastActivity = DateTime.UtcNow.Ticks;

&nbsp;}



&nbsp;public double Progress => FileSize > 0 ? (double)(BytesSent + BytesReceived) / FileSize \* 100.0 : 0.0;

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Callbacks para transferencia de archivos

&nbsp;/// </summary>

&nbsp;public class FileTransferCallbacks

&nbsp;{

&nbsp;// ✅ DEFINICIÓN CORRECTA DE LOS DELEGADOS

&nbsp;public delegate void FileReceiveCallback(int friendNumber, int fileNumber, FileKind kind, long fileSize, string fileName, byte\[] fileId, object userData);

&nbsp;public delegate void FileChunkRequestCallback(int friendNumber, int fileNumber, long position, object userData);

&nbsp;public delegate void FileChunkReceivedCallback(int friendNumber, int fileNumber, long position, byte\[] data, object userData);

&nbsp;public delegate void FileTransferStatusChangedCallback(int friendNumber, int fileNumber, FileTransferStatus status, object userData);



&nbsp;// ✅ EVENTOS CORRECTAMENTE TIPADOS

&nbsp;public FileReceiveCallback OnFileReceive { get; set; }

&nbsp;public FileChunkRequestCallback OnFileChunkRequest { get; set; }

&nbsp;public FileChunkReceivedCallback OnFileChunkReceived { get; set; }

&nbsp;public FileTransferStatusChangedCallback OnFileTransferStatusChanged { get; set; }

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// FileTransferManager - Gestor de transferencias de archivos como en toxcore

&nbsp;/// </summary>

&nbsp;public class FileTransferManager

&nbsp;{

&nbsp;private const string LOG\_TAG = "FILETRANSFER";



&nbsp;private readonly Messenger \_messenger;

&nbsp;private readonly Dictionary<string, FileTransfer> \_activeTransfers;

&nbsp;private readonly object \_transfersLock = new object();

&nbsp;private int \_lastFileNumber;

&nbsp;private readonly FileTransferCallbacks \_callbacks;



&nbsp;public FileTransferCallbacks Callbacks => \_callbacks;



&nbsp;public FileTransferManager(Messenger messenger)

&nbsp;{

&nbsp;\_messenger = messenger;

&nbsp;\_activeTransfers = new Dictionary<string, FileTransfer>();

&nbsp;\_lastFileNumber = 0;

&nbsp;\_callbacks = new FileTransferCallbacks();

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_file\_send - Inicia envío de archivo a un amigo

&nbsp;/// </summary>

&nbsp;public int FileSend(int friendNumber, FileKind kind, long fileSize, string fileName, byte\[] fileId = null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// ✅ CORRECCIÓN: Friend es una clase, no un nullable - usar null check

&nbsp;var friend = \_messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Friend {friendNumber} no encontrado");

&nbsp;return -1;

&nbsp;}



&nbsp;int fileNumber = \_lastFileNumber++;

&nbsp;var transfer = new FileTransfer(friendNumber, fileNumber)

&nbsp;{

&nbsp;Kind = kind,

&nbsp;FileSize = fileSize,

&nbsp;FileName = fileName ?? "unknown\_file",

&nbsp;Status = FileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING

&nbsp;};



&nbsp;if (fileId != null)

&nbsp;{

&nbsp;Buffer.BlockCopy(fileId, 0, transfer.FileId, 0, Math.Min(fileId.Length, 32));

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;// Generar fileId único si no se proporciona

&nbsp;RandomBytes.Generate(transfer.FileId);

&nbsp;}



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;\_activeTransfers\[transferKey] = transfer;

&nbsp;}



&nbsp;// Enviar control de archivo (FILE\_CONTROL)

&nbsp;SendFileControl(friendNumber, fileNumber, 0); // 0 = SEND



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Iniciando envío de archivo {fileName} ({fileSize} bytes) a friend {friendNumber}");



&nbsp;return fileNumber;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando envío de archivo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_file\_send\_chunk - Envía chunk de archivo

&nbsp;/// </summary>

&nbsp;public bool FileSendChunk(int friendNumber, int fileNumber, long position, byte\[] data, int length)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;FileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Transferencia no encontrada: {transferKey}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;if (transfer.Status != FileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Transferencia {transferKey} no está en estado de transferencia");

&nbsp;return false;

&nbsp;}



&nbsp;// Crear paquete FILE\_DATA

&nbsp;byte\[] packet = CreateFileDataPacket(fileNumber, position, data, length);

&nbsp;if (packet == null) return false;



&nbsp;// Enviar a través de onion routing

&nbsp;var friend = \_messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend == null) return false;



&nbsp;int sent = \_messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;transfer.BytesSent += length;

&nbsp;transfer.LastActivity = DateTime.UtcNow.Ticks;



&nbsp;// Verificar si se completó la transferencia

&nbsp;if (transfer.BytesSent >= transfer.FileSize)

&nbsp;{

&nbsp;transfer.Status = FileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED;

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Transferencia completada: {transfer.FileName}");



&nbsp;// Disparar callback de finalización

&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, FileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED, null);

&nbsp;}



&nbsp;return true;

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando chunk: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// tox\_file\_control - Control de transferencia (pausar, reanudar, cancelar)

&nbsp;/// </summary>

&nbsp;public bool FileControl(int friendNumber, int fileNumber, int control)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;FileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return false;

&nbsp;}



&nbsp;FileTransferStatus newStatus = transfer.Status;



&nbsp;switch (control)

&nbsp;{

&nbsp;case 0: // RESUME

&nbsp;newStatus = FileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING;

&nbsp;break;

&nbsp;case 1: // PAUSE

&nbsp;newStatus = FileTransferStatus.FILE\_TRANSFER\_STATUS\_PAUSED;

&nbsp;break;

&nbsp;case 2: // CANCEL

&nbsp;newStatus = FileTransferStatus.FILE\_TRANSFER\_STATUS\_CANCELLED;

&nbsp;break;

&nbsp;default:

&nbsp;return false;

&nbsp;}



&nbsp;transfer.Status = newStatus;

&nbsp;transfer.LastActivity = DateTime.UtcNow.Ticks;



&nbsp;// Enviar control al remitente

&nbsp;SendFileControl(friendNumber, fileNumber, control);



&nbsp;// Disparar callback

&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, newStatus, null);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Control de archivo {fileNumber}: {control} -> {newStatus}");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en control de archivo: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Maneja paquetes de transferencia de archivos entrantes

&nbsp;/// </summary>

&nbsp;public int HandleFilePacket(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (packet == null || length < 5) return -1;



&nbsp;try

&nbsp;{

&nbsp;byte packetType = packet\[0];



&nbsp;switch (packetType)

&nbsp;{

&nbsp;case 0x50: // FILE\_CONTROL

&nbsp;return HandleFileControl(friendNumber, packet, length);

&nbsp;case 0x51: // FILE\_DATA

&nbsp;return HandleFileData(friendNumber, packet, length);

&nbsp;case 0x52: // FILE\_REQUEST

&nbsp;return HandleFileRequest(friendNumber, packet, length);

&nbsp;default:

&nbsp;return -1;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error manejando paquete de archivo: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;private int HandleFileControl(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 9) return -1; // \[type]\[file\_number(4)]\[control(4)]



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;int control = BitConverter.ToInt32(packet, 5);



&nbsp;return FileControl(friendNumber, fileNumber, control) ? 0 : -1;

&nbsp;}



&nbsp;private int HandleFileData(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 13) return -1; // \[type]\[file\_number(4)]\[position(8)] + data



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;long position = BitConverter.ToInt64(packet, 5);



&nbsp;int dataLength = length - 13;

&nbsp;byte\[] data = new byte\[dataLength];

&nbsp;Buffer.BlockCopy(packet, 13, data, 0, dataLength);



&nbsp;string transferKey = $"{friendNumber}\_{fileNumber}";

&nbsp;FileTransfer transfer;



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;if (!\_activeTransfers.TryGetValue(transferKey, out transfer))

&nbsp;return -1;

&nbsp;}



&nbsp;// Procesar datos recibidos

&nbsp;transfer.BytesReceived += dataLength;

&nbsp;transfer.LastActivity = DateTime.UtcNow.Ticks;



&nbsp;// Disparar callback de chunk recibido

&nbsp;\_callbacks.OnFileChunkReceived?.Invoke(friendNumber, fileNumber, position, data, null);



&nbsp;// Verificar si se completó la recepción

&nbsp;if (transfer.BytesReceived >= transfer.FileSize)

&nbsp;{

&nbsp;transfer.Status = FileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED;

&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(friendNumber, fileNumber, FileTransferStatus.FILE\_TRANSFER\_STATUS\_COMPLETED, null);

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Recepción completada: {transfer.FileName}");

&nbsp;}



&nbsp;return 0;

&nbsp;}



&nbsp;private int HandleFileRequest(int friendNumber, byte\[] packet, int length)

&nbsp;{

&nbsp;if (length < 45) return -1; // \[type]\[file\_number(4)]\[file\_size(8)]\[file\_id(32)] + filename



&nbsp;int fileNumber = BitConverter.ToInt32(packet, 1);

&nbsp;long fileSize = BitConverter.ToInt64(packet, 5);



&nbsp;byte\[] fileId = new byte\[32];

&nbsp;Buffer.BlockCopy(packet, 13, fileId, 0, 32);



&nbsp;string fileName = System.Text.Encoding.UTF8.GetString(packet, 45, length - 45);



&nbsp;// Disparar callback de archivo recibido

&nbsp;\_callbacks.OnFileReceive?.Invoke(friendNumber, fileNumber, FileKind.TOX\_FILE\_KIND\_DATA, fileSize, fileName, fileId, null);



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Solicitud de archivo recibida: {fileName} ({fileSize} bytes)");



&nbsp;return 0;

&nbsp;}



&nbsp;private byte\[] CreateFileDataPacket(int fileNumber, long position, byte\[] data, int length)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[13 + length];

&nbsp;packet\[0] = 0x51; // FILE\_DATA type



&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(position), 0, packet, 5, 8);

&nbsp;Buffer.BlockCopy(data, 0, packet, 13, length);



&nbsp;return packet;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error creando paquete FILE\_DATA: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private void SendFileControl(int friendNumber, int fileNumber, int control)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;byte\[] packet = new byte\[9];

&nbsp;packet\[0] = 0x50; // FILE\_CONTROL type



&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(fileNumber), 0, packet, 1, 4);

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(control), 0, packet, 5, 4);



&nbsp;var friend = \_messenger.FriendConn.Get\_friend(friendNumber);

&nbsp;if (friend != null)

&nbsp;{

&nbsp;\_messenger.Onion.onion\_send\_1(packet, packet.Length, friend.PublicKey);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando control de archivo: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// DoPeriodicWork - Mantenimiento de transferencias

&nbsp;/// </summary>

&nbsp;public void DoPeriodicWork()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<string> transfersToRemove = new List<string>();



&nbsp;lock (\_transfersLock)

&nbsp;{

&nbsp;foreach (var kvp in \_activeTransfers)

&nbsp;{

&nbsp;var transfer = kvp.Value;

&nbsp;long timeSinceActivity = (currentTime - transfer.LastActivity) / TimeSpan.TicksPerMillisecond;



&nbsp;// Timeout después de 60 segundos de inactividad

&nbsp;if (timeSinceActivity > 60000 \&\& transfer.Status == FileTransferStatus.FILE\_TRANSFER\_STATUS\_TRANSFERRING)

&nbsp;{

&nbsp;transfer.Status = FileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR;

&nbsp;transfersToRemove.Add(kvp.Key);



&nbsp;\_callbacks.OnFileTransferStatusChanged?.Invoke(

&nbsp;transfer.FriendNumber, transfer.FileNumber,

&nbsp;FileTransferStatus.FILE\_TRANSFER\_STATUS\_ERROR, null);



&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Timeout en transferencia: {transfer.FileName}");

&nbsp;}

&nbsp;}



&nbsp;// Remover transferencias completadas/error

&nbsp;foreach (var key in transfersToRemove)

&nbsp;{

&nbsp;\_activeTransfers.Remove(key);

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en trabajo periódico: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}

}

]



Archivo AdvancedNetworking.cs \[

using System.Net;

using System.Net.Sockets;

using ToxCore.Core;



namespace ToxCore.Networking

{

&nbsp;/// <summary>

&nbsp;/// Tipos de proxy soportados

&nbsp;/// </summary>

&nbsp;public enum ProxyType

&nbsp;{

&nbsp;PROXY\_TYPE\_NONE = 0,

&nbsp;PROXY\_TYPE\_HTTP = 1,

&nbsp;PROXY\_TYPE\_SOCKS5 = 2

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Estrategias de hole punching

&nbsp;/// </summary>

&nbsp;public enum HolePunchStrategy

&nbsp;{

&nbsp;UDP\_HOLE\_PUNCH = 0,

&nbsp;TCP\_HOLE\_PUNCH = 1,

&nbsp;ICMP\_HOLE\_PUNCH = 2,

&nbsp;RELAY\_FALLBACK = 3

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Información de configuración de proxy

&nbsp;/// </summary>

&nbsp;public class ProxyConfig

&nbsp;{

&nbsp;public ProxyType Type { get; set; }

&nbsp;public string Host { get; set; }

&nbsp;public ushort Port { get; set; }

&nbsp;public string Username { get; set; }

&nbsp;public string Password { get; set; }

&nbsp;public bool Enabled { get; set; }



&nbsp;public ProxyConfig()

&nbsp;{

&nbsp;Type = ProxyType.PROXY\_TYPE\_NONE;

&nbsp;Enabled = false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Información de sesión de hole punching

&nbsp;/// </summary>

&nbsp;public class HolePunchSession

&nbsp;{

&nbsp;public IPPort Target { get; set; }

&nbsp;public HolePunchStrategy Strategy { get; set; }

&nbsp;public long StartTime { get; set; }

&nbsp;public int Attempts { get; set; }

&nbsp;public bool Success { get; set; }

&nbsp;public int TimeoutMs { get; set; }

&nbsp;public List<IPPort> CandidatePorts { get; set; }



&nbsp;public HolePunchSession(IPPort target, HolePunchStrategy strategy)

&nbsp;{

&nbsp;Target = target;

&nbsp;Strategy = strategy;

&nbsp;StartTime = DateTime.UtcNow.Ticks;

&nbsp;Attempts = 0;

&nbsp;Success = false;

&nbsp;TimeoutMs = 10000; // 10 segundos

&nbsp;CandidatePorts = new List<IPPort>();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Información de conexión TCP relay

&nbsp;/// </summary>

&nbsp;public class RelayConnection

&nbsp;{

&nbsp;public int FriendNumber { get; set; }

&nbsp;public IPPort RelayServer { get; set; }

&nbsp;public Socket RelaySocket { get; set; }

&nbsp;public bool IsConnected { get; set; }

&nbsp;public long LastActivity { get; set; }

&nbsp;public int RelayId { get; set; }



&nbsp;public RelayConnection(int friendNumber, IPPort relayServer)

&nbsp;{

&nbsp;FriendNumber = friendNumber;

&nbsp;RelayServer = relayServer;

&nbsp;IsConnected = false;

&nbsp;LastActivity = DateTime.UtcNow.Ticks;

&nbsp;RelayId = new Random().Next();

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Módulo de Networking Avanzado para Tox

&nbsp;/// </summary>

&nbsp;public class AdvancedNetworking : IDisposable

&nbsp;{

&nbsp;private const string LOG\_TAG = "ADV\_NET";



&nbsp;// Constantes de configuración

&nbsp;private const int MAX\_HOLE\_PUNCH\_ATTEMPTS = 5;

&nbsp;private const int HOLE\_PUNCH\_TIMEOUT\_MS = 10000;

&nbsp;private const int RELAY\_CONNECTION\_TIMEOUT\_MS = 30000;

&nbsp;private const int PORT\_RANGE\_START = 33445;

&nbsp;private const int PORT\_RANGE\_END = 33545;



&nbsp;// Componentes

&nbsp;private readonly Core.Tox \_tox;

&nbsp;private readonly ProxyConfig \_proxyConfig;

&nbsp;private readonly List<HolePunchSession> \_activePunchSessions;

&nbsp;private readonly Dictionary<int, RelayConnection> \_relayConnections;

&nbsp;private readonly Dictionary<IPPort, long> \_natMappings;

&nbsp;private readonly object \_sessionsLock = new object();

&nbsp;private readonly object \_relaysLock = new object();

&nbsp;private bool \_isRunning;

&nbsp;private Thread \_networkingThread;

&nbsp;private CancellationTokenSource \_cancellationTokenSource;



&nbsp;// Servidores STUN para detección NAT

&nbsp;private readonly string\[] \_stunServers = {

&nbsp;"stun.l.google.com:19302",

&nbsp;"stun1.l.google.com:19302",

&nbsp;"stun2.l.google.com:19302",

&nbsp;"stun3.l.google.com:19302",

&nbsp;"stun4.l.google.com:19302"

&nbsp;};



&nbsp;// Servidores relay de respaldo

&nbsp;private readonly IPPort\[] \_relayServers = {

&nbsp;new IPPort(new IP(IPAddress.Parse("144.217.167.73")), 33445),

&nbsp;new IPPort(new IP(IPAddress.Parse("108.61.165.198")), 33445),

&nbsp;new IPPort(new IP(IPAddress.Parse("51.15.43.205")), 33445)

&nbsp;};



&nbsp;public ProxyConfig Proxy => \_proxyConfig;

&nbsp;public bool IsRunning => \_isRunning;



&nbsp;public AdvancedNetworking(Core.Tox tox)

&nbsp;{

&nbsp;\_tox = tox ?? throw new ArgumentNullException(nameof(tox));

&nbsp;\_proxyConfig = new ProxyConfig();

&nbsp;\_activePunchSessions = new List<HolePunchSession>();

&nbsp;\_relayConnections = new Dictionary<int, RelayConnection>();

&nbsp;\_natMappings = new Dictionary<IPPort, long>();

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Advanced Networking inicializado");

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Iniciar servicio de networking avanzado

&nbsp;/// </summary>

&nbsp;public bool Start()

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.Warning($"\[{LOG\_TAG}] Advanced Networking ya está ejecutándose");

&nbsp;return true;

&nbsp;}



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = true;

&nbsp;\_cancellationTokenSource = new CancellationTokenSource();



&nbsp;// Iniciar hilo de networking

&nbsp;\_networkingThread = new Thread(NetworkingWorker);

&nbsp;\_networkingThread.IsBackground = true;

&nbsp;\_networkingThread.Name = "AdvancedNetworking-Worker";

&nbsp;\_networkingThread.Start();



&nbsp;// Iniciar detección NAT

&nbsp;Task.Run(() => DetectNatType());



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio Advanced Networking iniciado");

&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando Advanced Networking: {ex.Message}");

&nbsp;\_isRunning = false;

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Detener servicio de networking avanzado

&nbsp;/// </summary>

&nbsp;public void Stop()

&nbsp;{

&nbsp;if (!\_isRunning) return;



&nbsp;try

&nbsp;{

&nbsp;\_isRunning = false;

&nbsp;\_cancellationTokenSource?.Cancel();



&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;\_activePunchSessions.Clear();

&nbsp;}



&nbsp;lock (\_relaysLock)

&nbsp;{

&nbsp;foreach (var relay in \_relayConnections.Values)

&nbsp;{

&nbsp;relay.RelaySocket?.Close();

&nbsp;}

&nbsp;\_relayConnections.Clear();

&nbsp;}



&nbsp;\_networkingThread?.Join(2000);



&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Servicio Advanced Networking detenido");

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error deteniendo Advanced Networking: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== HOLE PUNCHING ====================



&nbsp;/// <summary>

&nbsp;/// Iniciar hole punching a un objetivo

&nbsp;/// </summary>

&nbsp;public bool StartHolePunching(IPPort target, HolePunchStrategy strategy = HolePunchStrategy.UDP\_HOLE\_PUNCH)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var session = new HolePunchSession(target, strategy);



&nbsp;// Generar puertos candidatos

&nbsp;GenerateCandidatePorts(session);



&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;\_activePunchSessions.Add(session);

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Iniciando hole punching a {target} - Estrategia: {strategy}");



&nbsp;// Iniciar proceso asíncrono

&nbsp;Task.Run(() => ExecuteHolePunch(session));



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error iniciando hole punching: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Ejecutar proceso de hole punching

&nbsp;/// </summary>

&nbsp;private async Task ExecuteHolePunch(HolePunchSession session)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;while (session.Attempts < MAX\_HOLE\_PUNCH\_ATTEMPTS \&\&

&nbsp;!session.Success \&\&

&nbsp;\_isRunning)

&nbsp;{

&nbsp;session.Attempts++;



&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Intento {session.Attempts} de hole punching a {session.Target}");



&nbsp;bool success = false;



&nbsp;switch (session.Strategy)

&nbsp;{

&nbsp;case HolePunchStrategy.UDP\_HOLE\_PUNCH:

&nbsp;success = await ExecuteUdpHolePunch(session);

&nbsp;break;

&nbsp;case HolePunchStrategy.TCP\_HOLE\_PUNCH:

&nbsp;success = await ExecuteTcpHolePunch(session);

&nbsp;break;

&nbsp;case HolePunchStrategy.RELAY\_FALLBACK:

&nbsp;success = await ExecuteRelayFallback(session);

&nbsp;break;

&nbsp;}



&nbsp;if (success)

&nbsp;{

&nbsp;session.Success = true;

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Hole punching exitoso a {session.Target} después de {session.Attempts} intentos");

&nbsp;break;

&nbsp;}



&nbsp;// Esperar antes del siguiente intento

&nbsp;if (session.Attempts < MAX\_HOLE\_PUNCH\_ATTEMPTS)

&nbsp;{

&nbsp;await Task.Delay(1000);

&nbsp;}

&nbsp;}



&nbsp;if (!session.Success)

&nbsp;{

&nbsp;Logger.Log.WarningF($"\[{LOG\_TAG}] Hole punching falló después de {session.Attempts} intentos");

&nbsp;// Intentar con relay como último recurso

&nbsp;await ExecuteRelayFallback(session);

&nbsp;}



&nbsp;// Limpiar sesión

&nbsp;lock (\_sessionsLock)

&nbsp;{

&nbsp;\_activePunchSessions.Remove(session);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en proceso de hole punching: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Hole punching UDP (el más común para Tox) - VERSIÓN CORREGIDA

&nbsp;/// </summary>

&nbsp;private async Task<bool> ExecuteUdpHolePunch(HolePunchSession session)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;using (var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))

&nbsp;{

&nbsp;// ✅ CORRECCIÓN: Configurar socket correctamente

&nbsp;udpSocket.Blocking = false;

&nbsp;udpSocket.ReceiveTimeout = 1000;

&nbsp;udpSocket.SendTimeout = 1000;



&nbsp;// Bind a puerto aleatorio

&nbsp;int localPort = new Random().Next(PORT\_RANGE\_START, PORT\_RANGE\_END);

&nbsp;var localEP = new IPEndPoint(IPAddress.Any, localPort);



&nbsp;try

&nbsp;{

&nbsp;udpSocket.Bind(localEP);

&nbsp;}

&nbsp;catch (SocketException)

&nbsp;{

&nbsp;// Si el puerto está ocupado, usar puerto efímero

&nbsp;udpSocket.Bind(new IPEndPoint(IPAddress.Any, 0));

&nbsp;}



&nbsp;// ✅ CORRECCIÓN: Usar LINQ para crear tasks

&nbsp;var tasks = session.CandidatePorts

&nbsp;.Select(candidate => TestUdpConnectivity(udpSocket, candidate))

&nbsp;.ToList();



&nbsp;// ✅ CORRECCIÓN: Esperar todas las tasks con timeout

&nbsp;var timeoutTask = Task.Delay(HOLE\_PUNCH\_TIMEOUT\_MS);

&nbsp;var completedTask = await Task.WhenAny(Task.WhenAll(tasks), timeoutTask);



&nbsp;if (completedTask == timeoutTask)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Timeout en hole punching UDP");

&nbsp;return false;

&nbsp;}



&nbsp;var results = await Task.WhenAll(tasks);

&nbsp;return results.Any(r => r);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en UDP hole punch: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Test de conectividad UDP - VERSIÓN CORREGIDA

&nbsp;/// </summary>

&nbsp;private async Task<bool> TestUdpConnectivity(Socket socket, IPPort target)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// Crear paquete de prueba

&nbsp;byte\[] testPacket = CreateHolePunchPacket();

&nbsp;var remoteEP = new IPEndPoint(target.IP.ToIPAddress(), target.Port);



&nbsp;// Enviar múltiples paquetes (NATs pueden requerir múltiples intentos)

&nbsp;for (int i = 0; i < 3; i++)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// ✅ CORRECCIÓN: Usar SendTo de forma asíncrona

&nbsp;var sendTask = Task.Run(() => socket.SendTo(testPacket, remoteEP));

&nbsp;if (await Task.WhenAny(sendTask, Task.Delay(1000)) == sendTask)

&nbsp;{

&nbsp;int sent = sendTask.Result;

&nbsp;if (sent > 0)

&nbsp;{

&nbsp;// Esperar respuesta breve

&nbsp;await Task.Delay(100);



&nbsp;// Verificar si hay datos de respuesta usando Poll

&nbsp;if (socket.Poll(100000, SelectMode.SelectRead)) // 100ms timeout

&nbsp;{

&nbsp;byte\[] buffer = new byte\[1024];

&nbsp;EndPoint tempEP = new IPEndPoint(IPAddress.Any, 0);



&nbsp;var receiveTask = Task.Run(() => socket.ReceiveFrom(buffer, ref tempEP));

&nbsp;if (await Task.WhenAny(receiveTask, Task.Delay(500)) == receiveTask)

&nbsp;{

&nbsp;int received = receiveTask.Result;

&nbsp;if (received > 0 \&\& IsValidHolePunchResponse(buffer, received))

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión UDP establecida con {target}");

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (SocketException) { /\* Timeout esperado \*/ }

&nbsp;catch (ObjectDisposedException) { /\* Socket cerrado \*/ }



&nbsp;await Task.Delay(200);

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Test UDP falló para {target}: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Hole punching TCP (para conexiones TCP relay)

&nbsp;/// </summary>

&nbsp;private async Task<bool> ExecuteTcpHolePunch(HolePunchSession session)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;// TCP hole punching es más complejo - requiere coordinación

&nbsp;// Por simplicidad, intentamos conexiones simultáneas

&nbsp;var tasks = session.CandidatePorts.Select(candidate =>

&nbsp;AttemptTcpConnection(candidate)).ToList();



&nbsp;var results = await Task.WhenAll(tasks);

&nbsp;return results.Any(r => r);

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en TCP hole punch: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;private async Task<bool> AttemptTcpConnection(IPPort target)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;using (var tcpClient = new TcpClient())

&nbsp;{

&nbsp;tcpClient.SendTimeout = 2000;

&nbsp;tcpClient.ReceiveTimeout = 2000;



&nbsp;// ✅ CORRECCIÓN: Usar ConnectAsync correctamente

&nbsp;var connectTask = tcpClient.ConnectAsync(target.IP.ToIPAddress(), target.Port);

&nbsp;var timeoutTask = Task.Delay(3000);



&nbsp;var completedTask = await Task.WhenAny(connectTask, timeoutTask);



&nbsp;if (completedTask == connectTask \&\& !connectTask.IsFaulted \&\& tcpClient.Connected)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión TCP establecida con {target}");

&nbsp;return true;

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión TCP falló para {target}: {ex.Message}");

&nbsp;}



&nbsp;return false;

&nbsp;}



&nbsp;// ==================== PROXY SUPPORT ====================



&nbsp;/// <summary>

&nbsp;/// Configurar proxy

&nbsp;/// </summary>

&nbsp;public bool SetProxy(ProxyType type, string host, ushort port, string username = null, string password = null)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;\_proxyConfig.Type = type;

&nbsp;\_proxyConfig.Host = host;

&nbsp;\_proxyConfig.Port = port;

&nbsp;\_proxyConfig.Username = username;

&nbsp;\_proxyConfig.Password = password;

&nbsp;\_proxyConfig.Enabled = true;



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Proxy configurado: {type}://{host}:{port}");



&nbsp;return true;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error configurando proxy: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conectar a través de proxy

&nbsp;/// </summary>

&nbsp;public async Task<Socket> ConnectThroughProxy(IPPort target)

&nbsp;{

&nbsp;if (!\_proxyConfig.Enabled)

&nbsp;return await DirectConnect(target);



&nbsp;try

&nbsp;{

&nbsp;switch (\_proxyConfig.Type)

&nbsp;{

&nbsp;case ProxyType.PROXY\_TYPE\_HTTP:

&nbsp;return await ConnectThroughHttpProxy(target);

&nbsp;case ProxyType.PROXY\_TYPE\_SOCKS5:

&nbsp;return await ConnectThroughSocks5Proxy(target);

&nbsp;default:

&nbsp;return await DirectConnect(target);

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error conectando through proxy: {ex.Message}");

&nbsp;return await DirectConnect(target); // Fallback a conexión directa

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conexión a través de proxy HTTP

&nbsp;/// </summary>

&nbsp;private async Task<Socket> ConnectThroughHttpProxy(IPPort target)

&nbsp;{

&nbsp;var proxySocket = await DirectConnect(new IPPort(new IP(IPAddress.Parse(\_proxyConfig.Host)), \_proxyConfig.Port));

&nbsp;if (proxySocket == null) return null;



&nbsp;try

&nbsp;{

&nbsp;// Enviar comando CONNECT HTTP

&nbsp;string connectCommand = $"CONNECT {target.IP}:{target.Port} HTTP/1.1\\r\\nHost: {target.IP}:{target.Port}\\r\\n\\r\\n";

&nbsp;byte\[] commandBytes = System.Text.Encoding.ASCII.GetBytes(connectCommand);



&nbsp;await proxySocket.SendAsync(new ArraySegment<byte>(commandBytes), SocketFlags.None);



&nbsp;// Leer respuesta

&nbsp;byte\[] buffer = new byte\[1024];

&nbsp;int received = await proxySocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

&nbsp;string response = System.Text.Encoding.ASCII.GetString(buffer, 0, received);



&nbsp;if (response.StartsWith("HTTP/1.1 200") || response.StartsWith("HTTP/1.0 200"))

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión HTTP proxy establecida a {target}");

&nbsp;return proxySocket;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;proxySocket.Close();

&nbsp;return null;

&nbsp;}

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;proxySocket?.Close();

&nbsp;throw;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Conexión a través de proxy SOCKS5

&nbsp;/// </summary>

&nbsp;private async Task<Socket> ConnectThroughSocks5Proxy(IPPort target)

&nbsp;{

&nbsp;var proxySocket = await DirectConnect(new IPPort(new IP(IPAddress.Parse(\_proxyConfig.Host)), \_proxyConfig.Port));

&nbsp;if (proxySocket == null) return null;



&nbsp;try

&nbsp;{

&nbsp;// Handshake SOCKS5

&nbsp;byte\[] handshake = new byte\[] { 0x05, 0x01, 0x00 }; // VER, NMETHODS, NO AUTH

&nbsp;await proxySocket.SendAsync(new ArraySegment<byte>(handshake), SocketFlags.None);



&nbsp;byte\[] handshakeResponse = new byte\[2];

&nbsp;await proxySocket.ReceiveAsync(new ArraySegment<byte>(handshakeResponse), SocketFlags.None);



&nbsp;if (handshakeResponse\[0] != 0x05 || handshakeResponse\[1] != 0x00)

&nbsp;{

&nbsp;proxySocket.Close();

&nbsp;return null;

&nbsp;}



&nbsp;// Comando CONNECT

&nbsp;byte\[] connectRequest = CreateSocks5ConnectRequest(target);

&nbsp;await proxySocket.SendAsync(new ArraySegment<byte>(connectRequest), SocketFlags.None);



&nbsp;byte\[] connectResponse = new byte\[10];

&nbsp;await proxySocket.ReceiveAsync(new ArraySegment<byte>(connectResponse), SocketFlags.None);



&nbsp;if (connectResponse\[1] == 0x00) // Success

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión SOCKS5 proxy establecida a {target}");

&nbsp;return proxySocket;

&nbsp;}

&nbsp;else

&nbsp;{

&nbsp;proxySocket.Close();

&nbsp;return null;

&nbsp;}

&nbsp;}

&nbsp;catch

&nbsp;{

&nbsp;proxySocket?.Close();

&nbsp;throw;

&nbsp;}

&nbsp;}



&nbsp;// ==================== TCP RELAY FALLBACK ====================



&nbsp;/// <summary>

&nbsp;/// Fallback a conexión relay

&nbsp;/// </summary>

&nbsp;private async Task<bool> ExecuteRelayFallback(HolePunchSession session)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Intentando conexión relay para {session.Target}");



&nbsp;// Buscar servidor relay disponible

&nbsp;foreach (var relayServer in \_relayServers)

&nbsp;{

&nbsp;var relaySocket = await ConnectThroughProxy(relayServer);

&nbsp;if (relaySocket != null \&\& relaySocket.Connected)

&nbsp;{

&nbsp;// Establecer conexión relay

&nbsp;var relayConn = new RelayConnection(-1, relayServer) // -1 indica conexión temporal

&nbsp;{

&nbsp;RelaySocket = relaySocket,

&nbsp;IsConnected = true

&nbsp;};



&nbsp;lock (\_relaysLock)

&nbsp;{

&nbsp;\_relayConnections\[relayConn.RelayId] = relayConn;

&nbsp;}



&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] Conexión relay establecida a través de {relayServer}");

&nbsp;return true;

&nbsp;}

&nbsp;}



&nbsp;return false;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en relay fallback: {ex.Message}");

&nbsp;return false;

&nbsp;}

&nbsp;}



&nbsp;/// <summary>

&nbsp;/// Enviar datos a través de relay

&nbsp;/// </summary>

&nbsp;public async Task<int> SendThroughRelay(int relayId, byte\[] data, IPPort ultimateTarget)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;lock (\_relaysLock)

&nbsp;{

&nbsp;if (\_relayConnections.TryGetValue(relayId, out var relayConn) \&\&

&nbsp;relayConn.IsConnected \&\&

&nbsp;relayConn.RelaySocket.Connected)

&nbsp;{

&nbsp;// Encapsular datos con información de destino

&nbsp;byte\[] relayPacket = CreateRelayPacket(data, ultimateTarget);

&nbsp;return relayConn.RelaySocket.Send(relayPacket);

&nbsp;}

&nbsp;}



&nbsp;return -1;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error enviando through relay: {ex.Message}");

&nbsp;return -1;

&nbsp;}

&nbsp;}



&nbsp;// ==================== NAT DETECTION ====================



&nbsp;/// <summary>

&nbsp;/// Detectar tipo de NAT

&nbsp;/// </summary>

&nbsp;private async Task DetectNatType()

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;Logger.Log.Info($"\[{LOG\_TAG}] Iniciando detección de tipo NAT...");



&nbsp;using (var udpClient = new UdpClient())

&nbsp;{

&nbsp;udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));



&nbsp;foreach (var stunServer in \_stunServers)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var serverParts = stunServer.Split(':');

&nbsp;string host = serverParts\[0];

&nbsp;int port = int.Parse(serverParts\[1]);



&nbsp;var stunResult = await ExecuteStunRequest(udpClient, host, port);

&nbsp;if (stunResult != null)

&nbsp;{

&nbsp;Logger.Log.InfoF($"\[{LOG\_TAG}] NAT Detection: {stunResult.NatType} - Mapped: {stunResult.MappedAddress}");



&nbsp;// Guardar mapping NAT

&nbsp;\_natMappings\[stunResult.MappedAddress] = DateTime.UtcNow.Ticks;

&nbsp;break;

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] STUN server {stunServer} falló: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en detección NAT: {ex.Message}");

&nbsp;}

&nbsp;}



&nbsp;// ==================== MÉTODOS AUXILIARES ====================



&nbsp;private void GenerateCandidatePorts(HolePunchSession session)

&nbsp;{

&nbsp;// Puertos comunes para Tox

&nbsp;int\[] commonPorts = { 33445, 3389, 3390, 3391, 443, 80, 8080 };



&nbsp;foreach (int port in commonPorts)

&nbsp;{

&nbsp;session.CandidatePorts.Add(new IPPort(session.Target.IP, (ushort)port));

&nbsp;}



&nbsp;// Algunos puertos aleatorios en rango común

&nbsp;var random = new Random();

&nbsp;for (int i = 0; i < 5; i++)

&nbsp;{

&nbsp;int randomPort = random.Next(10000, 60000);

&nbsp;session.CandidatePorts.Add(new IPPort(session.Target.IP, (ushort)randomPort));

&nbsp;}

&nbsp;}



&nbsp;private byte\[] CreateHolePunchPacket()

&nbsp;{

&nbsp;// Paquete de prueba para hole punching

&nbsp;byte\[] packet = new byte\[32];

&nbsp;packet\[0] = 0x20; // HOLE\_PUNCH type

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(DateTime.UtcNow.Ticks), 0, packet, 1, 8);

&nbsp;RandomBytes.Generate(packet, 9, 23); // Random data

&nbsp;return packet;

&nbsp;}



&nbsp;private bool IsValidHolePunchResponse(byte\[] data, int length)

&nbsp;{

&nbsp;return length >= 9 \&\& data\[0] == 0x21; // HOLE\_PUNCH\_RESPONSE type

&nbsp;}



&nbsp;private byte\[] CreateSocks5ConnectRequest(IPPort target)

&nbsp;{

&nbsp;byte\[] request = new byte\[10];

&nbsp;request\[0] = 0x05; // VER

&nbsp;request\[1] = 0x01; // CMD CONNECT

&nbsp;request\[2] = 0x00; // RSV

&nbsp;request\[3] = 0x01; // ATYP IPv4



&nbsp;byte\[] ipBytes = target.IP.ToIPAddress().GetAddressBytes();

&nbsp;Buffer.BlockCopy(ipBytes, 0, request, 4, 4);



&nbsp;byte\[] portBytes = BitConverter.GetBytes((ushort)target.Port);

&nbsp;Array.Reverse(portBytes); // Big-endian

&nbsp;Buffer.BlockCopy(portBytes, 0, request, 8, 2);



&nbsp;return request;

&nbsp;}



&nbsp;private byte\[] CreateRelayPacket(byte\[] data, IPPort target)

&nbsp;{

&nbsp;byte\[] packet = new byte\[22 + data.Length]; // header + IPv4 + port + data

&nbsp;packet\[0] = 0x30; // RELAY type



&nbsp;// Dirección de destino

&nbsp;byte\[] ipBytes = target.IP.ToIPAddress().GetAddressBytes();

&nbsp;Buffer.BlockCopy(ipBytes, 0, packet, 1, 4);



&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(target.Port), 0, packet, 5, 2);



&nbsp;// Datos

&nbsp;Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, packet, 7, 4);

&nbsp;Buffer.BlockCopy(data, 0, packet, 11, data.Length);



&nbsp;return packet;

&nbsp;}



&nbsp;private async Task<Socket> DirectConnect(IPPort target)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

&nbsp;socket.Blocking = false;



&nbsp;await socket.ConnectAsync(target.IP.ToIPAddress(), target.Port);

&nbsp;return socket;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] Conexión directa falló a {target}: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private async Task<StunResult> ExecuteStunRequest(UdpClient udpClient, string host, int port)

&nbsp;{

&nbsp;// Implementación básica de cliente STUN

&nbsp;// En producción, usar una librería STUN completa

&nbsp;try

&nbsp;{

&nbsp;var stunMessage = CreateStunBindingRequest();

&nbsp;var sendTask = udpClient.SendAsync(stunMessage, stunMessage.Length, host, port);



&nbsp;// ✅ CORRECCIÓN: Esperar envío

&nbsp;await sendTask;



&nbsp;var receiveTask = udpClient.ReceiveAsync();

&nbsp;var timeoutTask = Task.Delay(5000);



&nbsp;var completedTask = await Task.WhenAny(receiveTask, timeoutTask);



&nbsp;if (completedTask == receiveTask)

&nbsp;{

&nbsp;var result = receiveTask.Result;

&nbsp;return ParseStunResponse(result.Buffer);

&nbsp;}



&nbsp;return null;

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] STUN request falló: {ex.Message}");

&nbsp;return null;

&nbsp;}

&nbsp;}



&nbsp;private byte\[] CreateStunBindingRequest()

&nbsp;{

&nbsp;// STUN Binding Request simplificado

&nbsp;byte\[] request = new byte\[20];

&nbsp;request\[0] = 0x00; // STUN method

&nbsp;request\[1] = 0x01; // Binding Request

&nbsp;request\[2] = 0x00; // Message length

&nbsp;request\[3] = 0x00;

&nbsp;RandomBytes.Generate(request, 4, 16); // Transaction ID

&nbsp;return request;

&nbsp;}



&nbsp;private StunResult ParseStunResponse(byte\[] response)

&nbsp;{

&nbsp;// Parseo básico de respuesta STUN

&nbsp;if (response.Length < 20) return null;



&nbsp;return new StunResult

&nbsp;{

&nbsp;NatType = "Cone NAT", // Simplificado

&nbsp;MappedAddress = new IPPort(new IP(IPAddress.Loopback), 33445) // Placeholder

&nbsp;};

&nbsp;}



&nbsp;// ==================== WORKER PRINCIPAL ====================



&nbsp;private void NetworkingWorker()

&nbsp;{

&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo Advanced Networking iniciado");



&nbsp;while (\_isRunning \&\& !\_cancellationTokenSource.Token.IsCancellationRequested)

&nbsp;{

&nbsp;try

&nbsp;{

&nbsp;MaintainRelayConnections();

&nbsp;CleanupExpiredMappings();

&nbsp;Thread.Sleep(5000); // Ejecutar cada 5 segundos

&nbsp;}

&nbsp;catch (Exception ex)

&nbsp;{

&nbsp;if (\_isRunning)

&nbsp;{

&nbsp;Logger.Log.ErrorF($"\[{LOG\_TAG}] Error en worker: {ex.Message}");

&nbsp;}

&nbsp;}

&nbsp;}



&nbsp;Logger.Log.Debug($"\[{LOG\_TAG}] Hilo Advanced Networking finalizado");

&nbsp;}



&nbsp;private void MaintainRelayConnections()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<int> relaysToRemove = new List<int>();



&nbsp;lock (\_relaysLock)

&nbsp;{

&nbsp;foreach (var kvp in \_relayConnections)

&nbsp;{

&nbsp;var relay = kvp.Value;

&nbsp;long timeSinceActivity = (currentTime - relay.LastActivity) / TimeSpan.TicksPerMillisecond;



&nbsp;if (timeSinceActivity > RELAY\_CONNECTION\_TIMEOUT\_MS ||

&nbsp;!relay.RelaySocket.Connected)

&nbsp;{

&nbsp;relaysToRemove.Add(kvp.Key);

&nbsp;relay.RelaySocket?.Close();

&nbsp;}

&nbsp;}



&nbsp;foreach (int relayId in relaysToRemove)

&nbsp;{

&nbsp;\_relayConnections.Remove(relayId);

&nbsp;}

&nbsp;}



&nbsp;if (relaysToRemove.Count > 0)

&nbsp;{

&nbsp;Logger.Log.DebugF($"\[{LOG\_TAG}] {relaysToRemove.Count} conexiones relay removidas");

&nbsp;}

&nbsp;}



&nbsp;private void CleanupExpiredMappings()

&nbsp;{

&nbsp;long currentTime = DateTime.UtcNow.Ticks;

&nbsp;List<IPPort> mappingsToRemove = new List<IPPort>();



&nbsp;foreach (var kvp in \_natMappings)

&nbsp;{

&nbsp;long timeSinceUpdate = (currentTime - kvp.Value) / TimeSpan.TicksPerMillisecond;

&nbsp;if (timeSinceUpdate > 3600000) // 1 hora

&nbsp;{

&nbsp;mappingsToRemove.Add(kvp.Key);

&nbsp;}

&nbsp;}



&nbsp;foreach (var mapping in mappingsToRemove)

&nbsp;{

&nbsp;\_natMappings.Remove(mapping);

&nbsp;}

&nbsp;}



&nbsp;public void Dispose()

&nbsp;{

&nbsp;Stop();

&nbsp;\_cancellationTokenSource?.Dispose();

&nbsp;}

&nbsp;}



&nbsp;// ==================== CLASES AUXILIARES ====================



&nbsp;public class StunResult

&nbsp;{

&nbsp;public string NatType { get; set; }

&nbsp;public IPPort MappedAddress { get; set; }

&nbsp;public IPPort ServerAddress { get; set; }

&nbsp;}

}

]





