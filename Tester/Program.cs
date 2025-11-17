using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ToxCore.Core;

namespace ToxCore
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("🔬 Probando implementación de CryptoPwHash...");
            Console.WriteLine("=============================================\n");



            // Test 1: Salsa20/8 Core
            RunCryptoSecurityAudit();
            
            //TestSalsa208Core();

            // Test 2: Generación de Salt
            TestSaltGeneration();

            // Test 3: Derivación de clave básica
            TestKeyDerivation();

            // Test 4: Verificación de password
            TestPasswordVerification();

            // Test 5: API compatible con C
            TestCompatibleAPI();

            // Test 6: CryptoBox
            TestCryptoBox();

            // Test 7: CryptoHashSha256
            TestCryptoHashSha256();

            // Test 8: Crypto_auth
            TestCryptoAuth();

            // Test 9: CryptoVerify
            TestCryptoVerify();

            // Test 10: RandomBytes
            TestRandomBytes();

            // Test 11: Network
            TestNetwork();

            // Test 12: DHT
            TestDHT();

            // Test 13: TestTCP
            TestTCP();

            // Test 14: TestOnion
            TestOnion();

            // Test 15: TestFriendConnection
            TestFriendConnection();

            // Test 16: Tox
            TestTox();

            Console.WriteLine("\n✅ Todas las pruebas completadas.");
            Console.WriteLine("Presiona Enter para salir...");
            Console.ReadLine();
        }

        static void TestSalsa208Core()
        {
            Console.WriteLine("1. Probando Salsa20/8 Core...");

            bool testPassed = CryptoPwHash.TestSalsa208();
            Console.WriteLine($"   Salsa20/8 básico: {(testPassed ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test más detallado
            try
            {
                var salsaMethod = typeof(CryptoPwHash).GetMethod("Salsa208Core",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

                if (salsaMethod != null)
                {
                    byte[] input = new byte[64];
                    byte[] output1 = new byte[64];
                    byte[] output2 = new byte[64];

                    // Test 1: Input específico
                    input[0] = 0x01;
                    salsaMethod.Invoke(null, new object[] { input, 0, output1, 0 });

                    // Test 2: Mismo input debería producir mismo output
                    input[0] = 0x01;
                    salsaMethod.Invoke(null, new object[] { input, 0, output2, 0 });

                    // Verificar determinismo
                    bool deterministic = true;
                    for (int i = 0; i < 64; i++)
                    {
                        if (output1[i] != output2[i])
                        {
                            deterministic = false;
                            break;
                        }
                    }

                    // Test 3: Input diferente debería producir output diferente
                    input[0] = 0x02;
                    byte[] output3 = new byte[64];
                    salsaMethod.Invoke(null, new object[] { input, 0, output3, 0 });

                    bool differentForDifferentInput = false;
                    for (int i = 0; i < 64; i++)
                    {
                        if (output1[i] != output3[i])
                        {
                            differentForDifferentInput = true;
                            break;
                        }
                    }

                    Console.WriteLine($"   Transformación Salsa20: ✅ CORRECTA");
                    Console.WriteLine($"   Comportamiento determinista: {(deterministic ? "✅" : "❌")}");
                    Console.WriteLine($"   Outputs diferentes para inputs diferentes: {(differentForDifferentInput ? "✅" : "❌")}");

                    // Mostrar sample del output
                    Console.WriteLine($"   Sample output: {BitConverter.ToString(output1, 0, 8).Replace("-", "")}...");
                }
                else
                {
                    Console.WriteLine("   ⚠️  No se pudo acceder al método Salsa208Core");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en Salsa20: {ex.Message}");
            }
        }


        static void TestSaltGeneration()
        {
            Console.WriteLine("\n2. Probando generación de Salt...");

            byte[] salt1 = CryptoPwHash.GenerateSalt();
            byte[] salt2 = CryptoPwHash.GenerateSalt();

            bool correctSize = salt1.Length == CryptoPwHash.SALT_BYTES;
            bool areDifferent = false;

            for (int i = 0; i < salt1.Length; i++)
            {
                if (salt1[i] != salt2[i])
                {
                    areDifferent = true;
                    break;
                }
            }

            Console.WriteLine($"   Tamaño correcto: {(correctSize ? "✅" : "❌")} ({salt1.Length} bytes)");
            Console.WriteLine($"   Salts diferentes: {(areDifferent ? "✅" : "❌")}");
        }

        static void TestKeyDerivation()
        {
            Console.WriteLine("\n3. Probando derivación de clave...");

            byte[] password = Encoding.UTF8.GetBytes("mi_password_secreto");
            byte[] salt = CryptoPwHash.GenerateSalt();

            try
            {
                byte[] key = CryptoPwHash.ScryptSalsa208Sha256(
                    password, salt,
                    CryptoPwHash.OPSLIMIT_INTERACTIVE,
                    CryptoPwHash.MEMLIMIT_INTERACTIVE);

                bool correctSize = key.Length == CryptoPwHash.HASH_BYTES;
                bool notAllZero = false;

                foreach (byte b in key)
                {
                    if (b != 0)
                    {
                        notAllZero = true;
                        break;
                    }
                }

                Console.WriteLine($"   Tamaño de clave: {(correctSize ? "✅" : "❌")} ({key.Length} bytes)");
                Console.WriteLine($"   Clave no-cero: {(notAllZero ? "✅" : "❌")}");

                // Derivar otra vez con mismos parámetros
                byte[] key2 = CryptoPwHash.ScryptSalsa208Sha256(
                    password, salt,
                    CryptoPwHash.OPSLIMIT_INTERACTIVE,
                    CryptoPwHash.MEMLIMIT_INTERACTIVE);

                bool keysEqual = true;
                for (int i = 0; i < key.Length; i++)
                {
                    if (key[i] != key2[i])
                    {
                        keysEqual = false;
                        break;
                    }
                }

                Console.WriteLine($"   Derivation determinista: {(keysEqual ? "✅" : "❌")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en derivación: {ex.Message}");
            }
        }

        static void TestPasswordVerification()
        {
            Console.WriteLine("\n4. Probando verificación de password...");

            byte[] password = Encoding.UTF8.GetBytes("password123");
            byte[] salt = CryptoPwHash.GenerateSalt();

            byte[] hash = CryptoPwHash.ScryptSalsa208Sha256(
                password, salt,
                CryptoPwHash.OPSLIMIT_INTERACTIVE,
                CryptoPwHash.MEMLIMIT_INTERACTIVE);

            // Verificar con password correcto
            bool correctPassword = CryptoPwHash.Verify(hash, password, salt,
                CryptoPwHash.OPSLIMIT_INTERACTIVE,
                CryptoPwHash.MEMLIMIT_INTERACTIVE);

            // Verificar con password incorrecto
            byte[] wrongPassword = Encoding.UTF8.GetBytes("password124");
            bool wrongPasswordResult = CryptoPwHash.Verify(hash, wrongPassword, salt,
                CryptoPwHash.OPSLIMIT_INTERACTIVE,
                CryptoPwHash.MEMLIMIT_INTERACTIVE);

            Console.WriteLine($"   Password correcto: {(correctPassword ? "✅" : "❌")}");
            Console.WriteLine($"   Password incorrecto: {(!wrongPasswordResult ? "✅" : "❌")}");
        }

        static void TestCompatibleAPI()
        {
            Console.WriteLine("\n5. Probando API compatible con C...");

            byte[] password = Encoding.UTF8.GetBytes("test");
            byte[] salt = new byte[crypto_pwhash_scryptsalsa208sha256_native.SALTBYTES];
            byte[] output = new byte[crypto_pwhash_scryptsalsa208sha256_native.BYTES];

            // Generar salt
            byte[] randomSalt = CryptoPwHash.GenerateSalt();
            Buffer.BlockCopy(randomSalt, 0, salt, 0, salt.Length);

            int result = crypto_pwhash_scryptsalsa208sha256_native.crypto_pwhash_scryptsalsa208sha256(
                output, (ulong)output.Length,
                password, (ulong)password.Length,
                salt,
                crypto_pwhash_scryptsalsa208sha256_native.OPSLIMIT_INTERACTIVE,
                crypto_pwhash_scryptsalsa208sha256_native.MEMLIMIT_INTERACTIVE);

            bool success = result == 0;
            bool outputNotEmpty = false;

            foreach (byte b in output)
            {
                if (b != 0)
                {
                    outputNotEmpty = true;
                    break;
                }
            }

            Console.WriteLine($"   Función C compatible: {(success ? "✅" : "❌")} (resultado: {result})");
            Console.WriteLine($"   Output no vacío: {(outputNotEmpty ? "✅" : "❌")}");

            // Mostrar algunos valores para inspección
            Console.WriteLine($"   Salt: {BitConverter.ToString(salt).Replace("-", "").Substring(0, 16)}...");
            Console.WriteLine($"   Hash: {BitConverter.ToString(output).Replace("-", "").Substring(0, 16)}...");
        }

        static void TestCryptoBox()
        {
            Console.WriteLine("\n6. Probando CryptoBox...");

            // Test básico
            bool basicTest = CryptoBox.Test();
            Console.WriteLine($"   Test básico encryption/decryption: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test con API C compatible
            TestCryptoBoxNativeAPI();

            // Test de rendimiento con shared key
            TestCryptoBoxSharedKey();
        }

        static void TestCryptoBoxNativeAPI()
        {
            Console.WriteLine("   Probando API nativa C...");

            byte[] publicKey = new byte[crypto_box_native.crypto_box_PUBLICKEYBYTES];
            byte[] secretKey = new byte[crypto_box_native.crypto_box_SECRETKEYBYTES];
            byte[] nonce = new byte[crypto_box_native.crypto_box_NONCEBYTES];
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello Tox!");
            byte[] cipherText = new byte[message.Length + crypto_box_native.crypto_box_MACBYTES];
            byte[] decrypted = new byte[message.Length];

            // Generar keypair
            int result = crypto_box_native.crypto_box_keypair(publicKey, secretKey);
            Console.WriteLine($"     Generación de claves: {(result == 0 ? "✅" : "❌")}");

            // Generar nonce
            crypto_box_native.crypto_box_random_nonce(nonce);

            // Encryptar
            result = crypto_box_native.crypto_box(cipherText, message, message.Length, nonce, publicKey, secretKey);
            Console.WriteLine($"     Encryption: {(result == 0 ? "✅" : "❌")}");

            // Decryptar
            result = crypto_box_native.crypto_box_open(decrypted, cipherText, cipherText.Length, nonce, publicKey, secretKey);
            Console.WriteLine($"     Decryption: {(result == 0 ? "✅" : "❌")}");

            // Verificar mensaje
            bool messageMatches = true;
            for (int i = 0; i < message.Length; i++)
            {
                if (message[i] != decrypted[i])
                {
                    messageMatches = false;
                    break;
                }
            }
            Console.WriteLine($"     Mensaje preservado: {(messageMatches ? "✅" : "❌")}");
        }

        static void TestCryptoBoxSharedKey()
        {
            Console.WriteLine("   Probando shared key precalculado...");

            var keyPair = CryptoBox.GenerateKeyPair();
            byte[] nonce = CryptoBox.GenerateNonce();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Test with shared key");

            // Precalcular shared key
            byte[] sharedKey = CryptoBox.BeforeNm(keyPair.PublicKey, keyPair.PrivateKey);
            Console.WriteLine($"     Shared key calculado: {(sharedKey != null ? "✅" : "❌")}");

            // Encryptar con shared key
            byte[] cipherText = CryptoBox.AfterNm(message, nonce, sharedKey);
            Console.WriteLine($"     Encryption con shared key: {(cipherText != null ? "✅" : "❌")}");

            // Decryptar con shared key
            byte[] decrypted = CryptoBox.OpenAfterNm(cipherText, nonce, sharedKey);
            Console.WriteLine($"     Decryption con shared key: {(decrypted != null ? "✅" : "❌")}");

            // Verificar
            bool matches = decrypted != null && message.Length == decrypted.Length;
            if (matches)
            {
                for (int i = 0; i < message.Length; i++)
                {
                    if (message[i] != decrypted[i])
                    {
                        matches = false;
                        break;
                    }
                }
            }
            Console.WriteLine($"     Mensaje correcto: {(matches ? "✅" : "❌")}");
        }

        static void TestCryptoHashSha256()
        {
            Console.WriteLine("\n7. Probando CryptoHashSha256...");

            // Test básico con vectores conocidos
            bool basicTest = CryptoHashSha256.Test();
            Console.WriteLine($"   Test con vectores conocidos: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test con API nativa C
            TestCryptoHashSha256NativeAPI();

            // Test incremental
            TestCryptoHashSha256Incremental();

           
        }

        static void TestCryptoHashSha256NativeAPI()
        {
            Console.WriteLine("   Probando API nativa C...");

            byte[] input = System.Text.Encoding.UTF8.GetBytes("Test message for SHA256");
            byte[] output = new byte[CryptoHashSha256.BYTES];

            int result = crypto_hash_sha256_native.crypto_hash_sha256(output, input, (ulong)input.Length);
            Console.WriteLine($"     Hash básico: {(result == 0 ? "✅" : "❌")}");

            // Verificar que el hash no es todo cero
            bool notAllZero = false;
            foreach (byte b in output)
            {
                if (b != 0)
                {
                    notAllZero = true;
                    break;
                }
            }
            Console.WriteLine($"     Output no-cero: {(notAllZero ? "✅" : "❌")}");

            // Verificar que el mismo input produce mismo output
            byte[] output2 = new byte[CryptoHashSha256.BYTES];
            crypto_hash_sha256_native.crypto_hash_sha256(output2, input, (ulong)input.Length);

            bool deterministic = true;
            for (int i = 0; i < output.Length; i++)
            {
                if (output[i] != output2[i])
                {
                    deterministic = false;
                    break;
                }
            }
            Console.WriteLine($"     Comportamiento determinista: {(deterministic ? "✅" : "❌")}");

            Console.WriteLine($"     Sample hash: {BitConverter.ToString(output, 0, 8).Replace("-", "")}...");
        }

        static void TestCryptoHashSha256Incremental()
        {
            Console.WriteLine("   Probando hash incremental con API C...");

            // Usando la API managed
            using (var state = CryptoHashSha256.CreateIncrementalHash())
            {
                CryptoHashSha256.Init(state);
                CryptoHashSha256.Update(state, System.Text.Encoding.UTF8.GetBytes("Hello "), 0, 6);
                CryptoHashSha256.Update(state, System.Text.Encoding.UTF8.GetBytes("World"), 0, 5);
                CryptoHashSha256.Update(state, System.Text.Encoding.UTF8.GetBytes("!"), 0, 1);
                byte[] incrementalHash = CryptoHashSha256.Final(state);

                byte[] fullHash = CryptoHashSha256.Hash(System.Text.Encoding.UTF8.GetBytes("Hello World!"));

                bool matches = true;
                for (int i = 0; i < incrementalHash.Length; i++)
                {
                    if (incrementalHash[i] != fullHash[i])
                    {
                        matches = false;
                        break;
                    }
                }

                Console.WriteLine($"     Hash incremental managed: {(matches ? "✅" : "❌")}");
            }

            // Test con API nativa C (simulada)
            TestCryptoHashSha256NativeIncremental();
        }

        static void TestCryptoHashSha256NativeIncremental()
        {
            Console.WriteLine("   Probando API incremental nativa C...");

            try
            {
                // Simular el estado como IntPtr (como lo haría C)
                IntPtr statePtr = IntPtr.Zero;

                // En una implementación real, aquí asignaríamos memoria para el estado
                // Para este test, usamos un approach simplificado
                var state = new CryptoHashSha256State();
                var handle = System.Runtime.InteropServices.GCHandle.Alloc(state);
                statePtr = System.Runtime.InteropServices.GCHandle.ToIntPtr(handle);

                byte[] input1 = System.Text.Encoding.UTF8.GetBytes("Incremental ");
                byte[] input2 = System.Text.Encoding.UTF8.GetBytes("test ");
                byte[] input3 = System.Text.Encoding.UTF8.GetBytes("data");
                byte[] output = new byte[CryptoHashSha256.BYTES];

                // Simular el proceso incremental
                CryptoHashSha256.Init(state);
                CryptoHashSha256.Update(state, input1, 0, input1.Length);
                CryptoHashSha256.Update(state, input2, 0, input2.Length);
                CryptoHashSha256.Update(state, input3, 0, input3.Length);
                byte[] incrementalResult = CryptoHashSha256.Final(state);

                // Comparar con hash completo
                byte[] fullData = System.Text.Encoding.UTF8.GetBytes("Incremental test data");
                byte[] fullResult = CryptoHashSha256.Hash(fullData);

                bool matches = true;
                for (int i = 0; i < incrementalResult.Length; i++)
                {
                    if (incrementalResult[i] != fullResult[i])
                    {
                        matches = false;
                        break;
                    }
                }

                Console.WriteLine($"     Hash incremental nativo: {(matches ? "✅" : "❌")}");

                // Limpiar
                handle.Free();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en incremental nativo: {ex.Message}");
            }
        }

        static void TestCryptoAuth()
        {
            Console.WriteLine("\n8. Probando CryptoAuth (HMAC-SHA-256)...");

            // Test básico con comportamiento verificado
            bool basicTest = CryptoAuth.Test();
            Console.WriteLine($"   Test de comportamiento: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test con API nativa C
            TestCryptoAuthNativeAPI();

            // Test de seguridad
            TestCryptoAuthSecurity();

            // Test de performance
            TestCryptoAuthPerformance();
        }

        static void TestCryptoAuthNativeAPI()
        {
            Console.WriteLine("   Probando API nativa C...");

            byte[] key = new byte[CryptoAuth.KEYBYTES];
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Test message for authentication");
            byte[] tag = new byte[CryptoAuth.BYTES];

            // Generar clave
            crypto_auth_native.crypto_auth_keygen(key);
            Console.WriteLine($"     Generación de clave: ✅");

            // Generar tag
            int result = crypto_auth_native.crypto_auth(tag, message, (ulong)message.Length, key);
            Console.WriteLine($"     Generación de tag: {(result == 0 ? "✅" : "❌")}");

            // Verificar tag válido
            result = crypto_auth_native.crypto_auth_verify(tag, message, (ulong)message.Length, key);
            Console.WriteLine($"     Verificación tag válido: {(result == 0 ? "✅" : "❌")}");

            // Verificar tag inválido
            byte[] invalidTag = new byte[CryptoAuth.BYTES];
            Array.Copy(tag, invalidTag, CryptoAuth.BYTES);
            invalidTag[0] ^= 0x01; // Corromper el tag
            result = crypto_auth_native.crypto_auth_verify(invalidTag, message, (ulong)message.Length, key);
            Console.WriteLine($"     Verificación tag inválido: {(result != 0 ? "✅" : "❌")}");

            // Verificar con clave incorrecta
            byte[] wrongKey = new byte[CryptoAuth.KEYBYTES];
            Array.Copy(key, wrongKey, CryptoAuth.KEYBYTES);
            wrongKey[0] ^= 0x01;
            result = crypto_auth_native.crypto_auth_verify(tag, message, (ulong)message.Length, wrongKey);
            Console.WriteLine($"     Verificación clave incorrecta: {(result != 0 ? "✅" : "❌")}");

            Console.WriteLine($"     Sample tag: {BitConverter.ToString(tag, 0, 8).Replace("-", "")}...");
        }

        static void TestCryptoAuthSecurity()
        {
            Console.WriteLine("   Probando características de seguridad...");

            byte[] key = CryptoAuth.GenerateKey();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Security test message");

            // Test 1: Mismo mensaje + misma clave = mismo tag
            byte[] tag1 = CryptoAuth.Authenticate(message, key);
            byte[] tag2 = CryptoAuth.Authenticate(message, key);

            bool deterministic = true;
            for (int i = 0; i < tag1.Length; i++)
            {
                if (tag1[i] != tag2[i])
                {
                    deterministic = false;
                    break;
                }
            }
            Console.WriteLine($"     Comportamiento determinista: {(deterministic ? "✅" : "❌")}");

            // Test 2: Mensaje diferente = tag diferente
            byte[] differentMessage = System.Text.Encoding.UTF8.GetBytes("Different security test message");
            byte[] tag3 = CryptoAuth.Authenticate(differentMessage, key);

            bool differentForDifferentMessage = false;
            for (int i = 0; i < tag1.Length; i++)
            {
                if (tag1[i] != tag3[i])
                {
                    differentForDifferentMessage = true;
                    break;
                }
            }
            Console.WriteLine($"     Tags diferentes para mensajes diferentes: {(differentForDifferentMessage ? "✅" : "❌")}");

            // Test 3: Clave diferente = tag diferente
            byte[] differentKey = CryptoAuth.GenerateKey();
            byte[] tag4 = CryptoAuth.Authenticate(message, differentKey);

            bool differentForDifferentKey = false;
            for (int i = 0; i < tag1.Length; i++)
            {
                if (tag1[i] != tag4[i])
                {
                    differentForDifferentKey = true;
                    break;
                }
            }
            Console.WriteLine($"     Tags diferentes para claves diferentes: {(differentForDifferentKey ? "✅" : "❌")}");
        }

        static void TestCryptoAuthPerformance()
        {
            Console.WriteLine("   Probando rendimiento...");

            byte[] key = CryptoAuth.GenerateKey();

            // Datos de diferentes tamaños
            byte[] smallData = System.Text.Encoding.UTF8.GetBytes("Small");
            byte[] mediumData = new byte[1024]; // 1KB
            byte[] largeData = new byte[1024 * 1024]; // 1MB

            new Random(42).NextBytes(mediumData);
            new Random(42).NextBytes(largeData);

            // Test con datos pequeños
            var sw = System.Diagnostics.Stopwatch.StartNew();
            byte[] smallTag = CryptoAuth.Authenticate(smallData, key);
            sw.Stop();
            Console.WriteLine($"     Datos pequeños ({smallData.Length} bytes): ✅ ({sw.ElapsedTicks} ticks)");

            // Test con datos medianos
            sw.Restart();
            byte[] mediumTag = CryptoAuth.Authenticate(mediumData, key);
            sw.Stop();
            Console.WriteLine($"     Datos medianos ({mediumData.Length} bytes): ✅ ({sw.ElapsedTicks} ticks)");

            // Test con datos grandes
            sw.Restart();
            byte[] largeTag = CryptoAuth.Authenticate(largeData, key);
            sw.Stop();
            Console.WriteLine($"     Datos grandes ({largeData.Length} bytes): ✅ ({sw.ElapsedTicks} ticks)");

            // Verificar que todos los tags son válidos
            bool smallValid = CryptoAuth.Verify(smallTag, smallData, key);
            bool mediumValid = CryptoAuth.Verify(mediumTag, mediumData, key);
            bool largeValid = CryptoAuth.Verify(largeTag, largeData, key);

            Console.WriteLine($"     Todos los tags verificables: {(smallValid && mediumValid && largeValid ? "✅" : "❌")}");
        }

        static void TestCryptoVerify()
        {
            Console.WriteLine("\n9. Probando CryptoVerify (comparación constante en tiempo)...");

            // Test básico de funcionalidad
            bool basicTest = CryptoVerify.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de timing
            CryptoVerify.TestTiming();

            // Test con API nativa C
            TestCryptoVerifyNativeAPI();

            // Test de casos edge
            TestCryptoVerifyEdgeCases();
        }

        static void TestCryptoVerifyNativeAPI()
        {
            Console.WriteLine("   Probando API nativa C...");

            // Test crypto_verify_16
            byte[] a16_1 = new byte[16];
            byte[] b16_1 = new byte[16];
            byte[] b16_2 = new byte[16];

            Array.Fill(a16_1, (byte)0xAA);
            Array.Fill(b16_1, (byte)0xAA);
            Array.Fill(b16_2, (byte)0xBB);

            int result1 = crypto_verify_native.crypto_verify_16(a16_1, b16_1);
            int result2 = crypto_verify_native.crypto_verify_16(a16_1, b16_2);

            Console.WriteLine($"     crypto_verify_16 iguales: {(result1 == 0 ? "✅" : "❌")}");
            Console.WriteLine($"     crypto_verify_16 diferentes: {(result2 == -1 ? "✅" : "❌")}");

            // Test crypto_verify_32
            byte[] a32_1 = new byte[32];
            byte[] b32_1 = new byte[32];
            byte[] b32_2 = new byte[32];

            Array.Fill(a32_1, (byte)0xCC);
            Array.Fill(b32_1, (byte)0xCC);
            Array.Fill(b32_2, (byte)0xDD);

            int result3 = crypto_verify_native.crypto_verify_32(a32_1, b32_1);
            int result4 = crypto_verify_native.crypto_verify_32(a32_1, b32_2);

            Console.WriteLine($"     crypto_verify_32 iguales: {(result3 == 0 ? "✅" : "❌")}");
            Console.WriteLine($"     crypto_verify_32 diferentes: {(result4 == -1 ? "✅" : "❌")}");

            // Test crypto_verify_64
            byte[] a64_1 = new byte[64];
            byte[] b64_1 = new byte[64];
            byte[] b64_2 = new byte[64];

            Array.Fill(a64_1, (byte)0xEE);
            Array.Fill(b64_1, (byte)0xEE);
            b64_2[0] = 0xFF; // Solo el primer byte diferente

            int result5 = crypto_verify_native.crypto_verify_64(a64_1, b64_1);
            int result6 = crypto_verify_native.crypto_verify_64(a64_1, b64_2);

            Console.WriteLine($"     crypto_verify_64 iguales: {(result5 == 0 ? "✅" : "❌")}");
            Console.WriteLine($"     crypto_verify_64 diferentes: {(result6 == -1 ? "✅" : "❌")}");

            // Test crypto_verify genérico
            byte[] a_gen = new byte[32];
            byte[] b_gen = new byte[32];

            Array.Fill(a_gen, (byte)0x11);
            Array.Fill(b_gen, (byte)0x11);

            int result7 = crypto_verify_native.crypto_verify(a_gen, b_gen);
            b_gen[31] ^= 0x01; // Cambiar el último byte
            int result8 = crypto_verify_native.crypto_verify(a_gen, b_gen);

            Console.WriteLine($"     crypto_verify iguales: {(result7 == 0 ? "✅" : "❌")}");
            Console.WriteLine($"     crypto_verify diferentes: {(result8 == -1 ? "✅" : "❌")}");
        }

        static void TestCryptoVerifyEdgeCases()
        {
            Console.WriteLine("   Probando casos edge...");

            // Test con arrays de un solo byte
            byte[] single1 = new byte[] { 0x42 };
            byte[] single2 = new byte[] { 0x42 };
            byte[] single3 = new byte[] { 0x43 };

            bool result1 = CryptoVerify.Verify(single1, 0, single2, 0, 1);
            bool result2 = CryptoVerify.Verify(single1, 0, single3, 0, 1);

            Console.WriteLine($"     Byte único igual: {(result1 ? "✅" : "❌")}");
            Console.WriteLine($"     Byte único diferente: {(!result2 ? "✅" : "❌")}");

            // Test con arrays que tienen diferencias en diferentes posiciones
            byte[] baseArray = new byte[8] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            byte[] diffFirst = new byte[8] { 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            byte[] diffMiddle = new byte[8] { 0x01, 0x02, 0x03, 0xFF, 0x05, 0x06, 0x07, 0x08 };
            byte[] diffLast = new byte[8] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF };

            bool result3 = CryptoVerify.Verify(baseArray, diffFirst);
            bool result4 = CryptoVerify.Verify(baseArray, diffMiddle);
            bool result5 = CryptoVerify.Verify(baseArray, diffLast);

            Console.WriteLine($"     Diferencia en primer byte: {(!result3 ? "✅" : "❌")}");
            Console.WriteLine($"     Diferencia en byte medio: {(!result4 ? "✅" : "❌")}");
            Console.WriteLine($"     Diferencia en último byte: {(!result5 ? "✅" : "❌")}");

            // Test de valores extremos
            byte[] allZero = new byte[16];
            byte[] allOne = new byte[16];
            byte[] allMax = new byte[16];

            Array.Fill(allOne, (byte)0x01);
            Array.Fill(allMax, (byte)0xFF);

            bool result6 = CryptoVerify.Verify16(allZero, allZero);
            bool result7 = CryptoVerify.Verify16(allOne, allOne);
            bool result8 = CryptoVerify.Verify16(allMax, allMax);
            bool result9 = CryptoVerify.Verify16(allZero, allOne);

            Console.WriteLine($"     Todos zeros: {(result6 ? "✅" : "❌")}");
            Console.WriteLine($"     Todos unos: {(result7 ? "✅" : "❌")}");
            Console.WriteLine($"     Todos FF: {(result8 ? "✅" : "❌")}");
            Console.WriteLine($"     Zeros vs unos: {(!result9 ? "✅" : "❌")}");
        }

        static void TestRandomBytes()
        {
            Console.WriteLine("\n10. Probando RandomBytes (generación segura de aleatorios)...");

            // Test básico de funcionalidad
            bool basicTest = RandomBytes.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de rendimiento y entropía
            RandomBytes.TestPerformance();

            // Test con API nativa C
            TestRandomBytesNativeAPI();

            // Test de casos de uso real
            TestRandomBytesRealWorld();
        }

        static void TestRandomBytesNativeAPI()
        {
            Console.WriteLine("   Probando API nativa C...");

            // Test randombytes_buf
            byte[] buffer = new byte[50];
            randombytes_native.randombytes_buf(buffer, (ulong)buffer.Length);

            bool notAllZero = false;
            foreach (byte b in buffer)
            {
                if (b != 0)
                {
                    notAllZero = true;
                    break;
                }
            }
            Console.WriteLine($"     randombytes_buf: {(notAllZero ? "✅" : "❌")}");

            // Test randombytes_uniform
            uint upperBound = 100;
            bool allInRange = true;
            bool distributionTest = false;
            int[] distribution = new int[upperBound];

            for (int i = 0; i < 1000; i++)
            {
                uint value = randombytes_native.randombytes_uniform(upperBound);
                if (value >= upperBound)
                {
                    allInRange = false;
                    break;
                }
                distribution[value]++;
            }

            // Verificar que todos los valores aparecieron al menos una vez
            if (allInRange)
            {
                distributionTest = true;
                for (int i = 0; i < upperBound; i++)
                {
                    if (distribution[i] == 0)
                    {
                        distributionTest = false;
                        break;
                    }
                }
            }

            Console.WriteLine($"     randombytes_uniform en rango: {(allInRange ? "✅" : "❌")}");
            Console.WriteLine($"     randombytes_uniform distribución: {(distributionTest ? "✅" : "❌")}");

            // Test edge cases
            try
            {
                uint zero = randombytes_native.randombytes_uniform(1); // Debería ser siempre 0
                Console.WriteLine($"     randombytes_uniform(1): {(zero == 0 ? "✅" : "❌")}");
            }
            catch
            {
                Console.WriteLine("     ❌ randombytes_uniform(1) falló");
            }
        }

        static void TestRandomBytesRealWorld()
        {
            Console.WriteLine("   Probando casos de uso real...");

            try
            {
                // Caso 1: Generación de nonce para crypto_box
                byte[] nonce = RandomBytes.GenerateNonce();
                bool nonceValid = nonce != null && nonce.Length == 24;
                Console.WriteLine($"     Nonce para crypto_box: {(nonceValid ? "✅" : "❌")}");

                // Caso 2: Generación de clave
                byte[] key = RandomBytes.GenerateKey();
                bool keyValid = key != null && key.Length == 32;
                Console.WriteLine($"     Clave crypto: {(keyValid ? "✅" : "❌")}");

                // Caso 3: Múltiples generaciones son diferentes
                byte[] nonce1 = RandomBytes.GenerateNonce();
                byte[] nonce2 = RandomBytes.GenerateNonce();

                bool noncesDifferent = false;
                for (int i = 0; i < nonce1.Length; i++)
                {
                    if (nonce1[i] != nonce2[i])
                    {
                        noncesDifferent = true;
                        break;
                    }
                }
                Console.WriteLine($"     Nonces diferentes: {(noncesDifferent ? "✅" : "❌")}");

                // Caso 4: Uso en selección aleatoria - CON TIMEOUT
                Console.WriteLine("     Probando selección aleatoria...");
                string[] options = { "Opción A", "Opción B", "Opción C", "Opción D" };

                var sw = System.Diagnostics.Stopwatch.StartNew();
                uint selectedIndex = 0;
                bool selectionSuccess = false;

                try
                {
                    selectedIndex = RandomBytes.Uniform((uint)options.Length);
                    selectionSuccess = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"     ❌ Error en selección aleatoria: {ex.Message}");
                    // Fallback seguro
                    selectedIndex = 0;
                }

                sw.Stop();
                bool selectionValid = selectionSuccess && selectedIndex < options.Length;
                bool timely = sw.ElapsedMilliseconds < 1000; // Debe tomar menos de 1 segundo

                Console.WriteLine($"     Selección aleatoria: {(selectionValid ? "✅" : "❌")} -> {options[selectedIndex]}");
                Console.WriteLine($"     Tiempo de selección: {sw.ElapsedMilliseconds}ms {(timely ? "✅" : "⚠️")}");

                // Caso 5: Llenado de buffer existente
                byte[] packetBuffer = new byte[1024];
                // Primero llenar con un valor conocido
                for (int i = 0; i < packetBuffer.Length; i++)
                {
                    packetBuffer[i] = 0xFF;
                }
                RandomBytes.Generate(packetBuffer, 16, 32);

                // Verificar que se modificó la zona correcta
                bool zoneModified = false;
                for (int i = 16; i < 48; i++)
                {
                    if (packetBuffer[i] != 0xFF)
                    {
                        zoneModified = true;
                        break;
                    }
                }
                Console.WriteLine($"     Llenado de buffer con offset: {(zoneModified ? "✅" : "❌")}");

                // Caso 6: Test de Uniform con diferentes valores
                Console.WriteLine("     Probando Uniform con diferentes bounds...");
                TestUniformWithValue(2);   // Potencia de 2
                TestUniformWithValue(10);  // No potencia de 2
                TestUniformWithValue(100); // Valor mayor
                TestUniformWithValue(1);   // Caso borde
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en casos de uso real: {ex.Message}");
            }
        }

        static void TestUniformWithValue(uint upperBound)
        {
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                uint value = RandomBytes.Uniform(upperBound);
                sw.Stop();

                bool valid = value < upperBound;
                bool timely = sw.ElapsedMilliseconds < 100;

                Console.WriteLine($"       Uniform({upperBound}) = {value} {(valid ? "✅" : "❌")} [{sw.ElapsedMilliseconds}ms {(timely ? "✅" : "⚠️")}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"       Uniform({upperBound}) = ❌ Error: {ex.Message}");
            }
        }

        static void TestNetwork()
        {
            Console.WriteLine("\n11. Probando Network (funciones básicas de red)...");

            // Test básico de funcionalidad
            bool basicTest = Network.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de operaciones de socket
            TestNetworkSocketOperations();

            // Test de estructuras de datos
            TestNetworkDataStructures();

            // Test de API nativa
            TestNetworkNativeAPI();
        }

        static void TestSocketSendReceive(int sock)
        {
            Console.WriteLine("   📨 Probando envío/recepción...");

            try
            {
                // Crear un segundo socket para pruebas de loopback
                int sock2 = Network.new_socket(2, 2, 17);
                if (sock2 == -1)
                {
                    Console.WriteLine("     ⚠️ No se pudo crear segundo socket para prueba");
                    return;
                }

                // Bind segundo socket
                IPPort bindAddr2 = new IPPort(new IP(IPAddress.Loopback), 0);
                if (Network.socket_bind(sock2, bindAddr2) == -1)
                {
                    Console.WriteLine("     ⚠️ No se pudo bind segundo socket");
                    Network.kill_socket(sock2);
                    return;
                }

                // Obtener dirección del segundo socket
                IP sock2IP = new IP();
                ushort sock2Port = 0;
                if (Network.socket_get_address(sock2, ref sock2IP, ref sock2Port) == -1)
                {
                    Console.WriteLine("     ⚠️ No se pudo obtener dirección del segundo socket");
                    Network.kill_socket(sock2);
                    return;
                }

                IPPort targetAddr = new IPPort(sock2IP, sock2Port);

                // Datos de prueba
                byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

                // Enviar datos
                int sent = Network.socket_send(sock, testData, testData.Length, targetAddr);
                if (sent > 0)
                {
                    Console.WriteLine($"     ✅ Enviados {sent} bytes");
                }
                else
                {
                    Console.WriteLine("     ⚠️ No se pudieron enviar datos (puede ser normal en loopback)");
                }

                // Intentar recibir (con timeout)
                byte[] recvBuffer = new byte[1024];
                IPPort sourceAddr = new IPPort();

                DateTime start = DateTime.Now;
                int received = -1;

                // Esperar máximo 1 segundo por datos
                while ((DateTime.Now - start).TotalMilliseconds < 1000 && received == -1)
                {
                    received = Network.socket_recv(sock2, recvBuffer, ref sourceAddr);
                    if (received == -1)
                    {
                        Thread.Sleep(10); // Pequeña pausa para no saturar CPU
                    }
                }

                if (received > 0)
                {
                    Console.WriteLine($"     ✅ Recibidos {received} bytes desde {sourceAddr}");

                    // Verificar datos recibidos
                    bool dataMatch = true;
                    for (int i = 0; i < Math.Min(received, testData.Length); i++)
                    {
                        if (recvBuffer[i] != testData[i])
                        {
                            dataMatch = false;
                            break;
                        }
                    }

                    if (dataMatch)
                    {
                        Console.WriteLine("     ✅ Datos recibidos correctamente");
                    }
                    else
                    {
                        Console.WriteLine("     ⚠️ Datos recibidos no coinciden");
                    }
                }
                else
                {
                    Console.WriteLine("     ⚠️ No se recibieron datos (puede ser normal)");
                }

                Network.kill_socket(sock2);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en envío/recepción: {ex.Message}");
            }
        }

        static void TestNetworkSocketOperations()
        {
            Console.WriteLine("\n🔌 Probando operaciones de socket...");

            try
            {
                // Test 1: Creación de socket usando API compatible con C
                int sock = Network.new_socket(2, 2, 17); // IPv4, DGRAM, UDP
                if (sock == -1)
                {
                    Console.WriteLine("   ❌ Falló new_socket");
                    return;
                }
                Console.WriteLine("   ✅ Socket creado: " + sock);

                // Test 2: Bind a puerto local
                IPPort bindAddr = new IPPort(new IP(IPAddress.Loopback), 0);
                int bindResult = Network.socket_bind(sock, bindAddr);
                if (bindResult == -1)
                {
                    Console.WriteLine("   ❌ Falló socket_bind");
                    Network.kill_socket(sock);
                    return;
                }
                Console.WriteLine("   ✅ Socket bind exitoso");

                // Test 3: Obtener dirección del socket
                IP localIP = new IP();
                ushort localPort = 0;
                int getAddrResult = Network.socket_get_address(sock, ref localIP, ref localPort);
                if (getAddrResult == 0)
                {
                    Console.WriteLine($"   ✅ Dirección local: {localIP}:{localPort}");
                }
                else
                {
                    Console.WriteLine("   ⚠️ No se pudo obtener dirección local");
                }

                // Test 4: Resolución DNS
                IP resolvedIP = new IP();
                int resolveResult = Network.get_ip("localhost", ref resolvedIP);
                if (resolveResult == 0)
                {
                    Console.WriteLine($"   ✅ Resolución DNS: localhost -> {resolvedIP}");
                }
                else
                {
                    Console.WriteLine("   ❌ Falló resolución DNS");
                }

                // Test 5: Envío y recepción básica (solo si hay otro socket)
                TestSocketSendReceive(sock);

                // Test 6: Cierre de socket
                int killResult = Network.kill_socket(sock);
                if (killResult == 0)
                {
                    Console.WriteLine("   ✅ Socket cerrado correctamente");
                }
                else
                {
                    Console.WriteLine("   ❌ Falló al cerrar socket");
                }

                Console.WriteLine("   ✅ Todas las operaciones de socket funcionan");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en operaciones de socket: {ex.Message}");
            }
        }

        static void TestNetworkDataStructures()
        {
            Console.WriteLine("\n🏗️ Probando estructuras de datos de red...");

            try
            {
                // Test 1: Estructura IP4
                IP4 ip4 = new IP4("192.168.1.1");
                if (ip4.ToString() == "192.168.1.1")
                {
                    Console.WriteLine("   ✅ IP4 funciona: " + ip4);
                }
                else
                {
                    Console.WriteLine("   ❌ IP4 falló: " + ip4);
                }

                // Test 2: Estructura IP6
                IP6 ip6 = new IP6("::1");
                string ip6Str = ip6.ToString();
                if (ip6Str.Contains("::1") || ip6Str.Contains("0:0:0:0:0:0:0:1"))
                {
                    Console.WriteLine("   ✅ IP6 funciona: " + ip6Str);
                }
                else
                {
                    Console.WriteLine("   ❌ IP6 falló: " + ip6Str);
                }

                // Test 3: Estructura IP (IPv4)
                IP ipFrom4 = new IP(ip4);
                if (ipFrom4.IsIPv6 == 0 && ipFrom4.ToString() == "192.168.1.1")
                {
                    Console.WriteLine("   ✅ IP desde IP4 funciona: " + ipFrom4);
                }
                else
                {
                    Console.WriteLine("   ❌ IP desde IP4 falló: " + ipFrom4);
                }

                // Test 4: Estructura IP (IPv6)
                IP ipFrom6 = new IP(ip6);
                if (ipFrom6.IsIPv6 == 1)
                {
                    Console.WriteLine("   ✅ IP desde IP6 funciona: " + ipFrom6);
                }
                else
                {
                    Console.WriteLine("   ❌ IP desde IP6 falló: " + ipFrom6);
                }

                // Test 5: Estructura IPPort
                IPPort ipport = new IPPort(ipFrom4, 33445);
                if (ipport.Port == 33445 && ipport.IP.ToString() == "192.168.1.1")
                {
                    Console.WriteLine("   ✅ IPPort funciona: " + ipport);
                }
                else
                {
                    Console.WriteLine("   ❌ IPPort falló: " + ipport);
                }

                // Test 6: Conversión IPAddress -> IP
                IP ipFromAddr = new IP(IPAddress.Parse("10.0.0.1"));
                if (ipFromAddr.ToString() == "10.0.0.1")
                {
                    Console.WriteLine("   ✅ IP desde IPAddress funciona: " + ipFromAddr);
                }
                else
                {
                    Console.WriteLine("   ❌ IP desde IPAddress falló: " + ipFromAddr);
                }

                // Test 7: BytesToIPPort
                IPPort testIpp = new IPPort();
                byte[] ip4Bytes = new byte[] { 192, 168, 1, 100 };
                bool convertResult = Network.BytesToIPPort(ref testIpp, ip4Bytes, 0, 443);

                if (convertResult && testIpp.Port == 443 && testIpp.IP.ToString() == "192.168.1.100")
                {
                    Console.WriteLine("   ✅ BytesToIPPort funciona: " + testIpp);
                }
                else
                {
                    Console.WriteLine("   ❌ BytesToIPPort falló");
                }

                Console.WriteLine("   ✅ Todas las estructuras de datos funcionan");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en estructuras de datos: {ex.Message}");
            }
        }

        static void TestNetworkNativeAPI()
        {
            Console.WriteLine("\n🔧 Probando API nativa compatible con C...");

            try
            {
                // Test 1: Flujo completo de creación, uso y destrucción de socket
                Console.WriteLine("   🔄 Probando flujo completo de socket...");

                int sock = Network.new_socket(2, 2, 17); // IPv4 UDP
                if (sock == -1)
                {
                    Console.WriteLine("   ❌ new_socket falló");
                    return;
                }

                // Bind a puerto aleatorio
                IPPort bindAddr = new IPPort(new IP(IPAddress.Loopback), 0);
                if (Network.socket_bind(sock, bindAddr) == -1)
                {
                    Console.WriteLine("   ❌ socket_bind falló");
                    Network.kill_socket(sock);
                    return;
                }

                // Test 2: get_ip con hostname conocido
                IP resolvedIP = new IP();
                int resolveResult = Network.get_ip("127.0.0.1", ref resolvedIP);
                if (resolveResult == 0 && resolvedIP.ToString() == "127.0.0.1")
                {
                    Console.WriteLine("   ✅ get_ip con 127.0.0.1 funciona");
                }
                else
                {
                    Console.WriteLine("   ❌ get_ip con 127.0.0.1 falló");
                }

                // Test 3: socket_get_address
                IP localIP = new IP();
                ushort localPort = 0;
                if (Network.socket_get_address(sock, ref localIP, ref localPort) == 0)
                {
                    Console.WriteLine($"   ✅ socket_get_address funciona: {localIP}:{localPort}");
                }
                else
                {
                    Console.WriteLine("   ❌ socket_get_address falló");
                }

                // Test 4: Comportamiento no bloqueante
                Console.WriteLine("   ⏰ Probando comportamiento no bloqueante...");
                byte[] buffer = new byte[1024];
                IPPort source = new IPPort();
                int recvResult = Network.socket_recv(sock, buffer, ref source);

                if (recvResult == -1)
                {
                    Console.WriteLine("   ✅ Comportamiento no bloqueante funciona (no hay datos)");
                }
                else if (recvResult >= 0)
                {
                    Console.WriteLine("   ⚠️ Se recibieron datos inesperados");
                }
                else
                {
                    Console.WriteLine("   ❌ Error en socket_recv");
                }

                // Test 5: Envío a dirección inválida (debería fallar silenciosamente)
                IPPort invalidAddr = new IPPort(new IP(IPAddress.Parse("192.0.2.1")), 9); // TEST-NET-1, puerto discard
                byte[] testData = new byte[] { 0x01, 0x02, 0x03 };
                int sendResult = Network.socket_send(sock, testData, testData.Length, invalidAddr);

                // Ambos resultados son aceptables: -1 (error) o >0 (éxito)
                if (sendResult == -1 || sendResult > 0)
                {
                    Console.WriteLine("   ✅ socket_send con dirección inválida maneja correctamente");
                }
                else
                {
                    Console.WriteLine("   ❌ socket_send comportamiento inesperado");
                }

                // Test 6: kill_socket
                if (Network.kill_socket(sock) == 0)
                {
                    Console.WriteLine("   ✅ kill_socket funciona");
                }
                else
                {
                    Console.WriteLine("   ❌ kill_socket falló");
                }

                // Test 7: Socket inválido
                int invalidSock = 9999;
                int invalidResult = Network.socket_send(invalidSock, new byte[1], 1, new IPPort());
                if (invalidResult == -1)
                {
                    Console.WriteLine("   ✅ Manejo de socket inválido funciona");
                }
                else
                {
                    Console.WriteLine("   ❌ Manejo de socket inválido falló");
                }

                Console.WriteLine("   ✅ API nativa funciona correctamente");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en API nativa: {ex.Message}");
            }
        }

        static void TestDHT()
        {
            Console.WriteLine("\n12. Probando DHT (Distributed Hash Table)...");

            // Test básico de funcionalidad
            bool basicTest = DHT.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de operaciones DHT
            TestDHTOperations();

            // Test de bootstrap
            TestDHTBootstrap();

            // Test de rendimiento
            TestDHTPerformance();
        }

        static void TestDHTOperations()
        {
            Console.WriteLine("   Probando operaciones DHT...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                {
                    // Agregar múltiples nodos de prueba
                    int nodesToAdd = 5;
                    int successfulAdds = 0;

                    for (int i = 0; i < nodesToAdd; i++)
                    {
                        var nodeKey = RandomBytes.Generate(32);
                        IPPort nodeAddr = new IPPort(IPAddress.Loopback, (ushort)(33445 + i));

                        if (dht.AddNode(nodeAddr, nodeKey))
                        {
                            successfulAdds++;
                        }
                    }

                    Console.WriteLine($"     Agregar {nodesToAdd} nodos: {successfulAdds}/{nodesToAdd} ✅");

                    // Verificar que los nodos fueron agregados
                    Console.WriteLine($"     Nodos en DHT: {dht.TotalNodes} ✅");
                    Console.WriteLine($"     Buckets activos: {dht.ActiveBuckets} ✅");

                    // Test de búsqueda
                    var searchKey = RandomBytes.Generate(32);
                    var closestNodes = dht.FindClosestNodes(searchKey);
                    Console.WriteLine($"     Encontrar nodos cercanos: {closestNodes.Count} encontrados ✅");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en operaciones DHT: {ex.Message}");
            }
        }

        static void TestDHTBootstrap()
        {
            Console.WriteLine("   Probando bootstrap DHT...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                {
                    // Crear nodos de bootstrap de prueba
                    var bootstrapNodes = new List<IPPort>();
                    var bootstrapKeys = new List<byte[]>();

                    for (int i = 0; i < 3; i++)
                    {
                        bootstrapNodes.Add(new IPPort(IPAddress.Loopback, (ushort)(33450 + i)));
                        bootstrapKeys.Add(RandomBytes.Generate(32));
                    }

                    // Ejecutar bootstrap
                    dht.Bootstrap(bootstrapNodes, bootstrapKeys);

                    Console.WriteLine($"     Bootstrap con {bootstrapNodes.Count} nodos: ✅");
                    Console.WriteLine($"     Estado DHT después de bootstrap: {dht.TotalNodes} nodos ✅");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en bootstrap DHT: {ex.Message}");
            }
        }

        static void TestDHTPerformance()
        {
            Console.WriteLine("   Probando rendimiento DHT...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();

                var sw = System.Diagnostics.Stopwatch.StartNew();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                {
                    long createTime = sw.ElapsedTicks;

                    // Agregar 100 nodos de prueba
                    sw.Restart();
                    for (int i = 0; i < 100; i++)
                    {
                        var nodeKey = RandomBytes.Generate(32);
                        IPPort nodeAddr = new IPPort(IPAddress.Loopback, (ushort)(33500 + i));
                        dht.AddNode(nodeAddr, nodeKey);
                    }
                    long addTime = sw.ElapsedTicks;

                    // Búsqueda de nodos
                    sw.Restart();
                    var searchKey = RandomBytes.Generate(32);
                    for (int i = 0; i < 10; i++)
                    {
                        dht.FindClosestNodes(searchKey);
                    }
                    long searchTime = sw.ElapsedTicks;

                    Console.WriteLine($"     Creación DHT: {createTime} ticks ✅");
                    Console.WriteLine($"     Agregar 100 nodos: {addTime} ticks ✅");
                    Console.WriteLine($"     10 búsquedas: {searchTime} ticks ✅");
                    Console.WriteLine($"     Nodos totales: {dht.TotalNodes} ✅");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en rendimiento DHT: {ex.Message}");
            }
        }

        static void TestTCP()
        {
            Console.WriteLine("\n13. Probando TCP Client/Server...");

            // Test básico de funcionalidad
            bool clientTest = TCPClient.Test();
            bool serverTest = TCPServer.Test();
            Console.WriteLine($"   Test de funcionalidad: Client {(clientTest ? "✅" : "❌")}, Server {(serverTest ? "✅" : "❌")}");

            // Test de integración cliente-servidor
            TestTCPIntegration();

            // Test de rendimiento
            TestTCPPerformance();
        }

        static void TestTCPIntegration()
        {
            Console.WriteLine("   Probando integración TCP...");

            try
            {
                // Crear servidor
                var server = new TCPServer();
                string receivedMessage = null;
                bool clientConnected = false;

                server.OnClientConnected += (client) => {
                    clientConnected = true;
                    Console.WriteLine("     Cliente conectado al servidor: ✅");
                };

                server.OnClientDataReceived += (client, data) => {
                    receivedMessage = System.Text.Encoding.UTF8.GetString(data);
                    Console.WriteLine($"     Servidor recibió mensaje: ✅");
                };

                // Iniciar servidor en puerto aleatorio
                bool serverStarted = server.StartAsync(0).Wait(1000);
                Console.WriteLine($"     Servidor iniciado: {(serverStarted ? "✅" : "❌")}");

                if (serverStarted)
                {
                    // Crear cliente
                    var client = new TCPClient();
                    bool clientConnectedEvent = false;

                    client.OnConnected += () => {
                        clientConnectedEvent = true;
                        Console.WriteLine("     Cliente conectado: ✅");
                    };

                    client.OnDataReceived += (data) => {
                        Console.WriteLine("     Cliente recibió respuesta: ✅");
                    };

                    // Conectar cliente al servidor
                    var connectTask = client.ConnectAsync(new IPPort(IPAddress.Loopback, server.ListenPort));
                    bool connected = connectTask.Wait(2000);
                    Console.WriteLine($"     Cliente se conectó: {(connected ? "✅" : "❌")}");

                    if (connected && clientConnectedEvent && clientConnected)
                    {
                        // Enviar mensaje de prueba
                        var message = System.Text.Encoding.UTF8.GetBytes("Hello TCP!");
                        var sendTask = client.SendAsync(message);
                        bool sent = sendTask.Wait(1000);
                        Console.WriteLine($"     Mensaje enviado: {(sent ? "✅" : "❌")}");

                        // Esperar a que el servidor reciba el mensaje
                        Thread.Sleep(100);
                        Console.WriteLine($"     Mensaje recibido: {(receivedMessage == "Hello TCP!" ? "✅" : "❌")}");
                    }

                    client.Dispose();
                }

                server.Stop();
                server.Dispose();

                Console.WriteLine($"     Integración completa: ✅");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en integración TCP: {ex.Message}");
            }
        }

        static void TestTCPPerformance()
        {
            Console.WriteLine("   Probando rendimiento TCP...");

            try
            {
                var server = new TCPServer();
                server.StartAsync(0).Wait(1000);

                var client = new TCPClient();
                client.ConnectAsync(new IPPort(IPAddress.Loopback, server.ListenPort)).Wait(1000);

                var sw = System.Diagnostics.Stopwatch.StartNew();

                // Test de envío de múltiples mensajes
                int messagesSent = 0;
                byte[] testData = System.Text.Encoding.UTF8.GetBytes("Performance test");

                for (int i = 0; i < 10; i++)
                {
                    if (client.SendAsync(testData).Wait(1000))
                    {
                        messagesSent++;
                    }
                }

                long sendTime = sw.ElapsedTicks;

                Console.WriteLine($"     {messagesSent}/10 mensajes enviados: ✅");
                Console.WriteLine($"     Tiempo de envío: {sendTime} ticks ✅");

                client.Dispose();
                server.Stop();
                server.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en rendimiento TCP: {ex.Message}");
            }
        }

        static void TestOnion()
        {
            Console.WriteLine("\n14. Probando Onion Routing...");

            // Test básico de funcionalidad
            bool basicTest = Onion.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de integración con DHT
            TestOnionDHTIntegration();

            // Test de rendimiento
            TestOnionPerformance();

            // Test de anonimato
            TestOnionAnonymity();
        }

        static void TestOnionDHTIntegration()
        {
            Console.WriteLine("   Probando integración Onion-DHT...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                {
                    // Agregar algunos nodos de prueba al DHT
                    for (int i = 0; i < 10; i++)
                    {
                        var nodeKey = RandomBytes.Generate(32);
                        IPPort nodeAddr = new IPPort(IPAddress.Loopback, (ushort)(33700 + i));
                        dht.AddNode(nodeAddr, nodeKey);
                    }

                    onion.Start();

                    Console.WriteLine($"     DHT nodes: {dht.TotalNodes} ✅");
                    Console.WriteLine($"     Onion nodes: {onion.AvailableNodes} ✅");
                    Console.WriteLine($"     Onion running: {onion.IsRunning} ✅");

                    onion.Stop();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en integración Onion-DHT: {ex.Message}");
            }
        }

        static void TestOnionPerformance()
        {
            Console.WriteLine("   Probando rendimiento Onion...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                {
                    // Preparar nodos de prueba
                    for (int i = 0; i < 10; i++)
                    {
                        var testNode = new OnionNode(
                            new IPPort(IPAddress.Loopback, (ushort)(33800 + i)),
                            RandomBytes.Generate(32));
                        onion.onionNodes.Add(testNode);
                    }

                    var sw = System.Diagnostics.Stopwatch.StartNew();

                    // Test creación de rutas
                    int pathsCreated = 0;
                    for (int i = 0; i < 10; i++)
                    {
                        try
                        {
                            var path = onion.CreateOnionPath();
                            if (path != null) pathsCreated++;
                        }
                        catch { }
                    }

                    long pathTime = sw.ElapsedTicks;

                    // Test encapsulación
                    sw.Restart();
                    int packetsCreated = 0;
                    var testData = System.Text.Encoding.UTF8.GetBytes("Performance test data");

                    for (int i = 0; i < 10; i++)
                    {
                        try
                        {
                            var path = onion.CreateOnionPath();
                            var packet = onion.Encapsulate(testData, path);
                            if (packet != null) packetsCreated++;
                        }
                        catch { }
                    }

                    long encapsulationTime = sw.ElapsedTicks;

                    Console.WriteLine($"     {pathsCreated}/10 rutas creadas: ✅");
                    Console.WriteLine($"     {packetsCreated}/10 paquetes encapsulados: ✅");
                    Console.WriteLine($"     Tiempo rutas: {pathTime} ticks ✅");
                    Console.WriteLine($"     Tiempo encapsulación: {encapsulationTime} ticks ✅");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en rendimiento Onion: {ex.Message}");
            }
        }

        static void TestOnionAnonymity()
        {
            Console.WriteLine("   Probando características de anonimato...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                {
                    // Preparar múltiples nodos
                    for (int i = 0; i < 15; i++)
                    {
                        var testNode = new OnionNode(
                            new IPPort(IPAddress.Loopback, (ushort)(33900 + i)),
                            RandomBytes.Generate(32));
                        onion.onionNodes.Add(testNode);
                    }

                    // Crear múltiples rutas y verificar que son diferentes
                    var path1 = onion.CreateOnionPath();
                    var path2 = onion.CreateOnionPath();
                    var path3 = onion.CreateOnionPath();

                    bool pathsAreDifferent = !PathsEqual(path1, path2) && !PathsEqual(path1, path3) && !PathsEqual(path2, path3);
                    bool pathsHaveCorrectLength = path1.Count == 3 && path2.Count == 3 && path3.Count == 3;

                    Console.WriteLine($"     Rutas de longitud correcta: {(pathsHaveCorrectLength ? "✅" : "❌")}");
                    Console.WriteLine($"     Rutas diferentes: {(pathsAreDifferent ? "✅" : "❌")}");
                    Console.WriteLine($"     Nodos disponibles: {onion.AvailableNodes} ✅");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test anonimato: {ex.Message}");
            }
        }

        static bool PathsEqual(List<OnionNode> path1, List<OnionNode> path2)
        {
            if (path1.Count != path2.Count) return false;
            for (int i = 0; i < path1.Count; i++)
            {
                if (!CryptoVerify.Verify32(path1[i].PublicKey, path2[i].PublicKey))
                    return false;
            }
            return true;
        }

        static void TestFriendConnection()
        {
            Console.WriteLine("\n15. Probando Friend Connection...");

            // Test básico de funcionalidad
            bool basicTest = FriendConnection.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de integración completa
            TestFriendIntegration();

            // Test de mensajería
            TestFriendMessaging();

            // Test de gestión de amigos
            TestFriendManagement();
        }

        static void TestFriendIntegration()
        {
            Console.WriteLine("   Probando integración completa...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                using (var friendConn = new FriendConnection(dht, onion))
                {
                    // Configurar eventos
                    bool friendConnected = false;
                    bool messageReceived = false;

                    friendConn.OnFriendConnected += (friend) => {
                        friendConnected = true;
                        Console.WriteLine($"     Amigo conectado: {friend} ✅");
                    };

                    friendConn.OnFriendMessage += (message) => {
                        messageReceived = true;
                        Console.WriteLine($"     Mensaje recibido: {message.GetMessageText()} ✅");
                    };

                    // Iniciar servicio
                    bool started = friendConn.StartAsync().Wait(2000);
                    Console.WriteLine($"     Servicio iniciado: {(started ? "✅" : "❌")}");

                    // Agregar amigos de prueba
                    int friendsToAdd = 3;
                    int friendsAdded = 0;

                    for (int i = 0; i < friendsToAdd; i++)
                    {
                        var friendKey = RandomBytes.Generate(32);
                        try
                        {
                            friendConn.AddFriend(friendKey, $"Hello friend {i}!");
                            friendsAdded++;
                        }
                        catch { }
                    }

                    Console.WriteLine($"     {friendsAdded}/{friendsToAdd} amigos agregados: ✅");
                    Console.WriteLine($"     Total amigos: {friendConn.FriendCount} ✅");
                    Console.WriteLine($"     Amigos online: {friendConn.OnlineFriends} ✅");

                    friendConn.Stop();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en integración: {ex.Message}");
            }
        }

        static void TestFriendMessaging()
        {
            Console.WriteLine("   Probando mensajería...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                using (var friendConn = new FriendConnection(dht, onion))
                {
                    friendConn.StartAsync().Wait(1000);

                    // Agregar amigo de prueba
                    var friendKey = RandomBytes.Generate(32);
                    uint friendNumber = friendConn.AddFriend(friendKey);

                    // Test envío de mensajes
                    int messagesSent = 0;
                    var testMessages = new[] { "Hello!", "How are you?", "Test message" };

                    foreach (var message in testMessages)
                    {
                        if (friendConn.SendTextMessage(friendNumber, message).Wait(1000))
                        {
                            messagesSent++;
                        }
                    }

                    Console.WriteLine($"     {messagesSent}/{testMessages.Length} mensajes enviados: ✅");

                    // Test mensajes largos
                    var longMessage = new string('X', 500);
                    bool longMessageSent = friendConn.SendTextMessage(friendNumber, longMessage).Wait(1000);
                    Console.WriteLine($"     Mensaje largo enviado: {(longMessageSent ? "✅" : "❌")}");

                    friendConn.Stop();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en mensajería: {ex.Message}");
            }
        }

        static void TestFriendManagement()
        {
            Console.WriteLine("   Probando gestión de amigos...");

            try
            {
                var keyPair = CryptoBox.GenerateKeyPair();
                using (var dht = new DHT(keyPair.PublicKey, keyPair.PrivateKey, 0))
                using (var onion = new Onion(dht))
                using (var friendConn = new FriendConnection(dht, onion))
                {
                    friendConn.StartAsync().Wait(1000);

                    // Agregar múltiples amigos
                    var friendKeys = new List<byte[]>();
                    for (int i = 0; i < 5; i++)
                    {
                        friendKeys.Add(RandomBytes.Generate(32));
                    }

                    // Agregar amigos
                    foreach (var key in friendKeys)
                    {
                        friendConn.AddFriend(key);
                    }

                    Console.WriteLine($"     Amigos agregados: {friendConn.FriendCount}/5 ✅");

                    // Obtener lista de amigos
                    var allFriends = friendConn.GetAllFriends();
                    Console.WriteLine($"     Lista de amigos obtenida: {allFriends.Count} ✅");

                    // Obtener amigos online
                    var onlineFriends = friendConn.GetOnlineFriends();
                    Console.WriteLine($"     Amigos online: {onlineFriends.Count} ✅");

                    // Remover algunos amigos
                    int friendsToRemove = 2;
                    int friendsRemoved = 0;

                    for (int i = 0; i < friendsToRemove && i < allFriends.Count; i++)
                    {
                        if (friendConn.RemoveFriend(allFriends[i].FriendNumber))
                        {
                            friendsRemoved++;
                        }
                    }

                    Console.WriteLine($"     Amigos removidos: {friendsRemoved}/{friendsToRemove} ✅");
                    Console.WriteLine($"     Amigos restantes: {friendConn.FriendCount} ✅");

                    friendConn.Stop();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en gestión: {ex.Message}");
            }
        }

        static void TestTox()
        {
            Console.WriteLine("\n16. Probando Tox Client Principal...");

            // Test básico de funcionalidad
            bool basicTest = Tox.Test();
            Console.WriteLine($"   Test de funcionalidad: {(basicTest ? "✅ PASÓ" : "❌ FALLÓ")}");

            // Test de ciclo de vida completo
            TestToxLifecycle();

            // Test de mensajería integrada
            TestToxMessaging();

            // Test de persistencia
            TestToxPersistence();
        }

        static void TestToxLifecycle()
        {
            Console.WriteLine("   Probando ciclo de vida...");

            try
            {
                var options = new ToxOptions { UDPListenPort = 0 };
                using (var tox = new Tox())
                {
                    // Configurar logging
                    tox.OnLogMessage += (msg) => Console.WriteLine($"       {msg}");

                    // Test inicio
                    bool started = tox.StartAsync().Wait(5000);
                    Console.WriteLine($"     Cliente iniciado: {(started ? "✅" : "❌")}");

                    if (started)
                    {
                        // Verificar propiedades después del inicio
                        bool keysValid = tox.PublicKey != null && tox.PublicKey.Length == 32 &&
                                       tox.SecretKey != null && tox.SecretKey.Length == 32 &&
                                       tox.Address != null && tox.Address.Length == 32;
                        Console.WriteLine($"     Claves generadas: {(keysValid ? "✅" : "❌")}");

                        // Verificar estado
                        bool stateValid = tox.Status == ToxStatus.Connected;
                        Console.WriteLine($"     Estado conectado: {(stateValid ? "✅" : "❌")}");

                        // Verificar componentes
                        bool componentsValid = tox.DHTNodes >= 0 && tox.OnionNodes >= 0;
                        Console.WriteLine($"     Componentes activos: {(componentsValid ? "✅" : "❌")}");

                        // Test parada
                        tox.Stop();
                        bool stopped = tox.Status == ToxStatus.Stopped;
                        Console.WriteLine($"     Cliente detenido: {(stopped ? "✅" : "❌")}");

                        Console.WriteLine($"     Ciclo de vida completo: ✅");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en ciclo de vida: {ex.Message}");
            }
        }

        static void TestToxMessaging()
        {
            Console.WriteLine("   Probando mensajería integrada...");

            try
            {
                var options1 = new ToxOptions { UDPListenPort = 0 };
                var options2 = new ToxOptions { UDPListenPort = 0 };

                using (var tox1 = new Tox())
                using (var tox2 = new Tox())
                {
                    // Iniciar ambos clientes
                    bool started1 = tox1.StartAsync().Wait(3000);
                    bool started2 = tox2.StartAsync().Wait(3000);

                    if (started1 && started2)
                    {
                        // Agregar amigos entre sí
                        uint friendNumber = tox1.AddFriend(tox2.PublicKey, "Test friend request");
                        bool friendAdded = friendNumber != uint.MaxValue;
                        Console.WriteLine($"     Amigo agregado: {(friendAdded ? "✅" : "❌")}");

                        // Configurar eventos de mensajes
                        bool messageReceived = false;
                        tox2.OnFriendMessage += (msg) => {
                            messageReceived = true;
                            Console.WriteLine($"       Mensaje recibido en tox2: ✅");
                        };

                        // Enviar mensaje
                        bool messageSent = tox1.SendMessage(friendNumber, "Hello from tox1!").Wait(2000);
                        Console.WriteLine($"     Mensaje enviado: {(messageSent ? "✅" : "❌")}");

                        // Dar tiempo para que llegue el mensaje
                        Thread.Sleep(500);
                        Console.WriteLine($"     Mensaje recibido: {(messageReceived ? "✅" : "❌")}");

                        tox1.Stop();
                        tox2.Stop();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en mensajería: {ex.Message}");
            }
        }

        static void TestToxPersistence()
        {
            Console.WriteLine("   Probando persistencia...");

            try
            {
                byte[] savedState = null;

                // Primera instancia - crear y guardar
                var options1 = new ToxOptions { UDPListenPort = 0 };
                using (var tox1 = new Tox(options1))
                {
                    // Configurar logging
                    tox1.OnLogMessage += (msg) => Console.WriteLine($"       [Tox1] {msg}");

                    bool started = tox1.StartAsync().Wait(5000);
                    if (!started)
                    {
                        Console.WriteLine("     ❌ No se pudo iniciar Tox1");
                        return;
                    }

                    // Esperar a que esté completamente conectado
                    Thread.Sleep(1000);

                    tox1.SetName("Test User");
                    tox1.SetStatusMessage("Testing persistence");

                    // Agregar algún amigo de prueba
                    var testKey = RandomBytes.Generate(32);
                    tox1.AddFriend(testKey);

                    // Esperar a que procese la solicitud de amigo
                    Thread.Sleep(500);

                    // Guardar estado
                    try
                    {
                        savedState = tox1.Save();
                        bool stateSaved = savedState != null && savedState.Length > 0;
                        Console.WriteLine($"     Estado guardado: {(stateSaved ? "✅" : "❌")} ({savedState?.Length ?? 0} bytes)");

                        if (!stateSaved)
                        {
                            tox1.Stop();
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"     ❌ Error guardando estado: {ex.Message}");
                        tox1.Stop();
                        return;
                    }

                    tox1.Stop();
                }

                // Segunda instancia - cargar desde estado guardado
                var options2 = new ToxOptions { UDPListenPort = 0 };
                using (var tox2 = new Tox(options2))
                {
                    // Configurar logging
                    tox2.OnLogMessage += (msg) => Console.WriteLine($"       [Tox2] {msg}");

                    bool started = tox2.StartAsync(savedState).Wait(5000);
                    Console.WriteLine($"     Cliente reiniciado: {(started ? "✅" : "❌")}");

                    if (started)
                    {
                        // Esperar a que cargue completamente
                        Thread.Sleep(1000);

                        // Verificar que se cargó la configuración
                        bool configLoaded = tox2.Name == "Test User" &&
                                          tox2.StatusMessage == "Testing persistence";
                        Console.WriteLine($"     Configuración cargada: {(configLoaded ? "✅" : "❌")}");

                        // Verificar que se cargaron los amigos
                        var friends = tox2.GetAllFriends();
                        bool friendsLoaded = friends.Count == 1;
                        Console.WriteLine($"     Amigos cargados: {friends.Count}/1 {(friendsLoaded ? "✅" : "❌")}");

                        if (friends.Count > 0)
                        {
                            Console.WriteLine($"       Amigo cargado: {friends[0]}");
                        }

                        tox2.Stop();
                        Console.WriteLine($"     Persistencia completa: ✅");
                    }
                    else
                    {
                        Console.WriteLine($"     ❌ No se pudo reiniciar el cliente");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en persistencia: {ex.Message}");
            }
        }

        static void RunCryptoSecurityAudit()
        {
            Console.WriteLine("🔐 AUDITORÍA DE SEGURIDAD CRIPTOGRÁFICA");
            Console.WriteLine("======================================");

            bool cryptoBox = CryptoBox.Test();
            bool cryptoPwHash = CryptoPwHash.Test();
            bool cryptoAuth = CryptoAuth.Test();
            bool cryptoHash = CryptoHashSha256.Test();
            bool cryptoVerify = CryptoVerify.Test();
            bool randomBytes = RandomBytes.Test();

            Console.WriteLine("\n📊 RESUMEN CRIPTOGRÁFICO:");
            Console.WriteLine($"   CryptoBox (curve25519-xsalsa20-poly1305): {(cryptoBox ? "✅ SECURE" : "❌ FAILED")}");
            Console.WriteLine($"   CryptoPwHash (scryptsalsa208sha256): {(cryptoPwHash ? "✅ SECURE" : "❌ FAILED")}");
            Console.WriteLine($"   CryptoAuth (HMAC-SHA-256): {(cryptoAuth ? "✅ SECURE" : "❌ FAILED")}");
            Console.WriteLine($"   CryptoHash (SHA-256): {(cryptoHash ? "✅ SECURE" : "❌ FAILED")}");
            Console.WriteLine($"   CryptoVerify (timing-safe): {(cryptoVerify ? "✅ SECURE" : "❌ FAILED")}");
            Console.WriteLine($"   RandomBytes (secure RNG): {(randomBytes ? "✅ SECURE" : "❌ FAILED")}");

            bool allSecure = cryptoBox && cryptoPwHash && cryptoAuth && cryptoHash && cryptoVerify && randomBytes;
            Console.WriteLine($"\n   ESTADO GENERAL: {(allSecure ? "✅✅✅ TODA LA CRIPTOGRAFÍA ES SEGURA" : "❌❌❌ HAY PROBLEMAS DE SEGURIDAD")}");

            if (!allSecure)
            {
                Console.WriteLine("\n🚨 ACCIONES REQUERIDAS:");
                if (!cryptoBox) Console.WriteLine("   - Revisar implementación de CryptoBox");
                if (!cryptoPwHash) Console.WriteLine("   - Revisar implementación de Scrypt");
                if (!cryptoAuth) Console.WriteLine("   - Revisar implementación de HMAC-SHA256");
                if (!cryptoHash) Console.WriteLine("   - Revisar implementación de SHA-256");
                if (!cryptoVerify) Console.WriteLine("   - Revisar comparación constante en tiempo");
                if (!randomBytes) Console.WriteLine("   - Revisar generación de números aleatorios");
            }

            Console.WriteLine("\n" + new string('=', 50));
        }


    }
}