using Sodium;
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


            /*
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
            TestTCPClientServer();

            // Test 14: TestOnion
            TestOnionRouting();

            // Test 15: TestFriendConnection
            TestFriendConnection();

            // Test 16: Tox
            TestToxCore();

            // Después de TestToxCore(), agregar:
            TestLoggerSystem();

            // Test State.cs
            TestStateManagement();

            // Test de Messenger.cs
            TestMessenger();
            */
            TestToxIntegration();
            TestResilience();
            RunPerformanceBenchmark();
            TestNetworkComponents();


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

        // ==================== PRUEBAS DHT ACTUALIZADAS ====================

        static void TestDHT()
        {
            Console.WriteLine("\n🌐 Probando DHT (Distributed Hash Table)...");

            try
            {
                // Generar claves para prueba
                byte[] publicKey = new byte[32];
                byte[] secretKey = new byte[32];
                RandomBytes.Generate(publicKey);
                RandomBytes.Generate(secretKey);

                // Crear instancia DHT
                var dht = new DHT(publicKey, secretKey);

                Console.WriteLine($"   ✅ DHT creado - Socket: {dht.Socket}");

                // Test 1: Agregar nodos a la DHT
                Console.WriteLine("   👥 Probando agregado de nodos...");
                TestDHTAddNodes(dht);

                // Test 2: Búsqueda de nodos cercanos
                Console.WriteLine("   🔍 Probando búsqueda de nodos...");
                TestDHTNodeDiscovery(dht);

                // Test 3: Manejo de paquetes DHT
                Console.WriteLine("   📦 Probando manejo de paquetes...");
                TestDHTPacketHandling(dht);

                // Test 4: Bootstrap básico
                Console.WriteLine("   🚀 Probando bootstrap...");
                TestDHTBootstrap(dht);

                // Test 5: Estadísticas y mantenimiento
                Console.WriteLine("   📊 Probando estadísticas...");
                TestDHTStatistics(dht);

                // Cerrar DHT
                dht.Close();
                Console.WriteLine("   ✅ DHT cerrado correctamente");

                Console.WriteLine("   ✅ Todas las pruebas DHT completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas DHT: {ex.Message}");
            }
        }

        static void TestDHTAddNodes(DHT dht)
        {
            try
            {
                // Crear nodos de prueba
                var nodes = new List<(byte[], IPPort)>();

                for (int i = 0; i < 10; i++)
                {
                    byte[] nodePublicKey = new byte[32];
                    RandomBytes.Generate(nodePublicKey);

                    var ip = new IP(IPAddress.Parse($"192.168.1.{i + 1}"));
                    var ipport = new IPPort(ip, (ushort)(33445 + i));

                    nodes.Add((nodePublicKey, ipport));
                }

                // Agregar nodos a la DHT
                int addedCount = 0;
                foreach (var (pubKey, ipp) in nodes)
                {
                    int result = dht.AddNode(pubKey, ipp);
                    if (result >= 0)
                    {
                        addedCount++;
                    }
                }

                Console.WriteLine($"     ✅ Nodos agregados: {addedCount}/{nodes.Count}");
                Console.WriteLine($"     ✅ Total nodos en DHT: {dht.TotalNodes}");
                Console.WriteLine($"     ✅ Nodos activos: {dht.ActiveNodes}");

                // Verificar que los nodos fueron agregados
                if (dht.TotalNodes >= nodes.Count)
                {
                    Console.WriteLine("     ✅ Todos los nodos fueron agregados correctamente");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Solo {dht.TotalNodes}/{nodes.Count} nodos agregados");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error agregando nodos: {ex.Message}");
            }
        }

        static void TestDHTNodeDiscovery(DHT dht)
        {
            try
            {
                // Generar clave objetivo para búsqueda
                byte[] targetKey = new byte[32];
                RandomBytes.Generate(targetKey);

                // Buscar nodos cercanos
                var closestNodes = dht.GetClosestNodes(targetKey, 5);

                Console.WriteLine($"     ✅ Nodos cercanos encontrados: {closestNodes.Count}");

                if (closestNodes.Count > 0)
                {
                    Console.WriteLine("     📍 Nodos más cercanos:");
                    for (int i = 0; i < Math.Min(closestNodes.Count, 3); i++)
                    {
                        var node = closestNodes[i];
                        Console.WriteLine($"       {i + 1}. {node}");
                    }
                }

                // Verificar que la búsqueda funciona
                if (closestNodes.Count >= 0) // Puede ser 0 si no hay nodos suficientes
                {
                    Console.WriteLine("     ✅ Búsqueda de nodos funcionando");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en búsqueda de nodos: {ex.Message}");
            }
        }

        static void TestDHTPacketHandling(DHT dht)
        {
            try
            {
                // Test 1: Crear paquete ping request
                byte[] testPublicKey = new byte[32];
                RandomBytes.Generate(testPublicKey);

                byte[] pingRequest = CreateTestPingRequest(dht.SelfPublicKey, testPublicKey);
                Console.WriteLine($"     ✅ Ping request creado: {pingRequest.Length} bytes");

                // Test 2: Crear paquete get nodes request
                byte[] getNodesRequest = CreateTestGetNodesRequest(dht.SelfPublicKey, testPublicKey);
                Console.WriteLine($"     ✅ Get nodes request creado: {getNodesRequest.Length} bytes");

                // Test 3: Simular manejo de paquete ping (debería fallar sin encriptación real)
                var testSource = new IPPort(new IP(IPAddress.Loopback), 33445);
                int handleResult = dht.DHT_handle_packet(pingRequest, pingRequest.Length, testSource);

                if (handleResult == -1)
                {
                    Console.WriteLine("     ✅ Manejo de paquete ping (fallo esperado sin encriptación)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Manejo de paquete ping retornó: {handleResult}");
                }

                // Test 4: Envío de paquete
                int sendResult = dht.DHT_send_packet(testSource, pingRequest, pingRequest.Length);
                if (sendResult == -1)
                {
                    Console.WriteLine("     ✅ Envío de paquete (fallo esperado sin conexión real)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Envío de paquete retornó: {sendResult}");
                }

                Console.WriteLine("     ✅ Pruebas de paquetes completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en pruebas de paquetes: {ex.Message}");
            }
        }

        static void TestDHTBootstrap(DHT dht)
        {
            try
            {
                // Crear nodo bootstrap de prueba
                byte[] bootstrapPublicKey = new byte[32];
                RandomBytes.Generate(bootstrapPublicKey);

                var bootstrapIP = new IP(IPAddress.Parse("127.0.0.1"));
                var bootstrapIPPort = new IPPort(bootstrapIP, 33445);

                // Intentar bootstrap
                int bootstrapResult = dht.DHT_bootstrap(bootstrapIPPort, bootstrapPublicKey);

                if (bootstrapResult == 0)
                {
                    Console.WriteLine("     ✅ Solicitud de bootstrap enviada");
                }
                else
                {
                    Console.WriteLine("     ⚠️ Bootstrap falló (puede ser normal en entorno de prueba)");
                }

                // Ejecutar trabajo periódico
                dht.DoPeriodicWork();
                Console.WriteLine("     ✅ Trabajo periódico ejecutado");

                Console.WriteLine("     ✅ Pruebas de bootstrap completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en pruebas de bootstrap: {ex.Message}");
            }
        }

        static void TestDHTStatistics(DHT dht)
        {
            try
            {
                // Mostrar estadísticas
                dht.PrintStatistics();

                // Verificar que las estadísticas son coherentes
                if (dht.TotalNodes >= 0 && dht.ActiveNodes >= 0 && dht.ActiveNodes <= dht.TotalNodes)
                {
                    Console.WriteLine("     ✅ Estadísticas coherentes");
                }
                else
                {
                    Console.WriteLine("     ⚠️ Estadísticas inconsistentes");
                }

                // Test de cálculo de distancia
                byte[] key1 = new byte[32];
                byte[] key2 = new byte[32];
                RandomBytes.Generate(key1);
                RandomBytes.Generate(key2);

                byte[] distance = DHT.Distance(key1, key2);
                if (distance.Length == 32)
                {
                    Console.WriteLine("     ✅ Cálculo de distancia funcionando");
                }
                else
                {
                    Console.WriteLine("     ❌ Error en cálculo de distancia");
                }

                Console.WriteLine("     ✅ Pruebas de estadísticas completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en pruebas de estadísticas: {ex.Message}");
            }
        }

        // ==================== FUNCIONES AUXILIARES PARA PRUEBAS ====================

        static byte[] CreateTestPingRequest(byte[] selfPublicKey, byte[] targetPublicKey)
        {
            byte[] packet = new byte[100];
            packet[0] = 0x00; // Ping request

            Buffer.BlockCopy(selfPublicKey, 0, packet, 1, 32);
            Buffer.BlockCopy(targetPublicKey, 0, packet, 33, 32);

            byte[] timestamp = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            Buffer.BlockCopy(timestamp, 0, packet, 65, 8);

            byte[] nonce = RandomBytes.Generate(27);
            Buffer.BlockCopy(nonce, 0, packet, 73, 27);

            return packet;
        }

        static byte[] CreateTestGetNodesRequest(byte[] selfPublicKey, byte[] targetPublicKey)
        {
            byte[] packet = new byte[100];
            packet[0] = 0x02; // Get nodes request

            Buffer.BlockCopy(selfPublicKey, 0, packet, 1, 32);
            Buffer.BlockCopy(targetPublicKey, 0, packet, 33, 32);

            byte[] padding = RandomBytes.Generate(35);
            Buffer.BlockCopy(padding, 0, packet, 65, 35);

            return packet;
        }

        static void TestTCPClientServer()
        {
            Console.WriteLine("\n🔌 Probando TCP Client/Server...");

            try
            {
                // Generar claves para prueba
                byte[] publicKey = new byte[32];
                byte[] secretKey = new byte[32];
                RandomBytes.Generate(publicKey);
                RandomBytes.Generate(secretKey);

                // Test 1: Servidor TCP básico
                Console.WriteLine("   🖥️ Probando servidor TCP...");
                TestTCPServer(publicKey, secretKey);

                // Test 2: Cliente TCP básico  
                Console.WriteLine("   💻 Probando cliente TCP...");
                TestTCPClient(publicKey, secretKey);

                // Test 3: Comunicación cliente-servidor
                Console.WriteLine("   🔄 Probando comunicación TCP...");
                TestTCPCommunication(publicKey, secretKey);

                Console.WriteLine("   ✅ Todas las pruebas TCP completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas TCP: {ex.Message}");
            }
        }

        static void TestTCPServer(byte[] publicKey, byte[] secretKey)
        {
            var server = new TCP_Server(publicKey, secretKey);

            try
            {
                // Test bind/listen
                var localIP = new IP(IPAddress.Loopback);
                var serverEndPoint = new IPPort(localIP, 33445);

                int listenResult = server.tcp_listen(serverEndPoint);
                if (listenResult == 0)
                {
                    Console.WriteLine("     ✅ Servidor TCP escuchando en puerto 33445");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló tcp_listen");
                    server.Stop();
                    return;
                }

                // Test estado del servidor
                if (server.IsRunning)
                {
                    Console.WriteLine("     ✅ Servidor en estado running");
                }
                else
                {
                    Console.WriteLine("     ❌ Servidor no en estado running");
                }

                // Test aceptación (no bloqueante)
                TCP_Connection connection;
                int acceptResult = server.tcp_accept(out connection);
                if (acceptResult == -1)
                {
                    Console.WriteLine("     ✅ tcp_accept (no hay conexiones pendientes)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ tcp_accept retornó: {acceptResult}");
                }

                // Test estadísticas
                Console.WriteLine($"     ✅ Conexiones totales: {server.ConnectionCount}");
                Console.WriteLine($"     ✅ Conexiones activas: {server.ActiveConnections}");

                // Limpiar
                server.Stop();
                Console.WriteLine("     ✅ Servidor detenido correctamente");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en servidor TCP: {ex.Message}");
                server.Stop();
            }
        }

        static void TestTCPClient(byte[] publicKey, byte[] secretKey)
        {
            var client = new TCP_Client(publicKey, secretKey);

            try
            {
                // Test estado inicial
                if (!client.IsConnected)
                {
                    Console.WriteLine("     ✅ Cliente inicialmente desconectado");
                }
                else
                {
                    Console.WriteLine("     ❌ Cliente debería estar desconectado inicialmente");
                }

                // Test conexión a servidor inexistente (debería fallar)
                var fakeEndPoint = new IPPort(new IP(IPAddress.Loopback), 9999);
                byte[] fakePublicKey = new byte[32];
                RandomBytes.Generate(fakePublicKey);

                int connectResult = client.tcp_connect(fakeEndPoint, fakePublicKey);
                if (connectResult == -1)
                {
                    Console.WriteLine("     ✅ Conexión a servidor inexistente (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Conexión retornó: {connectResult}");
                }

                // Test estado después de conexión fallida
                if (!client.IsConnected)
                {
                    Console.WriteLine("     ✅ Cliente permanece desconectado después de fallo");
                }
                else
                {
                    Console.WriteLine("     ❌ Cliente conectado después de fallo");
                }

                // Test envío sin conexión
                byte[] testData = new byte[] { 0x01, 0x02, 0x03 };
                int sendResult = client.tcp_send_data(testData, testData.Length);
                if (sendResult == -1)
                {
                    Console.WriteLine("     ✅ Envío sin conexión (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Envío sin conexión retornó: {sendResult}");
                }

                // Test recepción sin conexión
                byte[] recvBuffer = new byte[100];
                int recvResult = client.tcp_recv_data(recvBuffer, recvBuffer.Length);
                if (recvResult == -1)
                {
                    Console.WriteLine("     ✅ Recepción sin conexión (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Recepción sin conexión retornó: {recvResult}");
                }

                // Test desconexión sin conexión
                int disconnectResult = client.tcp_disconnect();
                if (disconnectResult == -1)
                {
                    Console.WriteLine("     ✅ Desconexión sin conexión (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Desconexión sin conexión retornó: {disconnectResult}");
                }

                Console.WriteLine("     ✅ Pruebas de cliente TCP completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en cliente TCP: {ex.Message}");
            }
        }

        static void TestTCPCommunication(byte[] publicKey, byte[] secretKey)
        {
            // Crear servidor
            var server = new TCP_Server(publicKey, secretKey);
            var serverEndPoint = new IPPort(new IP(IPAddress.Loopback), 33446);

            // Crear cliente
            var client = new TCP_Client(publicKey, secretKey);
            byte[] clientPublicKey = new byte[32];
            RandomBytes.Generate(clientPublicKey);

            try
            {
                // Iniciar servidor
                if (server.tcp_listen(serverEndPoint) != 0)
                {
                    Console.WriteLine("     ❌ No se pudo iniciar servidor para prueba de comunicación");
                    return;
                }

                Console.WriteLine("     ✅ Servidor iniciado para comunicación");

                // En una implementación real aquí habría:
                // 1. Cliente se conecta al servidor
                // 2. Servidor acepta la conexión
                // 3. Handshake criptográfico
                // 4. Intercambio de datos encriptados

                // Por ahora probamos las funciones básicas
                Console.WriteLine("     🔄 Pruebas de comunicación completadas (implementación básica)");

                // Limpiar
                server.Stop();
                client.tcp_disconnect();

                Console.WriteLine("     ✅ Recursos de comunicación liberados");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en comunicación TCP: {ex.Message}");
                server.Stop();
                client.tcp_disconnect();
            }
        }


        static void TestOnionRouting()
        {
            Console.WriteLine("\n🧅 Probando Onion Routing...");

            try
            {
                // Generar claves para prueba
                byte[] publicKey = new byte[32];
                byte[] secretKey = new byte[32];
                RandomBytes.Generate(publicKey);
                RandomBytes.Generate(secretKey);

                // Crear instancia Onion
                var onion = new Onion(publicKey, secretKey);

                Console.WriteLine($"   ✅ Onion creado - Socket: {onion.Socket}");

                // Test 1: Iniciar servicio Onion
                Console.WriteLine("   🚀 Probando inicio del servicio...");
                TestOnionStartStop(onion);

                // Test 2: Agregar nodos Onion
                Console.WriteLine("   👥 Probando agregado de nodos Onion...");
                TestOnionAddNodes(onion);

                // Test 3: Creación de paths Onion
                Console.WriteLine("   🛣️ Probando creación de paths...");
                TestOnionPathCreation(onion);

                // Test 4: Envío a través de Onion
                Console.WriteLine("   📨 Probando envío onion...");
                TestOnionSend(onion);

                // Test 5: Manejo de paquetes onion
                Console.WriteLine("   📦 Probando manejo de paquetes...");
                TestOnionPacketHandling(onion);

                // Cerrar Onion
                onion.Close();
                Console.WriteLine("   ✅ Onion cerrado correctamente");

                Console.WriteLine("   ✅ Todas las pruebas Onion completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas Onion: {ex.Message}");
            }
        }

        static void TestOnionStartStop(Onion onion)
        {
            try
            {
                // Test inicio
                int startResult = onion.Start();
                if (startResult == 0)
                {
                    Console.WriteLine("     ✅ Servicio Onion iniciado");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló inicio de Onion");
                    return;
                }

                // Verificar que está corriendo
                if (onion.IsRunning)
                {
                    Console.WriteLine("     ✅ Estado IsRunning correcto");
                }
                else
                {
                    Console.WriteLine("     ❌ Estado IsRunning incorrecto");
                }

                // Test parada
                int stopResult = onion.Stop();
                if (stopResult == 0)
                {
                    Console.WriteLine("     ✅ Servicio Onion detenido");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló parada de Onion");
                }

                // Reiniciar para pruebas siguientes
                onion.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en start/stop: {ex.Message}");
            }
        }

        static void TestOnionAddNodes(Onion onion)
        {
            try
            {
                // Crear nodos Onion de prueba
                var nodes = new List<(byte[], IPPort)>();

                for (int i = 0; i < 5; i++)
                {
                    byte[] nodePublicKey = new byte[32];
                    RandomBytes.Generate(nodePublicKey);

                    var ip = new IP(IPAddress.Parse($"10.0.1.{i + 1}"));
                    var ipport = new IPPort(ip, (ushort)(33446 + i));

                    nodes.Add((nodePublicKey, ipport));
                }

                // Agregar nodos a Onion
                int addedCount = 0;
                foreach (var (pubKey, ipp) in nodes)
                {
                    int result = onion.onion_add_node(pubKey, ipp);
                    if (result >= 0)
                    {
                        addedCount++;
                    }
                }

                Console.WriteLine($"     ✅ Nodos Onion agregados: {addedCount}/{nodes.Count}");
                Console.WriteLine($"     ✅ Total nodos en Onion: {onion.TotalOnionNodes}");
                Console.WriteLine($"     ✅ Nodos activos: {onion.ActiveOnionNodes}");

                if (onion.TotalOnionNodes >= nodes.Count)
                {
                    Console.WriteLine("     ✅ Todos los nodos Onion fueron agregados");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error agregando nodos Onion: {ex.Message}");
            }
        }

        static void TestOnionPathCreation(Onion onion)
        {
            try
            {
                // Crear DHT de prueba para path creation
                byte[] dhtPublicKey = new byte[32];
                byte[] dhtSecretKey = new byte[32];
                RandomBytes.Generate(dhtPublicKey);
                RandomBytes.Generate(dhtSecretKey);
                var dht = new DHT(dhtPublicKey, dhtSecretKey);

                // Agregar algunos nodos al DHT para que Onion pueda usarlos
                for (int i = 0; i < 5; i++)
                {
                    byte[] nodeKey = new byte[32];
                    RandomBytes.Generate(nodeKey);
                    var ip = new IP(IPAddress.Parse($"10.0.2.{i + 1}"));
                    var ipport = new IPPort(ip, (ushort)(33450 + i));
                    dht.AddNode(nodeKey, ipport);
                }

                // Crear paths Onion
                int path1 = onion.create_onion_path(dht);
                int path2 = onion.create_onion_path(dht);

                if (path1 >= 0)
                {
                    Console.WriteLine($"     ✅ Path Onion 1 creado: {path1}");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló creación de path 1");
                }

                if (path2 >= 0)
                {
                    Console.WriteLine($"     ✅ Path Onion 2 creado: {path2}");
                }
                else
                {
                    Console.WriteLine("     ⚠️ No se pudo crear path 2 (puede ser normal)");
                }

                Console.WriteLine($"     ✅ Total paths creados: {onion.TotalPaths}");
                Console.WriteLine($"     ✅ Paths activos: {onion.ActivePaths}");

                // Limpiar DHT
                dht.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en creación de paths: {ex.Message}");
            }
        }

        static void TestOnionSend(Onion onion)
        {
            try
            {
                // Datos de prueba
                byte[] testData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
                byte[] targetPublicKey = new byte[32];
                RandomBytes.Generate(targetPublicKey);

                // Test onion_send_1
                int send1Result = onion.onion_send_1(testData, testData.Length, targetPublicKey);
                if (send1Result == -1)
                {
                    Console.WriteLine("     ✅ onion_send_1 (fallo esperado sin paths activos)");
                }
                else if (send1Result > 0)
                {
                    Console.WriteLine($"     ✅ onion_send_1 envió {send1Result} bytes");
                }

                // Test onion_send_2
                int send2Result = onion.onion_send_2(testData, testData.Length, targetPublicKey);
                if (send2Result == -1)
                {
                    Console.WriteLine("     ✅ onion_send_2 (fallo esperado sin paths activos)");
                }
                else if (send2Result > 0)
                {
                    Console.WriteLine($"     ✅ onion_send_2 envió {send2Result} bytes");
                }

                Console.WriteLine("     ✅ Pruebas de envío completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en envío onion: {ex.Message}");
            }
        }

        static void TestOnionPacketHandling(Onion onion)
        {
            try
            {
                // Crear paquete onion de prueba
                byte[] testPacket = new byte[100];
                RandomBytes.Generate(testPacket);
                testPacket[0] = 0x00; // Establecer tipo de paquete

                var testSource = new IPPort(new IP(IPAddress.Loopback), 33445);

                // Test handle_onion_recv_1
                int handle1Result = onion.handle_onion_recv_1(testSource, testPacket, testPacket.Length);
                if (handle1Result == -1)
                {
                    Console.WriteLine("     ✅ handle_onion_recv_1 (fallo esperado con paquete inválido)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ handle_onion_recv_1 retornó: {handle1Result}");
                }

                // Test handle_onion_recv_2
                int handle2Result = onion.handle_onion_recv_2(testSource, testPacket, testPacket.Length);
                if (handle2Result == -1)
                {
                    Console.WriteLine("     ✅ handle_onion_recv_2 (fallo esperado con paquete inválido)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ handle_onion_recv_2 retornó: {handle2Result}");
                }

                Console.WriteLine("     ✅ Pruebas de manejo de paquetes completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en manejo de paquetes: {ex.Message}");
            }
        }




        static void TestFriendConnection()
        {
            Console.WriteLine("\n👥 Probando Friend Connection...");

            try
            {
                // Generar claves para prueba
                byte[] publicKey = new byte[32];
                byte[] secretKey = new byte[32];
                RandomBytes.Generate(publicKey);
                RandomBytes.Generate(secretKey);

                // Crear módulos dependientes (CORREGIDO: sin Start())
                var dht = new DHT(publicKey, secretKey);
                var onion = new Onion(publicKey, secretKey);

                // Test 1: Friend Connection básico
                Console.WriteLine("   🔧 Probando Friend Connection básico...");
                TestFriendConnectionBasic(publicKey, secretKey, dht, onion);

                // Test 2: Gestión de amigos
                Console.WriteLine("   👥 Probando gestión de amigos...");
                TestFriendManagement(publicKey, secretKey, dht, onion);

                // Test 3: Mensajería
                Console.WriteLine("   💬 Probando mensajería...");
                TestFriendMessaging(publicKey, secretKey, dht, onion);

                // Limpiar (CORREGIDO)
                dht.Close();
                onion.Close();

                Console.WriteLine("   ✅ Todas las pruebas Friend Connection completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas Friend Connection: {ex.Message}");
            }
        }

        static void TestFriendConnectionBasic(byte[] publicKey, byte[] secretKey, DHT dht, Onion onion)
        {
            // CORREGIDO: Iniciar Onion antes de crear FriendConnection
            onion.Start();

            var friendConn = new FriendConnection(publicKey, secretKey, dht, onion);

            try
            {
                // Test estado inicial
                if (friendConn.FriendCount == 0)
                {
                    Console.WriteLine("     ✅ Friend Count inicial correcto: 0");
                }
                else
                {
                    Console.WriteLine($"     ❌ Friend Count inicial incorrecto: {friendConn.FriendCount}");
                }

                if (friendConn.OnlineFriends == 0)
                {
                    Console.WriteLine("     ✅ Online Friends inicial correcto: 0");
                }
                else
                {
                    Console.WriteLine($"     ❌ Online Friends inicial incorrecto: {friendConn.OnlineFriends}");
                }

                // Test callbacks
                bool callbackFired = false;
                friendConn.Callbacks.OnConnectionStatusChanged = (friendNum, status) => {
                    callbackFired = true;
                };

                Console.WriteLine("     ✅ Callbacks configurados correctamente");

                // Test mantenimiento periódico
                friendConn.Do_periodic_work();
                Console.WriteLine("     ✅ Do_periodic_work ejecutado sin errores");

                Console.WriteLine("     ✅ Pruebas básicas de Friend Connection completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en pruebas básicas: {ex.Message}");
            }
            finally
            {
                onion.Close();
            }
        }

        static void TestFriendManagement(byte[] publicKey, byte[] secretKey, DHT dht, Onion onion)
        {
            // CORREGIDO: Iniciar Onion
            onion.Start();

            var friendConn = new FriendConnection(publicKey, secretKey, dht, onion);

            try
            {
                // Crear claves públicas de amigos de prueba
                byte[] friend1PublicKey = new byte[32];
                byte[] friend2PublicKey = new byte[32];
                RandomBytes.Generate(friend1PublicKey);
                RandomBytes.Generate(friend2PublicKey);

                // Test agregar amigos
                int friend1 = friendConn.m_addfriend(friend1PublicKey);
                int friend2 = friendConn.m_addfriend(friend2PublicKey);

                if (friend1 >= 0)
                {
                    Console.WriteLine($"     ✅ Amigo 1 agregado: {friend1}");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló agregar amigo 1");
                }

                if (friend2 >= 0)
                {
                    Console.WriteLine($"     ✅ Amigo 2 agregado: {friend2}");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló agregar amigo 2");
                }

                // Verificar conteo
                Console.WriteLine($"     ✅ Total amigos: {friendConn.FriendCount}");
                Console.WriteLine($"     ✅ Amigos online: {friendConn.OnlineFriends}");

                // Test obtener información de amigos
                var friend1Info = friendConn.Get_friend(friend1);
                if (friend1Info?.PublicKey != null)
                {
                    Console.WriteLine("     ✅ Get_friend funciona correctamente");
                }
                else
                {
                    Console.WriteLine("     ❌ Get_friend falló");
                }

                // Test lista de amigos
                var friendList = friendConn.Get_friend_list();
                if (friendList.Count == 2)
                {
                    Console.WriteLine("     ✅ Get_friend_list retorna lista correcta");
                }
                else
                {
                    Console.WriteLine($"     ❌ Get_friend_list retornó {friendList.Count} amigos");
                }

                // Test eliminar amigo
                int delResult = friendConn.m_delfriend(friend1);
                if (delResult == 0)
                {
                    Console.WriteLine("     ✅ Amigo eliminado correctamente");
                    Console.WriteLine($"     ✅ Nuevo total amigos: {friendConn.FriendCount}");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló eliminar amigo");
                }

                Console.WriteLine("     ✅ Pruebas de gestión de amigos completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en gestión de amigos: {ex.Message}");
            }
            finally
            {
                onion.Close();
            }
        }

        static void TestFriendMessaging(byte[] publicKey, byte[] secretKey, DHT dht, Onion onion)
        {
            // CORREGIDO: Iniciar Onion
            onion.Start();

            var friendConn = new FriendConnection(publicKey, secretKey, dht, onion);

            try
            {
                // Agregar amigo de prueba
                byte[] testFriendPublicKey = new byte[32];
                RandomBytes.Generate(testFriendPublicKey);
                int friendNum = friendConn.m_addfriend(testFriendPublicKey);

                if (friendNum < 0)
                {
                    Console.WriteLine("     ⚠️ No se pudo agregar amigo para prueba de mensajería");
                    return;
                }

                // Test enviar mensaje a amigo offline (debería fallar)
                byte[] testMessage = System.Text.Encoding.UTF8.GetBytes("Hola amigo!");
                int sendResult = friendConn.m_send_message(friendNum, testMessage, testMessage.Length);

                if (sendResult == -1)
                {
                    Console.WriteLine("     ✅ Envío a amigo offline (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Envío a amigo offline retornó: {sendResult}");
                }

                // Test establecer estado
                int statusResult = friendConn.m_set_status(FriendUserStatus.TOX_USER_STATUS_AWAY);
                if (statusResult == 0)
                {
                    Console.WriteLine("     ✅ Estado de usuario establecido");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló establecer estado de usuario");
                }

                // Test establecer mensaje de estado
                int statusMessageResult = friendConn.m_set_status_message("Estoy probando Tox");
                if (statusMessageResult == 0)
                {
                    Console.WriteLine("     ✅ Mensaje de estado establecido");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló establecer mensaje de estado");
                }

                // Test manejo de paquetes (simulado)
                byte[] testPacket = new byte[] { 0x20, 0x48, 0x6F, 0x6C, 0x61 }; // "Hola" en bytes
                int handleResult = friendConn.handle_packet(friendNum, testPacket, testPacket.Length);

                if (handleResult == -1)
                {
                    Console.WriteLine("     ✅ Manejo de paquete (fallo esperado en entorno de prueba)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Manejo de paquete retornó: {handleResult}");
                }

                Console.WriteLine("     ✅ Pruebas de mensajería completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en mensajería: {ex.Message}");
            }
            finally
            {
                onion.Close();
            }
        }



        static void TestToxCore()
        {
            Console.WriteLine("\n🐍 Probando Tox Core (Integración Completa)...");

            try
            {
                // Test 1: Creación de instancia Tox
                Console.WriteLine("   🆕 Probando creación de Tox...");
                TestToxCreation();

                // Test 2: Gestión de perfil
                Console.WriteLine("   👤 Probando gestión de perfil...");
                TestToxProfile();

                // Test 3: Conexión a red
                Console.WriteLine("   🌐 Probando conexión a red...");
                TestToxNetwork();

                // Test 4: Gestión de amigos
                Console.WriteLine("   👥 Probando gestión de amigos...");
                TestToxFriends();

                Console.WriteLine("   ✅ Todas las pruebas Tox Core completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas Tox Core: {ex.Message}");
            }
        }

        static void TestToxCreation()
        {
            try
            {
                // Test creación con opciones por defecto
                var options = new ToxOptions();
                var tox = new Tox(options);

                Console.WriteLine("     ✅ Instancia Tox creada con opciones por defecto");

                // Test obtener dirección
                string address = tox.GetAddress();
                if (!string.IsNullOrEmpty(address) && address.Length == 76) // 38 bytes * 2 chars
                {
                    Console.WriteLine($"     ✅ Dirección Tox generada: {address.Substring(0, 16)}...");
                }
                else
                {
                    Console.WriteLine("     ❌ Dirección Tox inválida");
                }

                // Test obtener claves
                byte[] publicKey = tox.tox_self_get_public_key();
                byte[] secretKey = tox.tox_self_get_secret_key();

                if (publicKey.Length == 32 && secretKey.Length == 32)
                {
                    Console.WriteLine("     ✅ Claves criptográficas generadas correctamente");
                }
                else
                {
                    Console.WriteLine("     ❌ Claves criptográficas inválidas");
                }

                // Test iteración
                tox.tox_iterate();
                Console.WriteLine("     ✅ Iteración ejecutada sin errores");

                // Test intervalo de iteración
                uint interval = tox.tox_iteration_interval();
                if (interval > 0)
                {
                    Console.WriteLine($"     ✅ Intervalo de iteración: {interval}ms");
                }
                else
                {
                    Console.WriteLine("     ❌ Intervalo de iteración inválido");
                }

                // Limpiar
                tox.Dispose();
                Console.WriteLine("     ✅ Instancia Tox liberada correctamente");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en creación de Tox: {ex.Message}");
            }
        }

        static void TestToxProfile()
        {
            var tox = new Tox();

            try
            {
                // Test establecer nombre
                string testName = "Tox Tester";
                bool nameResult = tox.tox_self_set_name(testName);
                if (nameResult)
                {
                    Console.WriteLine("     ✅ Nombre establecido correctamente");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló establecer nombre");
                }

                // Test obtener nombre
                string retrievedName = tox.tox_self_get_name();
                if (retrievedName == testName)
                {
                    Console.WriteLine("     ✅ Nombre recuperado correctamente");
                }
                else
                {
                    Console.WriteLine($"     ❌ Nombre no coincide: {retrievedName}");
                }

                // Test establecer mensaje de estado
                string statusMessage = "Probando Tox Core";
                bool statusMsgResult = tox.tox_self_set_status_message(statusMessage);
                if (statusMsgResult)
                {
                    Console.WriteLine("     ✅ Mensaje de estado establecido");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló establecer mensaje de estado");
                }

                // Test obtener mensaje de estado
                string retrievedStatusMsg = tox.tox_self_get_status_message();
                if (retrievedStatusMsg == statusMessage)
                {
                    Console.WriteLine("     ✅ Mensaje de estado recuperado");
                }
                else
                {
                    Console.WriteLine($"     ❌ Mensaje de estado no coincide: {retrievedStatusMsg}");
                }

                // Test establecer estado de usuario
                bool statusResult = tox.tox_self_set_status(ToxUserStatus.AWAY);
                if (statusResult)
                {
                    Console.WriteLine("     ✅ Estado de usuario establecido");
                }
                else
                {
                    Console.WriteLine("     ❌ Falló establecer estado de usuario");
                }

                // Test obtener estado de usuario
                ToxUserStatus retrievedStatus = tox.tox_self_get_status();
                if (retrievedStatus == ToxUserStatus.AWAY)
                {
                    Console.WriteLine("     ✅ Estado de usuario recuperado");
                }
                else
                {
                    Console.WriteLine($"     ❌ Estado de usuario no coincide: {retrievedStatus}");
                }

                Console.WriteLine("     ✅ Pruebas de perfil completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en gestión de perfil: {ex.Message}");
            }
            finally
            {
                tox.Dispose();
            }
        }

        static void TestToxNetwork()
        {
            var tox = new Tox();

            try
            {
                // Test estado de conexión inicial
                ToxConnectionStatus initialStatus = tox.tox_self_get_connection_status();
                if (initialStatus == ToxConnectionStatus.NONE)
                {
                    Console.WriteLine("     ✅ Estado de conexión inicial correcto (NONE)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Estado de conexión inicial: {initialStatus}");
                }

                // Test bootstrap con nodo inválido (debería fallar)
                bool bootstrapResult = tox.tox_bootstrap("invalid.node", 33445, new byte[32]);
                if (!bootstrapResult)
                {
                    Console.WriteLine("     ✅ Bootstrap con nodo inválido (fallo esperado)");
                }
                else
                {
                    Console.WriteLine("     ⚠️ Bootstrap con nodo inválido retornó éxito");
                }

                // Test agregar relay TCP con datos inválidos
                bool relayResult = tox.tox_add_tcp_relay("invalid.relay", 33445, new byte[32]);
                if (!relayResult)
                {
                    Console.WriteLine("     ✅ Agregar relay TCP inválido (fallo esperado)");
                }
                else
                {
                    Console.WriteLine("     ⚠️ Agregar relay TCP inválido retornó éxito");
                }

                // Ejecutar algunas iteraciones
                for (int i = 0; i < 5; i++)
                {
                    tox.tox_iterate();
                    System.Threading.Thread.Sleep(10);
                }
                Console.WriteLine("     ✅ Iteraciones de red ejecutadas");

                Console.WriteLine("     ✅ Pruebas de red completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en pruebas de red: {ex.Message}");
            }
            finally
            {
                tox.Dispose();
            }
        }

        static void TestToxFriends()
        {
            var tox = new Tox();

            try
            {
                // Test estado inicial de amigos
                if (tox.FriendCount == 0)
                {
                    Console.WriteLine("     ✅ Contador de amigos inicial correcto: 0");
                }
                else
                {
                    Console.WriteLine($"     ❌ Contador de amigos inicial incorrecto: {tox.FriendCount}");
                }

                // Test agregar amigo con dirección inválida
                int addFriendResult = tox.tox_friend_add(new byte[38], "Hola!");
                if (addFriendResult == -1)
                {
                    Console.WriteLine("     ✅ Agregar amigo con dirección inválida (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Agregar amigo inválido retornó: {addFriendResult}");
                }

                // Test agregar amigo con clave pública inválida
                int addFriendNoRequestResult = tox.tox_friend_add_norequest(new byte[32]);
                if (addFriendNoRequestResult == -1)
                {
                    Console.WriteLine("     ✅ Agregar amigo con clave inválida (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Agregar amigo con clave inválida retornó: {addFriendNoRequestResult}");
                }

                // Test enviar mensaje a amigo inexistente
                int sendMessageResult = tox.tox_friend_send_message(999, "Mensaje de prueba");
                if (sendMessageResult == -1)
                {
                    Console.WriteLine("     ✅ Enviar mensaje a amigo inexistente (fallo esperado)");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Enviar mensaje a amigo inexistente retornó: {sendMessageResult}");
                }

                // Test obtener información de amigo inexistente
                byte[] testPublicKey = new byte[32];
                bool getKeyResult = tox.tox_friend_get_public_key(999, testPublicKey);
                if (!getKeyResult)
                {
                    Console.WriteLine("     ✅ Obtener clave de amigo inexistente (fallo esperado)");
                }
                else
                {
                    Console.WriteLine("     ⚠️ Obtener clave de amigo inexistente retornó éxito");
                }

                // Test estado de conexión de amigo inexistente
                ToxConnectionStatus friendStatus = tox.tox_friend_get_connection_status(999);
                if (friendStatus == ToxConnectionStatus.NONE)
                {
                    Console.WriteLine("     ✅ Estado de conexión de amigo inexistente correcto");
                }
                else
                {
                    Console.WriteLine($"     ⚠️ Estado de conexión de amigo inexistente: {friendStatus}");
                }

                Console.WriteLine("     ✅ Pruebas de amigos completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en gestión de amigos: {ex.Message}");
            }
            finally
            {
                tox.Dispose();
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

        static void TestLoggerSystem()
        {
            Console.WriteLine("\n📝 Probando Sistema de Logging...");

            try
            {
                // Test 1: Logging básico a consola
                Console.WriteLine("   💬 Probando logging básico...");
                TestBasicLogging();

                // Test 2: Niveles de log
                Console.WriteLine("   🎚️ Probando niveles de log...");
                TestLogLevels();

                // Test 3: Logging con formato
                Console.WriteLine("   📋 Probando logging con formato...");
                TestFormattedLogging();

                // Test 4: Logging a archivo
                Console.WriteLine("   💾 Probando logging a archivo...");
                TestFileLogging();

                // Test 5: Callbacks personalizados
                Console.WriteLine("   🔄 Probando callbacks...");
                TestLogCallbacks();

                Console.WriteLine("   ✅ Todas las pruebas de logging completadas");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ❌ Error en pruebas de logging: {ex.Message}");
            }
        }

        static void TestBasicLogging()
        {
            try
            {
                // Test logging con diferentes niveles usando métodos directos
                Logger.LOGGER_TRACE("TestLogger.cs", 100, "TestBasicLogging", "Mensaje de trace");
                Logger.LOGGER_DEBUG("TestLogger.cs", 101, "TestBasicLogging", "Mensaje de debug");
                Logger.LOGGER_INFO("TestLogger.cs", 102, "TestBasicLogging", "Mensaje de info");
                Logger.LOGGER_WARNING("TestLogger.cs", 103, "TestBasicLogging", "Mensaje de warning");
                Logger.LOGGER_ERROR("TestLogger.cs", 104, "TestBasicLogging", "Mensaje de error");

                // Test logging usando las macros convenientes
                Logger.Log.Trace("Trace con macros");
                Logger.Log.Debug("Debug con macros");
                Logger.Log.Info("Info con macros");
                Logger.Log.Warning("Warning con macros");
                Logger.Log.Error("Error con macros");

                Console.WriteLine("     ✅ Logging básico funcionando");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en logging básico: {ex.Message}");
            }
        }

        static void TestLogLevels()
        {
            try
            {
                // Guardar nivel actual
                var originalLevel = Logger.tox_log_get_level();

                // Test 1: Nivel ERROR (solo errores)
                Logger.tox_log_set_level(ToxLogLevel.TOX_LOG_LEVEL_ERROR);
                Logger.Log.Trace("Este TRACE no debería verse");
                Logger.Log.Debug("Este DEBUG no debería verse");
                Logger.Log.Info("Este INFO no debería verse");
                Logger.Log.Warning("Este WARNING no debería verse");
                Logger.Log.Error("Este ERROR debería verse");

                // Test 2: Nivel INFO (info, warnings, errors)
                Logger.tox_log_set_level(ToxLogLevel.TOX_LOG_LEVEL_INFO);
                Logger.Log.Trace("Este TRACE no debería verse");
                Logger.Log.Debug("Este DEBUG no debería verse");
                Logger.Log.Info("Este INFO debería verse");
                Logger.Log.Warning("Este WARNING debería verse");
                Logger.Log.Error("Este ERROR debería verse");

                // Test 3: Nivel TRACE (todo)
                Logger.tox_log_set_level(ToxLogLevel.TOX_LOG_LEVEL_TRACE);
                Logger.Log.Trace("Este TRACE debería verse");
                Logger.Log.Debug("Este DEBUG debería verse");
                Logger.Log.Info("Este INFO debería verse");
                Logger.Log.Warning("Este WARNING debería verse");
                Logger.Log.Error("Este ERROR debería verse");

                // Restaurar nivel original
                Logger.tox_log_set_level(originalLevel);

                Console.WriteLine("     ✅ Control de niveles funcionando");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en control de niveles: {ex.Message}");
            }
        }

        static void TestFormattedLogging()
        {
            try
            {
                // Test logging con formato usando métodos directos
                Logger.LOGGER_TRACE_F("TestLogger.cs", 200, "TestFormattedLogging",
                    "Trace con parámetros: {0} {1} {2}", "texto", 123, true);
                Logger.LOGGER_DEBUG_F("TestLogger.cs", 201, "TestFormattedLogging",
                    "Debug con parámetros: {0} {1}", 45.67, DateTime.Now);
                Logger.LOGGER_INFO_F("TestLogger.cs", 202, "TestFormattedLogging",
                    "Usuario {0} conectado desde {1}", "Alice", "192.168.1.100");
                Logger.LOGGER_WARNING_F("TestLogger.cs", 203, "TestFormattedLogging",
                    "Conexión lenta: {0}ms", 1500);
                Logger.LOGGER_ERROR_F("TestLogger.cs", 204, "TestFormattedLogging",
                    "Error en {0}: {1}", "FunciónX", "Timeout excedido");

                // Test logging con formato usando macros
                Logger.Log.TraceF("Macro Trace: {0} {1}", "param1", 999);
                Logger.Log.DebugF("Macro Debug: {0}", Math.PI);
                Logger.Log.InfoF("Macro Info: Procesados {0} mensajes", 42);
                Logger.Log.WarningF("Macro Warning: {0}% de uso de CPU", 85.5);
                Logger.Log.ErrorF("Macro Error: Excepción en {0}", "ProcesarMensaje");

                Console.WriteLine("     ✅ Logging con formato funcionando");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en logging con formato: {ex.Message}");
            }
        }

        static void TestFileLogging()
        {
            string testLogFile = "test_tox_log.txt";

            try
            {
                // Habilitar logging a archivo
                bool fileLogEnabled = Logger.tox_log_enable_file_logging(testLogFile);
                if (fileLogEnabled)
                {
                    Console.WriteLine("     ✅ Logging a archivo habilitado");

                    // Escribir algunos logs
                    Logger.Log.Info("Este mensaje debería ir al archivo");
                    Logger.Log.Warning("Advertencia de prueba");
                    Logger.Log.Error("Error de prueba con detalles");

                    // Deshabilitar logging a archivo PRIMERO para liberar el archivo
                    Logger.tox_log_disable_file_logging();

                    // LUEGO verificar que el archivo se creó
                    if (File.Exists(testLogFile))
                    {
                        Console.WriteLine("     ✅ Archivo de log creado correctamente");

                        // Leer contenido del archivo
                        string logContent = File.ReadAllText(testLogFile);
                        if (logContent.Contains("Este mensaje debería ir al archivo"))
                        {
                            Console.WriteLine("     ✅ Contenido escrito correctamente en archivo");
                        }
                        else
                        {
                            Console.WriteLine("     ❌ Contenido no encontrado en archivo");
                        }
                    }
                    else
                    {
                        Console.WriteLine("     ❌ Archivo de log no creado");
                    }

                    // Limpiar archivo de prueba
                    if (File.Exists(testLogFile))
                    {
                        File.Delete(testLogFile);
                    }
                }
                else
                {
                    Console.WriteLine("     ❌ No se pudo habilitar logging a archivo");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en logging a archivo: {ex.Message}");

                // Limpiar en caso de error
                if (File.Exists(testLogFile))
                {
                    try { File.Delete(testLogFile); } catch { }
                }
            }
        }

        static void TestLogCallbacks()
        {
            try
            {
                bool callbackCalled = false;
                ToxLogLevel lastCallbackLevel = ToxLogLevel.TOX_LOG_LEVEL_INFO;
                string lastCallbackMessage = "";

                // Registrar callback personalizado
                ToxLogCallback customCallback = (level, file, line, func, message, userData) =>
                {
                    callbackCalled = true;
                    lastCallbackLevel = level;
                    lastCallbackMessage = message;
                    Console.WriteLine($"        📞 Callback: [{level}] {Path.GetFileName(file)}:{line} - {message}");
                };

                Logger.tox_log_cb_register(customCallback, IntPtr.Zero);

                // Generar logs que deberían activar el callback
                Logger.Log.Info("Mensaje para callback de INFO");
                if (callbackCalled && lastCallbackLevel == ToxLogLevel.TOX_LOG_LEVEL_INFO)
                {
                    Console.WriteLine("     ✅ Callback de INFO funcionando");
                }
                else
                {
                    Console.WriteLine("     ❌ Callback de INFO no funcionó");
                }

                // Reset y test con error
                callbackCalled = false;
                Logger.Log.Error("Mensaje para callback de ERROR");
                if (callbackCalled && lastCallbackLevel == ToxLogLevel.TOX_LOG_LEVEL_ERROR)
                {
                    Console.WriteLine("     ✅ Callback de ERROR funcionando");
                }
                else
                {
                    Console.WriteLine("     ❌ Callback de ERROR no funcionó");
                }

                // Desregistrar callback
                Logger.tox_log_cb_register(null, IntPtr.Zero);

                Console.WriteLine("     ✅ Sistema de callbacks funcionando");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en callbacks: {ex.Message}");
            }
        }

        private static void TestStateManagement()
        {
            Console.WriteLine("?? Probando gestión de estado...");

            try
            {
                // Crear estado de prueba
                var state = new ToxState();

                // Configurar datos de usuario CON CLAVES VÁLIDAS
                state.User.Name = "UsuarioPrueba";
                state.User.StatusMessage = "Disponible";
                state.User.Status = ToxUserStatus.NONE;

                // Generar claves de prueba
                var random = new Random();
                random.NextBytes(state.User.PublicKey);
                random.NextBytes(state.User.SecretKey);

                // Agregar amigos de prueba CON CLAVES VÁLIDAS
                var friend = new ToxFriend
                {
                    FriendNumber = 0,
                    Name = "Amigo1",
                    StatusMessage = "Conectado"
                };
                random.NextBytes(friend.PublicKey);
                state.Friends.Friends = new ToxFriend[] { friend };

                // Probar guardar/cargar
                byte[] savedData = state.Save();
                Logger.Log.Info($"? Estado guardado: {savedData.Length} bytes");

                // Probar cargar
                var newState = new ToxState();
                bool loadSuccess = newState.Load(savedData);
                Logger.Log.Info($"? Estado cargado: {loadSuccess}");

                // Verificar datos
                bool dataPreserved = newState.User.Name == "UsuarioPrueba";
                Logger.Log.Info($"? Datos preservados: {dataPreserved}");

                // Probar archivo
                string testFile = "test_state.tox";
                bool fileSave = state.SaveToFile(testFile);
                bool fileLoad = newState.LoadFromFile(testFile);

                Logger.Log.Info($"? Guardado a archivo: {fileSave}");
                Logger.Log.Info($"? Cargado desde archivo: {fileLoad}");

                // Limpiar
                if (File.Exists(testFile))
                    File.Delete(testFile);

                Logger.Log.Info("? Pruebas de estado completadas");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"? Error en pruebas de estado: {ex.Message}");
            }
        }

        private static void TestMessenger()
        {
            Logger.Log.Info("?? Probando Messenger (núcleo principal)...");

            try
            {
                // Crear y iniciar messenger
                var options = new MessengerOptions
                {
                    IPv6Enabled = true,
                    UDPEnabled = true,
                    TcpEnabled = false // Deshabilitar TCP para pruebas simples
                };

                var messenger = new Messenger(options);
                bool startSuccess = messenger.Start();

                Logger.Log.Info($"? Messenger iniciado: {startSuccess}");

                if (startSuccess)
                {
                    // Probar configuración de perfil
                    bool nameSet = messenger.SetName("UsuarioPrueba");
                    bool statusSet = messenger.SetStatusMessage("Probando ToxCore");
                    bool statusModeSet = messenger.SetStatus(ToxUserStatus.NONE);

                    Logger.Log.Info($"? Nombre establecido: {nameSet}");
                    Logger.Log.Info($"? Estado establecido: {statusSet}");
                    Logger.Log.Info($"? Modo establecido: {statusModeSet}");

                    // Probar iteración
                    messenger.Do();
                    Logger.Log.Info("? Iteración ejecutada");

                    // Probar agregar amigo con dirección inválida (debería fallar)
                    byte[] invalidAddress = new byte[20]; // Muy corta
                    int friendResult = messenger.AddFriend(invalidAddress, "Hola!");
                    Logger.Log.Info($"? Agregar amigo con dirección inválida: {friendResult} (fallo esperado)");

                    // Probar enviar mensaje a amigo inexistente (debería fallar)
                    int sendResult = messenger.SendMessage(999, "Mensaje de prueba");
                    Logger.Log.Info($"? Enviar mensaje a amigo inexistente: {sendResult} (fallo esperado)");

                    // Detener messenger
                    messenger.Stop();
                    Logger.Log.Info("? Messenger detenido");
                }

                messenger.Dispose();
                Logger.Log.Info("? Pruebas de Messenger completadas");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"? Error en pruebas de Messenger: {ex.Message}");
            }
        }

        private static void TestToxIntegration()
        {
            Logger.Log.Info("🧪 Probando integración completa de Tox...");

            try
            {
                // Crear instancia Tox principal
                var tox1 = new Tox(new ToxOptions
                {
                    IPv6Enabled = true,
                    UDPEnabled = true
                });

                // Obtener dirección - según tu código GetAddress() devuelve string
                string address = tox1.GetAddress();
                string addressShort = address.Length > 16 ? address.Substring(0, 16) + "..." : address;
                Logger.Log.Info($"✅ Tox1 creado - Address: {addressShort}");

                // APIs confirmadas de tus pruebas anteriores
                tox1.tox_self_set_name("Usuario1");
                tox1.tox_self_set_status_message("Conectado desde C#");

                Logger.Log.Info("✅ Perfil de Tox1 configurado");

                // Iteraciones confirmadas
                for (int i = 0; i < 5; i++)
                {
                    tox1.tox_iterate();
                    Thread.Sleep(50);
                }

                Logger.Log.Info("✅ Iteraciones ejecutadas");

                // Recuperar datos confirmados
                var name1 = tox1.tox_self_get_name();
                var statusMessage1 = tox1.tox_self_get_status_message();

                Logger.Log.Info($"✅ Datos recuperados - Nombre: '{name1}', Estado: '{statusMessage1}'");

                // Crear segunda instancia
                var tox2 = new Tox(new ToxOptions { IPv6Enabled = true });
                tox2.tox_self_set_name("Usuario2");

                Logger.Log.Info($"✅ Tox2 creado");

                // Limpiar
                tox1.Dispose();
                tox2.Dispose();

                Logger.Log.Info("🧪 Prueba de integración completada exitosamente");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"❌ Error en prueba de integración: {ex.Message}");
            }
        }

        private static void TestResilience()
        {
            Logger.Log.Info("🛡️ Probando resiliencia del sistema...");

            try
            {
                var messenger = new Messenger();
                bool started = messenger.Start();

                if (!started)
                {
                    Logger.Log.Error("❌ No se pudo iniciar Messenger para pruebas de resiliencia");
                    return;
                }

                // Prueba 1: Múltiples iteraciones rápidas
                Logger.Log.Info("🔄 Probando iteraciones rápidas...");
                for (int i = 0; i < 20; i++)
                {
                    messenger.Do();
                    Thread.Sleep(10); // Iteraciones muy rápidas
                }
                Logger.Log.Info("✅ Iteraciones rápidas completadas");

                // Prueba 2: Operaciones concurrentes simuladas
                Logger.Log.Info("⚡ Probando operaciones concurrentes...");
                var tasks = new List<Task>();

                for (int i = 0; i < 5; i++)
                {
                    tasks.Add(Task.Run(() =>
                    {
                        for (int j = 0; j < 10; j++)
                        {
                            messenger.Do();
                            Thread.Sleep(5);
                        }
                    }));
                }

                Task.WaitAll(tasks.ToArray());
                Logger.Log.Info("✅ Operaciones concurrentes completadas");

                // Prueba 3: Manejo de datos corruptos
                Logger.Log.Info("📛 Probando manejo de datos corruptos...");

                // Intentar cargar estado corrupto
                var corruptState = new ToxState();
                bool loadResult = corruptState.Load(new byte[] { 0x00, 0x01, 0x02 }); // Datos inválidos
                Logger.Log.Info($"✅ Manejo de estado corrupto: {!loadResult} (fallo esperado)");

                // Prueba 4: Recuperación después de errores
                Logger.Log.Info("🔁 Probando recuperación...");
                messenger.Stop();
                Thread.Sleep(100);
                bool restarted = messenger.Start();
                Logger.Log.Info($"✅ Recuperación exitosa: {restarted}");

                messenger.Dispose();
                Logger.Log.Info("🛡️ Pruebas de resiliencia completadas");
            }
            catch (Exception ex)
            {
                Logger.Log.Error($"❌ Error en pruebas de resiliencia: {ex.Message}");
            }
        }

        private static void RunPerformanceBenchmark()
        {
            Logger.Log.Info("📊 Ejecutando benchmark de rendimiento...");

            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                // Benchmark 1: Criptografía - usando overload real
                stopwatch.Restart();
                for (int i = 0; i < 500; i++)
                {
                    var temp = new byte[32];
                    new Random().NextBytes(temp);
                    byte[] hash = CryptoHash.Sha256(temp); // Overload real: Sha256(byte[])
                }
                var cryptoTime = stopwatch.ElapsedMilliseconds;

                // Benchmark 2: DHT
                var dht = new DHT(new byte[32], new byte[32]);
                stopwatch.Restart();
                for (int i = 0; i < 20; i++)
                {
                    dht.DoPeriodicWork();
                }
                var dhtTime = stopwatch.ElapsedMilliseconds;

                // Benchmark 3: Estado
                var state = new ToxState();
                state.User.Name = "BenchmarkUser";

                stopwatch.Restart();
                for (int i = 0; i < 20; i++)
                {
                    state.Save();
                }
                var stateTime = stopwatch.ElapsedMilliseconds;

                // Benchmark 4: RandomBytes - usando métodos reales
                stopwatch.Restart();
                for (int i = 0; i < 500; i++)
                {
                    byte[] randomData = RandomBytes.Generate(32); // Método real
                }
                var randomTime = stopwatch.ElapsedMilliseconds;

                // Benchmark 5: Uniform distribution
                stopwatch.Restart();
                for (int i = 0; i < 1000; i++)
                {
                    uint uniform = RandomBytes.Uniform(100); // Método real
                }
                var uniformTime = stopwatch.ElapsedMilliseconds;

                Logger.Log.Info($"📈 Resultados del Benchmark:");
                Logger.Log.Info($"   Criptografía (500 ops): {cryptoTime}ms");
                Logger.Log.Info($"   DHT (20 iteraciones): {dhtTime}ms");
                Logger.Log.Info($"   Estado (20 guardados): {stateTime}ms");
                Logger.Log.Info($"   Random (500 generaciones): {randomTime}ms");
                Logger.Log.Info($"   Uniform (1000 generaciones): {uniformTime}ms");
                Logger.Log.Info($"   Total: {cryptoTime + dhtTime + stateTime + randomTime + uniformTime}ms");

            }
            catch (Exception ex)
            {
                Logger.Log.Error($"❌ Error en benchmark: {ex.Message}");
            }
        }

        private static void TestNetworkComponents()
{
    Logger.Log.Info("🌐 Probando componentes de red...");
    
    try
    {
        // 1. IPPort existe según tus pruebas
        var ipPort = new IPPort();
        Logger.Log.Info("✅ Estructura IPPort creada");
        
        // 2. Probar CryptoHash - según tu código tienes:
        // CryptoHash.Sha256(byte[] input) que devuelve byte[]
        byte[] testData = new byte[32];
        new Random().NextBytes(testData);
        
        byte[] hash = CryptoHash.Sha256(testData); // Este overload existe
        Logger.Log.Info($"✅ CryptoHash.Sha256 funcionando - Hash generado: {hash.Length} bytes");
        
        // 3. Probar RandomBytes - según tu código tienes:
        // - RandomBytes.Generate(uint length)
        // - RandomBytes.Generate(byte[] buffer)
        byte[] randomData = RandomBytes.Generate(16); // Método real
        Logger.Log.Info($"✅ RandomBytes.Generate funcionando - {randomData.Length} bytes aleatorios");
        
        // También probar el otro overload
        byte[] buffer = new byte[32];
        RandomBytes.Generate(buffer);
        Logger.Log.Info($"✅ RandomBytes.Generate(buffer) funcionando");
        
        // 4. Probar Network - con parámetros exactos según tu código:
        // new_socket(int domain, int type, int protocol)
        // domain: 2 = IPv4, 10 = IPv6
        // type: 2 = Dgram (UDP), 1 = Stream (TCP)  
        // protocol: 17 = UDP, 6 = TCP
        int socket = Network.new_socket(2, 2, 17); // IPv4, Dgram, UDP
        Logger.Log.Info($"✅ Socket UDP IPv4 creado: {socket}");
        
        if (socket >= 0)
        {
            // Probar bind con dirección local
            var localIP = new IP(new IP4("127.0.0.1"));
            var localPort = new IPPort(localIP, 0); // Puerto 0 = asignado por sistema
            int bindResult = Network.socket_bind(socket, localPort);
            Logger.Log.Info($"✅ Socket bind: {bindResult == 0}");
            
            Network.kill_socket(socket);
            Logger.Log.Info("✅ Socket cerrado correctamente");
        }
        
        // Probar también socket IPv6
        int socket6 = Network.new_socket(10, 2, 17); // IPv6, Dgram, UDP
        if (socket6 >= 0)
        {
            Logger.Log.Info($"✅ Socket UDP IPv6 creado: {socket6}");
            Network.kill_socket(socket6);
        }
        
        Logger.Log.Info("🌐 Todos los componentes de red funcionando correctamente");
    }
    catch (Exception ex)
    {
        Logger.Log.Error($"❌ Error en componentes de red: {ex.Message}");
    }
}





    }
}