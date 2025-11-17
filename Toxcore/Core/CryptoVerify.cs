using System;
using System.Security.Cryptography;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de crypto_verify
    /// Comparación constante en tiempo para evitar timing attacks
    /// </summary>
    public static class CryptoVerify
    {
        public const int BYTES = 32; // Tamaño estándar para comparaciones

        /// <summary>
        /// Comparación constante en tiempo de dos arrays de bytes
        /// </summary>
        public static bool Verify(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));
            if (a.Length != b.Length)
                throw new ArgumentException("Arrays must have the same length");

            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Comparación constante en tiempo de dos arrays de bytes con longitud específica
        /// </summary>
        public static bool Verify(byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));
            if (aOffset < 0 || aOffset >= a.Length)
                throw new ArgumentOutOfRangeException(nameof(aOffset));
            if (bOffset < 0 || bOffset >= b.Length)
                throw new ArgumentOutOfRangeException(nameof(bOffset));
            if (length < 0 || aOffset + length > a.Length || bOffset + length > b.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            // Implementación manual de comparación constante en tiempo
            int result = 0;
            for (int i = 0; i < length; i++)
            {
                result |= a[aOffset + i] ^ b[bOffset + i];
            }
            return result == 0;
        }

        /// <summary>
        /// Comparación constante en tiempo para arrays de 16 bytes
        /// </summary>
        public static bool Verify16(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));
            if (a.Length != 16 || b.Length != 16)
                throw new ArgumentException("Arrays must be 16 bytes long");

            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Comparación constante en tiempo para arrays de 32 bytes
        /// </summary>
        public static bool Verify32(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));
            if (a.Length != 32 || b.Length != 32)
                throw new ArgumentException("Arrays must be 32 bytes long");

            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Comparación constante en tiempo para arrays de 64 bytes
        /// </summary>
        public static bool Verify64(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));
            if (a.Length != 64 || b.Length != 64)
                throw new ArgumentException("Arrays must be 64 bytes long");

            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Versión que retorna int para compatibilidad con C (0 = iguales, -1 = diferentes)
        /// </summary>
        public static int VerifyReturn(byte[] a, byte[] b)
        {
            try
            {
                return Verify(a, b) ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// Test de comparación constante en tiempo CORREGIDO
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de CryptoVerify...");

                // Test 1: Arrays iguales
                byte[] a1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
                byte[] b1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

                if (!Verify(a1, b1))
                {
                    Console.WriteLine("     ❌ Test 1 falló: Arrays iguales no coincidieron");
                    return false;
                }
                Console.WriteLine("     ✅ Test 1 - Arrays iguales: PASÓ");

                // Test 2: Arrays diferentes
                byte[] a2 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
                byte[] b2 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06 };

                if (Verify(a2, b2))
                {
                    Console.WriteLine("     ❌ Test 2 falló: Arrays diferentes coincidieron");
                    return false;
                }
                Console.WriteLine("     ✅ Test 2 - Arrays diferentes: PASÓ");

                // Test 3: Arrays de diferentes longitudes (debería lanzar excepción)
                try
                {
                    byte[] a3 = new byte[5];
                    byte[] b3 = new byte[6];
                    Verify(a3, b3);
                    Console.WriteLine("     ❌ Test 3 falló: No lanzó excepción por longitudes diferentes");
                    return false;
                }
                catch (ArgumentException)
                {
                    // Esperado
                    Console.WriteLine("     ✅ Test 3 - Longitudes diferentes: PASÓ");
                }

                // Test 4: Verify16
                byte[] a4 = new byte[16];
                byte[] b4 = new byte[16];
                for (int i = 0; i < 16; i++)
                {
                    a4[i] = (byte)0x42;
                    b4[i] = (byte)0x42;
                }

                if (!Verify16(a4, b4))
                {
                    Console.WriteLine("     ❌ Test 4 falló: Verify16 con arrays iguales");
                    return false;
                }
                Console.WriteLine("     ✅ Test 4 - Verify16: PASÓ");

                // Test 5: Verify32
                byte[] a5 = new byte[32];
                byte[] b5 = new byte[32];
                for (int i = 0; i < 32; i++)
                {
                    a5[i] = (byte)0x99;
                    b5[i] = (byte)0x99;
                }

                if (!Verify32(a5, b5))
                {
                    Console.WriteLine("     ❌ Test 5 falló: Verify32 con arrays iguales");
                    return false;
                }
                Console.WriteLine("     ✅ Test 5 - Verify32: PASÓ");

                // Test 6: Verify64
                byte[] a6 = new byte[64];
                byte[] b6 = new byte[64];
                for (int i = 0; i < 64; i++)
                {
                    a6[i] = (byte)0xFF;
                    b6[i] = (byte)0xFF;
                }

                if (!Verify64(a6, b6))
                {
                    Console.WriteLine("     ❌ Test 6 falló: Verify64 con arrays iguales");
                    return false;
                }
                Console.WriteLine("     ✅ Test 6 - Verify64: PASÓ");

                // Test 7: Comparación con offset
                byte[] a7 = new byte[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };
                byte[] b7 = new byte[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };

                if (!Verify(a7, 2, b7, 2, 5))
                {
                    Console.WriteLine("     ❌ Test 7 falló: Comparación con offset iguales");
                    return false;
                }
                Console.WriteLine("     ✅ Test 7 - Comparación con offset: PASÓ");

                // Test 8: Comparación con offset diferente
                byte[] a8 = new byte[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00 };
                byte[] b8 = new byte[10] { 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x00, 0x00, 0x00 };

                if (Verify(a8, 2, b8, 2, 5))
                {
                    Console.WriteLine("     ❌ Test 8 falló: Comparación con offset diferentes");
                    return false;
                }
                Console.WriteLine("     ✅ Test 8 - Comparación con offset diferente: PASÓ");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test: {ex.Message}");
                Console.WriteLine($"     Stack trace: {ex.StackTrace}");
                return false;
            }
        }

        /// <summary>
        /// Test de timing (verificación visual de que el tiempo es constante)
        /// </summary>
        public static void TestTiming()
        {
            Console.WriteLine("   Probando características de timing...");

            // Crear arrays grandes para hacer la prueba más evidente
            byte[] largeArray1 = new byte[1024];
            byte[] largeArray2 = new byte[1024];
            byte[] largeArray3 = new byte[1024];

            Array.Fill(largeArray1, (byte)0x42);
            Array.Fill(largeArray2, (byte)0x42);
            Array.Fill(largeArray3, (byte)0x43); // Diferente en el primer byte

            var sw = System.Diagnostics.Stopwatch.StartNew();

            // Comparación de arrays iguales (debería recorrer todo el array)
            bool result1 = Verify(largeArray1, largeArray2);
            long time1 = sw.ElapsedTicks;

            sw.Restart();

            // Comparación de arrays diferentes en el primer byte (debería recorrer todo el array también)
            bool result2 = Verify(largeArray1, largeArray3);
            long time2 = sw.ElapsedTicks;

            // Los tiempos deberían ser similares (comparación constante en tiempo)
            double timeDifference = Math.Abs(time1 - time2);
            double timeRatio = (double)Math.Max(time1, time2) / Math.Min(time1, time2);

            Console.WriteLine($"     Tiempo arrays iguales: {time1} ticks");
            Console.WriteLine($"     Tiempo arrays diferentes: {time2} ticks");
            Console.WriteLine($"     Diferencia: {timeDifference} ticks");
            Console.WriteLine($"     Ratio: {timeRatio:F2}");
            Console.WriteLine($"     Timing constante: {(timeRatio < 2.0 ? "✅" : "⚠️")}"); // Ratio < 2.0 es aceptable
        }
    }

    /// <summary>
    /// API compatible con nombres C originales
    /// </summary>
    public static class crypto_verify_native
    {
        public const int crypto_verify_BYTES = CryptoVerify.BYTES;

        public static int crypto_verify(byte[] x, byte[] y)
        {
            try
            {
                return CryptoVerify.VerifyReturn(x, y);
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_verify_16(byte[] x, byte[] y)
        {
            try
            {
                return CryptoVerify.Verify16(x, y) ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_verify_32(byte[] x, byte[] y)
        {
            try
            {
                return CryptoVerify.Verify32(x, y) ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_verify_64(byte[] x, byte[] y)
        {
            try
            {
                return CryptoVerify.Verify64(x, y) ? 0 : -1;
            }
            catch
            {
                return -1;
            }
        }
    }
}