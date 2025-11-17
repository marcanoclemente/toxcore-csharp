using System;
using System.Security.Cryptography;

namespace ToxCore.Core
{
    /// <summary>
    /// Implementación de randombytes
    /// Generación segura de bytes aleatorios para crypto
    /// </summary>
    public static class RandomBytes
    {
        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        private static readonly object rngLock = new object();

        /// <summary>
        /// Genera bytes aleatorios criptográficamente seguros
        /// </summary>
        public static byte[] Generate(uint length)
        {
            if (length == 0)
                return Array.Empty<byte>();

            byte[] buffer = new byte[length];
            lock (rngLock)
            {
                rng.GetBytes(buffer);
            }
            return buffer;
        }

        /// <summary>
        /// Llena un buffer existente con bytes aleatorios
        /// </summary>
        public static void Generate(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (buffer.Length == 0) return;

            lock (rngLock)
            {
                rng.GetBytes(buffer);
            }
        }

        /// <summary>
        /// Llena una porción de un buffer con bytes aleatorios
        /// </summary>
        public static void Generate(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset >= buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0) return;

            // Crear un buffer temporal y copiar
            byte[] temp = new byte[count];
            lock (rngLock)
            {
                rng.GetBytes(temp);
            }
            Buffer.BlockCopy(temp, 0, buffer, offset, count);
        }

        /// <summary>
        /// Genera un número aleatorio en el rango [0, upperBound)
        /// </summary>
        /// <summary>
        /// Genera un número aleatorio en el rango [0, upperBound) sin bias
        /// </summary>
        public static uint Uniform(uint upperBound)
        {
            if (upperBound == 0)
                throw new ArgumentOutOfRangeException(nameof(upperBound), "Upper bound must be greater than 0");

            if (upperBound == 1)
                return 0;

            // Para upperBound potencias de 2, podemos usar máscara simple
            if ((upperBound & (upperBound - 1)) == 0) // Es potencia de 2
            {
                byte[] bytes = Generate(4);
                uint valueP = BitConverter.ToUInt32(bytes, 0);
                return valueP & (upperBound - 1);
            }

            // Para valores no potencia de 2, usar método de rechazo
            uint min = uint.MaxValue - (uint.MaxValue % upperBound);
            uint value;

            // Límite de intentos para evitar bucles infinitos
            int maxAttempts = 100;
            int attempts = 0;

            do
            {
                byte[] bytes = Generate(4);
                value = BitConverter.ToUInt32(bytes, 0);
                attempts++;

                if (attempts > maxAttempts)
                {
                    // Fallback: usar módulo simple (puede tener bias pequeño pero evita bucle infinito)
                    return value % upperBound;
                }
            } while (value >= min);

            return value % upperBound;
        }

        /// <summary>
        /// Genera un nonce aleatorio de 24 bytes (para crypto_box)
        /// </summary>
        public static byte[] GenerateNonce()
        {
            return Generate(24);
        }

        /// <summary>
        /// Genera una clave aleatoria de 32 bytes
        /// </summary>
        public static byte[] GenerateKey()
        {
            return Generate(32);
        }

        /// <summary>
        /// Test de generación de bytes aleatorios
        /// </summary>
        public static bool Test()
        {
            try
            {
                Console.WriteLine("     Ejecutando tests de RandomBytes...");

                // Test 1: Generación básica
                byte[] random1 = Generate(32);
                if (random1.Length != 32)
                {
                    Console.WriteLine("     ❌ Test 1 falló: Longitud incorrecta");
                    return false;
                }

                // Verificar que no es todo cero (muy improbable)
                bool allZero = true;
                foreach (byte b in random1)
                {
                    if (b != 0)
                    {
                        allZero = false;
                        break;
                    }
                }
                if (allZero)
                {
                    Console.WriteLine("     ❌ Test 1 falló: Output todo cero");
                    return false;
                }
                Console.WriteLine("     ✅ Test 1 - Generación básica: PASÓ");

                // Test 2: Generación a buffer existente
                byte[] buffer = new byte[64];
                Generate(buffer);

                allZero = true;
                foreach (byte b in buffer)
                {
                    if (b != 0)
                    {
                        allZero = false;
                        break;
                    }
                }
                if (allZero)
                {
                    Console.WriteLine("     ❌ Test 2 falló: Buffer todo cero");
                    return false;
                }
                Console.WriteLine("     ✅ Test 2 - Generación a buffer: PASÓ");

                // Test 3: Generación con offset
                byte[] bufferWithOffset = new byte[100];
                Array.Fill(bufferWithOffset, (byte)0xFF); // Llenar con 0xFF
                Generate(bufferWithOffset, 10, 50);

                // Verificar que la zona modificada no es todo 0xFF
                bool allFF = true;
                for (int i = 10; i < 60; i++)
                {
                    if (bufferWithOffset[i] != 0xFF)
                    {
                        allFF = false;
                        break;
                    }
                }
                if (allFF)
                {
                    Console.WriteLine("     ❌ Test 3 falló: Zona con offset no modificada");
                    return false;
                }

                // Verificar que las zonas fuera del offset no se modificaron
                for (int i = 0; i < 10; i++)
                {
                    if (bufferWithOffset[i] != 0xFF)
                    {
                        Console.WriteLine("     ❌ Test 3 falló: Zona antes del offset modificada");
                        return false;
                    }
                }
                for (int i = 60; i < 100; i++)
                {
                    if (bufferWithOffset[i] != 0xFF)
                    {
                        Console.WriteLine("     ❌ Test 3 falló: Zona después del offset modificada");
                        return false;
                    }
                }
                Console.WriteLine("     ✅ Test 3 - Generación con offset: PASÓ");

                // Test 4: Uniform distribution (test estadístico básico)
                uint upperBound = 100;
                int[] counts = new int[upperBound];
                int samples = 10000;

                for (int i = 0; i < samples; i++)
                {
                    uint value = Uniform(upperBound);
                    if (value >= upperBound)
                    {
                        Console.WriteLine("     ❌ Test 4 falló: Valor fuera de rango");
                        return false;
                    }
                    counts[value]++;
                }

                // Verificar distribución básica (cada valor debería aparecer al menos una vez)
                for (int i = 0; i < upperBound; i++)
                {
                    if (counts[i] == 0)
                    {
                        Console.WriteLine($"     ❌ Test 4 falló: Valor {i} nunca generado");
                        return false;
                    }
                }
                Console.WriteLine("     ✅ Test 4 - Distribución uniforme: PASÓ");

                // Test 5: Generaciones consecutivas producen resultados diferentes
                byte[] random2 = Generate(32);
                bool sameAsFirst = true;
                for (int i = 0; i < 32; i++)
                {
                    if (random1[i] != random2[i])
                    {
                        sameAsFirst = false;
                        break;
                    }
                }
                if (sameAsFirst)
                {
                    Console.WriteLine("     ❌ Test 5 falló: Dos generaciones iguales (muy improbable)");
                    return false;
                }
                Console.WriteLine("     ✅ Test 5 - Generaciones diferentes: PASÓ");

                // Test 6: Funciones de conveniencia
                byte[] nonce = GenerateNonce();
                if (nonce.Length != 24)
                {
                    Console.WriteLine("     ❌ Test 6 falló: Nonce tamaño incorrecto");
                    return false;
                }

                byte[] key = GenerateKey();
                if (key.Length != 32)
                {
                    Console.WriteLine("     ❌ Test 6 falló: Key tamaño incorrecto");
                    return false;
                }
                Console.WriteLine("     ✅ Test 6 - Funciones de conveniencia: PASÓ");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     ❌ Error en test: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Test de rendimiento y entropía
        /// </summary>
        public static void TestPerformance()
        {
            Console.WriteLine("   Probando rendimiento y entropía...");

            var sw = System.Diagnostics.Stopwatch.StartNew();

            // Generar 1MB de datos aleatorios
            byte[] largeData = Generate(1024 * 1024);
            long timeLarge = sw.ElapsedTicks;

            sw.Restart();

            // Generar muchos chunks pequeños
            for (int i = 0; i < 1000; i++)
            {
                Generate(100);
            }
            long timeSmall = sw.ElapsedTicks;

            Console.WriteLine($"     1MB de datos: {timeLarge} ticks");
            Console.WriteLine($"     1000 chunks de 100 bytes: {timeSmall} ticks");

            // Test básico de entropía (verificar que los bytes están distribuidos)
            int[] byteCounts = new int[256];
            foreach (byte b in largeData)
            {
                byteCounts[b]++;
            }

            // Calcular chi-cuadrado básico (simplificado)
            double expected = largeData.Length / 256.0;
            double chiSquare = 0;
            for (int i = 0; i < 256; i++)
            {
                double diff = byteCounts[i] - expected;
                chiSquare += (diff * diff) / expected;
            }

            // Chi-cuadrado para 255 grados de libertad, p=0.05 es ~293
            bool goodDistribution = chiSquare < 350; // Umbral conservador
            Console.WriteLine($"     Distribución chi-cuadrado: {chiSquare:F2}");
            Console.WriteLine($"     Buena distribución: {(goodDistribution ? "✅" : "⚠️")}");
        }
    }

    /// <summary>
    /// API compatible con nombres C originales
    /// </summary>
    public static class randombytes_native
    {
        public static void randombytes(byte[] buf, ulong len)
        {
            if (buf == null) throw new ArgumentNullException(nameof(buf));
            RandomBytes.Generate(buf, 0, (int)len);
        }

        public static uint randombytes_uniform(uint upperBound)
        {
            return RandomBytes.Uniform(upperBound);
        }

        public static void randombytes_buf(byte[] buf, ulong len)
        {
            randombytes(buf, len);
        }

        public static void randombytes_buf_deterministic(byte[] buf, ulong len, byte[] seed)
        {
            // Para compatibilidad, pero en producción usamos RNG criptográfico
            // Esta función sería para tests determinísticos
            throw new NotImplementedException("Deterministic randombytes not implemented for production use");
        }
    }
}