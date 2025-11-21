using System.Security.Cryptography;

namespace ToxCore.Core
{
    /// <summary>
    /// Estado para hash incremental (wrapper alrededor de IncrementalHash)
    /// </summary>
    public class CryptoHashSha256State : IDisposable
    {
        internal IncrementalHash IncrementalHash { get; }

        public CryptoHashSha256State()
        {
            IncrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        }

        public void Dispose()
        {
            IncrementalHash?.Dispose();
        }
    }

    /// <summary>
    /// Implementación de crypto_hash_sha256
    /// Hash SHA-256 para integridad de datos
    /// </summary>
    public static class CryptoHashSha256
    {
        public const int BYTES = 32; // 256 bits = 32 bytes
        public const int STATEBYTES = 64; // Tamaño típico del estado en implementaciones C

        /// <summary>
        /// Calcula el hash SHA-256 de los datos de entrada
        /// </summary>
        public static byte[] Hash(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));

            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(input);
            }
        }

        /// <summary>
        /// Calcula el hash SHA-256 de una porción de datos
        /// </summary>
        public static byte[] Hash(byte[] input, int offset, int count)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (offset < 0 || offset >= input.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || offset + count > input.Length)
                throw new ArgumentOutOfRangeException(nameof(count));

            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(input, offset, count);
            }
        }

        /// <summary>
        /// Crea un estado para hash incremental
        /// </summary>
        public static CryptoHashSha256State CreateIncrementalHash()
        {
            return new CryptoHashSha256State();
        }

        /// <summary>
        /// Inicializa un estado para hash incremental
        /// </summary>
        public static void Init(CryptoHashSha256State state)
        {
            // El estado ya se inicializa en el constructor
            // Esta función existe para compatibilidad con la API C
            if (state == null) throw new ArgumentNullException(nameof(state));
        }

        /// <summary>
        /// Actualiza el estado hash con nuevos datos
        /// </summary>
        public static void Update(CryptoHashSha256State state, byte[] input, int offset, int count)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (offset < 0 || offset >= input.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || offset + count > input.Length)
                throw new ArgumentOutOfRangeException(nameof(count));

            state.IncrementalHash.AppendData(input, offset, count);
        }

        /// <summary>
        /// Finaliza el hash y obtiene el resultado
        /// </summary>
        public static byte[] Final(CryptoHashSha256State state)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            return state.IncrementalHash.GetHashAndReset();
        }

        /// <summary>
        /// Versión con output pre-allocated para compatibilidad con C
        /// </summary>
        public static bool Hash(byte[] output, int outputOffset, byte[] input, int inputOffset, int inputLength)
        {
            try
            {
                byte[] hash = Hash(input, inputOffset, inputLength);
                Buffer.BlockCopy(hash, 0, output, outputOffset, BYTES);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test con vectores conocidos de SHA-256
        /// </summary>
        public static bool Test()
        {
            // Test vector 1: "abc"
            byte[] test1 = System.Text.Encoding.UTF8.GetBytes("abc");
            byte[] expected1 = new byte[] {
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
                0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
                0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
                0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
            };

            byte[] result1 = Hash(test1);
            if (!CompareByteArrays(result1, expected1))
                return false;

            // Test vector 2: Cadena vacía
            byte[] test2 = new byte[0];
            byte[] expected2 = new byte[] {
                0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
                0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
                0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
                0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
            };

            byte[] result2 = Hash(test2);
            if (!CompareByteArrays(result2, expected2))
                return false;

            // Test incremental completo
            using (var state = CreateIncrementalHash())
            {
                Init(state);
                Update(state, System.Text.Encoding.UTF8.GetBytes("Hello "), 0, 6);
                Update(state, System.Text.Encoding.UTF8.GetBytes("World"), 0, 5);
                Update(state, System.Text.Encoding.UTF8.GetBytes("!"), 0, 1);
                byte[] resultIncremental = Final(state);

                byte[] expectedFull = Hash(System.Text.Encoding.UTF8.GetBytes("Hello World!"));
                if (!CompareByteArrays(resultIncremental, expectedFull))
                    return false;
            }

            return true;
        }

        private static bool CompareByteArrays(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
    }

    /// <summary>
    /// API compatible con nombres C originales
    /// </summary>
    public static class crypto_hash_sha256_native
    {
        public const int crypto_hash_sha256_BYTES = CryptoHashSha256.BYTES;
        public const int crypto_hash_sha256_STATEBYTES = CryptoHashSha256.STATEBYTES;

        public static int crypto_hash_sha256(byte[] @out, byte[] @in, ulong inlen)
        {
            try
            {
                byte[] inputSegment = new byte[inlen];
                Buffer.BlockCopy(@in, 0, inputSegment, 0, (int)inlen);

                byte[] hash = CryptoHashSha256.Hash(inputSegment);
                Buffer.BlockCopy(hash, 0, @out, 0, CryptoHashSha256.BYTES);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_hash_sha256_init(IntPtr statePtr)
        {
            try
            {
                // En C, state es un buffer de bytes, en C# usamos un objeto managed
                // Para compatibilidad, almacenamos el estado managed en un GCHandle
                var state = new CryptoHashSha256State();
                var handle = System.Runtime.InteropServices.GCHandle.Alloc(state);
                System.Runtime.InteropServices.Marshal.WriteIntPtr(statePtr,
                    System.Runtime.InteropServices.GCHandle.ToIntPtr(handle));
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_hash_sha256_update(IntPtr statePtr, byte[] @in, ulong inlen)
        {
            try
            {
                var handle = System.Runtime.InteropServices.GCHandle.FromIntPtr(statePtr);
                var state = (CryptoHashSha256State)handle.Target;
                CryptoHashSha256.Update(state, @in, 0, (int)inlen);
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        public static int crypto_hash_sha256_final(IntPtr statePtr, byte[] @out)
        {
            try
            {
                var handle = System.Runtime.InteropServices.GCHandle.FromIntPtr(statePtr);
                var state = (CryptoHashSha256State)handle.Target;

                byte[] hash = CryptoHashSha256.Final(state);
                Buffer.BlockCopy(hash, 0, @out, 0, CryptoHashSha256.BYTES);

                // Liberar el handle
                state.Dispose();
                handle.Free();

                return 0;
            }
            catch
            {
                return -1;
            }
        }
    }
}