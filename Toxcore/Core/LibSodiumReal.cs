using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ToxCore.Core
{
    internal static class LibSodiumReal
    {
        private const string LIBSODIUM = "libsodium";

        // crypto_pwhash_scryptsalsa208sha256
        [DllImport(LIBSODIUM, EntryPoint = "crypto_pwhash_scryptsalsa208sha256")]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(
            byte[] @out, ulong outlen,
            byte[] passwd, ulong passwdlen,
            byte[] salt,
            ulong opslimit, nuint memlimit);

        // crypto_pwhash_scryptsalsa208sha256_str_verify
        [DllImport(LIBSODIUM, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str_verify")]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(
            byte[] str, byte[] passwd, ulong passwdlen);

        // crypto_pwhash_scryptsalsa208sha256_str
        [DllImport(LIBSODIUM, EntryPoint = "crypto_pwhash_scryptsalsa208sha256_str")]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(
            byte[] str, byte[] passwd, ulong passwdlen,
            ulong opslimit, nuint memlimit);
    }
}
