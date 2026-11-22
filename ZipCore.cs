// ZipCore.cs —— ZipCrackerN 核心：ZipCrypto / WinZip AES 密码校验与暴力破解，支持 Zip64
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace ZipCrackerN
{
    public sealed class ZipTarget
    {
        public enum ArchiveFormat { Zip, Rar, SevenZip }

        public string Path;
        public string EntryName = "";
        public ArchiveFormat Format = ArchiveFormat.Zip;
        public bool External { get { return Format != ArchiveFormat.Zip; } }
        public bool NeedsFullVerify { get { return !External; } }
        public byte[] EncHeader = new byte[0];     // ZipCrypto 12 字节加密头
        public byte[] Salt = new byte[0];           // AES salt
        public byte[] PwdVerifier = new byte[0];    // AES 2 字节密码校验值
        public byte[] AuthCode = new byte[0];       // AES 10 字节认证码
        public ushort Flags;
        public ushort Method;                       // 实际压缩方式：0=存储，8=deflate
        public ushort ModTime;
        public uint Crc;
        public long CompSize;
        public long UncompSize;
        public long DataOffset;
        public long DataSize;
        public bool Encrypted;
        public bool Aes;
        public bool IsZip64;
        public int AesVersion;
        public int AesStrength;
        public int AesKeyLen;
        public int AesSaltLen;
        public string Unsupported = "";

        static readonly uint[] CrcTable = BuildTable();

        static uint[] BuildTable()
        {
            uint[] t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int j = 0; j < 8; j++)
                {
                    if ((c & 1u) != 0) c = 0xEDB88320u ^ (c >> 1);
                    else c = c >> 1;
                }
                t[i] = c;
            }
            return t;
        }

        static uint CrcByte(uint crc, uint b)
        {
            return ((crc >> 8) & 0xFFFFFFu) ^ CrcTable[(crc ^ b) & 0xFFu];
        }

        static uint Crc32(byte[] data, int offset, int count)
        {
            uint c = 0xFFFFFFFFu;
            for (int i = offset; i < offset + count; i++)
                c = CrcTable[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        static bool ReadExact(Stream s, byte[] buf, int offset, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = s.Read(buf, offset + got, count - got);
                if (n <= 0) return false;
                got += n;
            }
            return true;
        }

        static ushort U16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }
        static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }

        public ZipTarget(string path)
        {
            Path = path;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] head = new byte[8];
                    int n = fs.Read(head, 0, head.Length);
                    if (n >= 7 && head[0] == (byte)'R' && head[1] == (byte)'a' && head[2] == (byte)'r' &&
                        head[3] == (byte)'!' && head[4] == 0x1A && head[5] == 0x07)
                    {
                        Format = ArchiveFormat.Rar;
                        InitExternal();
                        return;
                    }
                    if (n >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC &&
                        head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C)
                    {
                        Format = ArchiveFormat.SevenZip;
                        InitExternal();
                        return;
                    }
                    fs.Seek(0, SeekOrigin.Begin);
                    Parse(fs);
                }
            }
            catch (Exception ex)
            {
                Unsupported = "无法打开压缩包：" + ex.Message;
            }
        }

        static string _sevenZipPath;
        static bool _sevenZipSearched;
        static readonly object SevenZipGate = new object();

        static string FindSevenZip()
        {
            lock (SevenZipGate)
            {
                if (_sevenZipSearched) return _sevenZipPath;
                _sevenZipSearched = true;
                // 优先使用程序目录内置的 7-Zip
                string baseDir = "";
                try { baseDir = System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName); }
                catch { }
                if (!string.IsNullOrEmpty(baseDir))
                {
                    string[] bundled;
                    if (IntPtr.Size == 4)
                    {
                        // 32 位进程优先找 32 位组件，避免运行 64 位 7z.exe 失败
                        bundled = new string[]
                        {
                            System.IO.Path.Combine(baseDir, "7z", "7z.x86.exe"),
                            System.IO.Path.Combine(baseDir, "7z", "x86", "7z.exe"),
                            System.IO.Path.Combine(baseDir, "7z", "7z32.exe"),
                            System.IO.Path.Combine(baseDir, "7z", "7z.exe"),
                            System.IO.Path.Combine(baseDir, "7z.exe"),
                            System.IO.Path.Combine(baseDir, "tools", "7z.exe")
                        };
                    }
                    else
                    {
                        bundled = new string[]
                        {
                            System.IO.Path.Combine(baseDir, "7z", "7z.exe"),
                            System.IO.Path.Combine(baseDir, "7z.exe"),
                            System.IO.Path.Combine(baseDir, "tools", "7z.exe")
                        };
                    }
                    for (int i = 0; i < bundled.Length; i++)
                    {
                        if (File.Exists(bundled[i])) { _sevenZipPath = bundled[i]; return _sevenZipPath; }
                    }
                }
                string[] fixedPaths = new string[]
                {
                    @"C:\Program Files\7-Zip\7z.exe",
                    @"C:\Program Files (x86)\7-Zip\7z.exe"
                };
                for (int i = 0; i < fixedPaths.Length; i++)
                {
                    if (File.Exists(fixedPaths[i])) { _sevenZipPath = fixedPaths[i]; return _sevenZipPath; }
                }
                string pathEnv = Environment.GetEnvironmentVariable("PATH");
                if (!string.IsNullOrEmpty(pathEnv))
                {
                    string[] dirs = pathEnv.Split(';');
                    for (int i = 0; i < dirs.Length; i++)
                    {
                        try
                        {
                            string p = System.IO.Path.Combine(dirs[i].Trim(), "7z.exe");
                            if (File.Exists(p)) { _sevenZipPath = p; return _sevenZipPath; }
                        }
                        catch { }
                    }
                }
                return null;
            }
        }

        void InitExternal()
        {
            if (FindSevenZip() == null)
            {
                Unsupported = "未找到 7z.exe，无法处理 RAR / 7z 压缩包";
                return;
            }
            // 用错误密码测试一次：返回 0 说明压缩包没有加密
            if (ExternalTest("__ZipCrackerN_Wrong_Password__"))
            {
                Unsupported = "该压缩包未加密";
                return;
            }
            Encrypted = true;
        }

        bool ExternalTest(string pwd)
        {
            string tool = FindSevenZip();
            if (tool == null) return false;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(tool);
                psi.Arguments = "t -p" + pwd + " -y \"" + Path.Replace("\"", "") + "\"";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process p = Process.Start(psi))
                {
                    // 同时异步排空 stdout/stderr，避免任一管道写满导致 7z 阻塞、程序死锁
                    p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { };
                    p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(120000))
                    {
                        try { p.Kill(); } catch { }
                        return false;
                    }
                    try { p.WaitForExit(2000); } catch { } // 等待异步读取收尾
                    return p.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        void Parse(FileStream fs)
        {
            long fileSize = fs.Length;
            if (fileSize < 22) { Unsupported = "文件过小，不是有效的 zip 包"; return; }

            int scan = (int)Math.Min(fileSize, 22L + 65535L);
            byte[] tail = new byte[scan];
            fs.Seek(fileSize - scan, SeekOrigin.Begin);
            if (!ReadExact(fs, tail, 0, scan)) { Unsupported = "文件读取失败"; return; }

            int eocd = -1;
            int fallback = -1;
            for (int i = scan - 22; i >= 0; i--)
            {
                if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 0x05 && tail[i + 3] == 0x06)
                {
                    int commentLen = U16(tail, i + 20);
                    if (i + 22 + commentLen == scan) { eocd = i; break; }
                    if (fallback < 0) fallback = i;
                }
            }
            if (eocd < 0) eocd = fallback;
            if (eocd < 0) { Unsupported = "未找到 zip 目录，可能不是 zip 文件"; return; }

            long eocdAbs = fileSize - scan + eocd;
            ushort entriesDisk = U16(tail, eocd + 8);
            ushort entriesTotal = U16(tail, eocd + 10);
            uint cdSize32 = U32(tail, eocd + 12);
            uint cdOffset32 = U32(tail, eocd + 16);
            long cdSize = cdSize32;
            long cdOffset = cdOffset32;
            bool zip64 = false;

            bool mustZip64 = (cdOffset32 == 0xFFFFFFFFu || cdSize32 == 0xFFFFFFFFu);
            if (mustZip64 || entriesDisk == 0xFFFF || entriesTotal == 0xFFFF)
            {
                bool gotZip64 = false;
                long locAbs = eocdAbs - 20;
                if (locAbs >= 0)
                {
                    fs.Seek(locAbs, SeekOrigin.Begin);
                    byte[] loc = new byte[20];
                    if (ReadExact(fs, loc, 0, 20) &&
                        loc[0] == 0x50 && loc[1] == 0x4B && loc[2] == 0x06 && loc[3] == 0x07)
                    {
                        long z64Off = BitConverter.ToInt64(loc, 8);
                        if (z64Off >= 0 && z64Off + 56 <= fileSize)
                        {
                            fs.Seek(z64Off, SeekOrigin.Begin);
                            byte[] z = new byte[56];
                            if (ReadExact(fs, z, 0, 56) &&
                                z[0] == 0x50 && z[1] == 0x4B && z[2] == 0x06 && z[3] == 0x06)
                            {
                                cdSize = BitConverter.ToInt64(z, 40);
                                cdOffset = BitConverter.ToInt64(z, 48);
                                zip64 = true;
                                gotZip64 = true;
                            }
                        }
                    }
                }
                if (!gotZip64 && mustZip64) { Unsupported = "Zip64 目录损坏"; return; }
            }

            if (cdOffset < 0 || cdSize < 0 || cdOffset > fileSize) { Unsupported = "中央目录偏移无效"; return; }
            long cdEnd = cdOffset + cdSize;
            if (cdEnd < cdOffset || cdEnd > fileSize) cdEnd = fileSize;

            fs.Seek(cdOffset, SeekOrigin.Begin);
            bool foundEnc = false;
            byte[] sig = new byte[4];
            byte[] cd = new byte[42];

            while (fs.Position + 4 <= cdEnd &&
                   ReadExact(fs, sig, 0, 4) &&
                   sig[0] == 0x50 && sig[1] == 0x4B && sig[2] == 0x01 && sig[3] == 0x02)
            {
                if (!ReadExact(fs, cd, 0, 42)) { Unsupported = "中央目录解析失败"; return; }

                ushort flags = U16(cd, 4);
                ushort method = U16(cd, 6);
                ushort modTime = U16(cd, 8);
                uint crc = U32(cd, 12);
                uint comp32 = U32(cd, 16);
                uint uncomp32 = U32(cd, 20);
                ushort nameLen = U16(cd, 24);
                ushort extraLen = U16(cd, 26);
                ushort commentLen = U16(cd, 28);
                uint local32 = U32(cd, 38);

                byte[] name = new byte[nameLen];
                if (nameLen > 0 && !ReadExact(fs, name, 0, nameLen)) { Unsupported = "文件名读取失败"; return; }
                byte[] extra = new byte[extraLen];
                if (extraLen > 0 && !ReadExact(fs, extra, 0, extraLen)) { Unsupported = "扩展字段读取失败"; return; }
                if (commentLen > 0) fs.Seek(commentLen, SeekOrigin.Current);

                long comp = comp32;
                long uncomp = uncomp32;
                long localOff = local32;
                int aesVersion = 0;
                int aesStrength = 0;
                int aesMethod = 0;
                bool hasZip64Extra = false;

                ParseZip64Extra(extra, comp32, uncomp32, local32, ref comp, ref uncomp, ref localOff, ref hasZip64Extra);
                ParseAesExtra(extra, ref aesVersion, ref aesStrength, ref aesMethod);

                if ((flags & 0x1) == 0) continue;

                if (uncomp32 == 0xFFFFFFFFu && uncomp == 0xFFFFFFFFL)
                { Unsupported = "Zip64 扩展缺少原始大小"; return; }
                if (comp32 == 0xFFFFFFFFu && comp == 0xFFFFFFFFL)
                { Unsupported = "Zip64 扩展缺少压缩大小"; return; }
                if (local32 == 0xFFFFFFFFu && localOff == 0xFFFFFFFFL)
                { Unsupported = "Zip64 扩展缺少本地偏移"; return; }

                Flags = flags;
                Method = method;
                ModTime = modTime;
                Crc = crc;
                CompSize = comp;
                UncompSize = uncomp;
                IsZip64 = zip64 || hasZip64Extra;
                Aes = (method == 99);

                if (name != null)
                {
                    try { EntryName = Encoding.UTF8.GetString(name); }
                    catch { EntryName = Encoding.GetEncoding(437).GetString(name); }
                }

                if (localOff < 0 || localOff + 30 > fileSize) { Unsupported = "本地文件头偏移无效"; return; }
                fs.Seek(localOff, SeekOrigin.Begin);
                byte[] local = new byte[30];
                if (!ReadExact(fs, local, 0, 30) ||
                    local[0] != 0x50 || local[1] != 0x4B || local[2] != 0x03 || local[3] != 0x04)
                { Unsupported = "本地文件头解析失败"; return; }

                ushort lnameLen = U16(local, 26);
                ushort lextraLen = U16(local, 28);
                long dataStart = localOff + 30 + lnameLen + lextraLen;
                if (dataStart < 0 || dataStart > fileSize) { Unsupported = "数据偏移无效"; return; }

                // 部分工具只在本地文件头写 AES 扩展字段
                if (Aes && aesVersion == 0 && lextraLen > 0)
                {
                    byte[] localExtra = new byte[lextraLen];
                    fs.Seek(localOff + 30 + lnameLen, SeekOrigin.Begin);
                    if (ReadExact(fs, localExtra, 0, lextraLen))
                        ParseAesExtra(localExtra, ref aesVersion, ref aesStrength, ref aesMethod);
                }

                if (Aes)
                {
                    if (aesVersion != 1 && aesVersion != 2)
                    { Unsupported = "WinZip AES 扩展字段无效"; return; }
                    if (aesStrength < 1 || aesStrength > 3)
                    { Unsupported = "WinZip AES 强度无效"; return; }
                    if (aesMethod != 0 && aesMethod != 8)
                    { Unsupported = "不支持的 AES 压缩方式：" + aesMethod; return; }

                    AesVersion = aesVersion;
                    AesStrength = aesStrength;
                    Method = (ushort)aesMethod;
                    AesKeyLen = aesStrength == 1 ? 16 : (aesStrength == 2 ? 24 : 32);
                    AesSaltLen = aesStrength == 1 ? 8 : (aesStrength == 2 ? 12 : 16);

                    long overhead = AesSaltLen + 2 + 10;
                    if (comp < overhead) { Unsupported = "AES 数据长度异常"; return; }

                    fs.Seek(dataStart, SeekOrigin.Begin);
                    Salt = new byte[AesSaltLen];
                    PwdVerifier = new byte[2];
                    AuthCode = new byte[10];
                    if (!ReadExact(fs, Salt, 0, Salt.Length) ||
                        !ReadExact(fs, PwdVerifier, 0, PwdVerifier.Length))
                    { Unsupported = "AES 头部读取失败"; return; }
                    fs.Seek(dataStart + comp - 10, SeekOrigin.Begin);
                    if (!ReadExact(fs, AuthCode, 0, AuthCode.Length))
                    { Unsupported = "AES 认证码读取失败"; return; }

                    DataOffset = dataStart + AesSaltLen + 2;
                    DataSize = comp - overhead;
                }
                else
                {
                    if (method != 0 && method != 8)
                    { Unsupported = "不支持的压缩方式：" + method; return; }
                    if (comp < 12) { Unsupported = "加密数据长度异常"; return; }

                    fs.Seek(dataStart, SeekOrigin.Begin);
                    EncHeader = new byte[12];
                    if (!ReadExact(fs, EncHeader, 0, EncHeader.Length))
                    { Unsupported = "加密头读取失败"; return; }
                    DataOffset = dataStart + 12;
                    DataSize = comp - 12;
                }

                if (DataOffset < 0 || DataSize < 0 || DataOffset + DataSize > fileSize)
                { Unsupported = "压缩数据超出文件范围"; return; }

                // 传统 ZipCrypto 在数据描述符模式下，中央目录 CRC 可能为 0
                if (!Aes && Crc == 0 && (Flags & 0x8) != 0)
                {
                    fs.Seek(dataStart + comp, SeekOrigin.Begin);
                    byte[] dsig = new byte[4];
                    if (ReadExact(fs, dsig, 0, 4))
                    {
                        long off = (dsig[0] == 0x50 && dsig[1] == 0x4B && dsig[2] == 0x07 && dsig[3] == 0x08) ? 4 : 0;
                        byte[] dcrc = new byte[4];
                        if (ReadExact(fs, dcrc, 0, 4)) Crc = BitConverter.ToUInt32(dcrc, 0);
                    }
                }

                if (UncompSize == 0 && Crc == 0)
                {
                    Unsupported = "该压缩包条目内容为空，无法可靠校验密码";
                    return;
                }

                Encrypted = true;
                foundEnc = true;
                break;
            }

            if (!foundEnc) Unsupported = "该压缩包未加密";
        }

        void ParseAesExtra(byte[] extra, ref int version, ref int strength, ref int method)
        {
            int p = 0;
            while (p + 4 <= extra.Length)
            {
                ushort id = U16(extra, p);
                ushort sz = U16(extra, p + 2);
                int q = p + 4;
                if (q + sz > extra.Length) break;
                if (id == 0x9901 && sz >= 7)
                {
                    int ver = U16(extra, q);
                    if (extra[q + 2] == (byte)'A' && extra[q + 3] == (byte)'E')
                    {
                        version = ver;
                        strength = extra[q + 4];
                        method = U16(extra, q + 5);
                    }
                }
                p = q + sz;
            }
        }

        void ParseZip64Extra(byte[] extra, uint comp32, uint uncomp32, uint local32,
            ref long comp, ref long uncomp, ref long local, ref bool hasZip64)
        {
            int p = 0;
            while (p + 4 <= extra.Length)
            {
                ushort id = U16(extra, p);
                ushort sz = U16(extra, p + 2);
                int q = p + 4;
                int end = q + sz;
                if (end > extra.Length) break;
                if (id == 0x0001)
                {
                    hasZip64 = true;
                    int r = q;
                    if (uncomp32 == 0xFFFFFFFFu && r + 8 <= end)
                    { uncomp = BitConverter.ToInt64(extra, r); r += 8; }
                    if (comp32 == 0xFFFFFFFFu && r + 8 <= end)
                    { comp = BitConverter.ToInt64(extra, r); r += 8; }
                    if (local32 == 0xFFFFFFFFu && r + 8 <= end)
                    { local = BitConverter.ToInt64(extra, r); r += 8; }
                }
                p = end;
            }
        }

        static void UpdateKeys(uint[] keys, byte c)
        {
            keys[0] = CrcByte(keys[0], c);
            keys[1] = (uint)((keys[1] + (keys[0] & 0xFF)) * 134775813L + 1L);
            keys[2] = CrcByte(keys[2], (keys[1] >> 24) & 0xFF);
        }

        void InitKeys(uint[] keys, string pwd)
        {
            keys[0] = 0x12345678u; keys[1] = 0x23456789u; keys[2] = 0x34567890u;
            byte[] pb = Encoding.UTF8.GetBytes(pwd);
            foreach (byte c in pb) UpdateKeys(keys, c);
        }

        void InitKeysFromChars(uint[] keys, char[] chars, int len)
        {
            keys[0] = 0x12345678u; keys[1] = 0x23456789u; keys[2] = 0x34567890u;
            for (int i = 0; i < len; i++) UpdateKeys(keys, (byte)chars[i]);
        }

        byte AdvanceHeader(uint[] keys)
        {
            byte last = 0;
            for (int i = 0; i < 12; i++)
            {
                uint c = EncHeader[i];
                uint k = keys[2] | 2u;
                byte p = (byte)(c ^ (byte)((((ulong)k * (k ^ 1)) >> 8) & 0xFF));
                UpdateKeys(keys, p);
                last = p;
            }
            return last;
        }

        bool CheckKeys(uint[] keys)
        {
            byte last = AdvanceHeader(keys);
            byte crcHi = (byte)(Crc >> 24);
            byte timeHi = (byte)(ModTime >> 8);
            return last == crcHi || last == timeHi;
        }

        byte[] DeriveAes(byte[] pwd)
        {
            using (Rfc2898DeriveBytes k = new Rfc2898DeriveBytes(pwd, Salt, 1000))
            {
                return k.GetBytes(AesKeyLen * 2 + 2);
            }
        }

        // 校验阶段只需要密码校验值所在的 PBKDF2 块，避免为每个候选计算全部 4 个块
        byte[] Pbkdf2Block(byte[] pwd, int blockIndex)
        {
            byte[] saltBlock = new byte[Salt.Length + 4];
            Array.Copy(Salt, saltBlock, Salt.Length);
            int n = blockIndex + 1;
            saltBlock[Salt.Length] = (byte)(n >> 24);
            saltBlock[Salt.Length + 1] = (byte)(n >> 16);
            saltBlock[Salt.Length + 2] = (byte)(n >> 8);
            saltBlock[Salt.Length + 3] = (byte)n;

            using (HMACSHA1 h = new HMACSHA1(pwd))
            {
                byte[] u = h.ComputeHash(saltBlock);
                byte[] t = (byte[])u.Clone();
                for (int i = 1; i < 1000; i++)
                {
                    u = h.ComputeHash(u);
                    for (int j = 0; j < 20; j++) t[j] ^= u[j];
                }
                return t;
            }
        }

        bool CheckAes(byte[] pwd)
        {
            if (Salt.Length == 0 || PwdVerifier.Length < 2) return false;
            int offset = AesKeyLen * 2;
            byte[] block = Pbkdf2Block(pwd, offset / 20);
            int pos = offset % 20;
            return block[pos] == PwdVerifier[0] && block[pos + 1] == PwdVerifier[1];
        }

        public bool Check(string pwd)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(pwd);
            if (Aes) return CheckAes(Encoding.UTF8.GetBytes(pwd));
            uint[] keys = new uint[3];
            InitKeys(keys, pwd);
            return CheckKeys(keys);
        }

        public bool CheckChars(char[] chars, int len)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(new string(chars, 0, len));
            if (Aes) return CheckAes(PasswordBytes(chars, len));
            uint[] keys = new uint[3];
            return CheckChars(chars, len, keys);
        }

        public bool CheckChars(char[] chars, int len, uint[] keys)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(new string(chars, 0, len));
            if (Aes) return CheckAes(PasswordBytes(chars, len));
            InitKeysFromChars(keys, chars, len);
            return CheckKeys(keys);
        }

        static byte[] PasswordBytes(char[] chars, int len)
        {
            byte[] b = new byte[len];
            for (int i = 0; i < len; i++) b[i] = (byte)chars[i];
            return b;
        }

        public bool FullVerify(string pwd)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(pwd);
            if (Aes)
            {
                byte[] dk = DeriveAes(Encoding.UTF8.GetBytes(pwd));
                if (dk[AesKeyLen * 2] != PwdVerifier[0] || dk[AesKeyLen * 2 + 1] != PwdVerifier[1]) return false;
                return VerifyAes(dk);
            }
            uint[] keys = new uint[3];
            InitKeys(keys, pwd);
            AdvanceHeader(keys);
            return VerifyPayload(false, null, null, keys);
        }

        public bool FullVerifyChars(char[] chars, int len)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(new string(chars, 0, len));
            if (Aes)
            {
                byte[] dk = DeriveAes(PasswordBytes(chars, len));
                if (dk[AesKeyLen * 2] != PwdVerifier[0] || dk[AesKeyLen * 2 + 1] != PwdVerifier[1]) return false;
                return VerifyAes(dk);
            }
            uint[] keys = new uint[3];
            InitKeysFromChars(keys, chars, len);
            AdvanceHeader(keys);
            return VerifyPayload(false, null, null, keys);
        }

        public bool FullVerifyChars(char[] chars, int len, uint[] keys)
        {
            if (!Encrypted) return false;
            if (External) return ExternalTest(new string(chars, 0, len));
            if (Aes)
            {
                byte[] dk = DeriveAes(PasswordBytes(chars, len));
                if (dk[AesKeyLen * 2] != PwdVerifier[0] || dk[AesKeyLen * 2 + 1] != PwdVerifier[1]) return false;
                return VerifyAes(dk);
            }
            InitKeysFromChars(keys, chars, len);
            AdvanceHeader(keys);
            return VerifyPayload(false, null, null, keys);
        }

        bool VerifyAes(byte[] derived)
        {
            byte[] encKey = new byte[AesKeyLen];
            byte[] authKey = new byte[AesKeyLen];
            Array.Copy(derived, 0, encKey, 0, AesKeyLen);
            Array.Copy(derived, AesKeyLen, authKey, 0, AesKeyLen);
            return VerifyPayload(true, encKey, authKey, null);
        }

        bool VerifyPayload(bool aes, byte[] encKey, byte[] authKey, uint[] cryptoKeys)
        {
            try
            {
                using (PayloadStream ps = new PayloadStream(Path, DataOffset, DataSize, aes, encKey, authKey, cryptoKeys))
                {
                    long outCount = 0;
                    uint crc = 0xFFFFFFFFu;
                    byte[] buf = new byte[16384];

                    if (Method == 0)
                    {
                        int n;
                        while ((n = ps.Read(buf, 0, buf.Length)) > 0)
                        {
                            outCount += n;
                            if (Crc != 0)
                            {
                                for (int i = 0; i < n; i++)
                                    crc = CrcTable[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
                            }
                        }
                    }
                    else if (Method == 8)
                    {
                        byte[] mac = null;
                        DeflateStream ds = new DeflateStream(ps, CompressionMode.Decompress);
                        try
                        {
                            int n;
                            while ((n = ds.Read(buf, 0, buf.Length)) > 0)
                            {
                                outCount += n;
                                if (Crc != 0)
                                {
                                    for (int i = 0; i < n; i++)
                                        crc = CrcTable[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
                                }
                            }
                            ps.Drain();
                            if (aes) mac = ps.FinishHmac();
                        }
                        finally
                        {
                            ds.Dispose();
                        }
                        if (aes && !MatchAuth(mac)) return false;
                    }
                    else return false;

                    if (aes && Method == 0)
                    {
                        if (!MatchAuth(ps.FinishHmac())) return false;
                    }

                    if (UncompSize > 0 && outCount != UncompSize) return false;
                    if (Crc != 0 && (crc ^ 0xFFFFFFFFu) != Crc) return false;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        bool MatchAuth(byte[] mac)
        {
            if (mac == null || mac.Length < 10 || AuthCode.Length < 10) return false;
            for (int i = 0; i < 10; i++) if (mac[i] != AuthCode[i]) return false;
            return true;
        }

        public static void ReleaseBuffers() { }

        sealed class AesCtr : IDisposable
        {
            Aes _aes;
            ICryptoTransform _enc;
            byte[] _counter = new byte[16];
            byte[] _ks = new byte[16];
            int _pos = 16;

            public AesCtr(byte[] key)
            {
                _aes = System.Security.Cryptography.Aes.Create();
                _aes.Mode = CipherMode.ECB;
                _aes.Padding = PaddingMode.None;
                _aes.Key = key;
                _enc = _aes.CreateEncryptor();
                _counter[0] = 1; // WinZip AES：小端计数器从 1 开始
            }

            public void Transform(byte[] buffer, int offset, int count)
            {
                for (int i = 0; i < count; i++)
                {
                    if (_pos == 16)
                    {
                        _enc.TransformBlock(_counter, 0, 16, _ks, 0);
                        Increment();
                        _pos = 0;
                    }
                    buffer[offset + i] ^= _ks[_pos++];
                }
            }

            void Increment()
            {
                for (int i = 0; i < 16; i++)
                {
                    _counter[i]++;
                    if (_counter[i] != 0) break;
                }
            }

            public void Dispose()
            {
                if (_enc != null) _enc.Dispose();
                if (_aes != null) _aes.Dispose();
            }
        }

        sealed class PayloadStream : Stream
        {
            FileStream _fs;
            long _remaining;
            bool _aes;
            AesCtr _ctr;
            uint[] _keys;
            HMACSHA1 _hmac;
            byte[] _hmacScratch = new byte[65536];
            bool _hmacDone;

            public PayloadStream(string path, long offset, long size, bool aes,
                byte[] encKey, byte[] authKey, uint[] cryptoKeys)
            {
                _fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                _fs.Seek(offset, SeekOrigin.Begin);
                _remaining = size;
                _aes = aes;
                if (aes)
                {
                    _ctr = new AesCtr(encKey);
                    _hmac = new HMACSHA1(authKey);
                }
                else
                {
                    _keys = new uint[3];
                    Array.Copy(cryptoKeys, _keys, 3);
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_remaining <= 0) return 0;
                int want = (int)Math.Min((long)count, _remaining);
                int n = _fs.Read(buffer, offset, want);
                if (n <= 0) return 0;
                _remaining -= n;

                if (_aes)
                {
                    if (_hmacScratch.Length < n) _hmacScratch = new byte[n];
                    _hmac.TransformBlock(buffer, offset, n, _hmacScratch, 0);
                    _ctr.Transform(buffer, offset, n);
                }
                else
                {
                    for (int i = 0; i < n; i++)
                    {
                        uint c = buffer[offset + i];
                        uint k = _keys[2] | 2u;
                        byte p = (byte)(c ^ (byte)((((ulong)k * (k ^ 1)) >> 8) & 0xFF));
                        UpdateKeys(_keys, p);
                        buffer[offset + i] = p;
                    }
                }
                return n;
            }

            public void Drain()
            {
                byte[] b = new byte[4096];
                while (Read(b, 0, b.Length) > 0) { }
            }

            public byte[] FinishHmac()
            {
                if (_hmac == null) return null;
                if (!_hmacDone)
                {
                    _hmac.TransformFinalBlock(new byte[0], 0, 0);
                    _hmacDone = true;
                }
                return _hmac.Hash;
            }

            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (_hmac != null) _hmac.Dispose();
                    if (_ctr != null) _ctr.Dispose();
                    if (_fs != null) _fs.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }

    public static class Brute
    {
        public static string Run(ZipTarget target, string charset, int minLen, int maxLen,
            Func<bool> shouldStop, Action<int, long> onProgress)
        {
            return Run(target, charset, minLen, maxLen, shouldStop, onProgress, 1);
        }

        public static string Run(ZipTarget target, string charset, int minLen, int maxLen,
            Func<bool> shouldStop, Action<int, long> onProgress, int threads)
        {
            if (target == null || charset == null || charset.Length == 0) return null;
            if (minLen < 1) minLen = 1;
            if (maxLen < minLen) return null;
            if (threads < 1) threads = 1;
            if (threads > 256) threads = 256;

            State st = new State();
            st.Target = target;
            st.Cs = charset.ToCharArray();
            st.MinLen = minLen;
            st.MaxLen = maxLen;
            st.Tasks = (maxLen - minLen + 1) * st.Cs.Length;
            st.ShouldStop = shouldStop;
            st.OnProgress = onProgress;
            st.Ascii = true;
            for (int i = 0; i < st.Cs.Length; i++) if (st.Cs[i] > 127) { st.Ascii = false; break; }

            if (threads > st.Tasks) threads = st.Tasks;
            Thread[] ths = new Thread[threads];
            for (int i = 0; i < threads; i++)
            {
                Thread th = new Thread(st.Worker);
                th.IsBackground = true;
                th.Name = "zipcracker-worker-" + i;
                ths[i] = th;
                th.Start();
            }
            for (int i = 0; i < threads; i++) ths[i].Join();

            if (onProgress != null) onProgress(maxLen, Interlocked.Read(ref st.Tried));
            ZipTarget.ReleaseBuffers();
            if (st.Error != null)
                throw new InvalidOperationException("破解线程异常：" + st.Error.Message, st.Error);
            return st.Found;
        }

        sealed class State
        {
            public ZipTarget Target;
            public char[] Cs;
            public int MinLen;
            public int MaxLen;
            public int Tasks;
            public Func<bool> ShouldStop;
            public Action<int, long> OnProgress;
            public bool Ascii;

            public int NextTask = -1;
            public int FoundFlag;
            public string Found;
            public long Tried;
            public long LastReported;
            public Exception Error;
            public readonly object Gate = new object();

            void Report(long localAdded, int len)
            {
                if (localAdded <= 0) return;
                long total = Interlocked.Add(ref Tried, localAdded);
                // 多线程回调可能乱序到达，用锁保证回调收到的 total 严格递增
                lock (Gate)
                {
                    if (total > LastReported)
                    {
                        LastReported = total;
                        if (OnProgress != null) OnProgress(len, total);
                    }
                }
            }

            public void Worker()
            {
                long local = 0;
                uint[] keys = new uint[3];
                try
                {
                    int c = Cs.Length;
                    while (Thread.VolatileRead(ref FoundFlag) == 0)
                    {
                        if (ShouldStop != null && ShouldStop()) break;
                        int task = Interlocked.Increment(ref NextTask);
                        if (task >= Tasks) break;

                        int L = MinLen + task / c;
                        int first = task % c;
                        int[] dig = new int[L];
                        char[] cur = new char[L];
                        dig[0] = first;
                        for (int i = 0; i < L; i++) cur[i] = Cs[dig[i]];

                        while (true)
                        {
                            if (Thread.VolatileRead(ref FoundFlag) != 0) return;
                            if (ShouldStop != null && ShouldStop()) return;

                            local++;
                            // RAR/7z 每个候选都要启动 7z.exe，进度必须逐个上报
                            if (Target.External || (local & 0x3FF) == 0)
                            {
                                Report(local, L);
                                local = 0;
                            }

                            bool ok;
                            string pwd = null;
                            if (Ascii)
                            {
                                ok = Target.CheckChars(cur, L, keys);
                                if (ok && Target.NeedsFullVerify) ok = Target.FullVerifyChars(cur, L, keys);
                            }
                            else
                            {
                                pwd = new string(cur);
                                ok = Target.Check(pwd);
                                if (ok && Target.NeedsFullVerify) ok = Target.FullVerify(pwd);
                            }
                            if (ok)
                            {
                                if (pwd == null) pwd = new string(cur);
                                lock (Gate)
                                {
                                    if (Found == null)
                                    {
                                        Found = pwd;
                                        Interlocked.Exchange(ref FoundFlag, 1);
                                    }
                                }
                                Report(local, L);
                                local = 0;
                                return;
                            }

                            int i2 = L - 1;
                            while (i2 >= 1)
                            {
                                int d = dig[i2] + 1;
                                if (d < c)
                                {
                                    dig[i2] = d;
                                    cur[i2] = Cs[d];
                                    break;
                                }
                                dig[i2] = 0;
                                cur[i2] = Cs[0];
                                i2--;
                            }
                            if (i2 < 1) break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    lock (Gate)
                    {
                        if (Error == null) Error = ex;
                    }
                    Interlocked.Exchange(ref FoundFlag, 1);
                }
                finally
                {
                    Report(local, 0);
                }
            }
        }
    }
}
