// ZipCore.cs —— ZipCrackerN 核心：传统 ZipCrypto 密码校验与暴力破解
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;

namespace ZipCrackerN
{
    public sealed class ZipTarget
    {
        public string Path;
        public string EntryName = "";
        public byte[] EncHeader = new byte[0];
        public byte[] Data = new byte[0];
        public ushort Flags;
        public ushort Method;
        public ushort ModTime;
        public uint Crc;
        public int CompSize;
        public long UncompSize;
        public bool Encrypted;
        public bool Aes;
        public string Unsupported = "";

        // FullVerify 的共享缓冲区：避免每次校验都分配整个压缩数据大小的数组
        static readonly object VerifyGate = new object();
        static byte[] _plainBuf;
        static byte[] _chunkBuf;

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

        static uint Crc32(byte[] data)
        {
            return Crc32(data, 0, data.Length);
        }

        static uint Crc32(byte[] data, int offset, int count)
        {
            uint c = 0xFFFFFFFFu;
            for (int i = offset; i < offset + count; i++)
            {
                c = CrcTable[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
            }
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

        public ZipTarget(string path)
        {
            Path = path;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    Parse(fs);
                }
            }
            catch (Exception ex)
            {
                Unsupported = "无法打开压缩包：" + ex.Message;
            }
        }

        void Parse(FileStream fs)
        {
            long size = fs.Length;
            if (size < 22) { Unsupported = "文件过小，不是有效的 zip 包"; return; }
            int scan = (int)Math.Min(size, 22L + 65535L);
            byte[] buf = new byte[scan];
            fs.Seek(size - scan, SeekOrigin.Begin);
            if (!ReadExact(fs, buf, 0, scan)) { Unsupported = "文件读取失败"; return; }
            int got = scan;
            int eocd = -1;
            for (int i = got - 22; i >= 0; i--)
            {
                if (buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 0x05 && buf[i + 3] == 0x06) { eocd = i; break; }
            }
            if (eocd < 0) { Unsupported = "未找到 zip 目录，可能不是 zip 文件"; return; }
            uint cdOffset = BitConverter.ToUInt32(buf, eocd + 16);
            // 遍历中央目录，找第一个加密条目（多文件压缩包也支持）
            fs.Seek(cdOffset, SeekOrigin.Begin);
            bool foundEnc = false;
            byte[] sig = new byte[4];
            byte[] cd = new byte[42];
            byte[] name = null;
            uint localOff = 0;
            uint uncompU = 0;
            while (ReadExact(fs, sig, 0, 4) && sig[0] == 0x50 && sig[1] == 0x4B && sig[2] == 0x01 && sig[3] == 0x02)
            {
                if (!ReadExact(fs, cd, 0, 42)) { Unsupported = "中央目录解析失败"; return; }
                Flags = BitConverter.ToUInt16(cd, 4);
                Method = BitConverter.ToUInt16(cd, 6);
                ModTime = BitConverter.ToUInt16(cd, 8);
                Crc = BitConverter.ToUInt32(cd, 12);
                CompSize = (int)BitConverter.ToUInt32(cd, 16);
                uncompU = BitConverter.ToUInt32(cd, 20);
                UncompSize = uncompU;
                ushort nameLen = BitConverter.ToUInt16(cd, 24);
                ushort extraLen = BitConverter.ToUInt16(cd, 26);
                ushort commentLen = BitConverter.ToUInt16(cd, 28);
                localOff = BitConverter.ToUInt32(cd, 38);
                name = new byte[nameLen];
                if (nameLen > 0 && !ReadExact(fs, name, 0, nameLen)) { Unsupported = "文件名读取失败"; return; }
                if (extraLen > 0) fs.Seek(extraLen, SeekOrigin.Current);
                if (commentLen > 0) fs.Seek(commentLen, SeekOrigin.Current);
                if ((Flags & 0x1) != 0) { foundEnc = true; break; }
            }
            if (!foundEnc) { Unsupported = "该压缩包未加密"; return; }
            if (Method == 99) { Aes = true; Unsupported = "该压缩包使用 WinZip AES 加密，本工具暂不支持"; return; }
            if (Method != 0 && Method != 8) { Unsupported = "不支持的压缩方式：" + Method; return; }
            if (CompSize < 0 || uncompU == 0xFFFFFFFFu || localOff == 0xFFFFFFFFu) { Unsupported = "暂不支持 Zip64 大文件"; return; }
            if (name != null)
            {
                try { EntryName = Encoding.UTF8.GetString(name); }
                catch { EntryName = Encoding.GetEncoding(437).GetString(name); }
            }
            Encrypted = true;
            fs.Seek(localOff, SeekOrigin.Begin);
            byte[] local = new byte[30];
            if (!ReadExact(fs, local, 0, 30) || local[0] != 0x50 || local[1] != 0x4B || local[2] != 0x03 || local[3] != 0x04)
            { Unsupported = "本地文件头解析失败"; Encrypted = false; return; }
            ushort lnameLen = BitConverter.ToUInt16(local, 26);
            ushort lextraLen = BitConverter.ToUInt16(local, 28);
            fs.Seek(localOff + 30 + lnameLen + lextraLen, SeekOrigin.Begin);
            EncHeader = new byte[12];
            if (!ReadExact(fs, EncHeader, 0, 12)) { Unsupported = "加密头读取失败"; Encrypted = false; return; }
            // 中央目录里的压缩大小包含 12 字节加密头，实际密文长度要减掉
            int bodySize = CompSize - 12;
            if (bodySize < 0) { Unsupported = "压缩数据大小异常"; Encrypted = false; return; }
            Data = new byte[bodySize];
            if (bodySize > 0 && !ReadExact(fs, Data, 0, bodySize)) { Unsupported = "数据读取失败，压缩包可能已损坏"; Encrypted = false; return; }
            // 只有设置了数据描述符标志(bit 3)且中央目录 CRC 为 0 时才读取描述符，
            // 否则会误把后续数据当成 CRC
            if (Crc == 0 && (Flags & 0x8) != 0)
            {
                long afterBody = fs.Position;
                byte[] dsig = new byte[4];
                if (ReadExact(fs, dsig, 0, 4))
                {
                    long off = (dsig[0] == 0x50 && dsig[1] == 0x4B && dsig[2] == 0x07 && dsig[3] == 0x08) ? 4 : 0;
                    byte[] dcrc = new byte[4];
                    if (ReadExact(fs, dcrc, 0, 4))
                    {
                        Crc = BitConverter.ToUInt32(dcrc, 0);
                    }
                    fs.Seek(afterBody, SeekOrigin.Begin);
                }
            }
            // 空条目没有 CRC 可用于最终校验，仅凭加密头会产生误报，直接提示不支持
            if (UncompSize == 0 && Crc == 0)
            {
                Unsupported = "该压缩包条目内容为空，无法可靠校验密码";
                Encrypted = false;
                return;
            }
        }

        public static void ReleaseBuffers()
        {
            lock (VerifyGate)
            {
                _plainBuf = null;
                _chunkBuf = null;
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

        // 破解时直接使用 char 初始化密钥，避免每个候选密码都分配 string 和 UTF-8 字节数组
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

        public bool Check(string pwd)
        {
            if (!Encrypted) return false;
            uint[] keys = new uint[3];
            InitKeys(keys, pwd);
            return CheckKeys(keys);
        }

        public bool CheckChars(char[] chars, int len)
        {
            uint[] keys = new uint[3];
            return CheckChars(chars, len, keys);
        }

        /// <summary>使用调用方复用的 keys 数组检查候选密码，避免每次分配。</summary>
        public bool CheckChars(char[] chars, int len, uint[] keys)
        {
            if (!Encrypted) return false;
            InitKeysFromChars(keys, chars, len);
            return CheckKeys(keys);
        }

        public bool FullVerify(string pwd)
        {
            if (!Encrypted) return false;
            uint[] keys = new uint[3];
            InitKeys(keys, pwd);
            return FullVerifyKeys(keys);
        }

        public bool FullVerifyChars(char[] chars, int len)
        {
            uint[] keys = new uint[3];
            return FullVerifyChars(chars, len, keys);
        }

        public bool FullVerifyChars(char[] chars, int len, uint[] keys)
        {
            if (!Encrypted) return false;
            InitKeysFromChars(keys, chars, len);
            return FullVerifyKeys(keys);
        }

        bool FullVerifyKeys(uint[] keys)
        {
            if (!Encrypted) return false;
            // 校验只在加密头命中后才调用；用锁复用缓冲区，限制大压缩包的内存峰值
            lock (VerifyGate)
            {
                AdvanceHeader(keys);
                int len = Data.Length;
                if (_plainBuf == null || _plainBuf.Length < len) _plainBuf = new byte[Math.Max(len, 1024)];
                byte[] plain = _plainBuf;
                for (int i = 0; i < len; i++)
                {
                    uint c = Data[i];
                    uint k = keys[2] | 2u;
                    byte p = (byte)(c ^ (byte)((((ulong)k * (k ^ 1)) >> 8) & 0xFF));
                    UpdateKeys(keys, p);
                    plain[i] = p;
                }
                if (Method == 0)
                {
                    // 存储型：解出明文直接与 CRC 比对；拿不到 CRC 时仅靠加密头校验
                    return Crc == 0 ? true : Crc32(plain, 0, len) == Crc;
                }
                if (Method == 8)
                {
                    try
                    {
                        long outCount = 0;
                        uint crc = 0xFFFFFFFFu;
                        using (MemoryStream ms = new MemoryStream(plain, 0, len, false))
                        using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
                        {
                            if (_chunkBuf == null) _chunkBuf = new byte[16384];
                            int n;
                            while ((n = ds.Read(_chunkBuf, 0, _chunkBuf.Length)) > 0)
                            {
                                outCount += n;
                                if (Crc != 0)
                                {
                                    for (int i = 0; i < n; i++)
                                        crc = CrcTable[(crc ^ _chunkBuf[i]) & 0xFFu] ^ (crc >> 8);
                                }
                            }
                        }
                        if (UncompSize > 0 && outCount != UncompSize) return false;
                        return Crc == 0 ? true : (crc ^ 0xFFFFFFFFu) == Crc;
                    }
                    catch { return false; }
                }
                return false;
            }
        }
    }

    public static class Brute
    {
        /// <summary>单线程破解（兼容旧调用）。</summary>
        public static string Run(ZipTarget target, string charset, int minLen, int maxLen,
            Func<bool> shouldStop, Action<int, long> onProgress)
        {
            return Run(target, charset, minLen, maxLen, shouldStop, onProgress, 1);
        }

        /// <summary>
        /// 多线程破解。按“长度 + 首字符”切分任务，每个任务内部枚举其余位，
        /// 任务由所有线程动态领取，保证候选密码不重复、不遗漏。
        /// 返回密码，未找到返回 null。threads 为线程数（1 表示单线程）。
        /// </summary>
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

            // 所有线程结束后再报一次最终总数，保证进度不会因回调乱序而倒退
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
            public int FoundFlag;          // 0=继续，1=已找到/出错/需停止
            public string Found;
            public long Tried;
            public Exception Error;
            public readonly object Gate = new object();

            void Report(long localAdded, int len)
            {
                if (localAdded <= 0) return;
                long total = Interlocked.Add(ref Tried, localAdded);
                if (OnProgress != null) OnProgress(len, total);
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
                            if ((local & 0x3FF) == 0)
                            {
                                Report(local, L);
                                local = 0;
                            }

                            bool ok;
                            string pwd = null;
                            if (Ascii)
                            {
                                ok = Target.CheckChars(cur, L, keys) && Target.FullVerifyChars(cur, L, keys);
                            }
                            else
                            {
                                // 非 ASCII 字符集按 UTF-8 语义校验，保证与 Check(string) 一致
                                pwd = new string(cur);
                                ok = Target.Check(pwd) && Target.FullVerify(pwd);
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

                            // 首字符固定，递增后面的位；枚举完即本任务结束
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
