// ZipCrackerN.cs —— Win32 原生界面 + ZipCore 暴力破解
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using ZipCrackerN;

internal static class Win
{
    public const int WS_OVERLAPPEDWINDOW = 0x00CF0000;
    public const int WS_OVERLAPPED = 0x00000000;
    public const int WS_CAPTION = 0x00C00000;
    public const int WS_SYSMENU = 0x00080000;
    public const int WS_MINIMIZEBOX = 0x00020000;
    public const int WS_MAXIMIZEBOX = 0x00010000;
    public const int WS_VISIBLE = 0x10000000;
    public const int WS_CHILD = 0x40000000;
    public const int WS_TABSTOP = 0x00010000;
    public const int WS_BORDER = 0x00800000;
    public const int WS_VSCROLL = 0x00200000;
    public const int WS_EX_LEFT = 0x00000000;
    public const int ES_AUTOHSCROLL = 0x0080;
    public const int ES_READONLY = 0x0800;
    public const int ES_NUMBER = 0x2000;
    public const int ES_LEFT = 0x0000;
    public const int BS_AUTOCHECKBOX = 0x0003;
    public const int BS_PUSHBUTTON = 0x0000;
    public const int BM_GETCHECK = 0x00F0;
    public const int BM_SETCHECK = 0x00F1;
    public const int BST_CHECKED = 0x0001;
    public const int BST_UNCHECKED = 0x0000;
    public const int BN_CLICKED = 0;
    public const int WM_COMMAND = 0x0111;
    public const int WM_CLOSE = 0x0010;
    public const int WM_DESTROY = 0x0002;
    public const int WM_NCCREATE = 0x0081;
    public const int WM_TIMER = 0x0113;
    public const int WM_SETFONT = 0x0030;
    public const int WM_GETTEXT = 0x000D;
    public const int WM_DROPFILES = 0x0233;
    public const int WM_SETICON = 0x0080;
    public const int ICON_SMALL = 0;
    public const int ICON_BIG = 1;
    public const int IMAGE_ICON = 1;
    public const uint LR_LOADFROMFILE = 0x0010;
    public const uint LR_DEFAULTSIZE = 0x0040;
    public const int SM_CXICON = 11;
    public const int SM_CYICON = 12;
    public const int SM_CXSMICON = 49;
    public const int SM_CYSMICON = 50;
    // up-down (spin) 控件
    public const int UDS_WRAP = 0x0001;
    public const int UDS_SETBUDDYINT = 0x0002;
    public const int UDS_ALIGNRIGHT = 0x0004;
    public const int UDS_ALIGNLEFT = 0x0008;
    public const int UDS_AUTOBUDDY = 0x0010;
    public const int UDS_ARROWKEYS = 0x0020;
    public const int UDS_HORZ = 0x0040;
    public const int UDS_NOTHOUSANDS = 0x0080;
    public const uint UDM_SETRANGE32 = 0x0400 + 111;
    public const uint UDM_SETPOS32 = 0x0400 + 113;
    public const uint UDM_SETBUDDY = 0x0400 + 105;
    public const uint ICC_UPDOWN_CLASS = 0x00000010;
    public const int WM_DPICHANGED = 0x02E0;
    public const int SWP_NOZORDER = 0x0004;
    public const int SWP_NOMOVE = 0x0002;
    public const int SM_CXSCREEN = 0;
    public const int SM_CYSCREEN = 1;
    public const int COLOR_BTNFACE = 15;
    public const int IDI_APPLICATION = 32512;
    public const int SPI_GETNONCLIENTMETRICS = 0x0029;
    public const int LOGPIXELSX = 88;
    public const int CF_UNICODETEXT = 13;
    public const int GHND = 0x0042;
    public const int OFN_FILEMUSTEXIST = 0x00001000;
    public const int OFN_HIDEREADONLY = 0x00000004;
    public const int MB_OK = 0, MB_YESNO = 4, MB_ICONWARNING = 0x30, MB_ICONERROR = 0x10, IDYES = 6;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MSG
    {
        public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam;
        public int time; public int pt_x; public int pt_y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DROPFILES
    {
        public uint pFiles; public int x; public int y; public int fNC; public int fWide;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INITCOMMONCONTROLSEX
    {
        public int dwSize;
        public uint dwICC;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOGFONTW
    {
        public int lfHeight; public int lfWidth; public int lfEscapement; public int lfOrientation; public int lfWeight;
        public byte lfItalic; public byte lfUnderline; public byte lfStrikeOut; public byte lfCharSet;
        public byte lfOutPrecision; public byte lfClipPrecision; public byte lfQuality; public byte lfPitchAndFamily;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string lfFaceName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NONCLIENTMETRICSW
    {
        public int cbSize;
        public int iBorderWidth; public int iScrollWidth; public int iScrollHeight; public int iCaptionWidth; public int iCaptionHeight;
        public LOGFONTW lfCaptionFont;
        public int iSmCaptionWidth; public int iSmCaptionHeight;
        public LOGFONTW lfSmCaptionFont;
        public int iMenuWidth; public int iMenuHeight;
        public LOGFONTW lfMenuFont;
        public LOGFONTW lfStatusFont;
        public LOGFONTW lfMessageFont;
        public int iPaddedBorderWidth;
    }

    public delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public WndProc lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class OPENFILENAMEW
    {
        public int lStructSize;
        public IntPtr hwndOwner;
        public IntPtr hInstance;
        public string lpstrFilter;
        public IntPtr lpstrCustomFilter;
        public int nMaxCustFilter;
        public int nFilterIndex;
        public StringBuilder lpstrFile;
        public int nMaxFile;
        public StringBuilder lpstrFileTitle;
        public int nMaxFileTitle;
        public string lpstrInitialDir;
        public string lpstrTitle;
        public int Flags;
        public short nFileOffset;
        public short nFileExtension;
        public string lpstrDefExt;
        public IntPtr lCustData;
        public IntPtr lpfnHook;
        public string lpTemplateName;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr CreateWindowExW(int ex, string cls, string text, int style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr hInst, IntPtr param);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string text);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool UpdateWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr DefWindowProcW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern void PostQuitMessage(int code);
    [DllImport("user32.dll")] public static extern bool DestroyWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hgt, int flags);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, StringBuilder l);
    [DllImport("user32.dll")] public static extern bool EnableWindow(IntPtr h, bool enable);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] public static extern int GetMessageW(out MSG msg, IntPtr h, uint min, uint max);
    [DllImport("user32.dll")] public static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] public static extern IntPtr DispatchMessageW(ref MSG msg);
    [DllImport("user32.dll", SetLastError = true)] public static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
    [DllImport("user32.dll")] public static extern IntPtr LoadIconW(IntPtr h, IntPtr name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr LoadImageW(IntPtr hInst, string name, uint type, int cx, int cy, uint flags);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern uint ExtractIconExW(string file, int index, out IntPtr large, out IntPtr small, int count);
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll")] public static extern IntPtr LoadCursorW(IntPtr h, IntPtr name);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern uint DragQueryFileW(IntPtr hDrop, uint iFile, StringBuilder file, uint cch);
    [DllImport("shell32.dll")] public static extern void DragFinish(IntPtr hDrop);
    [DllImport("shell32.dll")] public static extern void DragAcceptFiles(IntPtr hWnd, bool accept);
    public delegate IntPtr SUBCLASSPROC(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam, UIntPtr uIdSubclass, UIntPtr dwRefData);
    [DllImport("comctl32.dll")] public static extern bool SetWindowSubclass(IntPtr hWnd, SUBCLASSPROC proc, UIntPtr uIdSubclass, UIntPtr dwRefData);
    [DllImport("comctl32.dll")] public static extern IntPtr DefSubclassProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("comctl32.dll")] public static extern bool InitCommonControlsEx(ref INITCOMMONCONTROLSEX icc);
    [DllImport("user32.dll")] public static extern uint SetTimer(IntPtr h, uint id, uint ms, IntPtr cb);
    [DllImport("user32.dll")] public static extern bool KillTimer(IntPtr h, uint id);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int MessageBoxW(IntPtr h, string text, string title, int flags);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern IntPtr SetProcessDpiAwarenessContext(IntPtr value);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("gdi32.dll")] public static extern int GetDeviceCaps(IntPtr dc, int index);
    [DllImport("gdi32.dll")] public static extern IntPtr CreateFontIndirectW(ref LOGFONTW lf);
    [DllImport("gdi32.dll")] public static extern bool DeleteObject(IntPtr o);
    [DllImport("user32.dll")] public static extern bool SystemParametersInfoW(uint action, uint param, ref NONCLIENTMETRICSW v, uint winIni);
    [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll")] public static extern bool EmptyClipboard();
    [DllImport("user32.dll")] public static extern IntPtr SetClipboardData(uint fmt, IntPtr mem);
    [DllImport("user32.dll")] public static extern bool CloseClipboard();
    [DllImport("kernel32.dll")] public static extern IntPtr GlobalAlloc(uint flags, UIntPtr size);
    [DllImport("kernel32.dll")] public static extern IntPtr GlobalLock(IntPtr mem);
    [DllImport("kernel32.dll")] public static extern bool GlobalUnlock(IntPtr mem);
    [DllImport("kernel32.dll")] public static extern IntPtr GlobalFree(IntPtr mem);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandleW(string name);
    [DllImport("comdlg32.dll", CharSet = CharSet.Unicode)] public static extern bool GetOpenFileNameW([In, Out] OPENFILENAMEW ofn);
    [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
}

internal sealed class App
{
    const int ID_L_PATH = 1000, ID_PATH = 1001, ID_BROWSE = 1002;
    const int ID_L_CHARSET = 1003;
    const int ID_UP = 1101, ID_LOW = 1102, ID_DIG = 1103;
    const int ID_L_LEN = 1004, ID_MIN = 1201, ID_MAX = 1202, ID_L_TO = 1005;
    const int ID_START = 1301, ID_STOP = 1302;
    const int ID_LAB_LEN = 1401, ID_LAB_TRIED = 1402, ID_LAB_SPEED = 1403, ID_LAB_STATUS = 1404;
    const int ID_L_RESULT = 1006, ID_RESULT = 1501, ID_COPY = 1502;
    const int ID_NOTE = 1601;

    const string APP_NAME = "ZipCrackerN - ZIP 密码恢复工具";

    static App _app;
    static readonly Win.WndProc _wndProcRoot = WndProcEntry;
    static readonly Win.SUBCLASSPROC _editSubclassRoot = EditSubclassProc;
    IntPtr hWnd;
    IntPtr hFont;
    IntPtr pathEdit, browseBtn, upBox, lowBox, digBox, minEdit, maxEdit, upMin, upMax, startBtn, stopBtn;
    IntPtr hIconBig, hIconSmall;
    bool iconBigOwned, iconSmallOwned;
    IntPtr labLen, labTried, labSpeed, labStatus, resultEdit, copyBtn;
    double scale = 1.0;

    Thread worker;
    volatile bool stopFlag;
    volatile bool finished;
    volatile string foundPwd;
    volatile string statusText = "请选择 ZIP 文件并开始";
    volatile int curLen;
    volatile int threadCount = 1;
    long tried;
    long prevTried;
    DateTime prevTick;

    static int HIWORD(IntPtr w) { return (int)((long)w >> 16) & 0xFFFF; }
    static int LOWORD(IntPtr w) { return (int)((long)w & 0xFFFF); }

    static void LoadAppIcons(out IntPtr big, out IntPtr small, out bool bigOwned, out bool smallOwned)
    {
        big = IntPtr.Zero;
        small = IntPtr.Zero;
        bigOwned = false;
        smallOwned = false;
        string exePath = "";
        try { exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName; }
        catch { }
        if (!string.IsNullOrEmpty(exePath))
        {
            // 优先使用程序目录下的 ICON.ico
            string iconPath = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(exePath), "ICON.ico");
            if (System.IO.File.Exists(iconPath))
            {
                int cx = Win.GetSystemMetrics(Win.SM_CXICON);
                int cy = Win.GetSystemMetrics(Win.SM_CYICON);
                big = Win.LoadImageW(IntPtr.Zero, iconPath, Win.IMAGE_ICON, cx, cy, Win.LR_LOADFROMFILE);
                small = Win.LoadImageW(IntPtr.Zero, iconPath, Win.IMAGE_ICON,
                    Win.GetSystemMetrics(Win.SM_CXSMICON), Win.GetSystemMetrics(Win.SM_CYSMICON), Win.LR_LOADFROMFILE);
                bigOwned = big != IntPtr.Zero;
                smallOwned = small != IntPtr.Zero;
            }
            // 文件不存在时回退到 exe 内嵌图标（编译时的 ICON.ico）
            if (big == IntPtr.Zero || small == IntPtr.Zero)
            {
                IntPtr a = IntPtr.Zero, b = IntPtr.Zero;
                uint n = 0;
                try { n = Win.ExtractIconExW(exePath, 0, out a, out b, 1); }
                catch { a = IntPtr.Zero; b = IntPtr.Zero; }
                if (n > 0)
                {
                    if (big == IntPtr.Zero) { big = a; bigOwned = a != IntPtr.Zero; }
                    else if (a != IntPtr.Zero) Win.DestroyIcon(a);
                    if (small == IntPtr.Zero) { small = b; smallOwned = b != IntPtr.Zero; }
                    else if (b != IntPtr.Zero) Win.DestroyIcon(b);
                }
            }
        }
        if (big == IntPtr.Zero) big = Win.LoadIconW(IntPtr.Zero, new IntPtr(Win.IDI_APPLICATION));
        if (small == IntPtr.Zero) small = big;
    }

    [STAThread]
    public static void Main()
    {
        try { Win.SetProcessDpiAwarenessContext(new IntPtr(-4)); }
        catch { try { Win.SetProcessDPIAware(); } catch { } }

        IntPtr inst = Win.GetModuleHandleW(null);
        IntPtr iconBig, iconSmall;
        bool bigOwned, smallOwned;
        LoadAppIcons(out iconBig, out iconSmall, out bigOwned, out smallOwned);

        Win.WNDCLASSEXW wc = new Win.WNDCLASSEXW();
        wc.cbSize = (uint)Marshal.SizeOf(typeof(Win.WNDCLASSEXW));
        wc.style = 0;
        wc.lpfnWndProc = _wndProcRoot;
        wc.hInstance = inst;
        wc.hIcon = iconBig != IntPtr.Zero ? iconBig : Win.LoadIconW(IntPtr.Zero, new IntPtr(Win.IDI_APPLICATION));
        wc.hCursor = Win.LoadCursorW(IntPtr.Zero, new IntPtr(32512));
        wc.hbrBackground = new IntPtr(Win.COLOR_BTNFACE + 1);
        wc.lpszClassName = "ZipCrackerNMainWnd";
        wc.hIconSm = iconSmall != IntPtr.Zero ? iconSmall : wc.hIcon;
        if (Win.RegisterClassExW(ref wc) == 0) return;

        _app = new App();
        _app.hIconBig = iconBig;
        _app.hIconSmall = iconSmall;
        _app.iconBigOwned = bigOwned;
        _app.iconSmallOwned = smallOwned;
        _app.hWnd = Win.CreateWindowExW(0, "ZipCrackerNMainWnd", APP_NAME, Win.WS_OVERLAPPED | Win.WS_CAPTION | Win.WS_SYSMENU | Win.WS_MINIMIZEBOX | Win.WS_VISIBLE,
            80, 80, 560, 470, IntPtr.Zero, IntPtr.Zero, inst, IntPtr.Zero);
        if (_app.hWnd == IntPtr.Zero) return;
        if (_app.hIconBig != IntPtr.Zero) Win.SendMessageW(_app.hWnd, Win.WM_SETICON, (IntPtr)Win.ICON_BIG, _app.hIconBig);
        if (_app.hIconSmall != IntPtr.Zero) Win.SendMessageW(_app.hWnd, Win.WM_SETICON, (IntPtr)Win.ICON_SMALL, _app.hIconSmall);
        Win.INITCOMMONCONTROLSEX icc = new Win.INITCOMMONCONTROLSEX();
        icc.dwSize = Marshal.SizeOf(typeof(Win.INITCOMMONCONTROLSEX));
        icc.dwICC = Win.ICC_UPDOWN_CLASS;
        Win.InitCommonControlsEx(ref icc);
        _app.CreateControls();
        _app.ApplyFont();
        _app.Layout();
        Win.ShowWindow(_app.hWnd, 1);
        Win.UpdateWindow(_app.hWnd);
        Win.SetTimer(_app.hWnd, 1, 200, IntPtr.Zero);

        string[] argv = Environment.GetCommandLineArgs();
        if (argv.Length >= 3 && argv[1] == "--selftest")
        {
            _app.RunSelfTest(argv[2], argv.Length >= 4 ? argv[3] : null, argv.Length >= 5 ? argv[4] : "low");
            return;
        }

        Win.MSG msg;
        while (Win.GetMessageW(out msg, IntPtr.Zero, 0, 0) > 0)
        {
            Win.TranslateMessage(ref msg);
            Win.DispatchMessageW(ref msg);
        }
    }

    static IntPtr WndProcEntry(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (_app != null && _app.hWnd == hWnd) return _app.WndProc(hWnd, msg, wParam, lParam);
        return Win.DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    static IntPtr EditSubclassProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam, UIntPtr uIdSubclass, UIntPtr dwRefData)
    {
        if (msg == Win.WM_DROPFILES)
        {
            if (_app != null) _app.HandleDrop(wParam);
            return IntPtr.Zero;
        }
        return Win.DefSubclassProc(hWnd, msg, wParam, lParam);
    }

    void HandleDrop(IntPtr hDrop)
    {
        try
        {
            uint count = Win.DragQueryFileW(hDrop, 0xFFFFFFFFu, null, 0);
            if (count > 0)
            {
                uint len = Win.DragQueryFileW(hDrop, 0, null, 0);
                StringBuilder sb = new StringBuilder((int)len + 2);
                Win.DragQueryFileW(hDrop, 0, sb, (uint)sb.Capacity);
                Win.SetWindowTextW(pathEdit, sb.ToString());
            }
        }
        finally
        {
            Win.DragFinish(hDrop);
        }
    }

    IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        switch (msg)
        {
            case Win.WM_COMMAND:
                int id = LOWORD(wParam);
                int code = HIWORD(wParam);
                if (code == Win.BN_CLICKED) OnClick(id);
                return IntPtr.Zero;
            case Win.WM_TIMER:
                if (wParam == (IntPtr)1) OnTick();
                return IntPtr.Zero;
            case Win.WM_DROPFILES:
                HandleDrop(wParam);
                return IntPtr.Zero;
            case Win.WM_DPICHANGED:
                {
                    IntPtr lprc = lParam;
                    int l = 0, t = 0, r = 0, b = 0;
                    try
                    {
                        int[] rc = new int[4];
                        Marshal.Copy(lprc, rc, 0, 4);
                        l = rc[0]; t = rc[1]; r = rc[2]; b = rc[3];
                    }
                    catch { }
                    Win.SetWindowPos(hWnd, IntPtr.Zero, l, t, r - l, b - t, Win.SWP_NOZORDER);
                    Layout();
                    ApplyFont();
                    return IntPtr.Zero;
                }
            case Win.WM_CLOSE:
                stopFlag = true;
                Win.DestroyWindow(hWnd);
                return IntPtr.Zero;
            case Win.WM_DESTROY:
                Win.KillTimer(hWnd, 1);
                if (hFont != IntPtr.Zero) Win.DeleteObject(hFont);
                if (iconBigOwned && hIconBig != IntPtr.Zero) { Win.DestroyIcon(hIconBig); hIconBig = IntPtr.Zero; }
                if (iconSmallOwned && hIconSmall != IntPtr.Zero) { Win.DestroyIcon(hIconSmall); hIconSmall = IntPtr.Zero; }
                Win.PostQuitMessage(0);
                return IntPtr.Zero;
        }
        return Win.DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    void CreateControls()
    {
        IntPtr inst = Win.GetModuleHandleW(null);
        MakeStatic("压缩包", 10, 12, 60, 18, ID_L_PATH);
        pathEdit = Win.CreateWindowExW(Win.WS_EX_LEFT, "EDIT", "", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.ES_AUTOHSCROLL | Win.WS_BORDER,
            80, 10, 370, 24, hWnd, (IntPtr)ID_PATH, inst, IntPtr.Zero);
        browseBtn = Win.CreateWindowExW(0, "BUTTON", "浏览…", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_PUSHBUTTON,
            460, 10, 90, 24, hWnd, (IntPtr)ID_BROWSE, inst, IntPtr.Zero);
        Win.DragAcceptFiles(hWnd, true);
        Win.DragAcceptFiles(pathEdit, true);
        Win.SetWindowSubclass(pathEdit, _editSubclassRoot, (UIntPtr)1, UIntPtr.Zero);
        MakeStatic("密码类型", 10, 42, 120, 18, ID_L_CHARSET);
        upBox = Win.CreateWindowExW(0, "BUTTON", "大写字母 (A-Z)", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_AUTOCHECKBOX,
            18, 62, 150, 20, hWnd, (IntPtr)ID_UP, inst, IntPtr.Zero);
        lowBox = Win.CreateWindowExW(0, "BUTTON", "小写字母 (a-z)", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_AUTOCHECKBOX,
            190, 62, 150, 20, hWnd, (IntPtr)ID_LOW, inst, IntPtr.Zero);
        digBox = Win.CreateWindowExW(0, "BUTTON", "数字 (0-9)", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_AUTOCHECKBOX,
            362, 62, 120, 20, hWnd, (IntPtr)ID_DIG, inst, IntPtr.Zero);
        Win.SendMessageW(lowBox, Win.BM_SETCHECK, (IntPtr)Win.BST_CHECKED, IntPtr.Zero);
        MakeStatic("密码长度", 10, 88, 70, 18, ID_L_LEN);
        minEdit = Win.CreateWindowExW(Win.WS_EX_LEFT, "EDIT", "1", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.ES_NUMBER | Win.WS_BORDER,
            90, 86, 50, 22, hWnd, (IntPtr)ID_MIN, inst, IntPtr.Zero);
        upMin = Win.CreateWindowExW(0, "msctls_updown32", "", Win.WS_CHILD | Win.WS_VISIBLE | Win.UDS_ALIGNRIGHT | Win.UDS_SETBUDDYINT | Win.UDS_AUTOBUDDY | Win.UDS_ARROWKEYS | Win.UDS_NOTHOUSANDS,
            0, 0, 0, 0, hWnd, IntPtr.Zero, inst, IntPtr.Zero);
        Win.SendMessageW(upMin, Win.UDM_SETRANGE32, (IntPtr)1, (IntPtr)12);
        Win.SendMessageW(upMin, Win.UDM_SETPOS32, IntPtr.Zero, (IntPtr)1);
        MakeStatic("到", 148, 88, 20, 18, ID_L_TO);
        maxEdit = Win.CreateWindowExW(Win.WS_EX_LEFT, "EDIT", "4", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.ES_NUMBER | Win.WS_BORDER,
            172, 86, 50, 22, hWnd, (IntPtr)ID_MAX, inst, IntPtr.Zero);
        upMax = Win.CreateWindowExW(0, "msctls_updown32", "", Win.WS_CHILD | Win.WS_VISIBLE | Win.UDS_ALIGNRIGHT | Win.UDS_SETBUDDYINT | Win.UDS_AUTOBUDDY | Win.UDS_ARROWKEYS | Win.UDS_NOTHOUSANDS,
            0, 0, 0, 0, hWnd, IntPtr.Zero, inst, IntPtr.Zero);
        Win.SendMessageW(upMax, Win.UDM_SETRANGE32, (IntPtr)1, (IntPtr)12);
        Win.SendMessageW(upMax, Win.UDM_SETPOS32, IntPtr.Zero, (IntPtr)4);
        startBtn = Win.CreateWindowExW(0, "BUTTON", "开始破解", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_PUSHBUTTON,
            18, 118, 120, 30, hWnd, (IntPtr)ID_START, inst, IntPtr.Zero);
        stopBtn = Win.CreateWindowExW(0, "BUTTON", "停止", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_PUSHBUTTON,
            150, 118, 120, 30, hWnd, (IntPtr)ID_STOP, inst, IntPtr.Zero);
        Win.EnableWindow(stopBtn, false);
        labLen = MakeStatic("当前长度：-", 18, 162, 520, 18, ID_LAB_LEN);
        labTried = MakeStatic("已尝试：0", 18, 184, 520, 18, ID_LAB_TRIED);
        labSpeed = MakeStatic("速度：0 个/秒", 18, 206, 520, 18, ID_LAB_SPEED);
        labStatus = MakeStatic(statusText, 18, 228, 520, 18, ID_LAB_STATUS);
        MakeStatic("密码：", 18, 258, 520, 18, ID_L_RESULT);
        resultEdit = Win.CreateWindowExW(Win.WS_EX_LEFT, "EDIT", "", Win.WS_CHILD | Win.WS_VISIBLE | Win.ES_READONLY | Win.ES_AUTOHSCROLL | Win.WS_BORDER,
            18, 278, 430, 24, hWnd, (IntPtr)ID_RESULT, inst, IntPtr.Zero);
        copyBtn = Win.CreateWindowExW(0, "BUTTON", "复制密码", Win.WS_CHILD | Win.WS_VISIBLE | Win.WS_TABSTOP | Win.BS_PUSHBUTTON,
            460, 278, 90, 24, hWnd, (IntPtr)ID_COPY, inst, IntPtr.Zero);
        Win.EnableWindow(copyBtn, false);
        MakeStatic("用于找回自己遗忘密码的压缩包，请勿用于非法用途。", 18, 316, 520, 18, ID_NOTE);
    }

    IntPtr MakeStatic(string text, int x, int y, int w, int h, int id)
    {
        return Win.CreateWindowExW(0, "STATIC", text, Win.WS_CHILD | Win.WS_VISIBLE,
            x, y, w, h, hWnd, (IntPtr)id, Win.GetModuleHandleW(null), IntPtr.Zero);
    }

    IntPtr Ctl(int id) { return Win.GetDlgItem(hWnd, id); }

    void ApplyFont()
    {
        if (hFont != IntPtr.Zero) { Win.DeleteObject(hFont); hFont = IntPtr.Zero; }
        Win.NONCLIENTMETRICSW ncm = new Win.NONCLIENTMETRICSW();
        ncm.cbSize = Marshal.SizeOf(typeof(Win.NONCLIENTMETRICSW));
        if (Win.SystemParametersInfoW(Win.SPI_GETNONCLIENTMETRICS, 0, ref ncm, 0))
        {
            hFont = Win.CreateFontIndirectW(ref ncm.lfMessageFont);
        }
        if (hFont == IntPtr.Zero) return;
        int[] ids = { ID_L_PATH, ID_PATH, ID_BROWSE, ID_L_CHARSET, ID_UP, ID_LOW, ID_DIG, ID_L_LEN, ID_MIN, ID_L_TO,
            ID_MAX, ID_START, ID_STOP, ID_LAB_LEN, ID_LAB_TRIED, ID_LAB_SPEED, ID_LAB_STATUS, ID_L_RESULT, ID_RESULT, ID_COPY, ID_NOTE };
        foreach (int id in ids)
        {
            IntPtr h = Ctl(id);
            if (h != IntPtr.Zero) Win.SendMessageW(h, Win.WM_SETFONT, hFont, (IntPtr)1);
        }
    }

    int Dpi()
    {
        string fake = Environment.GetEnvironmentVariable("ZIPCC_FAKE_DPI");
        int fd;
        if (!string.IsNullOrEmpty(fake) && int.TryParse(fake, out fd) && fd > 0) return fd;
        try
        {
            uint d = Win.GetDpiForWindow(hWnd);
            if (d > 0) return (int)d;
        }
        catch { }
        IntPtr dc = Win.GetDC(IntPtr.Zero);
        if (dc == IntPtr.Zero) return 96;
        int v = Win.GetDeviceCaps(dc, Win.LOGPIXELSX);
        Win.ReleaseDC(IntPtr.Zero, dc);
        return v > 0 ? v : 96;
    }

    void Layout()
    {
        int dpi = Dpi();
        double sc = dpi / 96.0;
        int workW = Win.GetSystemMetrics(Win.SM_CXSCREEN);
        int workH = Win.GetSystemMetrics(Win.SM_CYSCREEN);
        // 不让窗口变成“全屏”：宽不超过 82%、高不超过 85%，并居中
        double capW = (workW * 0.82) / 560.0;
        double capH = (workH * 0.85) / 470.0;
        double s = Math.Min(sc, Math.Min(capW, capH));
        if (s < 0.4) s = 0.4;
        scale = s;
        Move(Ctl(ID_L_PATH), 10, 12, 60, 18);
        Move(pathEdit, 80, 10, 370, 24);
        Move(browseBtn, 460, 10, 90, 24);
        Move(Ctl(ID_L_CHARSET), 10, 42, 120, 18);
        Move(upBox, 18, 62, 150, 20);
        Move(lowBox, 190, 62, 150, 20);
        Move(digBox, 362, 62, 120, 20);
        Move(Ctl(ID_L_LEN), 10, 88, 70, 18);
        Move(minEdit, 90, 86, 50, 22);
        Win.SendMessageW(upMin, Win.UDM_SETBUDDY, minEdit, IntPtr.Zero);
        Move(Ctl(ID_L_TO), 148, 88, 20, 18);
        Move(maxEdit, 172, 86, 50, 22);
        Win.SendMessageW(upMax, Win.UDM_SETBUDDY, maxEdit, IntPtr.Zero);
        Move(startBtn, 18, 118, 120, 30);
        Move(stopBtn, 150, 118, 120, 30);
        Move(labLen, 18, 162, 520, 18);
        Move(labTried, 18, 184, 520, 18);
        Move(labSpeed, 18, 206, 520, 18);
        Move(labStatus, 18, 228, 520, 18);
        Move(Ctl(ID_L_RESULT), 18, 258, 520, 18);
        Move(resultEdit, 18, 278, 430, 24);
        Move(copyBtn, 460, 278, 90, 24);
        Move(Ctl(ID_NOTE), 18, 316, 520, 18);
        int ww = (int)(560 * s), hh = (int)(470 * s);
        int wx = (workW - ww) / 2, wy = (workH - hh) / 2;
        if (wx < 0) wx = 0;
        if (wy < 0) wy = 0;
        Win.SetWindowPos(hWnd, IntPtr.Zero, wx, wy, ww, hh, Win.SWP_NOZORDER);
    }

    void Move(IntPtr h, int x, int y, int w, int hgt)
    {
        if (h == IntPtr.Zero) return;
        Win.SetWindowPos(h, IntPtr.Zero, (int)(x * scale), (int)(y * scale), (int)(w * scale), (int)(hgt * scale), Win.SWP_NOZORDER);
    }

    string GetText(IntPtr h)
    {
        StringBuilder sb = new StringBuilder(1024);
        Win.SendMessageW(h, Win.WM_GETTEXT, (IntPtr)1024, sb);
        return sb.ToString();
    }

    bool IsChecked(IntPtr h)
    {
        return Win.SendMessageW(h, Win.BM_GETCHECK, IntPtr.Zero, IntPtr.Zero) == (IntPtr)Win.BST_CHECKED;
    }



    void OnClick(int id)
    {
        switch (id)
        {
            case ID_BROWSE:
                Browse();
                break;
            case ID_START:
                StartBrute();
                break;
            case ID_STOP:
                stopFlag = true;
                statusText = "正在停止…";
                break;
            case ID_COPY:
                CopyResult();
                break;
        }
    }

    void Browse()
    {
        using (System.Windows.Forms.OpenFileDialog dlg = new System.Windows.Forms.OpenFileDialog())
        {
            dlg.Filter = "ZIP 压缩包 (*.zip)|*.zip|所有文件 (*.*)|*.*";
            dlg.Title = "选择 ZIP 文件";
            dlg.CheckFileExists = true;
            if (dlg.ShowDialog(new Win32Owner(hWnd)) == System.Windows.Forms.DialogResult.OK)
            {
                Win.SetWindowTextW(pathEdit, dlg.FileName);
            }
        }
    }

    void StartBrute()
    {
        if (worker != null && worker.IsAlive) return;
        string path = GetText(pathEdit).Trim();
        if (path.Length == 0 || !System.IO.File.Exists(path))
        {
            Win.MessageBoxW(hWnd, "请先选择一个存在的 ZIP 文件", APP_NAME, Win.MB_OK | Win.MB_ICONWARNING);
            return;
        }
        StringBuilder cs = new StringBuilder();
        if (IsChecked(upBox)) cs.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (IsChecked(lowBox)) cs.Append("abcdefghijklmnopqrstuvwxyz");
        if (IsChecked(digBox)) cs.Append("0123456789");
        if (cs.Length == 0)
        {
            Win.MessageBoxW(hWnd, "请至少勾选一个密码类型（大写字母 / 小写字母 / 数字）", APP_NAME, Win.MB_OK | Win.MB_ICONWARNING);
            return;
        }
        int minLen, maxLen;
        if (!int.TryParse(GetText(minEdit), out minLen) || !int.TryParse(GetText(maxEdit), out maxLen)
            || minLen < 1 || maxLen < minLen || maxLen > 12)
        {
            Win.MessageBoxW(hWnd, "密码长度范围不正确（1 ≤ 最小 ≤ 最大 ≤ 12）", APP_NAME, Win.MB_OK | Win.MB_ICONWARNING);
            return;
        }
        if (cs.Length > 36 && maxLen > 6)
        {
            int r = Win.MessageBoxW(hWnd, "密码类型较多且长度较长，破解可能耗时很久，继续吗？", APP_NAME, Win.MB_YESNO | Win.MB_ICONWARNING);
            if (r != Win.IDYES) return;
        }
        ZipTarget target;
        try { target = new ZipTarget(path); }
        catch (Exception ex)
        {
            Win.MessageBoxW(hWnd, "无法打开压缩包：" + ex.Message, APP_NAME, Win.MB_OK | Win.MB_ICONERROR);
            return;
        }
        if (target.Unsupported.Length > 0)
        {
            Win.MessageBoxW(hWnd, target.Unsupported, APP_NAME, Win.MB_OK | Win.MB_ICONWARNING);
            return;
        }
        if (target.Aes)
        {
            Win.MessageBoxW(hWnd, "该压缩包使用 WinZip AES 加密，本工具暂不支持", APP_NAME, Win.MB_OK | Win.MB_ICONWARNING);
            return;
        }

        stopFlag = false;
        finished = false;
        foundPwd = null;
        curLen = 0;
        int tc = Environment.ProcessorCount;
        if (tc < 1) tc = 1;
        if (tc > 32) tc = 32;
        threadCount = tc;
        Interlocked.Exchange(ref tried, 0L);
        prevTried = 0;
        prevTick = DateTime.UtcNow;
        statusText = "已开始（" + threadCount + " 线程）";
        Win.SetWindowTextW(resultEdit, "");
        Win.EnableWindow(copyBtn, false);
        Win.EnableWindow(startBtn, false);
        Win.EnableWindow(stopBtn, true);

        string charset = cs.ToString();
        worker = new Thread(delegate()
        {
            string found = null;
            try
            {
                found = Brute.Run(target, charset, minLen, maxLen, delegate() { return stopFlag; },
                    delegate(int L, long n)
                    {
                        if (L > 0) curLen = L;
                        // 多线程回调可能乱序到达，只允许尝试次数单调递增
                        if (n > Interlocked.Read(ref tried)) Interlocked.Exchange(ref tried, n);
                    },
                    threadCount);
            }
            catch (Exception ex)
            {
                foundPwd = null;
                statusText = "破解出错：" + ex.Message;
                finished = true;
                return;
            }
            foundPwd = found;
            if (found != null) statusText = "已找到密码";
            else if (stopFlag) statusText = "已停止";
            else statusText = "未找到密码（请增大长度范围或勾选更多密码类型）";
            finished = true;
        });
        worker.IsBackground = true;
        worker.Start();
    }

    void OnTick()
    {
        DateTime now = DateTime.UtcNow;
        double dt = (now - prevTick).TotalSeconds;
        long n = Interlocked.Read(ref tried);
        if (dt > 0.1)
        {
            long speed = (long)((n - prevTried) / dt);
            Win.SetWindowTextW(labSpeed, "速度：" + speed + " 个/秒");
            prevTried = n;
            prevTick = now;
        }
        Win.SetWindowTextW(labLen, threadCount > 1
            ? "当前长度：多线程（" + threadCount + " 线程）"
            : (curLen > 0 ? "当前长度：" + curLen : "当前长度：-"));
        Win.SetWindowTextW(labTried, "已尝试：" + n);
        Win.SetWindowTextW(labStatus, "状态：" + statusText);
        if (finished)
        {
            if (foundPwd != null)
            {
                statusText = "已找到密码";
                Win.SetWindowTextW(resultEdit, foundPwd);
                Win.EnableWindow(copyBtn, true);
            }
            else if (stopFlag) statusText = "已停止";
            Win.SetWindowTextW(labStatus, "状态：" + statusText);
            Win.EnableWindow(startBtn, true);
            Win.EnableWindow(stopBtn, false);
            worker = null; // 释放对目标数据/线程委托的引用，降低内存占用
            finished = false;
        }
    }



    sealed class Win32Owner : System.Windows.Forms.IWin32Window
    {
        readonly IntPtr _h;
        public Win32Owner(IntPtr h) { _h = h; }
        public IntPtr Handle { get { return _h; } }
    }

    static IntPtr MakeDrop(string path)
    {
        Win.DROPFILES df = new Win.DROPFILES();
        int hdr = Marshal.SizeOf(typeof(Win.DROPFILES));
        byte[] name = Encoding.Unicode.GetBytes(path + "\0");
        int size = hdr + name.Length;
        IntPtr mem = Win.GlobalAlloc(Win.GHND, (UIntPtr)size);
        IntPtr p = Win.GlobalLock(mem);
        df.pFiles = (uint)hdr;
        df.fWide = 1;
        Marshal.StructureToPtr(df, p, false);
        Marshal.Copy(name, 0, (IntPtr)((long)p + hdr), name.Length);
        Win.GlobalUnlock(mem);
        return mem;
    }

    internal void RunSelfTest(string zip, string outFile, string mode)
    {
        string m = string.IsNullOrEmpty(mode) ? "low" : mode;
        bool chkUp = (m == "up" || m == "all" || m == "updig");
        bool chkLow = (m == "low" || m == "all" || m == "lowdig");
        bool chkDig = (m == "dig" || m == "all" || m == "lowdig" || m == "updig");
        Win.SendMessageW(upBox, Win.BM_SETCHECK, (IntPtr)(chkUp ? Win.BST_CHECKED : Win.BST_UNCHECKED), IntPtr.Zero);
        Win.SendMessageW(lowBox, Win.BM_SETCHECK, (IntPtr)(chkLow ? Win.BST_CHECKED : Win.BST_UNCHECKED), IntPtr.Zero);
        Win.SendMessageW(digBox, Win.BM_SETCHECK, (IntPtr)(chkDig ? Win.BST_CHECKED : Win.BST_UNCHECKED), IntPtr.Zero);
        Win.SetWindowTextW(pathEdit, "");
        IntPtr hDrop = MakeDrop(zip);
        Win.SendMessageW(pathEdit, Win.WM_DROPFILES, hDrop, IntPtr.Zero);
        Thread.Sleep(100);
        string droppedPath = GetText(pathEdit);
        Win.SetWindowTextW(pathEdit, zip);
        Win.SetWindowTextW(minEdit, "1");
        Win.SetWindowTextW(maxEdit, "4");
        Win.SendMessageW(upMax, Win.UDM_SETPOS32, IntPtr.Zero, (IntPtr)6);
        Thread.Sleep(80);
        string spinCheck = GetText(maxEdit);
        Win.SendMessageW(upMax, Win.UDM_SETPOS32, IntPtr.Zero, (IntPtr)4);
        Win.SendMessageW(startBtn, 0x00F5, IntPtr.Zero, IntPtr.Zero); // 模拟点击“开始破解”
        for (int i = 0; i < 200; i++)
        {
            Thread.Sleep(100);
            if (foundPwd != null || finished) break;
        }
        string res = foundPwd != null ? "密码：" + foundPwd : "未找到";
        OnTick();
        string shown = GetText(resultEdit);
        if (!string.IsNullOrEmpty(outFile))
        {
            try { System.IO.File.WriteAllText(outFile, res + "|" + shown + "|" + droppedPath + "|spin=" + spinCheck + "|th=" + threadCount + "|" + statusText, Encoding.UTF8); } catch { }
        }
    }

    void CopyResult()
    {
        string text = GetText(resultEdit);
        if (text.Length == 0) return;
        if (Win.OpenClipboard(hWnd))
        {
            Win.EmptyClipboard();
            byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
            IntPtr mem = Win.GlobalAlloc(Win.GHND, (UIntPtr)(bytes.Length));
            if (mem != IntPtr.Zero)
            {
                IntPtr p = Win.GlobalLock(mem);
                Marshal.Copy(bytes, 0, p, bytes.Length);
                Win.GlobalUnlock(mem);
                Win.SetClipboardData(Win.CF_UNICODETEXT, mem);
            }
            Win.CloseClipboard();
        }
        statusText = "密码已复制到剪贴板";
    }
}
