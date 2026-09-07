package android.util;
public class Log {
    public static int d(String tag, String msg) { sbx.Log.ev("LOG", tag + ": " + msg); return 0; }
    public static int e(String tag, String msg) { sbx.Log.ev("LOG-E", tag + ": " + msg); return 0; }
    public static int w(String tag, String msg) { sbx.Log.ev("LOG-W", tag + ": " + msg); return 0; }
}
