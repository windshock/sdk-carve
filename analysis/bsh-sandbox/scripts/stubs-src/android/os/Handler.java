package android.os;
import sbx.Log;
public class Handler {
    public static int depth = 0;
    public boolean post(final Runnable r) { Log.ev("STUB", "handler.post(Runnable)"); return runDeep(r); }
    public boolean postDelayed(final Runnable r, long ms) { Log.ev("STUB", "handler.postDelayed(delay=" + ms + ")"); return true; }
    public void removeCallbacksAndMessages(Object t) { Log.ev("STUB", "handler.removeCallbacksAndMessages"); }
    static boolean runDeep(Runnable r) {
        if (depth > 3) { Log.ev("LIMIT", "runnable depth>3 skipped"); return true; }
        depth++;
        try { r.run(); } catch (Throwable t) { Log.ev("RUNNABLE-EX", t.getClass().getSimpleName() + ": " + t.getMessage()); }
        finally { depth--; }
        return true;
    }
}
