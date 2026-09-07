package android.widget;
import sbx.Log;
public class Toast {
    public static final int LENGTH_SHORT = 0, LENGTH_LONG = 1;
    public static Toast makeText(android.content.Context c, String msg, int dur) { Log.ev("STUB", "toast.makeText(" + (msg == null ? "null" : msg.length() > 80 ? msg.substring(0, 80) + "…" : msg) + ")"); return new Toast(); }
    public void show() { Log.ev("STUB", "toast.show()"); }
}
