package android.content;
import sbx.Log;
import android.net.Uri;
public class Intent {
    public static final String ACTION_VIEW = "android.intent.action.VIEW";
    public Intent(String action, Uri u) { Log.ev("STUB", "new Intent(" + action + ", " + (u == null ? "null" : u.toString()) + ")"); }
    public Intent() {}
    public String toString() { return "Intent(stub)"; }
}
