package androidx.appcompat.app;
import sbx.Log;
public class AppCompatActivity {
    public String getPackageName() { Log.ev("STUB", "activity.getPackageName()"); return "com.skt.skaf.syrup"; }
    public void runOnUiThread(Runnable r) { android.os.Handler.depth = android.os.Handler.depth; Log.ev("STUB", "activity.runOnUiThread(Runnable)"); try { r.run(); } catch (Throwable t) { Log.ev("RUNNABLE-EX", t.getClass().getSimpleName()); } }
    public void finish() { Log.ev("STUB", "activity.finish()"); }
    public void startActivity(android.content.Intent i) { Log.ev("STUB", "activity.startActivity(" + i + ")"); }
}
