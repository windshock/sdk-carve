package android.content;
import sbx.Log;
public class Context {
    public SharedPreferences getSharedPreferences(String n, int m) { Log.ev("STUB", "context.getSharedPreferences(" + n + ")"); return new SharedPreferences(); }
    public String getPackageName() { Log.ev("STUB", "context.getPackageName()"); return "com.skt.skaf.syrup"; }
    public void startActivity(Intent i) { Log.ev("STUB", "context.startActivity(" + i + ")"); }
}
