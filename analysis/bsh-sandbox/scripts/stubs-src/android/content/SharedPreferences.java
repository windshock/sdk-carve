package android.content;
import sbx.Log;
public class SharedPreferences {
    public String getString(String k, String d) { Log.ev("STUB", "prefs.getString(" + k + ")"); return ""; }
    public void putString(String k, String v) { Log.ev("STUB", "prefs.putString(" + k + ")"); }
    public int getInt(String k, int d) { Log.ev("STUB", "prefs.getInt(" + k + ")"); return 0; }
    public boolean getBoolean(String k, boolean d) { Log.ev("STUB", "prefs.getBoolean(" + k + ")"); return false; }
    public boolean contains(String k) { Log.ev("STUB", "prefs.contains(" + k + ")"); return false; }
}
