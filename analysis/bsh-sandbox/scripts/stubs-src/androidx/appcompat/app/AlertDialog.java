package androidx.appcompat.app;
import sbx.Log;
import android.content.DialogInterface;
public class AlertDialog {
    public void show() { Log.ev("STUB", "dialog.show()"); }
    public void dismiss() { Log.ev("STUB", "dialog.dismiss()"); }
    public static class Builder {
        public Builder(android.content.Context c) { Log.ev("STUB", "dialog.Builder()"); }
        public Builder setTitle(CharSequence t) { Log.ev("STUB", "dialog.setTitle(" + t + ")"); return this; }
        public Builder setMessage(CharSequence m) { Log.ev("STUB", "dialog.setMessage(" + (m == null ? "null" : m.toString().length() > 80 ? m.toString().substring(0, 80) + "…" : m.toString()) + ")"); return this; }
        public Builder setPositiveButton(String t, DialogInterface.OnClickListener l) { Log.ev("STUB", "dialog.setPositiveButton(" + t + ")"); return this; }
        public Builder setCancelable(boolean b) { Log.ev("STUB", "dialog.setCancelable(" + b + ")"); return this; }
        public AlertDialog show() { Log.ev("STUB", "dialog.show()"); return new AlertDialog(); }
    }
}
