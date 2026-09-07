package android.net;
import sbx.Log;
public class Uri {
    String s;
    Uri(String s) { this.s = s; }
    public static Uri parse(String s) { return new Uri(s); }
    public Builder buildUpon() { return new Builder(); }
    public String getQueryParameter(String k) { Log.ev("STUB", "uri.getQueryParameter(" + k + ")"); return "REPLAYTEST"; }
    public String toString() { return s; }
    public static class Builder {
        public Builder appendQueryParameter(String k, String v) { Log.ev("STUB", "uri.appendQueryParameter(" + k + "=" + v + ")"); return this; }
        public Uri build() { return new Uri("https://gad.api.gpakorea.invalid/page/replay"); }
        public String toString() { return build().toString(); }
    }
}
