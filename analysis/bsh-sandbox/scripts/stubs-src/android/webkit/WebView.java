package android.webkit;
import sbx.Log;
public class WebView extends android.view.View {
    String id, url = "";
    public WebView() { this.id = "webview"; }
    public WebView(String id) { this.id = id; }
    public void loadUrl(String u) { url = u; Log.ev("STUB", id + ".loadUrl(" + (u.length() > 140 ? u.substring(0, 140) + "…" : u) + ")"); }
    public String getUrl() { return url; }
    public WebSettings getSettings() { return new WebSettings(); }
    public void setWebViewClient(Object c) { Log.ev("STUB", id + ".setWebViewClient(...)"); }
    public void setWebChromeClient(Object c) { Log.ev("STUB", id + ".setWebChromeClient(...)"); }
    public void stopLoading() { Log.ev("STUB", id + ".stopLoading()"); }
    public void loadUrl(String u, java.util.Map<String, String> h) { Log.ev("STUB", id + ".loadUrl(headers=" + (h == null ? "null" : h.keySet()) + ")"); loadUrl(u); }
}
