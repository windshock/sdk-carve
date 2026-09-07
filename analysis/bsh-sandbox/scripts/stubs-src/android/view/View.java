package android.view;
import sbx.Log;
public class View {
    public static final int VISIBLE = 0, INVISIBLE = 4, GONE = 8;
    public void setVisibility(int v) { Log.ev("STUB", "view.setVisibility(" + v + ")"); }
    public int getVisibility() { return 0; }
}
