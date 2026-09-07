package sbx;
import java.util.*;
public class Log {
    public static final List<String> EVENTS = Collections.synchronizedList(new ArrayList<>());
    static final Set<String> DEDUPE = Collections.synchronizedSet(new LinkedHashSet<>());
    public static volatile boolean quiet = false;
    public static int fileReads = 0, denied = 0;
    public static synchronized void ev(String kind, String detail) {
        if (quiet) return;
        String line = "[" + kind + "] " + detail;
        if (DEDUPE.add(line) && DEDUPE.size() < 600) EVENTS.add(line);
    }
}
