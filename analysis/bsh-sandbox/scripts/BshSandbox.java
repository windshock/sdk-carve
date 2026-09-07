import bsh.EvalError;
import bsh.Interpreter;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;

/**
 * bsh-sandbox — GPA GAD 서버 스크립트 초경량 JVM 캐퍼빌리티 리플레이 (Level 1).
 *
 * JDK 17 + SecurityManager 감시(NET/EXEC/EXIT/FILE-W는 기록 후 DENY, 클래스로드는 기록만)
 * + 최소 Android/gad 스텁 클래스(stubs-src/) 주입. 서버 스크립트를 eval 후 관측된 훅을
 * 재호출하여 무엇을 시도하는지 JSON으로 기록한다. 도메인은 .invalid로 치환돼 우발 도달 차단.
 *
 * Usage: java -cp classes:bsh-2.0b5.jar BshSandbox <script.bsh> <out.json>
 */
public class BshSandbox {

    static class SbxSM extends SecurityManager {
        @Override public void checkPermission(Permission p) {
            if (sbx.Log.quiet) return;
            String n = p.getName() == null ? "" : p.getName();
            if (p instanceof java.net.SocketPermission) {
                sbx.Log.ev("NET-DENY", p.getActions() + " " + n); sbx.Log.denied++;
                throw new SecurityException("sandbox-deny-net");
            }
            if (p instanceof java.io.FilePermission) {
                if (p.getActions().contains("write") || p.getActions().contains("delete")) {
                    sbx.Log.ev("FILE-WRITE-DENY", n); sbx.Log.denied++;
                    throw new SecurityException("sandbox-deny-filewrite");
                }
                if (p.getActions().contains("read")) {
                    sbx.Log.fileReads++;
                    if ((n.contains("/Users/") || n.contains("Documents") || n.contains("Desktop"))
                            && !n.contains("bsh-sandbox")) sbx.Log.ev("FILE-READ", n);
                }
                return; // read 허용 — JDK/bsh 내부 리소스 접근 필요
            }
            if (n.startsWith("exitVM")) { sbx.Log.ev("EXIT-DENY", n); sbx.Log.denied++; throw new SecurityException("sandbox-deny-exit"); }
            if (n.equals("setSecurityManager")) {
                // 하니스 main의 직접 호출(설치/해제)만 허용, bsh(스크립트) 경유는 조작 시도로 거부
                Class direct = null;
                for (Class k : getClassContext()) {
                    String kn = k.getName();
                    if (kn.startsWith("java.") || kn.startsWith("jdk.") || kn.startsWith("BshSandbox$") || kn.equals("sbx.Log")) continue;
                    direct = k; break;
                }
                if (direct == BshSandbox.class) return;
                sbx.Log.ev("SM-TAMPER", "setSecurityManager via " + (direct == null ? "?" : direct.getName())); sbx.Log.denied++;
                throw new SecurityException("sandbox-keep-sm");
            }
            // 나머지 RuntimePermission/PropertyPermission 등은 허용 (트리이지 방해 금지)
        }
        @Override public void checkPackageAccess(String pkg) { sbx.Log.ev("CLASS", pkg); }
        @Override public void checkExec(String cmd) { sbx.Log.ev("EXEC-DENY", cmd); sbx.Log.denied++; throw new SecurityException("sandbox-deny-exec"); }
        @Override public void checkLink(String lib) { sbx.Log.ev("LINK-DENY", lib); sbx.Log.denied++; throw new SecurityException("sandbox-deny-link"); }
    }

    public static void main(String[] args) throws Exception {
        String scriptPath = args[0], outPath = args[1];
        File outF = new File(outPath).getAbsoluteFile();
        if (outF.getParentFile() != null && !outF.getParentFile().exists()) Files.createDirectories(outF.getParentFile().toPath());
        PrintWriter rawLog = new PrintWriter(Files.newBufferedWriter(Paths.get(outPath + ".rawlog"), StandardCharsets.UTF_8));
        String script = new String(Files.readAllBytes(Paths.get(scriptPath)), StandardCharsets.UTF_8);

        List<String> hookResults = new ArrayList<>();
        Interpreter i = new Interpreter();
        i.setStrictJava(true);
        // 관측된 주입 변수 세트 (부트스트랩: action/hold/medal/name/ball · 캠페인: cat/wind/hawaii/apple/vibe/flag/mDialog/mPref)
        android.content.Context cat = new android.content.Context();
        android.webkit.WebView wind = new android.webkit.WebView("wind");
        android.webkit.WebView hawaii = new android.webkit.WebView("hawaii");
        android.os.Handler hold = new android.os.Handler();
        com.gad.sdk.model.Advertisement apple = new com.gad.sdk.model.Advertisement();
        com.gad.sdk.viewmodel.GadViewModel vibe = new com.gad.sdk.viewmodel.GadViewModel();
        com.gad.sdk.viewmodel.GadViewModel medal = new com.gad.sdk.viewmodel.GadViewModel();
        com.gad.sdk.ui.fragment.GadPerformFragment flag = new com.gad.sdk.ui.fragment.GadPerformFragment();
        com.gad.sdk.util.Utils.Names name = new com.gad.sdk.util.Utils.Names();
        System.setSecurityManager(new SbxSM()); // JDK17: deprecated 경고 정상

        boolean evalOk = true;
        String evalErr = null;
        try { i.eval(script); }
        catch (Throwable t) {
            evalOk = false;
            evalErr = t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage());
            if (evalErr.length() > 2500) evalErr = evalErr.substring(0, 2500);
            sbx.Log.ev("EVAL-ERR", evalErr.length() > 160 ? evalErr.substring(0, 160) : evalErr);
        }

        // 바인딩은 eval 이후 — 스크립트 상단의 타입 선언이 변수를 초기화하므로 SDK와 동일 순서.
        // flag는 스크립트별 선언 타입이 다르다(캠페인=GadPerformFragment, 부트스트랩=GadAdListFragment).
        safeSet(i, "cat", cat); safeSet(i, "wind", wind); safeSet(i, "hawaii", hawaii);
        safeSet(i, "hold", hold); safeSet(i, "apple", apple); safeSet(i, "vibe", vibe);
        safeSet(i, "flag", new com.gad.sdk.ui.fragment.GadPerformFragment(), new com.gad.sdk.ui.fragment.GadAdListFragment());
        safeSet(i, "mPref", cat.getSharedPreferences("com.gad.sdk", 0));
        safeSet(i, "mDialog", (Object) null);
        safeSet(i, "action", new androidx.appcompat.app.AppCompatActivity()); safeSet(i, "medal", medal);
        safeSet(i, "name", name); safeSet(i, "ball", new com.gad.sdk.databinding.GadFragmentAdListInnerBinding());

        // 관측된 훅 재호출 — 인자는 실관측 URL 형태(도메인 .invalid 치환)
        String[] urlArgs = {
                "https://gad.api.gpakorea.invalid/page/mission.html?email=replay%40test.invalid&gad_tracking_id=REPLAYTEST",
                "https://accounts.google.com/ServiceLogin/signinchooser?continue=x",
                "https://m.youtube.com/watch?v=REPLAY"
        };
        String[][] hooks = {
                {"prepare", null}, {"setup", null}, {"checkValid", null},
                {"shouldOverrideUrlLoading", urlArgs[0]}, {"onPageStarted", urlArgs[0]},
                {"onLoadResource", urlArgs[0]}, {"onPageFinished", urlArgs[0]},
                {"onPageFinished", urlArgs[1]}, {"onPageFinished", urlArgs[2]},
                {"onPageLoaded", urlArgs[0]}, {"checkParticipation", null},
                {"isValidUrl", null}, {"destroy", null}
        };
        for (String[] h : hooks) {
            String call = h[1] == null ? h[0] + "()" : h[0] + "(\"" + h[1] + "\")";
            try {
                Object r = i.eval(call);
                if (r != null) hookResults.add(call + " -> " + trim(String.valueOf(r)));
            } catch (EvalError e) {
                String m = String.valueOf(e.getMessage());
                try { m += " [line " + e.getErrorLineNumber() + ": " + e.getErrorText() + "]"; } catch (Throwable ignore) {}
                Throwable cc = e.getCause();
                for (int lv = 0; cc != null && lv < 3; lv++) {
                    m += " <== " + cc.getClass().getSimpleName() + ": " + cc.getMessage();
                    cc = cc.getCause();
                }
                if (m.contains("Command not found") || m.contains("not defined") || m.contains("Typed variable")) continue;
                hookResults.add(call + " !! " + (m.length() > 500 ? m.substring(0, 500) : m));
                sbx.Log.ev("HOOK-ERR", call + " :: " + trim(m));
                rawLog.println("==== " + call + " ===="); e.printStackTrace(rawLog); rawLog.flush();
            } catch (Throwable t) {
                hookResults.add(call + " !! " + t.getClass().getSimpleName() + ": " + trim(String.valueOf(t.getMessage())));
                sbx.Log.ev("HOOK-EX", call + " :: " + t.getClass().getSimpleName());
            }
        }

        // 리플레이 종료 후 SM 해제(출력 쓰기 허용) — 스크립트는 이미 종료, 스크립트 경로 해제 시도는 SM-TAMPER로 기록됨
        System.setSecurityManager(null);

        StringBuilder j = new StringBuilder();
        j.append("{\n  \"script\": ").append(q(new File(scriptPath).getName())).append(",\n");
        j.append("  \"sha256\": ").append(q(sha256(script))).append(",\n");
        j.append("  \"eval_ok\": ").append(evalOk).append(",\n");
        if (evalErr != null) j.append("  \"eval_error\": ").append(q(evalErr)).append(",\n");
        j.append("  \"hook_results\": ").append(jsonList(hookResults)).append(",\n");
        j.append("  \"file_reads\": ").append(sbx.Log.fileReads).append(",\n");
        j.append("  \"denied\": ").append(sbx.Log.denied).append(",\n");
        j.append("  \"labels\": {\"TYPE_PARTICIPATION\": ").append(q(nvl(com.gad.sdk.util.Utils.Names.TYPE_PARTICIPATION)));
        j.append(", \"TYPE_INSTALL\": ").append(q(nvl(com.gad.sdk.util.Utils.Names.TYPE_INSTALL)));
        j.append(", \"TYPE_CPS\": ").append(q(nvl(com.gad.sdk.util.Utils.Names.TYPE_CPS))).append("},\n");
        j.append("  \"events\": ").append(jsonList(sbx.Log.EVENTS)).append("\n}\n");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(Paths.get(outPath).toAbsolutePath(), StandardCharsets.UTF_8))) { w.print(j); }
        rawLog.close();
        System.out.println("done " + new File(scriptPath).getName() + " events=" + sbx.Log.EVENTS.size() + " denied=" + sbx.Log.denied + " evalOk=" + evalOk);
    }

    static void safeSet(Interpreter i, String n, Object... candidates) {
        for (Object v : candidates) {
            try { i.set(n, v); return; } catch (Throwable ignore) {}
        }
        sbx.Log.ev("BIND-SKIP", n);
    }

    static String nvl(String s) { return s == null ? "" : s; }
    static String trim(String s) { return s == null ? "null" : (s.length() > 140 ? s.substring(0, 140) + "…" : s); }
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break; case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break; case '\r': break; case '\t': b.append("\\t"); break;
                default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append("\"").toString();
    }
    static String jsonList(List<String> l) {
        StringBuilder b = new StringBuilder("[");
        for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(", "); b.append(q(l.get(k))); }
        return b.append("]").toString();
    }
    static String sha256(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : h) b.append(String.format("%02x", x));
            return b.toString();
        } catch (Exception e) { return "err"; }
    }
}
