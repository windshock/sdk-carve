import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import java.io.File;
import java.nio.file.*;
import java.util.*;

/**
 * APKSHIELD (com.goggles / ahope) key extractor — unidbg, no device/Frida.
 * The white-box (libwbaes + assets/tables) only protects KEY DERIVATION; bulk asorg is standard AES-128-CBC.
 * This harness inits the white-box and prints callMethod("K", idx) for idx 0..N (the AES keys). Then decrypt
 * asorg OFFLINE (scripts/appshield_unpack.py).
 *
 *   -Dappdir=<dir>   dir with base.apk, native/<libs>.so, tables      (required)
 *   -Dlibs=...       comma load order (default IWAndroid,ahope_n,wbaes,ahope_o)
 *   -Dkeymax=N       probe callMethod("K",0..N)   (default 3)
 *   -Dprocess=...    fake process name (default com.example.app)
 * Build/run: javac -cp "$UNIDBG_CP" -d out AppShieldKeyExtract.java
 *            java  -cp "out:$UNIDBG_CP" -Dappdir=<dir> AppShieldKeyExtract
 */
public class AppShieldKeyExtract extends AbstractJni {
    public static void main(String[] a) throws Exception {
        String dir = req("appdir");
        String[] libs = System.getProperty("libs","libIWAndroid,libahope_n,libwbaes,libahope_o").split(",");
        int keymax = Integer.parseInt(System.getProperty("keymax","3"));
        String proc = System.getProperty("process","com.example.app");

        AndroidEmulator emu = AndroidEmulatorBuilder.for64Bit().setProcessName(proc).build();
        Memory mem = emu.getMemory(); mem.setLibraryResolver(new AndroidResolver(23));
        VM vm = emu.createDalvikVM(new File(dir+"/base.apk"));
        vm.setVerbose(false); vm.setJni(new AppShieldKeyExtract());

        List<Module> mods = new ArrayList<>();
        for (String l : libs) {
            String p = dir+"/native/"+(l.endsWith(".so")?l:l+".so");
            try { mods.add(vm.loadLibrary(new File(p), true).getModule()); System.out.println("[load] "+l); }
            catch (Throwable t){ System.out.println("[load-FAIL] "+l+" : "+t); }
        }
        DvmClass N = vm.resolveClass("com/goggles/Native");
        byte[] tables = Files.readAllBytes(Paths.get(dir+"/tables"));
        System.out.println("[tables] "+tables.length+" bytes");

        // white-box init (these single-overload JNI names resolve via DvmClass fine)
        callVoid(emu, N, "callMethodV(Ljava/lang/String;)V", new StringObject(vm,"I"));
        callVoid(emu, N, "callMethodW(Ljava/lang/String;[B)V", new StringObject(vm,"WI"), new ByteArray(vm,tables));

        // key derivation: callMethod(String,int) is OVERLOADED -> unidbg resolver fails -> direct symbol
        UnidbgPointer env = (UnidbgPointer) vm.getJNIEnv();
        long jcls = vm.addLocalObject(N.newObject(null));
        Symbol sym = findSym(mods, "Java_com_goggles_Native_callMethod__Ljava_lang_String_2I");
        if (sym == null) { System.out.println("[!] callMethod(String,int) symbol not found in any lib"); }
        else for (int i=0;i<=keymax;i++) {
            try { long js=vm.addLocalObject(new StringObject(vm,"K"));
                  Number r=sym.call(emu, env, jcls, js, i);
                  DvmObject<?> o=vm.getObject((int)(r.longValue()));
                  System.out.println("[key] callMethod(\"K\","+i+") = "+(o==null?("raw="+r):o.getValue()));
            } catch (Throwable t){ System.out.println("[key] idx "+i+" ERR "+t); }
        }
        // also dump the hardcoded string-crypto IV if you haven't read it from Native.b(): look for a 32-hex
        // literal there. Then: scripts/appshield_unpack.py <appdir>  (brutes keys x mode on asorg).
        emu.close();
    }
    static Symbol findSym(List<Module> mods, String name){
        for (Module m: mods){ try { Symbol s=m.findSymbolByName(name,false); if (s!=null) return s; } catch(Throwable ignore){} }
        return null;
    }
    static void callVoid(AndroidEmulator emu, DvmClass N, String sig, Object... args){
        try { N.callStaticJniMethod(emu, sig, args); System.out.println("[ok] "+sig); }
        catch (Throwable t){ System.out.println("[ERR] "+sig+" : "+t); }
    }
    static String req(String k){ String v=System.getProperty(k); if(v==null){System.err.println("missing -D"+k); System.exit(2);} return v; }
}
