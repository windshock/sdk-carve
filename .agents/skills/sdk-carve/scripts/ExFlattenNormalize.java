import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;

/**
 * exflatten-normalize — normalize exception-table-flattening + irreducible-flow obfuscation on a JVM
 * method so an off-the-shelf decompiler (CFR/Vineflower) can structure it. GENERIC technique, not tied to
 * any one sample. Built after all five mainstream decompilers (CFR/Vineflower/Fernflower/Corpseflower/jadx)
 * failed on a control-flow-obfuscated method whose exception table had ~1000 entries.
 *
 * The obfuscation this targets (two layers):
 *   L1 exception-table flattening : a method sliced into hundreds of tiny protected ranges funnelling to a
 *                                   handful of shared `ASTORE n; GOTO dispatch` handler stubs; many of the
 *                                   traps guard code that can throw nothing. -> no nested try/catch tree
 *                                   reproduces it -> CFR "ConfusedCFRException TRYBLOCK".
 *   L2 irreducible control flow   : backward GOTOs into shared terminal (return/throw) cleanup ladders make
 *                                   the CFG irreducible -> decompilers see fake UNCONDITIONALDOLOOPs.
 *
 * Passes (enable per method with flags):
 *   (always) flatten GOTO->GOTO chains
 *   --redundant : RedundantTrapRemover - drop traps whose [from,to) has no invoke or athrow (cannot throw)
 *   --split     : node-split — duplicate short terminal (xRETURN/ATHROW) blocks reached by a backward GOTO,
 *                 removing fake do-loops -> CFG becomes reducible
 *   --aggressive: merge every same-(handler,type) range into one [min,max)
 *   --unify     : (implies --aggressive) force all handlers onto ONE common [min, firstHandler) range =
 *                 a single try + multi-catch (nestable). This is usually what finally lets CFR decompile.
 *
 * Output is written for READABILITY, not re-execution: for Java-6 (class-file v50) targets StackMapTable is
 * optional, so stale frames are stripped and the class is rewritten with COMPUTE_MAXS only (no class loading).
 *
 * Build/run:
 *   javac -cp 'asm-9.7.jar:asm-tree-9.7.jar' exflatten-normalize.java     (produces ExFlattenNormalize.class)
 *   java  -cp 'asm-9.7.jar:asm-tree-9.7.jar:.' ExFlattenNormalize <in.jar> <out.class> <a/b/C> [flags]
 *   java  -jar cfr.jar <out.class>                                        # now decompiles
 *
 * Usage note: try flags incrementally — `--redundant` first, add `--split`, then `--unify` — and watch the
 * decompiler error evolve (TRYBLOCK -> UNCONDITIONALDOLOOP -> DOLOOP -> success). Verify the recovered source
 * against the raw `javap -c` bytecode; the normalizer changes structure, never semantics you rely on.
 */
public class ExFlattenNormalize {
    static boolean AGGRESSIVE, REDUNDANT, SPLIT, UNIFY;
    static int SPLIT_MAX = 40;

    public static void main(String[] args) throws Exception {
        if (args.length < 3) { System.err.println("args: <in.jar> <out.class> <internal/Class/Name> [--redundant --split --aggressive --unify]"); System.exit(2); }
        String inJar = args[0], outClass = args[1], target = args[2];
        for (String a : args) {
            if (a.equals("--aggressive")) AGGRESSIVE = true;
            if (a.equals("--redundant")) REDUNDANT = true;
            if (a.equals("--split")) SPLIT = true;
            if (a.equals("--unify")) { UNIFY = true; AGGRESSIVE = true; }
        }
        byte[] cls = readEntry(inJar, target + ".class");
        if (cls == null) { System.err.println("class not found: " + target); System.exit(2); }
        ClassReader cr = new ClassReader(cls);
        ClassNode cn = new ClassNode();
        cr.accept(cn, ClassReader.SKIP_FRAMES);

        for (MethodNode mn : cn.methods) {
            int tcb = mn.tryCatchBlocks == null ? 0 : mn.tryCatchBlocks.size();
            if (tcb < 10) continue;
            int before = tcb, gBefore = countGoto(mn);
            flattenGotoChains(mn);
            int removed = REDUNDANT ? removeRedundantTraps(mn) : 0;
            int split = SPLIT ? splitReturnGotos(mn) : 0;
            coalesceTryCatch(mn);
            stripFrames(mn);
            System.out.printf("  %-42s tryCatch %d->%d (redundant -%d), goto %d->%d, split +%d%n",
                mn.name + mn.desc, before, mn.tryCatchBlocks.size(), removed, gBefore, countGoto(mn), split);
        }
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        try (FileOutputStream fos = new FileOutputStream(outClass)) { fos.write(cw.toByteArray()); }
        System.out.println("wrote " + outClass);
    }

    static void flattenGotoChains(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions.toArray())
            if (insn instanceof JumpInsnNode && insn.getOpcode() == Opcodes.GOTO) {
                JumpInsnNode j = (JumpInsnNode) insn;
                LabelNode end = resolveGoto(j.label, new HashSet<>());
                if (end != null && end != j.label) j.label = end;
            }
    }
    static LabelNode resolveGoto(LabelNode lbl, Set<LabelNode> seen) {
        if (lbl == null || !seen.add(lbl)) return lbl;
        AbstractInsnNode p = lbl;
        while (p != null && (p instanceof LabelNode || p instanceof LineNumberNode || p instanceof FrameNode)) p = p.getNext();
        if (p instanceof JumpInsnNode && p.getOpcode() == Opcodes.GOTO) return resolveGoto(((JumpInsnNode) p).label, seen);
        return lbl;
    }

    static int removeRedundantTraps(MethodNode mn) {
        Map<LabelNode,Integer> pos = labelPositions(mn);
        AbstractInsnNode[] arr = mn.instructions.toArray();
        int removed = 0;
        for (Iterator<TryCatchBlockNode> it = mn.tryCatchBlocks.iterator(); it.hasNext(); ) {
            TryCatchBlockNode t = it.next();
            int s = pos.getOrDefault(t.start, -1), e = pos.getOrDefault(t.end, -1);
            if (s < 0 || e < 0) continue;
            boolean canThrow = false;
            for (int i = s; i < e && i < arr.length; i++) {
                int op = arr[i].getOpcode();
                if ((op >= Opcodes.INVOKEVIRTUAL && op <= Opcodes.INVOKEDYNAMIC) || op == Opcodes.ATHROW) { canThrow = true; break; }
            }
            if (!canThrow) { it.remove(); removed++; }
        }
        return removed;
    }

    static int splitReturnGotos(MethodNode mn) {
        int total = 0;
        for (int iter = 0; iter < 50; iter++) {
            boolean changed = false;
            for (AbstractInsnNode insn : mn.instructions.toArray()) {
                if (insn.getOpcode() != Opcodes.GOTO) continue;
                JumpInsnNode g = (JumpInsnNode) insn;
                List<AbstractInsnNode> seq = terminalSeq(g.label);
                if (seq == null) continue;
                Map<LabelNode,LabelNode> map = new HashMap<>();
                for (AbstractInsnNode n : seq) if (n instanceof LabelNode) map.put((LabelNode) n, new LabelNode());
                for (AbstractInsnNode n : seq) {
                    if (n instanceof JumpInsnNode) map.putIfAbsent(((JumpInsnNode) n).label, ((JumpInsnNode) n).label);
                    if (n instanceof LookupSwitchInsnNode) { LookupSwitchInsnNode s=(LookupSwitchInsnNode)n; map.putIfAbsent(s.dflt,s.dflt); for(LabelNode l:s.labels) map.putIfAbsent(l,l); }
                    if (n instanceof TableSwitchInsnNode)  { TableSwitchInsnNode s=(TableSwitchInsnNode)n;  map.putIfAbsent(s.dflt,s.dflt); for(LabelNode l:s.labels) map.putIfAbsent(l,l); }
                }
                InsnList clone = new InsnList();
                for (AbstractInsnNode n : seq) clone.add(n.clone(map));
                mn.instructions.insert(g, clone);
                mn.instructions.remove(g);
                changed = true; total++;
            }
            if (!changed) break;
        }
        return total;
    }
    static List<AbstractInsnNode> terminalSeq(LabelNode label) {
        List<AbstractInsnNode> seq = new ArrayList<>();
        AbstractInsnNode p = label; int n = 0;
        while (p != null && n <= SPLIT_MAX) {
            seq.add(p);
            int op = p.getOpcode();
            if (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) return seq;
            if (op == Opcodes.ATHROW) return seq;
            if (op == Opcodes.GOTO || op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH) return null;
            p = p.getNext();
            if (!(p instanceof LabelNode || p instanceof LineNumberNode || p instanceof FrameNode)) n++;
        }
        return null;
    }

    static void coalesceTryCatch(MethodNode mn) {
        List<TryCatchBlockNode> in = mn.tryCatchBlocks;
        Map<LabelNode,Integer> pos = labelPositions(mn);
        for (TryCatchBlockNode t : in) { LabelNode h = resolveGoto(t.handler, new HashSet<>()); if (h != null) t.handler = h; }
        Map<String,List<TryCatchBlockNode>> groups = new LinkedHashMap<>();
        for (TryCatchBlockNode t : in)
            groups.computeIfAbsent(System.identityHashCode(t.handler) + "|" + (t.type == null ? "any" : t.type), k -> new ArrayList<>()).add(t);
        List<TryCatchBlockNode> out = new ArrayList<>();
        for (List<TryCatchBlockNode> g : groups.values()) {
            g.sort(Comparator.comparingInt(t -> pos.getOrDefault(t.start, Integer.MAX_VALUE)));
            if (AGGRESSIVE) {
                TryCatchBlockNode f = g.get(0); LabelNode start = f.start, end = f.end; int es = pos.getOrDefault(end, -1);
                for (TryCatchBlockNode t : g) if (pos.getOrDefault(t.end, -1) > es) { end = t.end; es = pos.getOrDefault(end, -1); }
                out.add(new TryCatchBlockNode(start, end, f.handler, f.type));
            } else {
                TryCatchBlockNode cur = null; int curEnd = -1;
                for (TryCatchBlockNode t : g) {
                    int s = pos.getOrDefault(t.start, -1), e = pos.getOrDefault(t.end, -1);
                    if (cur == null) { cur = new TryCatchBlockNode(t.start, t.end, t.handler, t.type); curEnd = e; }
                    else if (s <= curEnd) { if (e > curEnd) { cur.end = t.end; curEnd = e; } }
                    else { out.add(cur); cur = new TryCatchBlockNode(t.start, t.end, t.handler, t.type); curEnd = e; }
                }
                if (cur != null) out.add(cur);
            }
        }
        if (UNIFY && !out.isEmpty()) {
            int gMin = Integer.MAX_VALUE, firstH = Integer.MAX_VALUE;
            for (TryCatchBlockNode t : out) { gMin = Math.min(gMin, pos.getOrDefault(t.start, gMin)); firstH = Math.min(firstH, pos.getOrDefault(t.handler, firstH)); }
            LabelNode start = labelAt(mn, gMin), end = labelAt(mn, firstH);
            List<TryCatchBlockNode> uni = new ArrayList<>();
            if (start != null && end != null)
                for (TryCatchBlockNode t : out) if (pos.getOrDefault(t.handler, 0) >= firstH) uni.add(new TryCatchBlockNode(start, end, t.handler, t.type));
            if (!uni.isEmpty()) out = uni;
        }
        out.sort(Comparator.<TryCatchBlockNode>comparingInt(t -> pos.getOrDefault(t.start, 0)).thenComparingInt(t -> pos.getOrDefault(t.end, 0)));
        mn.tryCatchBlocks = out;
    }

    static void stripFrames(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions.toArray()) if (insn instanceof FrameNode) mn.instructions.remove(insn);
    }
    static Map<LabelNode,Integer> labelPositions(MethodNode mn) {
        Map<LabelNode,Integer> pos = new HashMap<>(); int i = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) { if (insn instanceof LabelNode) pos.put((LabelNode) insn, i); i++; }
        return pos;
    }
    static LabelNode labelAt(MethodNode mn, int idx) {
        int i = 0; LabelNode last = null;
        for (AbstractInsnNode insn : mn.instructions.toArray()) { if (insn instanceof LabelNode) last = (LabelNode) insn; if (i == idx) return (insn instanceof LabelNode) ? (LabelNode) insn : last; i++; }
        return last;
    }
    static int countGoto(MethodNode mn) {
        int c = 0; for (AbstractInsnNode insn : mn.instructions.toArray()) if (insn.getOpcode() == Opcodes.GOTO) c++; return c;
    }
    static byte[] readEntry(String jar, String entry) throws IOException {
        try (ZipFile zf = new ZipFile(jar)) {
            ZipEntry e = zf.getEntry(entry); if (e == null) return null;
            try (InputStream is = zf.getInputStream(e); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                byte[] b = new byte[8192]; int n; while ((n = is.read(b)) > 0) bos.write(b, 0, n); return bos.toByteArray();
            }
        }
    }
}
