/**
 * @name SDK completeness in a CodeQL DB
 * @description Counts target-SDK types/methods present in the DB (source-extracted) and
 *              SDK-own sink call-sites, to compare whole-app vs carved (mirrors the
 *              jimple2cpg completeness metric). Roots: com.smart.sklb, bg, cg, dg.
 * @kind table
 * @id sdk-carve/completeness
 */

import java

predicate sdkPkg(RefType t) {
  exists(string p | p = t.getPackage().getName() |
    p = "com.smart.sklb" or p.matches("com.smart.sklb.%") or
    p = "bg" or p = "cg" or p = "dg")
}

int sdkTypes()   { result = count(RefType t | t.fromSource() and sdkPkg(t)) }
int sdkMethods() { result = count(Method m | m.fromSource() and sdkPkg(m.getDeclaringType())) }
int ownSinks()   {
  result = count(MethodCall c |
    c.getMethod().hasName(["putCol", "getBConfig", "getPdata", "userJoin"]))
}
int totalTypes() { result = count(RefType t | t.fromSource()) }

select totalTypes() as total_src_types, sdkTypes() as sdk_types,
       sdkMethods() as sdk_methods, ownSinks() as own_sink_cs
