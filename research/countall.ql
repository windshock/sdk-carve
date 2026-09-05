/**
 * @name Source type/method count
 * @description Counts source-extracted types and methods. For a carved DB (SDK-only by
 *              construction) this equals the SDK's extracted surface.
 * @kind table
 * @id sdk-carve/countall
 */
import java
select count(RefType t | t.fromSource() | t) as src_types,
       count(Method  m | m.fromSource() | m) as src_methods
