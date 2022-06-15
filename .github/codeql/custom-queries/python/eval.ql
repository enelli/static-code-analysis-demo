/**
 * @name Detect Eval Statements
 * @kind problem
 * @problem.severity warning
 * @id python/demo/eval
 */

import python

from Call call, Name name
where call.getFunc() = name and name.getId() = "eval"
select call, "Call to eval detected"