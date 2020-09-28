package cispa.permission.mapper.magic;

import soot.jimple.Stmt;

public interface InstructionVisitor {

    public void visit(Stmt stmt);

}
