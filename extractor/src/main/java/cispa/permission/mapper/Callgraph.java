package cispa.permission.mapper;

import soot.SootMethod;
import soot.Unit;
import soot.UnitPatchingChain;
import soot.jimple.InvokeExpr;
import soot.jimple.JimpleBody;
import soot.jimple.Stmt;
import soot.jimple.internal.JInvokeStmt;

import java.util.HashSet;
import java.util.Hashtable;

public class Callgraph {

    public class Node{

        private final HashSet<Node> callers = new HashSet<>();
        private final HashSet<Node> callees = new HashSet<>();

        public final String name;
        public SootMethod method;

        public Node(String name){
            this.name = name;
        }

        public void setMethod(SootMethod method){
            this.method = method;
        }

        public void addCaller(Node n){
            callers.add(n);
        }

        public void addCallee(Node n){
            callees.add(n);
        }

        public void calls(Node n){
            this.addCallee(n);
            n.addCaller(this);
        }
    }

    private final Hashtable<String, Node> nodes = new Hashtable<>();

    public Node getNode(String sig){
        Node node;
        if (nodes.contains(sig))
            node = nodes.get(sig);
        else {
            node = new Node(sig);
            nodes.put(sig, node);
        }
        return node;
    }

    public void visit(SootMethod method){
        String sig = method.getSignature();
        Node node = getNode(sig);
        if (node.method != null)
            return;
        node.method = method;
        JimpleBody body = (JimpleBody) method.retrieveActiveBody();
        UnitPatchingChain units = body.getUnits();
        for (Unit bx : units){
            Stmt s = (Stmt) bx;
            if (s instanceof JInvokeStmt) {
                InvokeExpr invoke = s.getInvokeExpr();
                node.calls(getNode(invoke.getMethod().getSignature()));
            }
        }
    }

}
