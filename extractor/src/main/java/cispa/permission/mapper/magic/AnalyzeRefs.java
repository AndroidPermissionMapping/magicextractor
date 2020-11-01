package cispa.permission.mapper.magic;

import cispa.permission.mapper.fuzzer.FuzzingGenerator;
import cispa.permission.mapper.Statistics;
import cispa.permission.mapper.Utils;
import cispa.permission.mapper.model.CallMethodAndArg;
import cispa.permission.mapper.model.ContentProviderQuery;
import cispa.permission.mapper.model.FoundMagicValues;
import cispa.permission.mapper.soot.exceptions.LoopException;
import cispa.permission.mapper.soot.exceptions.NoBodyException;
import cispa.permission.mapper.soot.exceptions.TooDeepException;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.*;
import soot.util.ArraySet;

import java.util.*;
import java.util.stream.Collectors;

public class AnalyzeRefs implements StmtSwitch, JimpleValueSwitch, ExprSwitch {

    private static final Logger logger = LoggerFactory.getLogger(AnalyzeRefs.class);

    private final int max_depth = 20;
    private final int depth;
    private final SootMethod method;
    private final JimpleBody body;
    private final ArrayList<Stmt> units = new ArrayList<Stmt>();
    private final HashMap<Local, State> states = new HashMap<>();
    private final HashMap<Value, Constant> constants = new HashMap<>();
    public AnalyzeRefs parent = null;

    private Frame frame = new Frame();
    private Value ret;
    public static boolean IGNORE_INTS = false;

    private final Map<String, List<FoundMagicValues>> cpClassNameToMagicValuesMap = new HashMap<>();

    private final FuzzingGenerator fuzzingGenerator;
    private final Statistics statistics;

    public AnalyzeRefs(FuzzingGenerator fuzzingGenerator, Statistics statistics, SootMethod m, int depth,
                       AnalyzeRefs parent) {
        this.fuzzingGenerator = fuzzingGenerator;
        this.statistics = statistics;

        this.parent = parent;
        this.depth = depth;
        method = m;
        //System.out.println("[" + depth + "] Created Analyzer for Method " + m.getSignature());

        ArraySet<String> parents = new ArraySet<>();

        for (AnalyzeRefs cursor = this; cursor != null; cursor = cursor.parent) {
            if (parents.contains(cursor.method.getSignature())) {
                throw new LoopException(m);
            }
            parents.add(cursor.method.getSignature());
        }

        if (depth > max_depth) {
            System.err.println("Stack-trace:");

            System.err.flush();
            throw new TooDeepException(m);
        }

        if (!m.hasActiveBody()) {
            throw new NoBodyException(m);
        }

        body = (JimpleBody) m.retrieveActiveBody();
        for (Local l : body.getParameterLocals()) {
            states.put(l, new State(l, method));
        }
        for (Unit u : body.getUnits()) {
            units.add((Stmt) u);
        }
    }


    public AnalyzeRefs(FuzzingGenerator fuzzingGenerator, Statistics statistics, SootMethod method, int depth) {
        this.fuzzingGenerator = fuzzingGenerator;
        this.statistics = statistics;

        logger.info("[" + depth + "] Created Analyzer for Method " + method.getSignature());
        if (depth > max_depth) {
            throw new TooDeepException(method);
        }

        if (!method.hasActiveBody()) {
            throw new NoBodyException(method);
        }

        this.method = method;

        body = (JimpleBody) method.retrieveActiveBody();
        for (Local l : body.getParameterLocals()) {
            states.put(l, new State(l, this.method));
        }
        for (Unit u : body.getUnits()) {
            units.add((Stmt) u);
        }
        this.depth = depth;
    }

    public void analyze() {
        for (Stmt s : units) {
            //System.out.println(s);
            s.apply(this);
        }
    }

    public void run() {
        analyze();
        reportResult(getLocalStates());
    }

    public ArrayList<State> getLocalStates() {
        ArrayList<State> result = new ArrayList<>();
        for (Local l : body.getParameterLocals()) {
            State s = states.get(l);
            s.eatChildren();
            result.add(s);
        }
        return result;
    }

    private Set<String> extractMagicValuesFromState(State state) {
        Set<String> magicValues = new HashSet<>(state.magic_equals);
        fuzzingGenerator
                .generateStreamForMagicSubstrings(state.magic_substring)
                .forEach(magicValues::add);
        return magicValues;
    }

    public void reportResult(ArrayList<State> states) {
        final String className = method.getDeclaringClass().getName();
        final String methodName = method.getName();

        List<FoundMagicValues> fuzzingData = cpClassNameToMagicValuesMap.getOrDefault(className, new ArrayList<>());

        if (methodName.equals("query")) {
            final int numberOfArgs = states.size();

            List<Set<String>> argsExceptUri = new ArrayList<>(numberOfArgs - 1);
            for (int i = 1; i < numberOfArgs; i++) {
                State state = states.get(i);
                Set<String> magicValues = extractMagicValuesFromState(state).stream()
                        .filter(item -> !item.equals("null"))
                        .collect(Collectors.toSet());
                argsExceptUri.add(magicValues);
            }

            ContentProviderQuery contentProviderQuery = new ContentProviderQuery(argsExceptUri);
            fuzzingData.add(contentProviderQuery);
            cpClassNameToMagicValuesMap.put(className, fuzzingData);
        }

        if (methodName.equals("call")) {
            final int numberOfArgs = states.size();
            final State firstArg = states.get(0);
            final State secondArg = states.get(1);

            if (numberOfArgs == 3) { // ContentProvider.call(..) with uri
                statistics.reportCallMethod(method.toString());

                Set<String> methodMagicValues = extractMagicValuesFromState(firstArg);
                Set<String> argMagicValues = extractMagicValuesFromState(secondArg);

                CallMethodAndArg callData = new CallMethodAndArg(methodMagicValues, argMagicValues);
                fuzzingData.add(callData);
                cpClassNameToMagicValuesMap.put(className, fuzzingData);

            } else if (numberOfArgs == 4) { // ContentProvider.call(..) with authority - API 29+
                // Process 1st arg - authority (String)
                if (!firstArg.magic_equals.isEmpty()) {
                    throw new IllegalStateException("Not implemented - call API 29+");
                }

            } else {
                throw new IllegalStateException("Not implemented");
            }


        }


        JSONArray obj = new JSONArray();
        for (State s : states) {
            obj.put(s.toJSON());
        }
        Utils.result(method, obj, "AnalyzeRefs");
    }

    @Override
    public void caseBreakpointStmt(BreakpointStmt stmt) {
        throw new RuntimeException("Stmt not implemented (" + stmt.getClass().toString() + "): " + stmt.toString());

    }

    @Override
    public void caseInvokeStmt(InvokeStmt stmt) {
        frame = apply(stmt.getInvokeExpr());
    }

    public Frame apply(Value value) {
        return apply(value, new Frame());
    }

    public Frame apply(Value value, Frame f) {
        Frame prev_frame = frame;
        frame = f;
        value.apply(this);
        Frame result = frame;
        frame = prev_frame;
        frame.observed.addAll(result.observed);
        return result;
    }

    @Override
    public void caseAssignStmt(AssignStmt stmt) {
        // r4 = r0.<com.android.providers.contacts.ContactsProvider2: java.util.concurrent.CountDownLatch mReadAccessLatch>
        Value right = stmt.getRightOp();
        Value left = stmt.getLeftOp();
        //System.out.println("left" +  left.getClass().toString());
        //System.out.println("right" +  right.getClass().toString());
        if (right instanceof Constant) {
            constants.put(left, (Constant) right);
        } else if (left instanceof Local) {
            State s = new State((Local) left, method);
            Frame f = new Frame();
            f.left_state = s;
            Frame result = apply(right, f);
            if (!result.observed.isEmpty()) {
                s.addParents(result.observed);
                states.putIfAbsent(s.local, s);
            }
        } else {
            // TODO: handle JArrayRef correctly
            apply(right);
        }

    }

    public State lookupState(Value v) {
        State s = states.getOrDefault(v, null);
        if (s != null) {
            frame.observed.add(s);
        }
        return s;
    }

    @Override
    public void caseIdentityStmt(IdentityStmt stmt) {
        //  r0 := @this: com.android.providers.contacts.ContactsProvider2
    }

    @Override
    public void caseEnterMonitorStmt(EnterMonitorStmt stmt) {
        frame = apply(stmt.getOp());

    }

    @Override
    public void caseExitMonitorStmt(ExitMonitorStmt stmt) {
        frame = apply(stmt.getOp());
    }

    @Override
    public void caseGotoStmt(GotoStmt stmt) {
        // useless

    }

    @Override
    public void caseIfStmt(IfStmt stmt) {
        // We dont care about control flow and we will iterate over both branches anyways, so yolo
        frame = apply(stmt.getCondition());
    }

    @Override
    public void caseLookupSwitchStmt(LookupSwitchStmt stmt) {

        //throw new RuntimeException("Stmt not implemented (" + stmt.getClass().toString() + "): " + stmt.toString());

    }

    @Override
    public void caseNopStmt(NopStmt stmt) {
        //throw new RuntimeException("Stmt not implemented (" + stmt.getClass().toString() + "): " + stmt.toString());

    }

    @Override
    public void caseRetStmt(RetStmt stmt) {
        throw new RuntimeException("Stmt not implemented (" + stmt.getClass().toString() + "): " + stmt.toString());

    }

    @Override
    public void caseReturnStmt(ReturnStmt stmt) {
        frame = apply(stmt.getOp());
        ret = stmt.getOp();

    }

    @Override
    public void caseReturnVoidStmt(ReturnVoidStmt stmt) {
        // useless

    }

    @Override
    public void caseTableSwitchStmt(TableSwitchStmt stmt) {
//        throw new RuntimeException("Stmt not implemented (" + stmt.getClass().toString() + "): " + stmt.toString());

    }

    @Override
    public void caseThrowStmt(ThrowStmt stmt) {
        frame = apply(stmt.getOp());
    }

    @Override
    public void caseDoubleConstant(DoubleConstant v) {
        if (!IGNORE_INTS) {
            frame.constant = Double.toString(v.value);
        }
    }

    @Override
    public void caseFloatConstant(FloatConstant v) {
        if (!IGNORE_INTS) {
            frame.constant = Float.toString(v.value);
        }
    }

    @Override
    public void caseIntConstant(IntConstant v) {
        if (!IGNORE_INTS) {
            frame.constant = Integer.toString(v.value);
        }
    }

    @Override
    public void caseLongConstant(LongConstant v) {
        if (!IGNORE_INTS) {
            frame.constant = Long.toString(v.value);
        }
    }

    @Override
    public void caseNullConstant(NullConstant v) {
        frame.constant = "null";
    }

    @Override
    public void caseStringConstant(StringConstant v) {
        frame.constant = v.value;
    }

    @Override
    public void caseClassConstant(ClassConstant v) {
//        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void caseMethodHandle(MethodHandle handle) {
        throw new RuntimeException("MethodHandle not implemented (" + handle.getClass().toString() + "): " + handle.toString());
    }

    @Override
    public void caseMethodType(MethodType type) {
        throw new RuntimeException("MethodType not implemented (" + type.getClass().toString() + "): " + type.toString());
    }

    @Override
    public void caseAddExpr(AddExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseAndExpr(AndExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseCmpExpr(CmpExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseCmpgExpr(CmpgExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseCmplExpr(CmplExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseDivExpr(DivExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseEqExpr(EqExpr v) {
        caseBinopExpr(v);
    }

    public void caseBinopExpr(BinopExpr v) {
        Frame r1 = apply(v.getOp1());
        Frame r2 = apply(v.getOp2());
        if (r1.constant != null && r2.state != null) {
            r2.state.magic_equals.add(r1.constant);
        } else if (r2.constant != null && r1.state != null) {
            r1.state.magic_equals.add(r2.constant);
        }
        // other cases are not relevant for magic
    }

    @Override
    public void caseNeExpr(NeExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseGeExpr(GeExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseGtExpr(GtExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseLeExpr(LeExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseLtExpr(LtExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseMulExpr(MulExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseOrExpr(OrExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseRemExpr(RemExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseShlExpr(ShlExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseShrExpr(ShrExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseUshrExpr(UshrExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseSubExpr(SubExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseXorExpr(XorExpr v) {
        caseBinopExpr(v);
    }

    @Override
    public void caseInterfaceInvokeExpr(InterfaceInvokeExpr v) {
        caseInvokeExpr(v);
        //throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }


    public boolean InvokeHook(InvokeExpr v) {
        SootMethod callee = v.getMethod();
        String signature = callee.getSignature();
        String clazz = callee.getDeclaringClass().getName();
        int arg_count = callee.getParameterCount();
        Value base = null;
        State base_state = null;
        String base_constant = null;
        if (v instanceof VirtualInvokeExpr) {
            base = ((VirtualInvokeExpr) v).getBase();
            Frame res = apply(base);
            base_state = res.state;
            base_constant = res.constant;
        }
        Value[] arg = new Value[arg_count];
        State[] arg_state = new State[arg_count];
        String[] arg_constant = new String[arg_count];

        for (int i = 0; i < arg_count; i++) {
            arg[i] = v.getArg(i);
            Frame res = apply(arg[i]);
            arg_state[i] = res.state;
            arg_constant[i] = res.constant;
        }

        switch (clazz) {
            case "android.net.Uri": {
                switch (signature) {
                    case "<android.net.Uri: java.lang.String getQueryParameter(java.lang.String)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.query_parameters.add(arg_constant[0]);
                        }
                        break;
                    default:
                        return true;
                }
                break;
            }
            case "android.os.Bundle": {
                if (callee.getName().startsWith("get") && base_state != null && arg_constant[0] != null) {
                    base_state.bundle_elements.add(new BundleElement(callee.getReturnType(), arg_constant[0], frame.left_state));
                }
                break;
            }
            case "android.content.ContentValues": {
                if (callee.getName().startsWith("get") && base_state != null && arg_constant[0] != null) {
                    base_state.cv_elements.add(new BundleElement(callee.getReturnType(), arg_constant[0], frame.left_state));
                }
                break;
            }
            case "java.lang.String": {
                switch (signature) {
                    case "<java.lang.String: boolean equals(java.lang.Object)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_equals.add(arg_constant[0]);
                        } else if (arg_state[0] != null && base_constant != null) {
                            arg_state[0].magic_equals.add(base_constant);
                        }
                        break;
                    case "<java.lang.String: boolean equalsIgnoreCase(java.lang.String)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_equals_ignorecase.add(arg_constant[0]);
                        } else if (arg_state[0] != null && base_constant != null) {
                            arg_state[0].magic_equals_ignorecase.add(base_constant);
                        }
                        break;
                    case "<java.lang.String: boolean startsWith(java.lang.String)>":
                    case "<java.lang.String: boolean contains(java.lang.CharSequence)>":
                    case "<java.lang.String: java.lang.String replaceAll(java.lang.String,java.lang.String)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_substring.add(arg_constant[0]);
                        } else if (arg_state[0] != null && base_constant != null) {
                            arg_state[0].magic_substring.add(base_constant);
                        }
                        break;
                    case "<java.lang.String: boolean matches(java.lang.String)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_regex.add(arg_constant[0]);
                        } else if (arg_state[0] != null && base_constant != null) {
                            arg_state[0].magic_regex.add(base_constant);
                        }
                        break;

                    case "<java.lang.String: int indexOf(int)>":
                    case "<java.lang.String: int lastIndexOf(int)>":
                    case "<java.lang.String: int lastIndexOf(int,int)>":
                    case "<java.lang.String: int indexOf(int,int)>":
                        if (IGNORE_INTS) {
                            break;
                        }
                    case "<java.lang.String: int indexOf(java.lang.String)>":
                    case "<java.lang.String: int indexOf(java.lang.String,int)>":
                    case "<java.lang.String: java.lang.String[] split(java.lang.String)>":
                    case "<java.lang.String: java.lang.String[] split(java.lang.String,int)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_split.add(arg_constant[0]);
                        }
                        break;
                    case "<java.lang.String: int length()>":
                        if (!IGNORE_INTS && base_constant != null) {
                            constants.put(base, IntConstant.v(base_constant.length()));
                        }
                        break;
                    case "<java.lang.String: char charAt(int)>":
                        if (!IGNORE_INTS && base_constant != null && arg_constant[0] != null) {
                            try {
                                constants.put(base, StringConstant.v(String.valueOf(base_constant.charAt(Integer.parseInt(arg_constant[0]))))); // TODO: char != string, but there is no charconst :/
                            } catch (java.lang.StringIndexOutOfBoundsException e) {

                            }
                        }
                        break;
                    case "<java.lang.String: java.lang.String substring(int)>":
                        if (base_constant != null && arg_constant[0] != null) {
                            try {
                                constants.put(base, StringConstant.v(base_constant.substring(Integer.parseInt(arg_constant[0]))));
                            } catch (java.lang.StringIndexOutOfBoundsException e) {

                            }
                        }
                        break;
                    case "<java.lang.String: java.lang.String substring(int,int)>":
                        if (base_constant != null && arg_constant[0] != null && arg_constant[1] != null) {
                            try {
                                constants.put(base, StringConstant.v(base_constant.substring(Integer.parseInt(arg_constant[0]), Integer.parseInt(arg_constant[1]))));
                            } catch (java.lang.StringIndexOutOfBoundsException e) {

                            }
                        }
                        break;
                    case "<java.lang.String: java.lang.String valueOf(long)>":
                    case "<java.lang.String: java.lang.String valueOf(int)>":
                        if (IGNORE_INTS) {
                            break;
                        }
                    case "<java.lang.String: java.lang.String valueOf(java.lang.Object)>":
                    case "<java.lang.String: void <init>(char[],int,int)>":
                        if (arg_constant[0] != null) {
                            constants.put(base, StringConstant.v(arg_constant[0]));
                        }
                        break;
                    case "<java.lang.String: char[] toCharArray()>":
                    case "<java.lang.String: java.lang.String toString()>":
                        if (base_constant != null) {
                            frame.constant = base_constant;
                        }
                        break;
                    case "<java.lang.String: java.lang.String trim()>":
                    case "<java.lang.String: java.lang.String replace(java.lang.CharSequence,java.lang.CharSequence)>":
                    case "<java.lang.String: boolean regionMatches(boolean,int,java.lang.String,int,int)>":
                        return true;
                    default:
                        return false;
                }
                break;
            }
            case "java.lang.StringBuilder":
            case "android.database.DatabaseUtils":
            case "java.util.ArrayList":
            case "java.util.Arrays":
            case "java.util.List":
            case "android.text.TextUtils":
            case "android.database.sqlite.SQLiteQueryBuilder":
            case "android.database.Cursor":
            case "java.lang.StringBuffer":
            case "java.lang.IllegalArgumentException":
            case "android.util.Log":
            case "android.content.UriMatcher":
            case "java.lang.Throwable":
            case "java.io.File":
            case "java.lang.Enum":
            case "android.database.MatrixCursor":
            case "android.database.MatrixCursor$RowBuilder":
            case "android.content.Context":
            case "android.content.ContentUris":
            case "java.lang.SecurityException":
            case "com.android.providers.contacts.VoicemailTable$Delegate":
            case "android.telephony.PhoneNumberUtils":
            case "java.util.Collections":
            case "android.text.util.Rfc822Tokenizer":
            case "java.lang.Character":
            case "java.text.RuleBasedCollator":
            case "java.util.regex.Pattern":
            case "android.database.sqlite.SQLiteDatabase":
            case "java.text.CollationKey":
            case "com.android.providers.contacts.SearchIndexManager$FtsQueryBuilder":
            case "java.lang.System":
            case "android.database.AbstractCursor":
            case "android.net.Uri$Builder":
            case "<java.lang.Float: java.lang.Float valueOf(float)>":
            case "android.util.ArrayMap":
            case "java.util.Map":
            case "com.android.internal.util.ArrayUtils":
            case "android.database.CursorWrapper":
            case "java.lang.UnsupportedOperationException":
            case "java.lang.NullPointerException":
            case "android.util.ArraySet":
            case "android.util.Set":
            case "android.database.sqlite.SQLiteProgram":
                // ignored
                break;
            default:
                switch (signature) {
                    case "<android.os.Bundle: android.os.Parcelable getParcelable(java.lang.String)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.bundle_elements.add(new BundleElement(arg[0].getType(), arg_constant[0]));
                        }
                        break;
                    case "<java.lang.Integer: boolean equals(java.lang.Object)>":
                        if (base_state != null && arg_constant[0] != null) {
                            base_state.magic_equals.add(arg_constant[0]);
                        } else if (arg_state[0] != null && base_constant != null) {
                            arg_state[0].magic_equals.add(base_constant);
                        }
                        break;
                    case "<java.lang.Long: java.lang.Long valueOf(java.lang.String)>":
                    case "<java.lang.Long: long parseLong(java.lang.String)>": // longs are strings for us anyways ^^
                    case "<java.lang.Long: java.lang.Long valueOf(long)>":
                    case "<java.lang.Integer: int parseInt(java.lang.String)>":
                    case "<java.lang.Integer: java.lang.Integer valueOf(int)>":
                    case "<java.lang.Long: java.lang.String toString(long)>":
                    case "<java.lang.Float: java.lang.Float valueOf(float)>":
                    case "<java.lang.Integer: java.lang.String toString(int)>":
                        if (IGNORE_INTS) {
                            break;
                        }
                        if (arg_constant[0] != null) {
                            frame.constant = arg_constant[0];
                        }
                        break;

                    case "<java.lang.Long: java.lang.String toString()>":
                    case "<java.lang.Integer: int intValue()>":
                    case "<java.lang.Long: long longValue()>":
                        if (IGNORE_INTS) {
                            break;
                        }
                    case "<java.lang.Object: java.lang.String toString()>":
                        if (base_constant != null) {
                            frame.constant = base_constant;
                        }
                        break;
                    case "<android.content.ContentValues: void put(java.lang.String,java.lang.String)>":
                    case "<android.net.Uri: android.net.Uri$Builder buildUpon()>":
                    case "<android.net.Uri$Builder: android.net.Uri build()>":
                    case "<android.net.Uri: java.lang.String toString()>":
                    case "<android.net.Uri: java.lang.String getPath()>":
                    case "<android.net.Uri: java.lang.String getEncodedQuery()>":
                    case "<android.content.Context: int checkCallingUriPermission(android.net.Uri,int)>":
                        break;
                    default:
                        return false;
                }
        }
        return true;
    }

    public void caseInvokeExpr(InvokeExpr v) {
        HashMap<Integer, Value> args_mapping = new HashMap<>();
        HashMap<Integer, Constant> constants_mapping = new HashMap<>();
        if (v.toString().endsWith("<java.lang.RuntimeException: void <init>(java.lang.String)>(\"Stub!\")")) {
            missingImplementation(method.getSignature());
        }
        int i = 0;
        for (Value arg : v.getArgs()) {
            if (states.containsKey(arg)) {
                args_mapping.put(i, arg);
            }
            Constant c = constants.getOrDefault(arg, null);
            if (c != null) {
                constants_mapping.put(i, c);
            }
            i++;
        }
        State base_state = null;

        if (v instanceof VirtualInvokeExpr) {
            base_state = lookupState(((VirtualInvokeExpr) v).getBase());
        }
        if (base_state != null || !args_mapping.isEmpty()) {
            if (!InvokeHook(v)) {
                try {
                    AnalyzeRefs callee_analyzer = new AnalyzeRefs(fuzzingGenerator, statistics, v.getMethod(), depth + 1, this);
                    i = 0;
                    for (Local l : callee_analyzer.body.getParameterLocals()) {
                        Constant c = constants_mapping.getOrDefault(i++, null);
                        if (c != null) {
                            callee_analyzer.constants.put(l, c);
                        }
                    }
                    State thiz_state = null;
                    if (base_state != null) {
                        Local thiz = callee_analyzer.body.getThisLocal();
                        thiz_state = new State(thiz, callee_analyzer.method);
                        callee_analyzer.states.put(thiz, thiz_state);
                    }
                    callee_analyzer.analyze();
                    ArrayList<State> result = callee_analyzer.getLocalStates();
                    State s = callee_analyzer.states.getOrDefault(callee_analyzer.ret, null);
                    for (i = 0; i < result.size(); i++) {
                        if (args_mapping.containsKey(i)) {
                            Value arg = args_mapping.get(i);
                            states.get(arg).merge(result.get(i));
                            if (s == result.get(i)) {
                                frame.observed.add(states.get(arg));
                                //System.out.println("Return value mapped: " + callee_analyzer.method.getName());
                            }
                            //System.out.println(result.get(i).toString() + " : " + arg);
                        }
                    }
                    Constant c = callee_analyzer.constants.getOrDefault(callee_analyzer.ret, null);
                    if (c != null) {
                        Frame res = apply(c);
                        frame.constant = res.constant;
                    }
                } catch (NoBodyException | LoopException | TooDeepException e) {
                    System.err.println(e.getMessage());
                }
            }
        }
    }

    @Override
    public void caseSpecialInvokeExpr(SpecialInvokeExpr v) {
        caseInvokeExpr(v);
    }


    @Override
    public void caseStaticInvokeExpr(StaticInvokeExpr v) {
        caseInvokeExpr(v);
    }

    public String getString(Value arg) {
        if (!arg.getType().toString().equals("java.lang.String")) {
            throw new RuntimeException("is not a string: " + arg.toString());
        }
        Frame result = apply(arg);
        if (result.constant != null) {
            return result.constant;
        }
        throw new RuntimeException("failed to get StringArg: " + arg.toString());
    }

    public String getStringArg(VirtualInvokeExpr v, int i) {
        return getString(v.getArg(i));
    }

    public void missingImplementation(String s) {
        System.err.println("[warn] " + s);
    }

    @Override
    public void caseVirtualInvokeExpr(VirtualInvokeExpr v) {
        caseInvokeExpr(v);
    }

    @Override
    public void caseDynamicInvokeExpr(DynamicInvokeExpr v) {
        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void caseCastExpr(CastExpr v) {
        // we dont care about the cast, so just pass it through
        frame = apply(v.getOp());
    }

    @Override
    public void caseInstanceOfExpr(InstanceOfExpr v) {
        frame = apply(v.getOp());
    }

    @Override
    public void caseNewArrayExpr(NewArrayExpr v) {
        // useless
    }

    @Override
    public void caseNewMultiArrayExpr(NewMultiArrayExpr v) {
        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void caseNewExpr(NewExpr v) {
        // should be useless to us
    }

    @Override
    public void caseLengthExpr(LengthExpr v) {
        frame = apply(v.getOp());
    }

    @Override
    public void caseNegExpr(NegExpr v) {
        frame = apply(v.getOp());
    }

    @Override
    public void caseArrayRef(ArrayRef v) {

        // TODO: arrays
    }

    @Override
    public void caseStaticFieldRef(StaticFieldRef v) {
        // useless
    }

    @Override
    public void caseInstanceFieldRef(InstanceFieldRef v) {
    }

    @Override
    public void caseParameterRef(ParameterRef v) {
        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void caseCaughtExceptionRef(CaughtExceptionRef v) {
        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void caseThisRef(ThisRef v) {
        throw new RuntimeException("Value not implemented (" + v.getClass().toString() + "): " + v.toString());
    }

    @Override
    public void defaultCase(Object obj) {
        throw new RuntimeException("not implemented (" + obj.getClass().toString() + "): " + obj.toString());

    }

    @Override
    public void caseLocal(Local l) {
        Constant c = constants.getOrDefault(l, null);
        if (c != null) {
            Frame result = apply(c);
            //System.out.println("Constant resolved: " + l.getName() + " -> " + result.constant);
            frame.constant = result.constant;
        }
        frame.state = lookupState(l);
    }

    public Map<String, List<FoundMagicValues>> getCpClassNameToMagicValuesMap() {
        return cpClassNameToMagicValuesMap;
    }
}
