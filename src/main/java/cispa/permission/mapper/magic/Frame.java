package cispa.permission.mapper.magic;

import java.util.HashSet;

public class Frame {

    public HashSet<State> observed = new HashSet<>();
    public String constant = null;
    public State state = null;

    public void merge(Frame f){
        observed.addAll(f.observed);
        constant = null;
        state = null;
    }

}
