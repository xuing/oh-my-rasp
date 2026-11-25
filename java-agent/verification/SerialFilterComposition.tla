---------------------- MODULE SerialFilterComposition ----------------------
EXTENDS Naturals, Sequences, FiniteSets

Filters == {"agent", "global", "stream"}
Votes == {"defer", "allow", "reject"}
VARIABLES decisions, attachment, phase, pipeline, calls, result
vars == <<decisions, attachment, phase, pipeline, calls, result>>

Init ==
    /\ decisions \in [Filters -> Votes]
    /\ decisions["agent"] # "allow"
    /\ attachment \in {"none", "sameGlobal", "sameCurrent", "distinct"}
    /\ phase = "open"
    /\ pipeline = <<>> /\ calls = <<>> /\ result = "defer"

Open ==
    /\ phase = "open"
    /\ pipeline' = <<"agent", "global">>
    /\ phase' = "attach"
    /\ UNCHANGED <<decisions, attachment, calls, result>>

Attach ==
    /\ phase = "attach"
    /\ pipeline' = IF attachment = "distinct" THEN Append(pipeline, "stream") ELSE pipeline
    /\ phase' = "check"
    /\ UNCHANGED <<decisions, attachment, calls, result>>

Check ==
    /\ phase = "check"
    /\ LET f == pipeline[Len(calls) + 1]
           vote == decisions[f]
       IN /\ calls' = Append(calls, f)
          /\ result' = IF vote = "defer" THEN result ELSE vote
          /\ phase' = IF vote = "reject" \/ Len(calls') = Len(pipeline) THEN "done" ELSE "check"
    /\ UNCHANGED <<decisions, attachment, pipeline>>

Next == Open \/ Attach \/ Check \/ (phase = "done" /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars

Required == {"agent", "global"} \cup (IF attachment = "distinct" THEN {"stream"} ELSE {})
Expected == IF \E f \in Required : decisions[f] = "reject" THEN "reject"
            ELSE IF \E f \in Required : decisions[f] = "allow" THEN "allow" ELSE "defer"
DecisionPreserved == phase = "done" => result = Expected
CalledOnce == Len(calls) = Cardinality({calls[i] : i \in 1..Len(calls)})
=============================================================================
