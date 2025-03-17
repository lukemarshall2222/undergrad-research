import { 
    createEpochOperator, 
    createGroubyOperator, 
    createMapOperator, 
    singleGroup, 
    counter, 
    filterGroups,
    createDistinctOperator,
    createFilterOperator,
    getMappedInt,
    keyGeqInt
} from './builtins-translated'
import { 
    $π, 
    opCreator, 
    Operator, 
    opResult, 
    opResultKind, 
    PacketHeaders 
} from './utils-translated';

function ident(next_op) : Operator {
    const firstFun = (headers: PacketHeaders) => {
        const tmpHeaders: Map<string, opResult> = new Map(headers);
        tmpHeaders.delete("eth.src");
        tmpHeaders.delete("eth.dst");
        return tmpHeaders;
    }
    return $π(createMapOperator(firstFun), next_op);
}

function countPkts(next_op: Operator) : Operator {
    return $π(createEpochOperator(1.0, "eid"), 
           $π(createGroubyOperator(singleGroup, counter, "pkts"), 
           next_op
        ))
}

function pktsPerSrcDst(next_op: Operator) : Operator{
    return $π(createEpochOperator(1.0, "eid"), 
           $π(createGroubyOperator(filterGroups(["ipv4.src", "ipv4.dst"]), counter, "pkts"),
           next_op
        ));
}

function distinctSrcs(next_op: Operator) : Operator {
    return $π(createEpochOperator(1.0, "eid"),
           $π(createDistinctOperator(filterGroups(["ipv4.src"])), 
           $π(createGroubyOperator(singleGroup, counter, "srcs"),
           next_op
        )));
}

function tcpNewCons(next_op: Operator) : Operator {
    const threshold: number = 40;
    return $π(createEpochOperator(1.0, "eid"),
           $π(createFilterOperator((headers: PacketHeaders) =>
                getMappedInt("ipv4.proto", headers) === 6 && 
                getMappedInt("l4.flags", headers) === 2 ),
           $π(createGroubyOperator(filterGroups(["ipv4.dst"]), counter, "cons"),
           $π(createFilterOperator(keyGeqInt("cons", threshold)),
           next_op
        ))));
}

function sshBruteForce(next_op: Operator) : Operator {
    const threshold: number = 40;
    return $π(createEpochOperator(1.0, "eid"),
           $π(createFilterOperator( (headers: PacketHeaders) =>
                getMappedInt("ipv4.proto", headers) === 6 && 
                getMappedInt("l4.flags", headers) === 22 ),
           $π(createDistinctOperator(filterGroups(["ipv4.src", "ipv4.dst", "ipv4.len"])),
           $π(createGroubyOperator(filterGroups(["ipv4.dst", "ipv4.len"]), counter, "srcs"),
           $π(createFilterOperator(keyGeqInt("srcs", threshold)),
           next_op
        )))));
}

function superSpreader(next_op: Operator) : Operator {
    const threshold: number = 40;
    return $π(createEpochOperator(1.0, "eid"),
           $π(createDistinctOperator(filterGroups(["ipv4.src", "ipv4.dst"])),
           $π(createGroubyOperator(filterGroups(["ipv4.src"]), counter, "dsts"),
           $π(createFilterOperator(keyGeqInt("dsts", threshold)),
           next_op
        ))));
}

function portScan(next_op: Operator) : Operator {
    const threshold: number = 40;
    return $π(createEpochOperator(1.0, "eid"),
           $π(createDistinctOperator(filterGroups(["ipv4.src", "l4.dport"])),
           $π(createGroubyOperator(filterGroups(["ipv4.src"]), counter, "dsts"),
           $π(createFilterOperator(keyGeqInt("dsts", threshold)),
           next_op
        ))));
}

function ddos(next_op: Operator) : Operator {
    const threshold: number = 45;
    return $π(createEpochOperator(1.0, "eid"),
           $π(createDistinctOperator(filterGroups(["ipv4.src", "ipv4.dst"])),
           $π(createGroubyOperator(filterGroups(["ipv4.dst"]), counter, "srcs"),
           $π(createFilterOperator(keyGeqInt("srcs", threshold)),
           next_op
    ))));
}


function synFloodSonata(next_op: Operator) : Operator[] {
    const threshold: number = 3;
    const epochDur: number = 1.0;
    const syns: opCreator = (next_op: Operator) => {
        return $π(createEpochOperator(epochDur, "eid"),
               $π(createFilterOperator((headers: PacketHeaders) => 
                    getMappedInt("ipv4.proto", headers) === 6 && 
                    getMappedInt("l4.flags", headers) === 22 ),
               $π(createGroubyOperator(filterGroups(["ipv4.dst"]), counter, "syns"),
               next_op
            )));
    }
      
}