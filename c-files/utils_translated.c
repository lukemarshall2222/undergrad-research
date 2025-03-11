#include <stdio.h>
#include <glib.h>
#include "utils.h"

operator __(opCreator opCreatorFunc, operator nextOp ) {
    return opCreatorFunc(nextOp);
}

dblOperator ____(dblOpCreator opCreatorFunc, operator nextOp) {
    return opCreatorFunc(nextOp);
}

char* stringOfMac(Bytes buf) {
    
}






