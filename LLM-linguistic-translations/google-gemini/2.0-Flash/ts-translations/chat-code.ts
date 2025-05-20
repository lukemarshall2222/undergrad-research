/**
 * Common utilities
 *
 * Includes minimal parsing of header fields into a map from strings to values
 */

import {
    sprintf
  } from 'sprintf-js';
  import {
    V4
  } from 'ipaddr.js';
  
  /**
   * Operators act on named "tuples" which are maps from strings to op_result types
   ***************************************************************************************/
  
  type MAC = string; // Represent MAC address as a colon-separated hex string
  type IPv4 = string; // Represent IPv4 address as a string
  
  type OpResult = // Variant type
    | {
      type: 'Float';
      value: number
    } // Tag for floating point vals
    | {
      type: 'Int';
      value: number
    } // Tag for int vals
    | {
      type: 'IPv4';
      value: IPv4
    } // Tag for IPv4 address
    | {
      type: 'MAC';
      value: MAC
    } // Tag for a MAC address
    | {
      type: 'Empty'
    }; // Tag for empty/missing val, possibly end of something
  
  type Tuple = Map < string, OpResult > ; // Defines tuple as a map from strings to op_results
  
  /**
   * Defines a data processing unit in a stream processing pipeline;
   * contains two functions
   */
  type Operator = {
    // Record type
    next: (tuple: Tuple) => void; // Takes in Map<string, op_result>, processes it in some way, most likely a side effect
    reset: (tuple: Tuple) => void; // Takes same thing, performs a reset op on it after processing
  };
  
  type OpCreator = (operator: Operator) => Operator;
  type DblOpCreator = (operator: Operator) => [Operator, Operator];
  
  /**
   * Right associative "chaining" operator
   * for passing output of one operator to the next under cps-style operator constructors
   */
  const at_equals_greater_than = (
    opCreatorFunc: OpCreator,
    nextOp: Operator
  ): Operator => opCreatorFunc(nextOp);
  // e.g.
  //    (epoch 1.0 "eid") @=> (groupby single_group count "pkts") @=> next_op
  // instead of:
  //    (epoch 1.0 "eid" (groupby single_group count "pkts" ) next_op)
  
  const at_double_equals_greater_than = (
    opCreatorFunc: DblOpCreator,
    op: Operator
  ): [Operator, Operator] => opCreatorFunc(op);
  
  /**
   * Conversion utilities
   ***************************************************************************************/
  
  /**
   * Formats the 6 bytes of the MAC address as a colon-separated string in hex
   */
  const string_of_mac = (buf: Uint8Array): string => {
    const byte_at = (index: number): number => buf[index];
    return sprintf(
      '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x',
      byte_at(0),
      byte_at(1),
      byte_at(2),
      byte_at(3),
      byte_at(4),
      byte_at(5)
    );
  };
  
  /**
   * Converts TCP flags into a human-readable string representation by matching
   * flags to formatted output
   */
  const tcp_flags_to_strings = (flags: number): string => {
    /**
     * Local Map allows storing and retrieving TCP flag names
     * and their bit operations easily
     */
    const tcpFlagsMap = new Map < string, number > ([
      ['FIN', 1 << 0],
      ['SYN', 1 << 1],
      ['RST', 1 << 2],
      ['PSH', 1 << 3],
      ['ACK', 1 << 4],
      ['URG', 1 << 5],
      ['ECE', 1 << 6],
      ['CWR', 1 << 7],
    ]);
  
    let acc = '';
    for (const [key, value] of tcpFlagsMap) {
      if ((flags & value) === value) {
        acc = acc === '' ? key : `<span class="math-inline">\{acc\}\|</span>{key}`;
      }
    }
    return acc;
  };
  
  /**
   * Checks if input is an Int OpResult, throws error otherwise
   */
  const int_of_op_result = (input: OpResult): number => {
    if (input.type === 'Int') {
      return input.value;
    }
    throw new Error('Trying to extract int from non-int result');
  };
  
  /**
   * Checks if input is a Float OpResult, throws error otherwise
   */
  const float_of_op_result = (input: OpResult): number => {
    if (input.type === 'Float') {
      return input.value;
    }
    throw new Error('Trying to extract float from non-float result');
  };
  
  /**
   * Returns the human-readable version of each OpResult value
   */
  const string_of_op_result = (input: OpResult): string => {
    switch (input.type) {
      case 'Float':
        return sprintf('%f', input.value);
      case 'Int':
        return String(input.value);
      case 'IPv4':
        return input.value;
      case 'MAC':
        return input.value;
      case 'Empty':
        return 'Empty';
    }
  };
  
  /**
   * Outputs the tuple in a human-readable form e.g.
   * "ipv4.src" => 192.168.1.1, "packet_count" => 10,
   */
  const string_of_tuple = (inputTuple: Tuple): string => {
    let acc = '';
    for (const [key, value] of inputTuple) {
      acc += `"${key}" => ${string_of_op_result(value)}, `;
    }
    return acc;
  };
  
  /**
   * Creates a Tuple (Map<string, OpResult>) out of a list of tuples
   */
  const tuple_of_list = (tupList: [string, OpResult][]): Tuple => {
    return new Map(tupList);
  };
  
  /**
   * Prints formatted representation of a Tuple
   */
  const dump_tuple = (outc: NodeJS.WriteStream, tup: Tuple): void => {
    outc.write(`${string_of_tuple(tup)}\n`);
  };
  
  /**
   * Retrieves the int value of the OpResult associated with a given key
   * in the given Tuple (Map<string, OpResult>)
   */
  const lookup_int = (key: string, tup: Tuple): number => {
    const result = tup.get(key);
    if (!result) {
      throw new Error(`Key "${key}" not found in tuple`);
    }
    return int_of_op_result(result);
  };
  
  /**
   * Retrieves the float value of the OpResult associated with a given key
   * in the given Tuple (Map<string, OpResult>)
   */
  const lookup_float = (key: string, tup: Tuple): number => {
    const result = tup.get(key);
    if (!result) {
      throw new Error(`Key "${key}" not found in tuple`);
    }
    return float_of_op_result(result);
  };
  
  /**
   * Built-in operator definitions
   * and common utilities for readability
   */
  
  // Assuming 'Utils' module in OCaml doesn't have direct equivalent here unless it contains specific helper functions
  // For now, we'll rely on built-in JavaScript/TypeScript functionalities
  
  const init_table_size: number = 10000;
  
  /**
   * Dump all fields of all tuples to the given output channel
   * Note that dump is terminal in that it does not take a continuation operator
   * as argument
   */
  /**
   * Returns an operator record with two functions:
   * next: dumps a given Tuple to the given output
   * reset: prints a reset message if the given show_reset is true
   */
  const dump_tuple_op = (
    outc: NodeJS.WriteStream,
    show_reset: boolean = false
  ): Operator => ({
    next: (tup: Tuple) => dump_tuple(outc, tup),
    reset: (tup: Tuple) => {
      if (show_reset) {
        dump_tuple(outc, tup);
        outc.write('[reset]\n');
      }
    },
  });
  
  /**
   * Tries to dump a nice csv-style output
   * Assumes all tuples have the same fields in the same order...
   */
  /**
   * Writes tuples to an output channel in CSV format
   * constructs operator record with two fields:
   * next: process tuples
   * reset: does nothing
   */
  const dump_as_csv = (
    outc: NodeJS.WriteStream,
    staticField: [string, string] | null = null,
    header: boolean = true
  ): Operator => {
    let first = header;
    return {
      next: (tup: Tuple) => {
        if (first) {
          if (staticField) {
            outc.write(`${staticField[0]},`);
          }
          let headerRow = '';
          for (const key of tup.keys()) {
            headerRow += `${key},`;
          }
          outc.write(`${headerRow.slice(0, -1)}\n`);
          first = false;
        }
        let dataRow = '';
        if (staticField) {
          dataRow += `${staticField[1]},`;
        }
        for (const value of tup.values()) {
          dataRow += `${string_of_op_result(value)},`;
        }
        outc.write(`${dataRow.slice(0, -1)}\n`);
      },
      reset: (_) => {},
    };
  };
  
  /**
   * Dumps csv in Walt's canonical csv format: src_ip, dst_ip, src_l4_port,
   * dst_l4_port, packet_count, byte_count, epoch_id
   * Unused fields are zeroed, map packet length to src_l4_port for ssh brute
   * force
   */
  const dump_walts_csv = (filename: string): Operator => {
    let outc: NodeJS.WriteStream | null = null;
    let first = true;
    return {
      next: (tup: Tuple) => {
        if (first) {
          outc = require('fs').openSync(filename, 'w');
          first = false;
        }
        const src_ip = string_of_op_result(tup.get('src_ip')!);
        const dst_ip = string_of_op_result(tup.get('dst_ip')!);
        const src_l4_port = string_of_op_result(tup.get('src_l4_port')!);
        const dst_l4_port = string_of_op_result(tup.get('dst_l4_port')!);
        const packet_count = string_of_op_result(tup.get('packet_count')!);
        const byte_count = string_of_op_result(tup.get('byte_count')!);
        const epoch_id = string_of_op_result(tup.get('epoch_id')!);
        if (outc) {
          require('fs').writeSync(
            outc,
            `<span class="math-inline">\{src\_ip\},</span>{dst_ip},<span class="math-inline">\{src\_l4\_port\},</span>{dst_l4_port},<span class="math-inline">\{packet\_count\},</span>{byte_count},${epoch_id}\n`
          );
        }
      },
      reset: (_) => {
        if (outc) {
          require('fs').closeSync(outc);
          outc = null;
          first = true;
        }
      },
    };
  };
  
  /**
   * Input is either "0" or and IPv4 address in string format,
   * returns corresponding OpResult
   */
  const get_ip_or_zero = (input: string): OpResult => {
    if (input === '0') {
      return {
        type: 'Int',
        value: 0
      };
    }
    return {
      type: 'IPv4',
      value: V4.parse(input).toString()
    };
  };
  
  /**
   * Reads an intermediate result CSV in Walt's canonical format
   * Injects epoch ids and incomming tuple counts into reset call
   */
  /**
   * TODO: read files in RR order...
   * otherwise the whole file gets cached in joins
   */
  /**
   * Reads multiple CSV files, extracts their network flow data, processes it into
   * tuples, and applies ops on the extracted data
   */
  const read_walts_csv = (
    fileNames: string[],
    ops: Operator[],
    epochIdKey: string = 'eid'
  ): void => {
    const inchsEidsTupcount = fileNames.map((filename) => ({
      inCh: require('fs').readFileSync(filename, 'utf-8').split('\n').filter(line => line.trim() !== ''),
      eid: {
        value: 0
      },
      tupCount: {
        value: 0
      },
      lineIndex: 0,
    }));
  
    let running = ops.length;
    while (running > 0) {
      for (let i = 0; i < inchsEidsTupcount.length; i++) {
        const {
          inCh,
          eid,
          tupCount,
          lineIndex
        } = inchsEidsTupcount[i];
        const op = ops[i % ops.length]; // Cycle through ops if fewer files than ops
  
        if (eid.value >= 0) {
          if (lineIndex < inCh.length) {
            const line = inCh[lineIndex];
            const parts = line.split(',');
            if (parts.length === 7) {
              try {
                const src_ip = parts[0];
                const dst_ip = parts[1];
                const src_l4_port = parseInt(parts[2], 10);
                const dst_l4_port = parseInt(parts[3], 10);
                const packet_count = parseInt(parts[4], 10);
                const byte_count = parseInt(parts[5], 10);
                const epoch_id = parseInt(parts[6], 10);
  
                let p: Tuple = new Map < string, OpResult > ();
                p.set('ipv4.src', get_ip_or_zero(src_ip));
                p.set('ipv4.dst', get_ip_or_zero(dst_ip));
                p.set('l4.sport', {
                  type: 'Int',
                  value: src_l4_port
                });
                p.set('l4.dport', {
                  type: 'Int',
                  value: dst_l4_port
                });
                p.set('packet_count', {
                  type: 'Int',
                  value: packet_count
                });
                p.set('byte_count', {
                  type: 'Int',
                  value: byte_count
                });
                p.set(epochIdKey, {
                  type: 'Int',
                  value: epoch_id
                });
  
                tupCount.value++;
                if (epoch_id > eid.value) {
                  while (epoch_id > eid.value) {
                    op.reset(
                      new Map < string, OpResult > ([
                        ['tuples', {
                          type: 'Int',
                          value: tupCount.value
                        }],
                        [epochIdKey, {
                          type: 'Int',
                          value: eid.value
                        }],
                      ])
                    );
                    tupCount.value = 0;
                    eid.value++;
                  }
                }
                op.next(
                  new Map < string, OpResult > ([
                    ['tuples', {
                      type: 'Int',
                      value: tupCount.value
                    }],
                    ...p,
                  ])
                );
                inchsEidsTupcount[i].lineIndex++;
              } catch (e) {
                console.error(`Failed to parse line: ${line}`, e);
                throw new Error(`Parse failure: ${e}`);
              }
            } else if (line.trim() !== '') {
              console.warn(`Skipping malformed line: ${line}`);
              inchsEidsTupcount[i].lineIndex++;
            } else {
              inchsEidsTupcount[i].lineIndex++;
            }
          } else {
            op.reset(
              new Map < string, OpResult > ([
                ['tuples', {
                  type: 'Int',
                  value: tupCount.value
                }],
                [epochIdKey, {
                  type: 'Int',
                  value: eid.value + 1
                }],
              ])
            );
            running--;
            eid.value = -1;
          }
        }
      }
    }
    console.log('Done.');
  };
  
  /**
   * Write the number of tuples passing through this operator each epoch
   * to the out_channel
   */
  /**
   * Tracks how many tuples processed per epoch and logs it to outc
   */
  const meta_meter = (
    name: string,
    outc: NodeJS.WriteStream,
    nextOp: Operator,
    staticField: string | null = null
  ): Operator => {
    const epochCount = {
      value: 0
    }; // # of times reset has been called
    const tupsCount ={
        value: 0
        }; // # of tuples processed before reset
        return {
        next: (tup: Tuple) => {
        tupsCount.value++;
        nextOp.next(tup);
        },
        reset: (tup: Tuple) => {
        outc.write(
        ${epochCount.value},${name},${tupsCount.value},${staticField || ''}\n
        );
        tupsCount.value = 0;
        epochCount.value++;
        nextOp.reset(tup);
        },
        };
        };
        
        /**
        
        Passes tuples through to op
        Resets op every w seconds
        Adds epoch id to tuple under key_out */ const epoch = ( epochWidth: number, keyOut: string, nextOp: Operator ): Operator => { const epochBoundary = { value: 0.0 }; const eid = { value: 0 }; return { next: (tup: Tuple) => { const time = float_of_op_result(tup.get('time')!); if (epochBoundary.value === 0.0) { epochBoundary.value = time + epochWidth; } else if (time >= epochBoundary.value) { while (time >= epochBoundary.value) { nextOp.reset(new Map < string, OpResult > ([ [keyOut, { type: 'Int', value: eid.value }], ])); epochBoundary.value += epochWidth; eid.value++; } } const newTup = new Map(tup); newTup.set(keyOut, { type: 'Int', value: eid.value }); nextOp.next(newTup); }, reset: (_) => { nextOp.reset(new Map < string, OpResult > ([ [keyOut, { type: 'Int', value: eid.value }], ])); epochBoundary.value = 0.0; eid.value = 0; }, }; };
        /**
const handleJoinSide = (
currHTble: Map < Tuple, Tuple > ,
otherHTbl: Map < Tuple, Tuple > ,
currEpochRef: {
value: number
},
otherEpochRef: {
value: number
},
f: KeyExtractor
): Operator => ({
next: (tup: Tuple) => {
/**
* extract the grouping key and remaining values, extract event
* ID from input tup
*/
const [key, vals_] = f(tup);
const currEpoch = get_mapped_int(eidKey, tup);

  while (currEpoch > currEpochRef.value) {
    if (otherEpochRef.value > currEpochRef.value) {
      nextOp.reset(
        new Map < string, OpResult > ([
          [eidKey, {
            type: 'Int',
            value: currEpochRef.value
          }],
        ])
      );
    }
    currEpochRef.value++;
  }
  const newTup = new Map(key);
  newTup.set(eidKey, {
    type: 'Int',
    value: currEpoch
  });
  const otherVals_ = otherHTbl.get(newTup);
  if (otherVals_) {
    const useLeft = (_: string, a: OpResult, _b: OpResult): OpResult | undefined => a;
    const mergedTup = new Map([...newTup, ...vals_, ...otherVals_]);
    nextOp.next(mergedTup);
    otherHTbl.delete(newTup);
  } else {
    currHTble.set(newTup, vals_);
  }
},
reset: (tup: Tuple) => {
  const currEpoch = get_mapped_int(eidKey, tup);
  while (currEpoch > currEpochRef.value) {
    if (otherEpochRef.value > currEpochRef.value) {
      nextOp.reset(
        new Map < string, OpResult > ([
          [eidKey, {
            type: 'Int',
            value: currEpochRef.value
          }],
        ])
      );
    }
    currEpochRef.value++;
  }
},
});

return [
handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch, leftExtractor),
handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch, rightExtractor),
];
};