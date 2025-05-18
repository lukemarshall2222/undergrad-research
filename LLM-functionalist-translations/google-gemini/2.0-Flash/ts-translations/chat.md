Prompt:

```typescript
/**
 * Common utilities
 *
 * Includes minimal parsing of header fields into a map from strings to values
 */

import {
  sprintf
} from 'sprintf-js';
import {
  v4 as ipaddr_v4
} from 'ip-address';

// Minimal emulation of Bytes (assuming it's used for MAC addresses)
type Bytes = string;

/**
 * Operators act on named "tuples" which are maps from strings to op_result types
 ***************************************************************************************/

type IpAddress = string; // Using string for simplicity, can be a more specific type

type OpResult =
  | {
      tag: 'Float';
      value: number
    } // tag for floating point vals
  | {
      tag: 'Int';
      value: number
    } // tag for int vals
  | {
      tag: 'IPv4';
      value: IpAddress
    } // tag for IPv4 address
  | {
      tag: 'MAC';
      value: Bytes
    } // tag for a MAC address
  | {
      tag: 'Empty'
    }; // tag for empty/missing val, possibly end of something

type Tuple = Map < string, OpResult > ;

interface Operator {
  next: (tuple: Tuple) => void; // takes in Map<string, op_result>, processes it in some way, most likely a side effect
  reset: (tuple: Tuple) => void; // takes same thing, performs a reset op on it after processing
}

type OpCreator = (operator: Operator) => Operator;
type DblOpCreator = (operator: Operator) => [Operator, Operator];

/**
 * Right associative "chaining" operator
 * for passing output of one operator to the next under cps-style operator constructors
 */
const at_equals_greater_than = (op_creator_func: OpCreator) => (next_op: Operator): Operator =>
  op_creator_func(next_op);
// e.g.
//    (epoch 1.0 "eid") @=> (groupby single_group count "pkts") @=> next_op
// instead of:
//    (epoch 1.0 "eid" (groupby single_group count "pkts" ) next_op)

const at_equals_equals_greater_than = (op_creator_func: DblOpCreator) => (op: Operator): [Operator, Operator] =>
  op_creator_func(op);

/**
 * Conversion utilities
 ***************************************************************************************/

/**
 * formats the 6 bytes of the MAC address as a colon-separated string in hex
 */
const string_of_mac = (buf: Bytes): string => {
  const byte_at = (index: number): number => parseInt(buf.substring(index * 2, index * 2 + 2), 16);
  return sprintf(
    '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x',
    byte_at(0),
    byte_at(1),
    byte_at(2),
    byte_at(3),
    byte_at(4),
    byte_at(5),
  );
};

/**
 * converts TCP flags into a human-readable string representation by matching
 * flags to formatted output
 */
const tcp_flags_to_strings = (flags: number): string => {
  // local module TCPFlagsMap allows storing and retrieving TCP flag names
  // and their bit operations easy
  const tcp_flags_map = new Map < string, number > ([
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
  for (const [key, value] of tcp_flags_map) {
    if ((flags & value) === value) {
      acc = acc === '' ? key : `${acc}|${key}`;
    }
  }
  return acc;
};

/**
 * checks if input is an Int op_result, raises exception otherwise
 */
const int_of_op_result = (input: OpResult): number => {
  if (input.tag === 'Int') {
    return input.value;
  }
  throw new Error('Trying to extract int from non-int result');
};

/**
 * checks if input is an Float op_result, raises exception otherwise
 */
const float_of_op_result = (input: OpResult): number => {
  if (input.tag === 'Float') {
    return input.value;
  }
  throw new Error('Trying to exctract float from non-float result');
};

/**
 * returns the human-readable version of each op_result value
 */
const string_of_op_result = (input: OpResult): string => {
  switch (input.tag) {
    case 'Float':
      return sprintf('%f', input.value);
    case 'Int':
      return input.value.toString();
    case 'IPv4':
      return input.value;
    case 'MAC':
      return string_of_mac(input.value);
    case 'Empty':
      return 'Empty';
  }
};

/**
 * outputs the tuple in a human-readble form e.g.
 * "ipv4.src" => 192.168.1.1, "packet_count" => 10,
 */
const string_of_tuple = (input_tuple: Tuple): string => {
  let acc = '';
  for (const [key, value] of input_tuple) {
    acc += `"${key}" => ${string_of_op_result(value)}, `;
  }
  return acc;
};

/**
 * creates a Tuple (Map<string, op_result>) out of a list of tuples
 */
const tuple_of_list = (tup_list: [string, OpResult][]): Tuple => {
  return new Map(tup_list);
};

/**
 * prints formatted representation of a Tuple
 */
const dump_tuple_fn = (outc: (message: string) => void) => (tup: Tuple): void => {
  outc(`${string_of_tuple(tup)}\n`);
};

/**
 * retrieves the int value of the op_result associated with a given key
 * in the given Tuple (Map<string, op_result>)
 */
const lookup_int = (key: string) => (tup: Tuple): number => {
  const value = tup.get(key);
  if (value) {
    return int_of_op_result(value);
  }
  throw new Error(`Key "${key}" not found in tuple`);
};

/**
 * retrieves the float value of the op_result associated with a given key
 * in the given Tuple (Map<string, op_result>)
 */
const lookup_float = (key: string) => (tup: Tuple): number => {
  const value = tup.get(key);
  if (value) {
    return float_of_op_result(value);
  }
  throw new Error(`Key "${key}" not found in tuple`);
};

/**
 * Built-in operator definitions
 * and common utilities for readability
 */

// Assuming Utils module is not needed for this translation

const init_table_size: number = 10000;

/**
 * Dump all fields of all tuples to the given output channel
 * Note that dump is terminal in that it does not take a continuation operator
 * as argument
 */
/**
 * returns an operator record with two functions:
 * next: dumps a given Tuple to the given output
 * reset: prints a reset message if the given show_reset is true
 */
const dump_tuple = (outc: (message: string) => void, show_reset: boolean = false): Operator => ({
  next: (tup: Tuple) => dump_tuple_fn(outc)(tup),
  reset: (tup: Tuple) => {
    if (show_reset) {
      dump_tuple_fn(outc)(tup);
      outc('[reset]\n');
    }
  },
});

/**
 * Tries to dump a nice csv-style output
 * Assumes all tuples have the same fields in the same order...
 */
/**
 * writes tuples to an output channel in CSV format
 * constructs operator record with two fields:
 * next: process tuples
 * reset: does nothing
 */
const dump_as_csv = (
  outc: (message: string) => void,
  static_field: [string, string] | null = null,
  header: boolean = true,
): Operator => {
  let first: boolean = header;
  return {
    next: (tup: Tuple) => {
      if (first) {
        if (static_field) {
          outc(`${static_field[0]},`);
        }
        let headerRow = '';
        for (const key of tup.keys()) {
          headerRow += `${key},`;
        }
        outc(`${headerRow}\n`);
        first = false;
      }
      let dataRow = '';
      if (static_field) {
        dataRow += `${static_field[1]},`;
      }
      for (const value of tup.values()) {
        dataRow += `${string_of_op_result(value)},`;
      }
      outc(`${dataRow}\n`);
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
  let outc: ((message: string) => void) | null = null;
  let first: boolean = true;
  return {
    next: (tup: Tuple) => {
      if (first) {
        // In a real Node.js environment, you would use fs.openSync and fs.writeFileSync
        // For this translation, we'll just log to console.
        console.log(`Opening file: ${filename} (simulated)`);
        outc = console.log;
        first = false;
      }
      if (outc) {
        outc(
          sprintf(
            '%s,%s,%s,%s,%s,%s,%s\n',
            string_of_op_result(tup.get('src_ip') !),
            string_of_op_result(tup.get('dst_ip') !),
            string_of_op_result(tup.get('src_l4_port') !),
            string_of_op_result(tup.get('dst_l4_port') !),
            string_of_op_result(tup.get('packet_count') !),
            string_of_op_result(tup.get('byte_count') !),
            string_of_op_result(tup.get('epoch_id') !),
          ),
        );
      }
    },
    reset: (_) => {},
  };
};

/**
 * input is either "0" or and IPv4 address in string format,
 * returns corresponding op_result
 */
const get_ip_or_zero = (input: string): OpResult => {
  if (input === '0') {
    return {
      tag: 'Int',
      value: 0
    };
  }
  try {
    if (ipaddr_v4.isValid(input)) {
      return {
        tag: 'IPv4',
        value: input
      };
    }
    return {
      tag: 'Int',
      value: 0
    }; // Handle invalid IP as zero for simplicity
  } catch (e) {
    return {
      tag: 'Int',
      value: 0
    }; // Handle parsing errors as zero
  }
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
 * reads multiple CSV files, extracts their network flow data, processes it into
 * tuples, and applies ops on the extracted data
 */
const read_walts_csv = (
  file_names: string[],
  ops: Operator[],
  epoch_id_key: string = 'eid',
): void => {
  const inchs_eids_tupcount = file_names.map((filename) => ({
    filename,
    eid: 0,
    tup_count: 0,
    lines: [], // Simulate reading all lines for simplicity
    index: 0,
  }));

  // Simulate reading files
  for (const fileInfo of inchs_eids_tupcount) {
    // In a real Node.js environment, you would use fs.readFileSync
    const fileContent = `192.168.1.1,192.168.1.2,80,443,10,1000,1\n192.168.1.3,192.168.1.4,22,50000,5,500,1\n0,192.168.1.5,1234,5678,2,200,2`; // Example content
    fileInfo.lines = fileContent.trim().split('\n');
  }

  let running = ops.length;
  while (running > 0) {
    for (let i = 0; i < inchs_eids_tupcount.length; i++) {
      const fileInfo = inchs_eids_tupcount[i];
      const op = ops[i % ops.length]; // Cycle through ops if fewer than files

      if (fileInfo.eid >= 0) {
        if (fileInfo.index < fileInfo.lines.length) {
          try {
            const line = fileInfo.lines[fileInfo.index];
            fileInfo.index++;
            const [src_ip, dst_ip, src_l4_port_str, dst_l4_port_str, packet_count_str, byte_count_str, epoch_id_str] =
              line.split(',');
            const src_l4_port = parseInt(src_l4_port_str, 10);
            const dst_l4_port = parseInt(dst_l4_port_str, 10);
            const packet_count = parseInt(packet_count_str, 10);
            const byte_count = parseInt(byte_count_str, 10);
            const epoch_id = parseInt(epoch_id_str, 10);

            let p: Tuple = new Map();
            p.set('ipv4.src', get_ip_or_zero(src_ip));
            p.set('ipv4.dst', get_ip_or_zero(dst_ip));
            p.set('l4.sport', {
              tag: 'Int',
              value: src_l4_port
            });
            p.set('l4.dport', {
              tag: 'Int',
              value: dst_l4_port
            });
            p.set('packet_count', {
              tag: 'Int',
              value: packet_count
            });
            p.set('byte_count', {
              tag: 'Int',
              value: byte_count
            });
            p.set(epoch_id_key, {
              tag: 'Int',
              value: epoch_id
            });

            fileInfo.tup_count++;
            if (epoch_id > fileInfo.eid) {
              while (epoch_id > fileInfo.eid) {
                op.reset(
                  new Map([
                    ['tuples', {
                      tag: 'Int',
                      value: fileInfo.tup_count
                    }],
                    [epoch_id_key, {
                      tag: 'Int',
                      value: fileInfo.eid
                    }],
                  ]),
                );
                fileInfo.tup_count = 0;
                fileInfo.eid++;
              }
            }
            op.next(new Map([['tuples', {
              tag: 'Int',
              value: fileInfo.tup_count
            }], ...p]));
          } catch (e) {
            console.error(`Failed to scan line: ${fileInfo.lines[fileInfo.index - 1]}`, e);
            throw new Error('Scan failure');
          }
        } else {
          op.reset(
            new Map([
              ['tuples', {
                tag: 'Int',
                value: fileInfo.tup_count
              }],
              [epoch_id_key, {
                tag: 'Int',
                value: fileInfo.eid + 1
              }],
            ]),
          );
          running--;
          fileInfo.eid = -1;
        }

Prompt: Give the rest of the translation

```typescript
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
 * tracks how many tuples processed per epoch and logs it to outc
 */
const meta_meter = (
  outc: (message: string) => void,
  name: string,
  next_op: Operator,
  static_field: string | null = null,
): Operator => {
  const epoch_count: {
    value: number
  } = {
    value: 0
  }; // # of times reset has been called
  const tups_count: {
    value: number
  } = {
    value: 0
  }; // # of tuples processed before reset
  return {
    next: (tup: Tuple) => {
      tups_count.value++;
      next_op.next(tup);
    },
    reset: (tup: Tuple) => {
      outc(
        sprintf(
          '%d,%s,%d,%s\n',
          epoch_count.value,
          name,
          tups_count.value,
          static_field !== null ? static_field : '',
        ),
      );
      tups_count.value = 0;
      epoch_count.value++;
      next_op.reset(tup);
    },
  };
};

/**
 * Passes tuples through to op
 * Resets op every w seconds
 * Adds epoch id to tuple under key_out
 */
const epoch = (epoch_width: number, key_out: string, next_op: Operator): Operator => {
  const epoch_boundary: {
    value: number
  } = {
    value: 0.0
  };
  const eid: {
    value: number
  } = {
    value: 0
  };
  return {
    next: (tup: Tuple) => {
      const time_op = tup.get('time');
      if (time_op && time_op.tag === 'Float') {
        const time = time_op.value;
        if (epoch_boundary.value === 0.0) {
          epoch_boundary.value = time + epoch_width;
        } else if (time >= epoch_boundary.value) {
          while (time >= epoch_boundary.value) {
            next_op.reset(new Map([
              [key_out, {
                tag: 'Int',
                value: eid.value
              }]
            ]));
            epoch_boundary.value += epoch_width;
            eid.value++;
          }
        }
        next_op.next(new Map([...tup, [key_out, {
          tag: 'Int',
          value: eid.value
        }]]));
      }
    },
    reset: (_) => {
      // resets the last epoch ID
      next_op.reset(new Map([
        [key_out, {
          tag: 'Int',
          value: eid.value
        }]
      ]));
      epoch_boundary.value = 0.0;
      eid.value = 0;
    },
  };
};

/**
 * Passes only tuples where f applied to the tuple returns true
 */
/**
 * creates a filtering opterator, applying the given operator if this one
 * returns true otherwise returning false
 */
const filter = (f: (tuple: Tuple) => boolean) => (next_op: Operator): Operator => ({
  next: (tup: Tuple) => {
    if (f(tup)) {
      next_op.next(tup);
    }
  },
  reset: (tup: Tuple) => next_op.reset(tup),
});

/**
 * (filter utility)
 * comparison function for testing int values against a threshold
 */
const key_geq_int = (key: string, threshold: number) => (tup: Tuple): boolean => {
  // tests an op_result val against a given threshold
  const value = tup.get(key);
  return value ? .tag === 'Int' && value.value >= threshold;
};

/**
 * (filter utility)
 * Looks up the given key and converts to Int op_result
 * if the key does not hold an int, this will raise an exception
 */
const get_mapped_int = (key: string) => (tup: Tuple): number => {
  const value = tup.get(key);
  if (value && value.tag === 'Int') {
    return value.value;
  }
  throw new Error(`Key "${key}" does not hold an int`);
};

/**
 * (filter utility)
 * Looks up the given key and converts to Float op_result
 * if the key does not hold an int, this will raise an exception
 */
const get_mapped_float = (key: string) => (tup: Tuple): number => {
  const value = tup.get(key);
  if (value && value.tag === 'Float') {
    return value.value;
  }
  throw new Error(`Key "${key}" does not hold a float`);
};

/**
 * Operator which applied the given function on all tuples
 * Passes resets, unchanged
 */
/**
 * applies the given operator to the result of this operator applied to the
 * Tuple
 */
const map = (f: (tuple: Tuple) => Tuple) => (next_op: Operator): Operator => ({
  next: (tup: Tuple) => next_op.next(f(tup)),
  reset: (tup: Tuple) => next_op.reset(tup),
});

type GroupingFunc = (tuple: Tuple) => Tuple;
type ReductionFunc = (acc: OpResult, current: Tuple) => OpResult;

/**
 * Groups the input Tuples according to canonic members returned by
 * key_extractor : Tuple -> Tuple
 * Tuples in each group are folded (starting with Empty) by
 * accumulate : op_result -> Tuple -> op_result
 * When reset, op is passed a Tuple for each group containing the union of
 * (i) the reset argument tuple,
 * (ii) the result of g for that group, and
 * (iii) a mapping from out_key to the result of the fold for that group
 */
const groupby = (
  groupby_fn: GroupingFunc,
  reduce: ReductionFunc,
  out_key: string,
  next_op: Operator,
): Operator => {
  const h_tbl: Map < Tuple, OpResult > = new Map();
  const reset_counter: {
    value: number
  } = {
    value: 0
  };
  return {
    next: (tup: Tuple) => {
      // grouping_key is sub-Tuple of original extracted by key_extractor
      const grouping_key: Tuple = groupby_fn(tup);
      // if the Tuple key is already in the hash table, its existing value
      // and the new values are grouped via the grouping mech else the new
      // values are grouped with Empty via the grouping mech
      const existing_val = h_tbl.get(grouping_key);
      h_tbl.set(grouping_key, reduce(existing_val || {
        tag: 'Empty'
      }, tup));
    },
    reset: (tup: Tuple) => {
      // track the counter reset
      reset_counter.value++;
      for (const [grouping_key, val_] of h_tbl) {
        // iterate over hashtable, !!! MORE info needed to figure this out
        const unioned_tup = new Map([...tup, ...grouping_key]);
        next_op.next(new Map([...unioned_tup, [out_key, val_]]));
      }
      next_op.reset(tup); // reset the next operator in line and clear the
      // hash table
      h_tbl.clear();
    },
  };
};

/**
 * (groupby utility : key_extractor)
 * Returns a new tuple with only the keys included in the incl_keys list
 */
const filter_groups = (incl_keys: string[]) => (tup: Tuple): Tuple => {
  const new_tup: Tuple = new Map();
  for (const key of incl_keys) {
    const value = tup.get(key);
    if (value) {
      new_tup.set(key, value);
    }
  }
  return new_tup;
};

/**
 * (groupby utility : key_extractor)
 * Grouping function (key_extractor) that forms a single group
 */
const single_group = (_: Tuple): Tuple => new Map();

/**
 * (groupby utility : grouping_mech)
 * Reduction function (f) to count tuples
 */
const counter = (acc: OpResult, _: Tuple): OpResult => {
  if (acc.tag === 'Empty') {
    return {
      tag: 'Int',
      value: 1
    };
  }
  if (acc.tag === 'Int') {
    return {
      tag: 'Int',
      value: acc.value + 1
    };
  }
  return acc;
};

/**
 * (groupby utility)
 * Reduction function (f) to sum values (assumed to be Int ()) of a given field
 */
const sum_ints = (search_key: string) => (init_val: OpResult, tup: Tuple): OpResult => {
  if (init_val.tag === 'Empty') {
    return {
      tag: 'Int',
      value: 0
    }; // empty init val, need to init the val to 0
  }
  if (init_val.tag === 'Int') {
    // actual int val, find the given search key
    const found_val = tup.get(search_key);
    if (found_val && found_val.tag === 'Int') {
      return {
        tag: 'Int',
        value: found_val.value + init_val.value
      }; // set its val to the sum of the
      // the given and current value if found else report failure
    }
    throw new Error(
      sprintf('\'sum_vals\' function failed to find integer value mapped to "%s"', search_key),
    );
  }
  return init_val;
};

/**
 * Returns a list of distinct elements (as determined by group_tup) each epoch
 * removes duplicate Tuples based on group_tup
 */
const distinct = (groupby_fn: GroupingFunc) => (next_op: Operator): Operator => {
  const h_tbl: Map < Tuple, boolean > = new Map();
  const reset_counter: {
    value: number
  } = {
    value: 0
  };
  return {
    next: (tup: Tuple) => {
      const grouping_key: Tuple = groupby_fn(tup);
      h_tbl.set(grouping_key, true);
    },
    reset: (tup: Tuple) => {
      reset_counter.value++;
      for (const key_ of h_tbl.keys()) {
        const merged_tup = new Map([...tup, ...key_]);
        next_op.next(merged_tup);
      }
      next_op.reset(tup);
      h_tbl.clear();
    },
  };
};

/**
 * Just sends both next and reset directly to two different downstream operators
 * i.e. splits the stream processing in two
 */
const split = (l: Operator, r: Operator): Operator => ({
  next: (tup: Tuple) => {
    l.next(tup);
    r.next(tup);
  },
  reset: (tup: Tuple) => {
    l.reset(tup);
    r.reset(tup);
  },
});

type KeyExtractor = (tuple: Tuple) => [Tuple, Tuple];

/**
 * Initial shot at a join semantic that doesn't require maintining entire state
 * Functions left and right transform input tuples into a key,value pair of tuples
 * The key determines a canonical tuple against which the other stream will match
 * The value determines extra fields which should be saved and added when a
 * match is made
 *
 * Requires tuples to have epoch id as int value in field referenced by eid_key.
 */
const join = (
  left_extractor: KeyExtractor,
  right_extractor: KeyExtractor,
  next_op: Operator,
  eid_key: string = 'eid',
): [Operator, Operator] => {
  const h_tbl1: Map < Tuple, Tuple > = new Map();
  const h_tbl2: Map < Tuple, Tuple > = new Map();
  const left_curr_epoch: {
    value: number
  } = {
    value: 0
  };
  const right_curr_epoch: {
    value: number
  } = {
    value: 0
  };

  const handle_join_side = (
    curr_h_tble: Map < Tuple, Tuple > ,
    other_h_tbl: Map < Tuple, Tuple > ,
    curr_epoch_ref: {
      value: number
    },
    other_epoch_ref: {
      value: number
    },
    f: KeyExtractor,
  ): Operator => ({
    next: (tup: Tuple) => {
      // extract the grouping key and remaining values, extract event
      // ID from input tup
      const [key, vals_] = f(tup);
      const curr_epoch = get_mapped_int(eid_key)(tup);

      while (curr_epoch > curr_epoch_ref.value) {
        if (other_epoch_ref.value > curr_epoch_ref.value) {
          next_op.reset(new Map([
            [eid_key, {
              tag: 'Int',
              value: curr_epoch_ref.value
            }]
          ]));
        }
        curr_epoch_ref.value++;
      }
      const new_tup = new Map([...key, [eid_key, {
        tag: 'Int',
        value: curr_epoch
      }]]);
      const other_val = other_h_tbl.get(new_tup);
      if (other_val) {
        const use_left = (_: string, a: OpResult, __?: OpResult) => a;
        other_h_tbl.delete(new_tup);
        next_op.next(new Map([...new_tup, ...vals_, ...other_val]));
      } else {
        curr_h_tble.set(new_tup, vals_);
      }
    },
    reset: (tup: Tuple) => {
      const curr_epoch = get_mapped_int(eid_key)(tup);
      while (curr_epoch > curr_epoch_ref.value) {
        if (other_epoch_ref.value > curr_epoch_ref.value) {
          next_op.reset(new Map([
            [eid_key, {
              tag: 'Int',
              value: curr_epoch_ref.value
            }]
          ]));
        }
        curr_epoch_ref.value++;
      }
    },
  });

  return [
    handle_join_side(h_tbl1, h_tbl2, left_curr_epoch, right_curr_epoch, left_extractor),
    handle_join_side(h_tbl2, h_tbl1, right_curr_epoch, left_curr_epoch, right_extractor),
  ];
};

/**
 * (join utility)
 * Returns a new tuple with only the keys included in the first of each pair in
 * keys
 * These keys are renamed to the second of each pair in keys
 * Use in conjunction with the join implementation above to get the "join left
 * with right on left.x = right.y" kind of thing
 */
const rename_filtered_keys = (renamings_pairs: [string, string][]) => (in_tup: Tuple): Tuple => {
  let new_tup: Tuple = new Map();
  for (const [old_key, new_key] of renamings_pairs) {
    const value = in_tup.get(old_key);
    if (value) {
      new_tup.set(new_key, value);
    }
  }
  return new_tup;
};

/**
 * Main entry point and implementation for simple header-dump operation
 */

// Assuming Utils and Builtins are now part of this file

// '@=>' is just a right-associative application to avoid nasty nested parens
const ident = (next_op: Operator): Operator =>
  map((tup: Tuple) => {
    const new_tup: Tuple = new Map();
    for (const [key_, value] of tup) {
      if (key_ !== 'eth.src' && key_ !== 'eth.dst') {
        new_tup.set(key_, value);
      }
    }
    return new_tup;
  })(next_op);

/**
 * assigns each tuple an epoch ID based on time by adding an eid key, counts
 * the number of tuples in each epoch, then passes the processed tuples to the
 * next_op
 */
const count_pkts = (next_op: Operator): Operator =>
  at_equals_greater_than(epoch(1.
```

Prompt: Give the rest of the translation

0, 'eid'))(at_equals_greater_than(groupby(single_group, counter, 'pkts'))(next_op));

/**
 * assigns each tuple an epoch ID based on time by adding an eid key, groups
 * them by source and dest ip, counts and stores the number of tuples in each
 * group, and passes result to next_op
 */
const pkts_per_src_dst = (next_op: Operator): Operator =>
  at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(groupby(filter_groups(['ipv4.src', 'ipv4.dst']), counter, 'pkts'))(next_op),
  );

const distinct_srcs = (next_op: Operator): Operator =>
  at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(distinct(filter_groups(['ipv4.src'])))(
      at_equals_greater_than(groupby(single_group, counter, 'srcs'))(next_op),
    ),
  );

/**
 * Sonata 1
 */
const tcp_new_cons = (next_op: Operator): Operator => {
  const threshold: number = 40;
  return at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(
      filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 2),
    )(
      at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'cons'))(
        at_equals_greater_than(filter(key_geq_int('cons', threshold)))(next_op),
      ),
    ),
  );
};

/**
 * Sonata 2
 */
const ssh_brute_force = (next_op: Operator): Operator => {
  const threshold: number = 40;
  return at_equals_greater_than(epoch(1.0, 'eid'))( // might need to elongate epoch for this one...
    at_equals_greater_than(
      distinct(filter_groups(['ipv4.src', 'ipv4.dst', 'ipv4.len'])),
    )(
      at_equals_greater_than(groupby(filter_groups(['ipv4.dst', 'ipv4.len']), counter, 'srcs'))(
        at_equals_greater_than(filter(key_geq_int('srcs', threshold)))(next_op),
      ),
    ),
  );
};

/**
 * Sonata 3
 */
const super_spreader = (next_op: Operator): Operator => {
  const threshold: number = 40;
  return at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(distinct(filter_groups(['ipv4.src', 'ipv4.dst'])))(
      at_equals_greater_than(groupby(filter_groups(['ipv4.src']), counter, 'dsts'))(
        at_equals_greater_than(filter(key_geq_int('dsts', threshold)))(next_op),
      ),
    ),
  );
};

/**
 * Sonata 4
 */
const port_scan = (next_op: Operator): Operator => {
  const threshold: number = 40;
  return at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(distinct(filter_groups(['ipv4.src', 'l4.dport'])))(
      at_equals_greater_than(groupby(filter_groups(['ipv4.src']), counter, 'ports'))(
        at_equals_greater_than(filter(key_geq_int('ports', threshold)))(next_op),
      ),
    ),
  );
};

/**
 * Sonata 5
 */
const ddos = (next_op: Operator): Operator => {
  const threshold: number = 45;
  return at_equals_greater_than(epoch(1.0, 'eid'))(
    at_equals_greater_than(distinct(filter_groups(['ipv4.src', 'ipv4.dst'])))(
      at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'srcs'))(
        at_equals_greater_than(filter(key_geq_int('srcs', threshold)))(next_op),
      ),
    ),
  );
};

/**
 * Sonata 6 --- Note this implements the Sonata semantic of this query
 *NOT* the intended semantic from NetQRE
 */
const syn_flood_sonata = (next_op: Operator): Operator[] => {
  const threshold: number = 3;
  const epoch_dur: number = 1.0;
  const syns = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 2),
      )(at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'syns'))(inner_next_op)),
    );
  const synacks = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 18),
      )(at_equals_greater_than(groupby(filter_groups(['ipv4.src']), counter, 'synacks'))(inner_next_op)),
    );
  const acks = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 16),
      )(at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'acks'))(inner_next_op)),
    );
  const [join_op1, join_op2] = at_equals_equals_greater_than(
    join(
      (tup: Tuple): [Tuple, Tuple] => [filter_groups(['host'])(tup), filter_groups(['syns+synacks'])(tup)],
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.dst', 'host']
      ])(tup), filter_groups(['acks'])(tup)],
    ),
  )(
    at_equals_greater_than(
      map((tup: Tuple) =>
        new Map([...tup, [
          'syns+synacks-acks', {
            tag: 'Int',
            value: get_mapped_int('syns+synacks')(tup) - get_mapped_int('acks')(tup)
          }
        ]])),
    )(at_equals_greater_than(filter(key_geq_int('syns+synacks-acks', threshold)))(next_op)),
  );
  const [join_op3, join_op4] = at_equals_equals_greater_than(
    join(
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.dst', 'host']
      ])(tup), filter_groups(['syns'])(tup)],
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.src', 'host']
      ])(tup), filter_groups(['synacks'])(tup)],
    ),
  )(
    at_equals_greater_than(
      map((tup: Tuple) =>
        new Map([...tup, [
          'syns+synacks', {
            tag: 'Int',
            value: get_mapped_int('syns')(tup) + get_mapped_int('synacks')(tup)
          }
        ]])),
    )(join_op1),
  );
  return [syns(join_op3), synacks(join_op4), acks(join_op2)];
};

/**
 * Sonata 7
 */
const completed_flows = (next_op: Operator): Operator[] => {
  const threshold: number = 1;
  const epoch_dur: number = 30.0;
  const syns = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 2),
      )(at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'syns'))(inner_next_op)),
    );
  const fins = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && (get_mapped_int('l4.flags')(tup) & 1) === 1),
      )(at_equals_greater_than(groupby(filter_groups(['ipv4.src']), counter, 'fins'))(inner_next_op)),
    );
  const [op1, op2] = at_equals_equals_greater_than(
    join(
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.dst', 'host']
      ])(tup), filter_groups(['syns'])(tup)],
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.src', 'host']
      ])(tup), filter_groups(['fins'])(tup)],
    ),
  )(
    at_equals_greater_than(
      map((tup: Tuple) =>
        new Map([...tup, [
          'diff', {
            tag: 'Int',
            value: get_mapped_int('syns')(tup) - get_mapped_int('fins')(tup)
          }
        ]])),
    )(at_equals_greater_than(filter(key_geq_int('diff', threshold)))(next_op)),
  );
  return [syns(op1), fins(op2)];
};

/**
 * Sonata 8
 */
const slowloris = (next_op: Operator): Operator[] => {
  const t1: number = 5;
  const t2: number = 500;
  const t3: number = 90;
  const epoch_dur: number = 1.0;
  const n_conns = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6),
      )(
        at_equals_greater_than(distinct(filter_groups(['ipv4.src', 'ipv4.dst', 'l4.sport'])))(
          at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'n_conns'))(
            at_equals_greater_than(filter((tup: Tuple) => get_mapped_int('n_conns')(tup) >= t1))(inner_next_op),
          ),
        ),
      ),
    );
  const n_bytes = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6),
      )(
        at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), sum_ints('ipv4.len'), 'n_bytes'))(
          at_equals_greater_than(filter((tup: Tuple) => get_mapped_int('n_bytes')(tup) >= t2))(inner_next_op),
        ),
      ),
    );
  const [op1, op2] = at_equals_equals_greater_than(
    join(
      (tup: Tuple): [Tuple, Tuple] => [filter_groups(['ipv4.dst'])(tup), filter_groups(['n_conns'])(tup)],
      (tup: Tuple): [Tuple, Tuple] => [filter_groups(['ipv4.dst'])(tup), filter_groups(['n_bytes'])(tup)],
    ),
  )(
    at_equals_greater_than(
      map((tup: Tuple) =>
        new Map([...tup, [
          'bytes_per_conn', {
            tag: 'Int',
            value: Math.floor(get_mapped_int('n_bytes')(tup) / get_mapped_int('n_conns')(tup))
          }
        ]])),
    )(at_equals_greater_than(filter((tup: Tuple) => get_mapped_int('bytes_per_conn')(tup) <= t3))(next_op)),
  );
  return [n_conns(op1), n_bytes(op2)];
};

const join_test = (next_op: Operator): Operator[] => {
  const epoch_dur: number = 1.0;
  const syns = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 2),
      )(inner_next_op),
    );
  const synacks = (inner_next_op: Operator): Operator =>
    at_equals_greater_than(epoch(epoch_dur, 'eid'))(
      at_equals_greater_than(
        filter((tup: Tuple) => get_mapped_int('ipv4.proto')(tup) === 6 && get_mapped_int('l4.flags')(tup) === 18),
      )(inner_next_op),
    );
  const [op1, op2] = at_equals_equals_greater_than(
    join(
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.src', 'host']
      ])(tup), rename_filtered_keys([
        ['ipv4.dst', 'remote']
      ])(tup)],
      (tup: Tuple): [Tuple, Tuple] => [rename_filtered_keys([
        ['ipv4.dst', 'host']
      ])(tup), filter_groups(['time'])(tup)],
    ),
  )(next_op);
  return [syns(op1), synacks(op2)];
};

const q3 = (next_op: Operator): Operator =>
  at_equals_greater_than(epoch(100.0, 'eid'))(
    at_equals_greater_than(distinct(filter_groups(['ipv4.src', 'ipv4.dst'])))(next_op),
  );

const q4 = (next_op: Operator): Operator =>
  at_equals_greater_than(epoch(10000.0, 'eid'))(
    at_equals_greater_than(groupby(filter_groups(['ipv4.dst']), counter, 'pkts'))(next_op),
  );

const queries: Operator[] = [at_equals_greater_than(ident)(dump_tuple(console.log))];

const run_queries = (): void => {
  Array.from({
    length: 20
  }, (_, i) => {
    let tup: Tuple = new Map < string, OpResult > ();
    tup.set('time', {
      tag: 'Float',
      value: 0.000000 + i
    });
    tup.set('eth.src', {
      tag: 'MAC',
      value: '\x00\x11\x22\x33\x44\x55'
    });
    tup.set('eth.dst', {
      tag: 'MAC',
      value: '\xAA\xBB\xCC\xDD\xEE\xFF'
    });
    tup.set('eth.ethertype', {
      tag: 'Int