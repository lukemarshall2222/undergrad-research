// common.ts

// Represents IPv4 address as a string (e.g., "192.168.1.1")
export type IPv4Address = string;
// Represents MAC address as a colon-separated hex string (e.g., "00:11:22:aa:bb:cc")
export type MacAddress = string;

// Discriminated union for operation results
export type OpResult =
  | { kind: "Float"; value: number }
  | { kind: "Int"; value: number }
  | { kind: "IPv4"; value: IPv4Address }
  | { kind: "MAC"; value: MacAddress }
  | { kind: "Empty" };

// Tuple: A map from string keys to OpResult values
export type Tuple = Map<string, OpResult>;

// Operator interface defining the processing functions
export interface Operator {
  next: (tuple: Tuple) => void;
  reset: (tuple: Tuple) => void;
}

// Type for functions that create operators (taking the next operator)
export type OpCreator = (nextOp: Operator) => Operator;

// Type for functions that create a pair of operators
export type DblOpCreator = (nextOp: Operator) => [Operator, Operator];


// --- Conversion Utilities ---

/**
 * Formats a Uint8Array MAC address buffer into a colon-separated hex string.
 * Assumes buffer has at least 6 bytes.
 */
export function macBufferToString(buf: Uint8Array): MacAddress {
    if (buf.length < 6) {
        throw new Error("MAC buffer too short");
    }
    return Array.from(buf.slice(0, 6))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(':');
}

/**
 * Converts TCP flags integer into a human-readable string (e.g., "SYN|ACK").
 */
export function tcpFlagsToStrings(flags: number): string {
    const flagMap: Record<string, number> = {
        "FIN": 1 << 0,
        "SYN": 1 << 1,
        "RST": 1 << 2,
        "PSH": 1 << 3,
        "ACK": 1 << 4,
        "URG": 1 << 5,
        "ECE": 1 << 6,
        "CWR": 1 << 7,
    };
    const activeFlags = Object.entries(flagMap)
        .filter(([_key, value]) => (flags & value) === value)
        .map(([key, _value]) => key);

    return activeFlags.join('|');
}

/**
 * Extracts integer value from OpResult, throws error if not Int.
 */
export function intOfOpResult(input: OpResult | undefined): number {
    if (input?.kind === "Int") {
        return input.value;
    }
    throw new Error(`Trying to extract int from non-int result: ${JSON.stringify(input)}`);
}

/**
 * Extracts float value from OpResult, throws error if not Float.
 */
export function floatOfOpResult(input: OpResult | undefined): number {
    if (input?.kind === "Float") {
        return input.value;
    }
    throw new Error(`Trying to extract float from non-float result: ${JSON.stringify(input)}`);
}

/**
 * Converts an OpResult to its string representation.
 */
export function stringOfOpResult(input: OpResult): string {
    switch (input.kind) {
        case "Float": return input.value.toString(); // Consider formatting (e.g., toFixed)
        case "Int": return input.value.toString();
        case "IPv4": return input.value;
        case "MAC": return input.value;
        case "Empty": return "Empty";
        default:
             // Ensure exhaustive check at compile time
             const exhaustiveCheck: never = input;
             throw new Error(`Unhandled OpResult kind: ${exhaustiveCheck}`);
    }
}

/**
 * Converts a Tuple (Map) to a human-readable string.
 * Example: "ipv4.src" => 192.168.1.1, "packet_count" => 10,
 */
export function stringOfTuple(inputTuple: Tuple): string {
    let result = "";
    inputTuple.forEach((value, key) => {
        result += `"${key}" => ${stringOfOpResult(value)}, `;
    });
    return result.replace(/, $/, ""); // Remove trailing comma and space
}

/**
 * Creates a Tuple (Map) from an array of key-value pairs.
 */
export function tupleOfList(tupList: [string, OpResult][]): Tuple {
    return new Map(tupList);
}

/**
 * Prints a formatted representation of a Tuple to the console.
 */
export function dumpTupleToConsole(tup: Tuple): void {
    console.log(stringOfTuple(tup));
}

/**
 * Retrieves the integer value associated with a key in a Tuple.
 * Throws an error if the key is not found or the value is not an Int.
 */
export function lookupInt(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return intOfOpResult(result);
}

/**
 * Retrieves the float value associated with a key in a Tuple.
 * Throws an error if the key is not found or the value is not a Float.
 */
export function lookupFloat(key: string, tup: Tuple): number {
    const result = tup.get(key);
    if (result === undefined) {
        throw new Error(`Key "${key}" not found in tuple`);
    }
    return floatOfOpResult(result);
}

/**
* Helper to create an IPv4 OpResult, handling "0" as Int 0.
*/
export function createIpOrZero(ipString: string): OpResult {
   if (ipString === "0") {
       return { kind: "Int", value: 0 };
   } else {
       // Basic validation could be added here
       return { kind: "IPv4", value: ipString };
   }
}