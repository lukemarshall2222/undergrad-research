#ifndef UTILS_H
#define UTILS_H

#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

using namespace std;

class IPv4Address {
 private:
  array<uint8_t, 4> address;

 public:
  IPv4Address(const string& ipString) {
    stringstream str(ipString);
    string segment;
    array<int, 4> parts;
    int i = 0;

    while (getline(str, segment, '.')) {
      if (i >= 4) {
        throw invalid_argument(
            "Error: given IPv4Address value has too many segments");
      }
      address[i++] = stoi(segment);
    }

    if (i != 4) {
      throw invalid_argument(
          "Error: IPv4 address attempted to be made out of an argument"
          " with the incorrect format");
    }
  }

  uint8_t getPart(size_t index) {
    if (index >= 4) {
      throw out_of_range("Index out of bounds for IPv4 address getPart");
    }
    return address[index];
  }

  string toString() {
    stringstream str;
    for (auto part : address) {
      str << static_cast<int>(part) << ".";
    }
    str << endl;
    return str.str();
  }

  void print() { cout << this->toString() << endl; }
};

class MACAddress {
 private:
  array<uint8_t, 6> address;

 public:
  MACAddress(const string& macString) {
    stringstream ss(macString);
    string segment;
    int i = 0;

    while (getline(ss, segment, ':')) {
      if (i >= 6) {
        throw invalid_argument("Invalid MAC address string: too many segments");
      }
      size_t pos = 0;
      address[i++] = stoi(segment, &pos, 16);
    }

    if (i != 6) {
      throw invalid_argument(
          "Error: MAC address attempted to be made out of an argument"
          " with the incorrect format");
    }
  }

  uint8_t getPart(size_t index) {
    if (index >= 6) {
      throw out_of_range("Index out of bounds for MAC address getPart");
    }
    return address[index];
  }

  array<uint8_t, 6> parts() { return address; }

  string toString() const {
    stringstream str;
    for (size_t i = 0; i < 6; i++) {
      str << hex << setw(2) << setfill('0') << static_cast<int>(address[i]);
      if (i < 5) {
        str << ":";
      }
    }
    return str.str();
  }

  void print() const { cout << toString() << endl; }
};

using opKinds = variant<float, int, IPv4Address, MACAddress, monostate>;

enum class OpResultType {
  Float,
  Int,
  IPv4,
  MAC,
  Empty,
};

struct OpResult {
  OpResultType typ;
  opKinds val;

  static OpResult Float(float val) {
    return {OpResultType::Float, opKinds(val)};
  }
  static OpResult Int(int val) { return {OpResultType::Int, opKinds(val)}; }
  static OpResult IPv4(IPv4Address val) {
    return {OpResultType::IPv4, opKinds(val)};
  }
  static OpResult MAC(MACAddress val) {
    return {OpResultType::MAC, opKinds(val)};
  }
  static OpResult Empty() { return {OpResultType::Empty, monostate{}}; }
};

using Headers = unordered_map<string, OpResult>;

using OpFunc = function<void(Headers)>;

struct Operator {
  OpFunc next;
  OpFunc reset;

  Operator(OpFunc next, OpFunc reset) : next(next), reset(reset) {};
};

using OpCreator = function<Operator(Operator)>;
using DblOpCreator = function<pair<Operator, Operator>(Operator)>;
using DblOpAcceptorOpCreator = function<Operator(pair<Operator, Operator>)>;

Operator __(OpCreator opCreator, Operator nextOp) { return opCreator(nextOp); }

pair<Operator, Operator> ___(DblOpCreator opCreator, Operator nextOp) {
  return opCreator(nextOp);
}

string tcpFlagsToStrings(int flags);
int intOfOpResult(OpResult input);
float floatOfOpResult(OpResult input);
string stringOfOpResult(OpResult input);
string stringOfHeaders(Headers inputHeaders);
Headers headersOfList(vector<pair<string, OpResult>> headersList);
void dumpHeaders(ofstream outc, Headers headers);
int lookupInt(string key, Headers headers);
float lookupFloats(string key, Headers headers);

#endif  // UTILS_H