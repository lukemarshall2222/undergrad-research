#include "utils.hpp"

string tcpFlagsToStrings(int flags) {
  unordered_map<string, int> tcpFlagsMap = {
      {"FIN", 1 << 0}, {"SYN", 1 << 1}, {"RST", 1 << 2}, {"PSH", 1 << 3},
      {"ACK", 1 << 4}, {"URG", 1 << 5}, {"ECE", 1 << 6}, {"CWR", 1 << 7}};

  vector<string> activeFlags;
  for (const auto &[key, value] : tcpFlagsMap) {
    if ((flags & value) == value) {
      activeFlags.push_back(key);
    }
  }

  string result;
  for (int i = 0; i < activeFlags.size(); i++) {
    if (i > 0) result += "|";
    result += activeFlags[i];
  }

  return result;
}

int intOfOpResult(OpResult input) {
  switch (input.typ) {
    case OpResultType::Int:
      return get<int>(input.val);
    default:
      throw invalid_argument(
          "Error: attempt made to extract an int value out of a non-"
          "int OpResult");
  }
}

float floatOfOpResult(OpResult input) {
  switch (input.typ) {
    case OpResultType::Float:
      return get<float>(input.val);
    default:
      throw invalid_argument(
          "Error: attempt made to extract a float value out of a non-"
          "float OpResult");
  }
}

string stringOfOpResult(OpResult input) {
  switch (input.typ) {
    case OpResultType::Float:
      return to_string(get<float>(input.val));
    case OpResultType::Int:
      return to_string(get<int>(input.val));
    case OpResultType::IPv4:
      return get<IPv4Address>(input.val).toString();
    case OpResultType::MAC:
      return get<MACAddress>(input.val).toString();
    case OpResultType::Empty:
      return "Empty";
  }
}

string stringOfHeaders(Headers inputHeaders) {
  reduce(inputHeaders.begin(), inputHeaders.end(), string(),
         [](string acc, const std::pair<const std::string, OpResult> &header) {
           return acc + "\"" + header.first + "\"" +
                  stringOfOpResult(header.second);
         });
}

Headers headersOfList(vector<pair<string, OpResult>> headersList) {
  Headers newMap;
  for (const auto &[key, val] : headersList) {
    newMap.insert({key, val});
  }

  return newMap;
}

void dumpHeaders(Headers headers) {
  cout << stringOfHeaders(headers) << endl;
}

int lookupInt(string key, Headers headers) {
  auto found = headers.find(key);
  return found != headers.end() ? intOfOpResult(found->second)
                                : intOfOpResult(OpResult::Empty());
}

float lookupFloats(string key, Headers headers) {
  auto found = headers.find(key);
  return found != headers.end() ? floatOfOpResult(found->second)
                                : floatOfOpResult(OpResult::Empty());
}