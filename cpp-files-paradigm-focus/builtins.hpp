#ifndef BUILTINS_H
#define BUILTINS_H

#include <string>
#include <fstream>
#include <functional>
#include <optional>
#include <variant>
#include <iostream>
#include <memory>
#include "utils.hpp"

using namespace std;

using GroupingFunc = function<Headers(Headers)>;
using ReductionFunc = function<OpResult(OpResult, Headers)>;
using KeyExtractor = function<pair<Headers, Headers>(Headers)>;

Operator dumpHeaders(Headers headers, bool showReset);
Operator dumpAsCSV(optional<pair<string, string>> staticField,
                   bool header);
Operator dumpWaltsCSV(string filename);
OpResult getIpOrZero(string input);
Headers singleton(string keyOut, OpResult val);
OpCreator epochCreator(float epochWidth, string keyOut);
OpCreator filterCreator(function<bool(Headers)> f);
bool keyGeqInt(string key, int threshold, Headers headers);
int getMappedInt(string key, Headers headers);
float getMappedFloat(string key, Headers headers);
OpCreator mapCreator(function<Headers(Headers)> f);
Headers unionHeaders(Headers h1, Headers h2);
OpCreator groupbyCreator(GroupingFunc groupby, ReductionFunc reduct,
                      string outKey);
Headers filterGroups(vector<string> inclKeys, Headers headers);
Headers singleGroup(Headers _);
OpResult counter(OpResult val, Headers _);
OpResult sumInts(string searchKey, OpResult initVal, Headers headers);
OpCreator distinctCreator(GroupingFunc groupby);
DblOpAcceptorOpCreator split();
Operator handleJoinSide(unordered_map<Headers, Headers> currHtbl,
                        unordered_map<Headers, Headers> otherHTbl,
                        int currEpochOuter, int otherEpochOuter,
                        KeyExtractor extractKey, Operator nextOp,
                        string eidKey = "eid");
DblOpCreator join(KeyExtractor leftExtractor, KeyExtractor rightExtractor,
                  string eidKey = "eid");
Headers renameFilteredKeys(vector<pair<string, string>> renamingPairs,
                           Headers inHeaders);

#endif
