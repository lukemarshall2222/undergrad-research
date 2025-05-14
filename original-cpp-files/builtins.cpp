#include "builtins.hpp"

Operator dump(ofstream out, bool showReset = false) {
  OpFunc next = [](Headers headers) { dumpHeaders(headers, true); };

  OpFunc reset = [showReset = move(showReset)](Headers headers) {
    if (showReset) {
      cout << "[reset]" << endl;
    }
  };

  return Operator(next, reset);
}

Operator dumpAsCSV(optional<pair<string, string>> staticField,
                   bool header = true) {
  bool first = header;

  OpFunc next = [&first, staticField = move(staticField)](Headers headers) {
    if (first) {
      if (staticField.has_value()) {
        cout << staticField.value().first << ",";
      } else {
        return;
      }
      for (const auto& [key, val] : headers) {
        cout << key << ",";
      }
      cout << endl;
      first = false;
    }
  };

  OpFunc reset = [](Headers _) { return; };

  return Operator(next, reset);
}

Operator dumpWaltsCSV(string filename) {
  auto shared = make_shared<ofstream>(filename);
  bool first = true;

  OpFunc next = [&first, shared](Headers headers) {
    if (first) {
      first = false;
    }
    string src_ip =
        get<IPv4Address>(headers.find("src_ip")->second.val).toString();
    string dst_ip =
        get<IPv4Address>(headers.find("dst_ip")->second.val).toString();

    *shared << src_ip << "," << dst_ip << ","
            << get<IPv4Address>(headers.find("dst_ip")->second.val).toString()
            << "," << get<int>(headers.find("src_l4_port")->second.val) << ","
            << get<int>(headers.find("dst_l4_port")->second.val) << ","
            << get<int>(headers.find("packet_count")->second.val) << ","
            << get<int>(headers.find("byte_count")->second.val) << ","
            << get<int>(headers.find("epoch_id")->second.val) << endl;
  };

  OpFunc reset = [](Headers _) { return; };

  return Operator(next, reset);
}

OpResult getIpOrZero(string input) {
  if (input == "0") {
    return OpResult::Int(0);
  }
  return OpResult::IPv4(IPv4Address(input));
}

OpCreator metaMeterCreator(string name, ofstream outc,
                           optional<string> staticField) {
  auto shared = make_shared<ofstream>(new ofstream(move(outc)));

  return [name, shared, staticField](Operator nextOp) {
    auto sharedNextOp = make_shared<Operator>(nextOp);
    int epochCount = 0;
    int headersCount = 0;

    OpFunc next = [&epochCount, &headersCount, sharedNextOp](Headers headers) {
      headersCount++;
      sharedNextOp->next(headers);
    };

    OpFunc reset = [shared, &epochCount, name, &headersCount, staticField,
                    sharedNextOp](Headers headers) {
      stringstream str;
      str << epochCount << "," << name << "," << headersCount
          << staticField.has_value()
          ? staticField.value()
          : "";
      headersCount = 0;
      epochCount++;
      sharedNextOp->reset(headers);
    };

    return Operator(next, reset);
  };
}

Headers singleton(string keyOut, OpResult val) { return {{keyOut, val}}; }

OpCreator epochCreator(float epochWidth, string keyOut) {
  return [&epochWidth, keyOut](Operator nextOp) {
    auto sharedNextOp = make_shared<Operator>(nextOp);
    float epochBoundary = 0.0f;
    int eid = 0;

    OpFunc next = [&epochBoundary, &epochWidth, sharedNextOp, &eid,
                   keyOut](Headers headers) {
      float time = floatOfOpResult(headers.find("time")->second);
      if (epochBoundary == 0.0f) {
        epochBoundary = time + epochWidth;
      } else {
        while (time >= epochBoundary) {
          (*sharedNextOp).reset(singleton(keyOut, OpResult::Int(eid)));
          epochBoundary += epochWidth;
          eid++;
        }
      }
      headers[keyOut] = OpResult::Int(eid);
      (*sharedNextOp).next(headers);
    };

    OpFunc reset = [&keyOut, &eid, &epochBoundary, sharedNextOp](Headers _) {
      (*sharedNextOp).reset(singleton(keyOut, OpResult::Int(eid)));
      epochBoundary = 0.0f;
      eid = 0;
    };

    return Operator(next, reset);
  };
}

OpCreator filterCreator(function<bool(Headers)> f) {
  return [f](Operator nextOp) {
    auto sharedNextOp = make_shared<Operator>(nextOp);

    OpFunc next = [f, sharedNextOp](Headers headers) {
      if (f(headers)) {
        sharedNextOp->next(headers);
      }
    };

    OpFunc reset = [sharedNextOp](Headers headers) {
      sharedNextOp->reset(headers);
    };

    return Operator(next, reset);
  };
}

bool keyGeqInt(string key, int threshold, Headers headers) {
  return intOfOpResult(headers.find(key)->second) >= threshold;
}

int getMappedInt(string key, Headers headers) {
  intOfOpResult(headers.find(key)->second);
}

float getMappedFloat(string key, Headers headers) {
  floatOfOpResult(headers.find(key)->second);
}

OpCreator mapCreator(function<Headers(Headers)> f) {
  return [f](Operator nextOp) {
    auto sharedNextOp = make_shared<Operator>(nextOp);

    OpFunc next = [f, sharedNextOp](Headers headers) {
      sharedNextOp->next(f(headers));
    };

    OpFunc reset = [sharedNextOp](Headers headers) {
      sharedNextOp->reset(headers);
    };

    return Operator(next, reset);
  };
}

Headers unionHeaders(Headers h1, Headers h2) {
  Headers newH;
  for (const auto [key, val] : h1) {
    newH[key] = val;
  }

  for (const auto [key, val] : h2) {
    newH[key] = val;
  }
}

OpCreator groupbyCreator(GroupingFunc groupby, ReductionFunc reduct,
                         string outKey) {
  return [groupby, reduct, &outKey](Operator nextOp) {
    unordered_map<Headers, OpResult> hTbl;
    int resetCounter = 0;

    OpFunc next = [groupby, &hTbl, reduct](Headers headers) {
      Headers groupingKey = groupby(headers);
      OpResult val;
      auto it = hTbl.find(groupingKey);
      if (it != hTbl.end()) {
        val = it->second;
        hTbl[groupingKey] = reduct(val, headers);
      } else {
        hTbl[groupingKey] = reduct(OpResult::Empty(), headers);
      }
    };

    OpFunc reset = [&resetCounter, &hTbl, nextOp, &outKey](Headers headers) {
      resetCounter++;
      for (const auto& [groupingKey, val] : hTbl) {
        Headers unionedHeaders = unionHeaders(headers, groupingKey);
        unionedHeaders[outKey] = val;
        nextOp.next(unionedHeaders);
      }
      nextOp.reset(headers);
      hTbl.clear();
    };

    return Operator(next, reset);
  };
}

Headers filterGroups(vector<string> inclKeys, Headers headers) {
  Headers newH;
  for (const auto& str : inclKeys) {
    auto it = headers.find(str);
    if (it != headers.end()) {
      newH[str] = it->second;
    }
  }
  return newH;
}

Headers singleGroup(Headers _) {
  Headers newH;
  return newH;
}

OpResult counter(OpResult val, Headers _) {
  switch (val.typ) {
    case OpResultType::Empty:
      return OpResult::Int(1);
    case OpResultType::Int:
      return OpResult::Int(get<int>(val.val) + 1);
    default:
      return val;
  }
}

OpResult sumInts(string searchKey, OpResult initVal, Headers headers) {
  switch (initVal.typ) {
    case OpResultType::Empty:
      return OpResult::Int(0);
    case OpResultType::Int:
      auto it = headers.find(searchKey);
      if (it != headers.end()) {
        return OpResult::Int(get<int>(initVal.val) + get<int>(it->second.val));
      } else {
        throw out_of_range(
            "'sum_vals' function failed to find intege"
            "value mapped to the given search key");
      }
    default:
      return initVal;
  }
}

OpCreator distinctCreator(GroupingFunc groupby) {
  unordered_map<Headers, bool> hTbl;
  int resetCounter = 0;

  return [groupby, &hTbl, &resetCounter](Operator nextOp) {
    OpFunc next = [groupby, &hTbl](Headers headers) {
      Headers groupingKey = groupby(headers);
      hTbl[groupingKey] = true;
    };

    OpFunc reset = [&resetCounter, &hTbl, nextOp](Headers headers) {
      resetCounter++;
      Headers unionedHeaders;
      for (const auto& [key, _] : hTbl) {
        unionedHeaders = unionHeaders(headers, key);
        nextOp.next(unionedHeaders);
      }
      nextOp.reset(headers);
      hTbl.clear();
    };

    return Operator(next, reset);
  };
}

DblOpAcceptorOpCreator split() {
  return [](pair<Operator, Operator> nextOps) {
    auto sharedL = make_shared<Operator>(move(nextOps.first));
    auto sharedR = make_shared<Operator>(move(nextOps.second));

    OpFunc next = [sharedL, sharedR](Headers headers) {
      sharedL->next(headers);
      sharedR->next(headers);
    };

    OpFunc reset = [sharedL, sharedR](Headers headers) {
      sharedL->reset(headers);
      sharedR->reset(headers);
    };

    return Operator(next, reset);
  };
}

Operator handleJoinSide(unordered_map<Headers, Headers> currHtbl,
                        unordered_map<Headers, Headers> otherHTbl,
                        int currEpochOuter, int otherEpochOuter,
                        KeyExtractor extractKey, Operator nextOp,
                        string eidKey = "eid") {
  auto sharedNextOp = make_shared<Operator>(move(nextOp));
  OpFunc next = [extractKey, eidKey, &currEpochOuter, sharedNextOp, &otherHTbl,
                 &currHtbl](Headers headers) {
    auto [key, val] = extractKey(headers);
    int currEpochInner = getMappedInt(eidKey, headers);

    while (currEpochInner > currEpochOuter) {
      if (currEpochOuter > currEpochInner) {
        sharedNextOp->reset(singleton(eidKey, OpResult::Int(currEpochOuter)));
        currEpochOuter++;
      }
    }
    Headers newH;
    newH[eidKey] = OpResult::Int(currEpochInner);
    auto it = otherHTbl.find(newH);
    if (it != otherHTbl.end()) {
      otherHTbl.erase(newH);
      Headers dblUnionedHeaders =
          unionHeaders(newH, unionHeaders(val, it->second));
    } else {
      currHtbl[newH] = it->second;
    }
  };

  OpFunc reset = [eidKey, &currEpochOuter, otherEpochOuter,
                  sharedNextOp](Headers headers) {
    int currEpochInner = getMappedInt(eidKey, headers);
    while (currEpochInner > currEpochOuter) {
      if (otherEpochOuter > currEpochOuter) {
        sharedNextOp->reset(singleton(eidKey, OpResult::Int(currEpochOuter)));
        currEpochOuter++;
      }
    }
  };

  return Operator(next, reset);
};

DblOpCreator join(KeyExtractor leftExtractor, KeyExtractor rightExtractor,
                  string eidKey = "eid") {
  unordered_map<Headers, Headers> hTbl1;
  unordered_map<Headers, Headers> hTbl2;
  int leftCurrEpoch = 0;
  int rightCurrEpoch = 0;

  return [&hTbl1, &hTbl2, &leftCurrEpoch, &rightCurrEpoch, leftExtractor,
          rightExtractor](Operator nextOp) {
    Operator op1 = handleJoinSide(hTbl1, hTbl2, leftCurrEpoch, rightCurrEpoch,
                                  leftExtractor, nextOp);
    Operator op2 = handleJoinSide(hTbl2, hTbl1, rightCurrEpoch, leftCurrEpoch,
                                  rightExtractor, nextOp);
    return make_pair(op1, op2);
  };
}

Headers renameFilteredKeys(vector<pair<string, string>> renamingPairs,
                           Headers inHeaders) {
  Headers newH;
  for (const auto& [oldKey, newKey] : renamingPairs) {
    auto it = inHeaders.find(oldKey);
    if (it != inHeaders.end()) {
      newH[newKey] = it->second;
    }
    return newH;
  }
  return newH;
}
