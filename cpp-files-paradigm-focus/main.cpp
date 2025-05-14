#include "builtins.hpp"
#include "utils.hpp"

Operator ident(Operator nextOp) {
  __(mapCreator([](Headers headers) {
       Headers newH;
       for (const auto& [key, val] : headers) {
         if (key != "eth.src" && key != "eth.dst") {
           newH[key] = val;
         }
       }
       return newH;
     }),
     nextOp);
}

Operator countPkts(Operator nextOp) {
  __(epochCreator(1.0, "pkts"),
     __(groupbyCreator(singleGroup, counter, "pkts"), nextOp));
}

Operator pktsPerSrcDist(Operator nextOp) {
  __(epochCreator(1.0, "eid"), __(groupbyCreator(
                                      [](Headers headers) {
                                        return filterGroups(
                                            {"ipv4.src", "ipv4.dst"}, headers);
                                      },
                                      counter, "pkts"),
                                  nextOp));
}

bool filterHelper(int proto, int flags, Headers headers) {
  return getMappedInt("ipv4.proto", headers) == proto &&
         getMappedInt("l4.flags", headers);
}

Operator distinctSrcs(Operator nextOp) {
  __(epochCreator(1.0, "eid"),
     __(distinctCreator([](Headers headers) {
          return filterGroups({"ipv4.src"}, headers);
        }),
        __(groupbyCreator(singleGroup, counter, "srcs"), nextOp)));
}

Operator tcpNewCons(Operator nextOp) {
  int threshold = 40;
  return __(epochCreator(1.0, "eid"),
            __(filterCreator(
                   [](Headers headers) { return filterHelper(6, 2, headers); }),
               __(groupbyCreator(
                      [](Headers headers) {
                        return filterGroups({"ipv4.src", "ipv4.dst"}, headers);
                      },
                      counter, "cons"),
                  __(filterCreator([threshold](Headers headers) {
                       return keyGeqInt("cons", threshold, headers);
                     }),
                     nextOp))));
}

Operator sshBruteForce(Operator nextOp) {
  int threshold = 40;
  __(filterCreator(
         [](Headers headers) { return filterHelper(6, 22, headers); }),
     __(distinctCreator([](Headers headers) {
          return filterGroups({"ipv4.src", "ipv4.dst", "ipv4.len"}, headers);
        }),

        __(groupbyCreator(
               [](Headers headers) {
                 return filterGroups({"ipv4.dst", "ipv4.len"}, headers);
               },
               counter, "srcs"),

           __(filterCreator([threshold](Headers headers) {
                return keyGeqInt("srcs", threshold, headers);
              }),
              nextOp))));
}

Operator superSpreader(Operator nextOp) {
  int threshold = 40;
  __(epochCreator(1.0, "eid"),
     __(distinctCreator([](Headers headers) {
          return filterGroups({"ipv4.src", "ipv4.dst"}, headers);
        }),
        __(filterCreator([threshold](Headers headers) {
             return keyGeqInt("dsts", threshold, headers);
           }),
           nextOp)));
}

Operator portScan(Operator nextOp) {
  int threshold = 40;
  return __(epochCreator(1.0, "eid"),
            __(distinctCreator([](Headers headers) {
                 return filterGroups({"ipv4.src", "l4.dport"}, headers);
               }),
               __(groupbyCreator(
                      [](Headers headers) {
                        return filterGroups({"ipv4.src"}, headers);
                      },
                      counter, "ports"),
                  __(filterCreator([threshold](Headers headers) {
                       return keyGeqInt("ports", threshold, headers);
                     }),
                     nextOp))));
}

Operator ddos(Operator nextOp) {
  int threshold = 45;
  __(epochCreator(1.0, "eid"),
     __(distinctCreator([](Headers headers) {
          return filterGroups({"ipv4.src", "ipv4.dst"}, headers);
        }),
        __(groupbyCreator(
               [](Headers headers) {
                 return filterGroups({"ipv4.dst"}, headers);
               },
               counter, "srcs"),
           nextOp)));
}

vector<Operator> synFloodSonata(Operator nextOp) {
  int threshold = 3;
  float epochDur = 1.0f;

  OpCreator syns = [epochDur](Operator endOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return filterHelper(6, 2, headers);
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.dst"}, headers);
                        },
                        counter, "syns"),
                    endOp)));
  };

  OpCreator synacks = [](Operator endOp) {
    return __(epochCreator(1.0, "eid"),
              __(filterCreator([](Headers headers) {
                   return filterHelper(6, 18, headers);
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.src"}, headers);
                        },
                        counter, "synacks"),
                    endOp)));
  };

  OpCreator acks = [epochDur](Operator nextOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return getMappedInt("ipv4.proto", headers) == 6 &&
                          getMappedInt("l4.flags", headers) == 16;
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.dst"}, headers);
                        },
                        counter, "acks"),
                    nextOp)));
  };

  auto [joinOp1, joinOp2] = ___(
      join(
          [](Headers headers) {
            return std::make_pair(filterGroups({"host"}, headers),
                                  filterGroups({"syns+synacks"}, headers));
          },
          [](Headers headers) {
            return std::make_pair(
                renameFilteredKeys({{"ipv4.dst", "host"}}, headers),
                filterGroups({"acks"}, headers));
          }),
      __(mapCreator([](Headers headers) {
           int syns_synacks = getMappedInt("syns+synacks", headers);
           int acks = getMappedInt("acks", headers);
           headers["syns+synacks-acks"] = OpResult::Int(syns_synacks - acks);
           return headers;
         }),
         __(filterCreator([threshold](Headers headers) {
              return keyGeqInt("syns+synacks-acks", threshold, headers);
            }),
            nextOp)));

  auto [joinOp3, joinOp4] =
      ___(join(
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.dst", "host"}}, headers),
                    filterGroups({"syns"}, headers));
              },
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.src", "host"}}, headers),
                    filterGroups({"synacks"}, headers));
              }),
          __(mapCreator([](Headers headers) {
               int syns = getMappedInt("syns", headers);
               int synacks = getMappedInt("synacks", headers);
               headers["syns+synacks"] = OpResult::Int(syns + synacks);
               return headers;
             }),
             joinOp1));

  return {syns(joinOp3), synacks(joinOp4), acks(joinOp2)};
}

vector<Operator> completedFlows(Operator nextOp) {
  int threshold = 1;
  float epochDur = 30.0f;

  OpCreator syns = [epochDur](Operator endOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return getMappedInt("ipv4.proto", headers) == 6 &&
                          getMappedInt("l4.flags", headers) == 2;
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.dst"}, headers);
                        },
                        counter, "syns"),
                    endOp)));
  };

  OpCreator fins = [epochDur](Operator endOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return getMappedInt("ipv4.proto", headers) == 6 &&
                          (getMappedInt("l4.flags", headers) & 1) == 1;
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.src"}, headers);
                        },
                        counter, "fins"),
                    endOp)));
  };

  auto [op1, op2] =
      ___(join(
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.dst", "host"}}, headers),
                    filterGroups({"syns"}, headers));
              },
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.src", "host"}}, headers),
                    filterGroups({"fins"}, headers));
              }),
          __(mapCreator([](Headers headers) {
               int syn = getMappedInt("syns", headers);
               int fin = getMappedInt("fins", headers);
               headers["diff"] = OpResult::Int(syn - fin);
               return headers;
             }),
             __(filterCreator([threshold](Headers headers) {
                  return keyGeqInt("diff", threshold, headers);
                }),
                nextOp)));

  return {syns(op1), fins(op2)};
}

vector<Operator> slowloris(Operator nextOp) {
  int t1 = 5;
  int t2 = 500;
  int t3 = 90;
  float epochDur = 1.0f;

  OpCreator n_conns = [epochDur, t1](Operator nextOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return getMappedInt("ipv4.proto", headers) == 6;
                 }),
                 __(distinctCreator([](Headers headers) {
                      return filterGroups({"ipv4.src", "ipv4.dst", "l4.sport"},
                                          headers);
                    }),
                    __(groupbyCreator(
                           [](Headers headers) {
                             return filterGroups({"ipv4.dst"}, headers);
                           },
                           counter, "n_conns"),
                       __(filterCreator([t1](Headers headers) {
                            return getMappedInt("n_conns", headers) >= t1;
                          }),
                          nextOp)))));
  };

  OpCreator n_bytes = [epochDur, t2](Operator nextOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return getMappedInt("ipv4.proto", headers) == 6;
                 }),
                 __(groupbyCreator(
                        [](Headers headers) {
                          return filterGroups({"ipv4.dst"}, headers);
                        },
                        [](OpResult val, Headers headers) {
                          return sumInts("ipv4.len", val, headers);
                        },
                        "n_bytes"),
                    __(filterCreator([t2](Headers headers) {
                         return getMappedInt("n_bytes", headers) >= t2;
                       }),
                       nextOp))));
  };

  auto [op1, op2] =
      ___(join(
              [](Headers headers) {
                return std::make_pair(filterGroups({"ipv4.dst"}, headers),
                                      filterGroups({"n_conns"}, headers));
              },
              [](Headers headers) {
                return std::make_pair(filterGroups({"ipv4.dst"}, headers),
                                      filterGroups({"n_bytes"}, headers));
              }),
          __(mapCreator([](Headers headers) {
               int n_bytes = getMappedInt("n_bytes", headers);
               int n_conns = getMappedInt("n_conns", headers);
               headers["bytes_per_conn"] = OpResult::Int(n_bytes / n_conns);
               return headers;
             }),
             __(filterCreator([t3](Headers headers) {
                  return getMappedInt("bytes_per_conn", headers) <= t3;
                }),
                nextOp)));

  return {n_conns(op1), n_bytes(op2)};
}

vector<Operator> joinTest(Operator nextOp) {
  float epochDur = 1.0f;

  OpCreator syns = [epochDur](Operator nextOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return filterHelper(6, 2, headers);
                 }),
                 nextOp));
  };

  OpCreator synacks = [epochDur](Operator nextOp) {
    return __(epochCreator(epochDur, "eid"),
              __(filterCreator([](Headers headers) {
                   return filterHelper(6, 18, headers);
                 }),
                 nextOp));
  };

  auto [op1, op2] =
      ___(join(
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.src", "host"}}, headers),
                    renameFilteredKeys({{"ipv4.dst", "remote"}}, headers));
              },
              [](Headers headers) {
                return std::make_pair(
                    renameFilteredKeys({{"ipv4.dst", "host"}}, headers),
                    filterGroups({"time"}, headers));
              }),
          nextOp);

  return {syns(op1), synacks(op2)};
}

OpCreator q3 = [](Operator nextOp) {
  return __(epochCreator(100.0f, "eid"),
            __(distinctCreator([](Headers headers) {
                 return filterGroups({"ipv4.src", "ipv4.dst"}, headers);
               }),
               nextOp));
};

OpCreator q4 = [](Operator nextOp) {
  return __(epochCreator(10000.0f, "eid"), __(groupbyCreator(
                                                  [](Headers headers) {
                                                    return filterGroups(
                                                        {"ipv4.dst"}, headers);
                                                  },
                                                  counter, "pkts"),
                                              nextOp));
};

vector<Operator> queries = {q4(dumpAsCSV())};

void runQueries() {
  for (int i = 0; i < 4; ++i) {
    Headers tup;

    tup["time"] = OpResult::Float(0.0 + static_cast<float>(i));
    tup["eth.src"] = OpResult::MAC(MACAddress("\x00\x11\x22\x33\x44\x55"));
    tup["eth.dst"] = OpResult::MAC(MACAddress("\xAA\xBB\xCC\xDD\xEE\xFF"));
    tup["eth.ethertype"] = OpResult::Int(0x0800);

    tup["ipv4.hlen"] = OpResult::Int(20 + i);
    tup["ipv4.proto"] = OpResult::Int(6);
    tup["ipv4.len"] = OpResult::Int(60);
    tup["ipv4.src"] = OpResult::IPv4(IPv4Address("127.0.0.1"));
    tup["ipv4.dst"] = OpResult::IPv4(IPv4Address("192.6.8.1"));

    tup["l4.sport"] = OpResult::Int(440);
    tup["l4.dport"] = OpResult::Int(50000);
    tup["l4.flags"] = OpResult::Int(10);

    for (auto& query : queries) {
      query.next(tup);
    }
  }

  std::cout << "Done\n";
}
