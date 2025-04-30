```bash
g++ -std=c++17 -Wall -Wextra -pedantic \
    utils.cpp builtins.cpp queries.cpp main.cpp \
    -o stream_processor -I. # -I. assumes headers are in the same dir

./stream_processor
```