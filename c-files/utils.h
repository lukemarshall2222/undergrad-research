#include <stdlib.h>
#include <arpa/inet.h>

// ---------------------------------------------------------------------------------------
// ---------------- Bytes object ---------------------------------------------------------
// ---------------------------------------------------------------------------------------

void freeBytes(Bytes*);
void setBytes(Bytes*, char*);
char getUint8(Bytes*, int);


typedef struct {
    char* bytes;
    void (*freeBytes)(Bytes*);
    void(*setBytes)(Bytes*, char*);
    char (*getUint8)(Bytes*, int);
} Bytes;

Bytes* createBytes() {
    Bytes* bytes = (Bytes*)malloc(sizeof(Bytes));
    bytes->bytes = (char*)malloc(sizeof(char)*6);
    bytes->freeBytes = freeBytes;
    bytes->setBytes = setBytes;
    bytes->getUint8 = getUint8;
    return bytes;
}

void freeBytes(Bytes* bytes) {
    free(bytes->bytes);
    free(bytes);
    return;
}

void setBytes(Bytes* bytes, char* content) {
    int bytes_len = 0;
    for (int i = 0; content[i] != '\0'; i++) {
        bytes_len++;
    }
    if (bytes_len > 4) {
        fprintf(stderr, "Error: Failed attempt to fit an Bytes of size %d \
                        in a bytearray of size %d", bytes_len, 6);
        exit(EXIT_FAILURE);
    }
    bytes->bytes = content;
    return;
}

char getUint8(Bytes* bytes, int index) {
    if (index >= 6 || index < 0) {
        fprintf("Error: Failed attempt to index a bytearray outside of its \
                allocated length of %d.", 6);
        exit(EXIT_FAILURE);
    }
    return bytes->bytes[index];
}

// ---------------------------------------------------------------------------------------
// ---------------- IPv4Address object ---------------------------------------------------
// ---------------------------------------------------------------------------------------

void setIPv4Address(IPv4Address address, char content[4]);
void getIPv4AddressByte(IPv4Address address, int index);
void freeIPv4Address(IPv4Address* address);

typedef struct {
    char* address;
    void (*setIPv4Address)(IPv4Address*, char content[4]);
    void (*getIPv4AddressByte)(IPv4Address*, int);
    void (*freeIPvAddress)(IPv4Address*);
} IPv4Address;

IPv4Address* createIPv4Address() {
    IPv4Address* address = (IPv4Address*)malloc(sizeof(IPv4Address));
    address->address = (char*)malloc(sizeof(char)*4);
    address->address = NULL;
    address->setIPv4Address = setIPv4Address;
    address->getIPv4AddressByte = getIPv4AddressByte;
    return address;
}

void setIPv4Address(IPv4Address address, char content[4]) {
    if (inet_pton(AF_INET, content, address.address) < 1) {
        perror("Error. Attempt made to set invalid IP address");
        exit(EXIT_FAILURE);
    } 
    return; 
}

void getIPv4AddressByte(IPv4Address address, int index) {
    if (address.address == NULL) {
        fprintf(stderr, "Error. \
            Attempt made to access byte of an unset IPv4Address");
        exit(EXIT_FAILURE);
    }
    if (index >= 4 || index < 0) {
        fprintf(stderr, "Error. \
            Attempt made to access byte of an address ");
    }
    return address.address[index];
}

void freeIPv4Address(IPv4Address* address) {
    free(address->address);
    free(address);
    return;
}

// ---------------------------------------------------------------------------------------
// ---------------- Type Definitions -----------------------------------------------------
// ---------------------------------------------------------------------------------------

typedef enum {
    FloatRes,
    IntRes,
    IPv4AddressRes,
    BytesRes,
    EmptyRes,
} opResultKind;


typedef struct {} Empty;

typedef union {
    float Float;
    int Int;
    IPv4Address IPv4;
    Bytes MAC;
    Empty Empty;
} opResultType;

typedef GHashTable* tuple;

typedef struct {
    void (*next)(tuple);
    void (*reset)(tuple);
} operator;

typedef struct {
    operator l;
    operator r;
} dblOperator;

typedef operator (*opCreator)(operator);
typedef dblOperator(*dblOpCreator)(operator);