#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <string.h>

typedef struct {    
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
	uint32_t metric;
} EntryData;
typedef uint32_t ADDR;
typedef uint32_t LEN;
typedef std::map<ADDR, EntryData*> RoutingTable;