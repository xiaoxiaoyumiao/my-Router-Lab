#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <string.h>
//#include "lookup.h"
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
	uint32_t metric; 
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/
uint32_t rev32(uint32_t given) {
    uint32_t tmp;
    for (int i=0;i<4;++i){
        tmp <<= 8;
        tmp += given % 0xFF;        
        given >>= 8;
    }
    return tmp;
}

RoutingTable table;

const int MAX_SIZE = 100000;
EntryData data_mem[MAX_SIZE];
int MAX_LEN = 32;
int pointer = 0;
EntryData* allocate(){
    //memset((void*)data_mem[pointer],0,MAX_LEN*sizeof(EntryData));
    for (int i=0;i<MAX_LEN;++i){
		data_mem[pointer] = {
				.if_index = 0,
				.nexthop = 0,
				.metric = 17};
		pointer+=1;
	}
    return &(data_mem[pointer-MAX_LEN]);
}
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
	printf("UPDATE:START UPDATING\n");
    uint32_t t_addr = entry.addr;
    if (insert){
		printf("UPDATE:INSERT\n");
        //insert
        EntryData entry_data = {entry.if_index, entry.nexthop, entry.metric};
        //EntryData* addr_entry = table.find(t_addr);
        if (table.find(t_addr) != table.end()) {//found
			printf("UPDATE:FOUND EXISTING\n");
			if ((entry_data.metric < table[t_addr][entry.len].metric) || 
				(entry_data.nexthop == table[t_addr][entry.len].nexthop)) {
				table[t_addr][entry.len] = entry_data; //insert or rewrite
			}	
        } else { //addr not found
			printf("UPDATE:NOT FOUND\n");
            EntryData* tmp = NULL;
            tmp = allocate();
            tmp[entry.len] = entry_data;
            table.insert(RoutingTable::value_type(t_addr,tmp));
        }
    } else {
		printf("UPDATE:DELETE\n");
        //EntryData* addr_entry = table.find(t_addr);		
        if (table.find(t_addr) != table.end()) { //exist
            table[t_addr][entry.len] = {
				.if_index = 0,
				.nexthop = 0,
				.metric = 17};
        }
    }
	printf("FINISH UPDATING\n");
  // TODO:
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
    uint32_t t_addr = addr;
    for (size_t i=0;i<32;i++){
        //EntryData* addr_entry = table.find(t_addr);
        if (table.find(t_addr) != table.end()) {//found
            EntryData tmp = table[t_addr][32-i];
            if (tmp.metric>0 && tmp.metric<16 && (tmp.nexthop != 0 || tmp.if_index != 0)){
                *nexthop = tmp.nexthop;
                *if_index = tmp.if_index;
                return true;
            }
        }
        t_addr = t_addr & ((1 << (32-i-1))-1); //remove the highest bit
    }
    return false;
}
