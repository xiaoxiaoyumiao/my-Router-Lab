#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

uint32_t get_int32(const uint8_t* array, uint8_t ptr) {
	return (((uint32_t)array[ptr+3])<<24) + 
				(((uint32_t)array[ptr+2])<<16) + 
				(((uint32_t)array[ptr+1])<<8) + 
				((uint32_t)array[ptr]);
}

bool set_int32(uint32_t num, uint8_t* array, uint8_t ptr) {
	array[ptr+3] = (uint8_t)((num >> 24) & 0xFF);
	array[ptr+2] = (uint8_t)((num >> 16) & 0xFF);
	array[ptr+1] = (uint8_t)((num >> 8) & 0xFF);
	array[ptr] = (uint8_t)((num) & 0xFF);	
	return true;
}

uint16_t get_int16(const uint8_t* array, uint8_t ptr) {
	return (((uint16_t)array[ptr])<<8) + array[ptr+1];
}

bool set_int16(uint16_t num, uint8_t* array, uint8_t ptr) {	
	array[ptr] = uint8_t(num >> 8); 
	array[ptr+1] = uint8_t(num & 0xFF);
	return true;
}
/*
bool is_mask(uint32_t m) {
    uint32_t p = 0, mm = 1;
    for (; p < 32 && !(m & mm); p++, mm <<= 1);
    for (; p < 32; p++, mm <<= 1)
        if (!(m & mm))
            return false;
    return true;
}
*/

bool is_mask(uint32_t mask) {
	uint32_t digit_loc = 1<<31;
	uint32_t digit = 0;
	bool flag = true;
	while (digit_loc) {
		 digit = mask & digit_loc;
		if (!digit) flag = false;
		else if (!flag) return false;
		digit_loc >>= 1;
	}
	return true;
}


//need to reverse bytes?
uint32_t get_metric(uint32_t metric) {
	return metric;
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  //get total length of IP packet(including header and data)
  uint32_t total_length = (((uint32_t)packet[2])<<8)+(uint32_t)packet[3];
  //ignore if actual length is less than total length
  if (total_length > len) return false;
  //check IP version to be 4
  //uint8_t IPversion = packet[0]; if (IPversion != 4) return false;
  //get header length in byte, also the start index of packet data
  uint16_t header_length = (packet[0] & 0xF) << 2;
  //check protocol to be UDP
  //uint8_t protocol = packet[9]; if (protocol != 17) return false;
  
  //work pointer, here pointing to start of UDP packet without checking UDP length
  uint8_t ptr = header_length;
  //here pointing to start of RIP packet
  ptr = ptr + 8;
  
  //get RIP command
  uint8_t command = packet[ptr];
  //check if command is 1 or 2
  if (command != 1 && command != 2) return false;  
  //if so, assign command field
  output->command = command; ptr++;  
  //get RIP version
  uint8_t version = packet[ptr];
  //check if RIP version is 2(RIPv2)
  if (version != 2) return false;ptr++;
  //ensure Zero field is 0
  if (packet[ptr] || packet[ptr+1]) return false;
  
  //start enumerating entries
  uint8_t entry_index = 0;
  
  //entering entry  
  ptr += 2;
  
  uint16_t family_identifier = 0;
  uint16_t route_tag = 0;
  uint32_t address = 0, mask = 0, next_hop = 0, metric = 0;
 
  //should stop when ptr >= total_length
  while (ptr < total_length) {
	  //now pointing to address family identifier
	  family_identifier = (((uint16_t)packet[ptr])<<8) + packet[ptr+1];
	  //check family identifier  
	  if (output->command == 1 && family_identifier != 0) return false;
	  if (output->command == 2 && family_identifier != 2) return false; 
	  
	  ptr += 2;
	  //now pointing to route tag
	  route_tag = get_int16(packet,ptr);
	  if (route_tag != 0) return false;
	  
	  ptr += 2;
	  //now pointing to IP address
	  address = get_int32(packet, ptr);
	  // need to reverse? 
	  output->entries[entry_index].addr = address;
					
	  ptr += 4;
	  //now pointing to subnet mask
	  mask = get_int32(packet, ptr);
	  //check if the mask if valid (like 11...1100..00)
	  if (!is_mask(ntohl(mask))) return false;
	  output->entries[entry_index].mask = mask;
	  
	  ptr += 4;
	  //now pointing to next hop
	  next_hop = get_int32(packet, ptr);
	  output->entries[entry_index].nexthop = next_hop;
	  
	  ptr += 4;
	  //now pointing to metric
	  metric = get_int32(packet, ptr);
	  metric = get_metric(metric);
	  //if (ntohl(metric) < 1 || ntohl(metric) > 16) return false;
	  if (metric < 1 || metric > 16) return false;
	  output->entries[entry_index].metric = metric;
	  
	  ptr += 4;
	  //now pointing to next entry or the end
	  entry_index++;
  }
  
  output->numEntries = entry_index;
	  
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  uint8_t ptr = 0;
  //construct command field
  buffer[ptr] = rip->command;ptr++;
  //construct version field
  buffer[ptr] = 2; ptr++;
  //construct zero field
  buffer[ptr] = 0; ptr++; buffer[ptr] = 0; ptr++;
  //construct entries;
  uint16_t family_identifier;
  for (int i=0;i<rip->numEntries; ++i){
	  //construct family identifier
	  if (rip->command == 1)
		  family_identifier = 0;
	  else if (rip->command == 2)
		  family_identifier = 2;
	  else //happen?
	      family_identifier = 0;
	  set_int16(family_identifier, buffer, ptr);
	  ptr += 2;
	  //construct route tag
	  buffer[ptr] = 0; ptr++; buffer[ptr] = 0; ptr++;
	  //construct address
	  set_int32(rip->entries[i].addr,buffer,ptr);
	  ptr += 4;
	  //construct mask
	  set_int32(rip->entries[i].mask,buffer,ptr);
	  ptr += 4;
	  //construct next hop
	  set_int32(rip->entries[i].nexthop,buffer,ptr);
	  ptr += 4;
	  //construct metric (need to reverse?)
	  set_int32(rip->entries[i].metric,buffer,ptr);
	  ptr += 4;	  
  }
  
  return ptr;
}
