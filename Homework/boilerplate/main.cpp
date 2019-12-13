#include "rip.h"
#include "router.h"
#include "router_hal.h"
//#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>

uint32_t len_to_mask(uint32_t len) {	
	uint32_t ret = 0;
	for (int i=0;i<len;++i){
		ret = (ret<<1)+1;
	}
	for (int i=len;i<32;++i){
		ret <<= 1;
	}
	return ret;
}

uint32_t mask_to_len(uint32_t mask) {
	uint32_t ret = 32;
	while (!(mask & 1)) {ret--;mask>>=1;}
	return ret;
}

//extern struct EntryData;
extern RoutingTable table;
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern bool resetIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};
//in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a};
macaddr_t multi_dst_mac = {0x01,0x00,0x5e,0x00,0x00,0x09}; 
int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  printf("INIT finihsed.\n");

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
	  printf("ENTRY CREATION: %d, %08x\n",i,addrs[i]);
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
		.metric = 1
    };
    update(true, entry);
  }
  
  printf("ENTRY CREATION finihsed.\n");
  
  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    // when testing, you can change 30s to 5s
    if (time > last_time + 5 * 1000) {
		printf("TIMER: START 30S CASTING.\n");
		
		RipPacket routingTablePacket;		
		routingTablePacket.command = 2;
		//routingTablePacket.numEntries = table.size();
		RoutingTable::iterator iter;
		
		printf("TIMER: START CONSTRUCTING RIP PACKET.\n");
		int index = 0;
		int ele = 0;
		iter = table.begin();		
		while (iter != table.end()) {			
			printf("TIMER: INDEX %d ELE %d\n", index, ele);
			
			if (iter->second != NULL) {
				
				for (int i=0;i<32;++i){			
					//printf("TIMER: INDEX %d, ITER %d\n", index,i);
					if (iter->second[i].metric != 17) { //valid data
						RipEntry tmp;
						tmp.addr = iter->first;
						tmp.mask = len_to_mask(i);
						tmp.nexthop = iter->second[i].nexthop; 
						tmp.metric = iter->second[i].metric; 
						routingTablePacket.entries[index] = tmp;
						index++;
					}
				}
			}
			iter++;
			ele++;
		}
		routingTablePacket.numEntries = index;
		
		for (int i=0;i<N_IFACE_ON_BOARD;++i) {		
			// version = 4, length = 5(*4byte)
			output[0] = 0x45;
			// type of service = 0
			output[1] = 0x00;
			// ID = 0
			output[4] = 0;
			output[5] = 0;
			// flags, fragmented offset = 0
			output[6] = 0;
			output[7] = 0;
			// time to live = 1
			output[8] = 0x01;
			// protocol = 17 (UDP)
			output[9] = 0x11;

			in_addr_t src_addr = addrs[i];
			in_addr_t dst_addr = 0x090000E0;
			// source address
			output[12] = dst_addr & 0xFF;
			output[13] = (dst_addr >> 8 ) & 0xFF;
			output[14] = (dst_addr >> 16) & 0xFF;
			output[15] = (dst_addr >> 24) & 0xFF;
			//dest address
			output[16] = src_addr & 0xFF;
			output[17] = (src_addr >> 8 ) & 0xFF;
			output[18] = (src_addr >> 8 ) & 0xFF;
			output[19] = (src_addr >> 8 ) & 0xFF;		  		  		 

			// TODO: fill UDP headers
			// port = 520
			output[20] = 0x02;
			output[21] = 0x08;
			output[22] = 0x02;
			output[23] = 0x08;
			// UDP checksum = 0
			output[26] = 0x00;
			output[27] = 0x00;

			// assembleRIP
			uint32_t rip_len = assemble(&routingTablePacket, &output[20 + 8]);
			uint32_t total_len = rip_len + 28;
			uint32_t udp_len = rip_len + 8;
			//set total length
			output[2] = total_len >> 8;
			output[3] = total_len & 0xFF;
			//set UDP length
			output[24] = udp_len >> 8;
			output[25] = udp_len & 0xFF;

			// TODO: checksum calculation for ip and udp
			// if you don't want to calculate udp checksum, set it to zero
			resetIPChecksum(output, total_len);

			printf("TIMER: START ASSEMBING OUTPUT FROM RIP PACKET.\n");
			uint32_t len = assemble(&routingTablePacket, output+28);
			printf("TIMER: START MULTICASTING.\n");

			for (int i=0;i<28;++i) {
			  printf("%02x ",output[i]);
			  if (i % 4 == 0){
				  printf("\n");
			  }
			}
			HAL_SendIPPacket(i,
				output,
				total_len,
				multi_dst_mac);
			
		}		
		// TODO: send complete routing table to every interface
		// ref. RFC2453 Section 3.8
		// multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
		printf("30s Timer\n");
		// TODO: print complete routing table to stdout/stderr
		iter = table.begin();
		while (iter != table.end()) {			
			for (int i=0;i<32;++i){			
				if (iter->second[i].metric != 17) { //valid data
					// addr mask nexthop metric
					printf("%08x %d %08x %08x %d\n",iter->first,iter->second[i].if_index,len_to_mask(i),iter->second[i].nexthop,iter->second[i].metric);			
				}
			}
			iter++;
		}
		last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }
	
	printf("HAL: RECEIVED PACKET.\n");

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
	
	printf("HAL: RECEIVED PACKET VALIDATED.\n");
	
    in_addr_t src_addr, dst_addr;
    // TODO: extract src_addr and dst_addr from packet (big endian)
	src_addr = ((uint32_t)packet[12]) + 
				(((uint32_t)packet[13]) << 8) + 
				(((uint32_t)packet[14]) << 16) + 
				(((uint32_t)packet[15]) << 24);
	dst_addr = ((uint32_t)packet[16]) + 
				(((uint32_t)packet[17]) << 8) + 
				(((uint32_t)packet[18]) << 16) + 
				(((uint32_t)packet[19]) << 24);
				
	printf("WHILE: src_addr: %08x dst_addr: %08x\n", src_addr, dst_addr);
	
    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: handle rip multicast address(224.0.0.9)

    if (dst_is_me) {
		
	  printf("WHILE: RECEIVED PACKET DEST IS ME.\n");
      // 3a.1
      RipPacket rip;
      // check and validate	  
      if (disassemble(packet, res, &rip)) {	  
        if (rip.command == 1) {
		printf("WHILE: RECEIVED PACKET IS REQUEST.\n");
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab

          RipPacket resp;
          // TODO: fill resp
		resp.command = 2;
		//resp.numEntries = table.size();
		RoutingTable::iterator iter;
		
		printf("TIMER: START CONSTRUCTING RIP PACKET.\n");
		int index = 0;
		int ele = 0;
		iter = table.begin();		
		while (iter != table.end()) {			
			printf("TIMER: INDEX %d ELE %d\n", index, ele);
			
			if (iter->second != NULL) {
				
				for (int i=0;i<32;++i){			
					//printf("TIMER: INDEX %d, ITER %d\n", index,i);
					if (iter->second[i].metric != 17) { //valid data
						RipEntry tmp;
						tmp.addr = iter->first;
						tmp.mask = len_to_mask(i);
						tmp.nexthop = iter->second[i].nexthop; 
						tmp.metric = iter->second[i].metric; 
						resp.entries[index] = tmp;
						index++;
					}
				}
			}
			iter++;
			ele++;
		}
		resp.numEntries = index;

          // TODO: fill IP headers
		  // version = 4, length = 5(*4byte)
          output[0] = 0x45;
		  // type of service = 0
		  output[1] = 0x00;
		  // ID = 0
		  output[4] = 0;
		  output[5] = 0;
		  // flags, fragmented offset = 0
		  output[6] = 0;
		  output[7] = 0;
		  // time to live = 1
		  output[8] = 0x01;
		  // protocol = 17 (UDP)
		  output[9] = 0x11;
		  
		  // source address
		  output[12] = dst_addr & 0xFF;
		  output[13] = (dst_addr >> 8 ) & 0xFF;
		  output[14] = (dst_addr >> 16) & 0xFF;
		  output[15] = (dst_addr >> 24) & 0xFF;
		  //dest address
		  output[16] = src_addr & 0xFF;
		  output[17] = (src_addr >> 8 ) & 0xFF;
		  output[18] = (src_addr >> 8 ) & 0xFF;
		  output[19] = (src_addr >> 8 ) & 0xFF;		  		  		 

          // TODO: fill UDP headers
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
		  output[22] = 0x02;
		  output[23] = 0x08;
		  // UDP checksum = 0
		  output[26] = 0x00;
		  output[27] = 0x00;

          // assembleRIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
		  uint32_t total_len = rip_len + 28;
		  uint32_t udp_len = rip_len + 8;
		  //set total length
		  output[2] = total_len >> 8;
		  output[3] = total_len & 0xFF;
		  //set UDP length
		  output[24] = udp_len >> 8;
		  output[25] = udp_len & 0xFF;
 
          // TODO: checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
		  resetIPChecksum(output, total_len);
		  for (int i=0;i<28;++i) {
			  printf("%02x ",output[i]);
			  if (i % 4 == 0){
				  printf("\n");
			  }
		  }

          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
		printf("WHILE: RECEIVED PACKET IS RESPONSE.\n");
          // 3a.2 response, ref. RFC2453 3.9.2
          // TODO: update routing table
		  for (int i=0;i<rip.numEntries;++i){			  
			  RoutingTableEntry tmp_entry = {
				.addr = rip.entries[i].addr, // big endian
				.len = mask_to_len(rip.entries[i].mask), // small endian
				.if_index = if_index,    // small endian
				.nexthop = rip.entries[i].nexthop,     // big endian, means direct
				.metric = rip.entries[i].metric 
			  };
			  if (1<=tmp_entry.metric && tmp_entry.metric<=15){
				  if (tmp_entry.metric == 15) {
					  //tmp_entry.metric = 16;
					  update(false, tmp_entry);
				  } else {
					  tmp_entry.metric++;
				  }
				  if (tmp_entry.nexthop == 0) {
					  tmp_entry.nexthop = tmp_entry.addr;
				  }
				  update(true, tmp_entry);
			  }
			  
		  }
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `query` and `update` but beware of the difference between exact match and longest prefix match
          // optional: triggered updates? ref. RFC2453 3.10.1
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO(optional): check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for nexthop %x\n", nexthop);
        }
      } else {
        // not found
        // TODO(optional): send ICMP Host Unreachable
        printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
      }
    }
  }
  return 0;
}
