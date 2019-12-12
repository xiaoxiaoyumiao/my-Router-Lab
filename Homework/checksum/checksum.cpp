#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    
    size_t b_len = packet[0] & 0x0F;
    uint16_t* buffer = (uint16_t*)packet;
    uint32_t sum = 0;
    for (size_t i=0;i<2*b_len;i++){
        if (i != 5)
            sum += buffer[i];          
    }    
    while (sum > 0xFFFF)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = sum ^ 0xFFFF;
    return (sum == buffer[5]);
  
}
