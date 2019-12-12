#include <stdint.h>
#include <stdlib.h>
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

bool resetIPChecksum(uint8_t *packet, size_t len) {
    
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
    buffer[5] = sum;
    return true;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
    if (!validateIPChecksum(packet,len)) return false;
    uint8_t b_ttl = packet[8];
    packet[8]--;
    resetIPChecksum(packet, len);
    return true;  
}
