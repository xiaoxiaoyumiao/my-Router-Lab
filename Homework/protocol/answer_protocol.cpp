#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

bool checkMask(const uint32_t m) {
    uint32_t p = 0, mm = 1;
    for (; p < 32 && !(m & mm); p++, mm <<= 1);
    for (; p < 32; p++, mm <<= 1)
        if (!(m & mm))
            return false;
    return true;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint16_t total_length = packet[2]; total_length = (total_length << 8) + packet[3];
    if (total_length > len) return false;

    uint32_t len_ip = packet[0] & 0xF; len_ip <<= 2;
    uint32_t p = len_ip + 8;

    if (packet[p] != 1 && packet[p] != 2) return false;
    output->command = packet[p];
    uint16_t Family = output->command == 1 ? 0 : 2;

    p += 1;
    
    if (packet[p] != 2) return false;

    p += 3;

    uint32_t i = 0;
    while (p < len) {
        uint16_t family = packet[p]; family = (family << 8) + packet[p + 1];
        if (family != Family) return false;

        p += 2;

        uint16_t tag = packet[p]; tag = (tag << 8) + packet[p + 1];
        if (tag != 0) return false;

        p += 2;

        output->entries[i].addr = packet[p + 3]; output->entries[i].addr = (output->entries[i].addr << 8) + packet[p + 2]; output->entries[i].addr = (output->entries[i].addr << 8) + packet[p + 1]; output->entries[i].addr = (output->entries[i].addr << 8) + packet[p];

        p += 4;
        
        output->entries[i].mask = packet[p + 3]; output->entries[i].mask = (output->entries[i].mask << 8) + packet[p + 2]; output->entries[i].mask = (output->entries[i].mask << 8) + packet[p + 1]; output->entries[i].mask = (output->entries[i].mask << 8) + packet[p];
        if (!checkMask(ntohl(output->entries[i].mask))) return false;

        p += 4;

        output->entries[i].nexthop = packet[p + 3]; output->entries[i].nexthop = (output->entries[i].nexthop << 8) + packet[p + 2]; output->entries[i].nexthop = (output->entries[i].nexthop << 8) + packet[p + 1]; output->entries[i].nexthop = (output->entries[i].nexthop << 8) + packet[p];

        p += 4;

        output->entries[i].metric = packet[p + 3]; output->entries[i].metric = (output->entries[i].metric << 8) + packet[p + 2]; output->entries[i].metric = (output->entries[i].metric << 8) + packet[p + 1]; output->entries[i].metric = (output->entries[i].metric << 8) + packet[p];
        if (ntohl(output->entries[i].metric) < 1 || 16 < ntohl(output->entries[i].metric)) return false;
        
        p += 4;
        i += 1;
    }

    output->numEntries = i;

    return true;
}

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    buffer[0] = rip->command; buffer[1] = 2;
    buffer[2] = buffer[3] = 0;
    uint16_t family = rip->command == 1 ? 0 : 2;
    uint32_t p = 4;
    for (int i = 0; i < rip->numEntries; i++) {
        buffer[p++] = 0; buffer[p++] = family;
        buffer[p++] = buffer[p++] = 0;
        buffer[p++] = rip->entries[i].addr & 0xFF; buffer[p++] = (rip->entries[i].addr >> 8) & 0xFF; buffer[p++] = (rip->entries[i].addr >> 16) & 0xFF; buffer[p++] = (rip->entries[i].addr >> 24) & 0xFF;
        buffer[p++] = rip->entries[i].mask & 0xFF; buffer[p++] = (rip->entries[i].mask >> 8) & 0xFF; buffer[p++] = (rip->entries[i].mask >> 16) & 0xFF; buffer[p++] = (rip->entries[i].mask >> 24) & 0xFF;
        buffer[p++] = rip->entries[i].nexthop & 0xFF; buffer[p++] = (rip->entries[i].nexthop >> 8) & 0xFF; buffer[p++] = (rip->entries[i].nexthop >> 16) & 0xFF; buffer[p++] = (rip->entries[i].nexthop >> 24) & 0xFF;
        buffer[p++] = rip->entries[i].metric & 0xFF; buffer[p++] = (rip->entries[i].metric >> 8) & 0xFF; buffer[p++] = (rip->entries[i].metric >> 16) & 0xFF; buffer[p++] = (rip->entries[i].metric >> 24) & 0xFF;
    }
    return p;
}