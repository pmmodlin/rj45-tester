#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Common registers */
#define W5500_MR       0x0000
#define W5500_IR       0x0015
#define W5500_GAR      0x0001
#define W5500_SUBR     0x0005
#define W5500_SHAR     0x0009
#define W5500_SIPR     0x000F
#define W5500_RTR      0x0019
#define W5500_RCR      0x001B
#define W5500_UIPR     0x0028
#define W5500_UPORTR   0x002C
#define W5500_PHYCFGR  0x002E
#define W5500_VERSIONR 0x0039

/* Socket registers */
#define Sn_MR      0x0000
#define Sn_CR      0x0001
#define Sn_IR      0x0002
#define Sn_SR      0x0003
#define Sn_PORT    0x0004
#define Sn_DHAR    0x0006
#define Sn_DIPR    0x000C
#define Sn_DPORT   0x0010
#define Sn_PROTO   0x0014
#define Sn_TTL     0x0016
#define Sn_RXBUF   0x001E
#define Sn_TXBUF   0x001F
#define Sn_TX_FSR  0x0020
#define Sn_TX_WR   0x0024
#define Sn_RX_RSR  0x0026
#define Sn_RX_RD   0x0028

#define Sn_MR_UDP    0x02
#define Sn_MR_IPRAW  0x03
#define Sn_MR_MACRAW 0x04

#define Sn_CR_OPEN  0x01
#define Sn_CR_CLOSE 0x10
#define Sn_CR_SEND  0x20
#define Sn_CR_RECV  0x40

#define Sn_IR_SENDOK  0x10
#define Sn_IR_TIMEOUT 0x08
#define Sn_IR_RECV    0x04

#define SOCK_CLOSED 0x00
#define SOCK_UDP    0x22
#define SOCK_IPRAW  0x32
#define SOCK_MACRAW 0x42

/* PHYCFGR bits */
#define PHY_RST  0x80
#define PHY_OPMD 0x40
#define PHY_DPX  0x04
#define PHY_SPD  0x02
#define PHY_LNK  0x01

/* IR bits */
#define IR_CONFLICT 0x80
#define IR_UNREACH  0x40

typedef enum {
    W5500SendOk,
    W5500SendTimeout, /* ARP or transmit timeout */
    W5500SendError,
} W5500SendResult;

void w5500_bus_init(void);
void w5500_bus_deinit(void);
void w5500_hw_reset(void);

void w5500_write(uint16_t addr, uint8_t block, const uint8_t* data, size_t len);
void w5500_read(uint16_t addr, uint8_t block, uint8_t* data, size_t len);

uint8_t w5500_read8(uint16_t addr);
void w5500_write8(uint16_t addr, uint8_t value);

/* Software reset and buffer setup. Returns false when the chip does not answer. */
bool w5500_init(const uint8_t mac[6]);
uint8_t w5500_version(void);
uint8_t w5500_phy(void);
void w5500_phy_set_mode(uint8_t opmdc);

void w5500_set_net(const uint8_t ip[4], const uint8_t mask[4], const uint8_t gw[4]);
void w5500_set_retry(uint16_t rtr_100us, uint8_t rcr);

uint8_t sock_read8(uint8_t s, uint16_t reg);
void sock_write8(uint8_t s, uint16_t reg, uint8_t value);
uint16_t sock_read16(uint8_t s, uint16_t reg);
void sock_write16(uint8_t s, uint16_t reg, uint16_t value);

bool sock_open(uint8_t s, uint8_t mode, uint16_t port, uint8_t proto);
void sock_close(uint8_t s);
uint8_t sock_status(uint8_t s);

uint16_t sock_rx_size(uint8_t s);
/* Read len bytes from RX buffer at the current pointer (advances local pointer only). */
void sock_rx_read(uint8_t s, uint16_t offset, uint8_t* data, uint16_t len);
/* Consume n bytes from RX buffer and issue RECV. */
void sock_rx_consume(uint8_t s, uint16_t n);

/* UDP / IPRAW send to ip:port. Blocks until SEND_OK or timeout. */
W5500SendResult sock_sendto(
    uint8_t s,
    const uint8_t* data,
    uint16_t len,
    const uint8_t ip[4],
    uint16_t port);
/* Non-blocking UDP send: begin, then poll until done. The W5500 resolves the
 * destination by ARP; after SEND_OK Sn_DHAR holds the resolved MAC. */
bool sock_sendto_begin(
    uint8_t s,
    const uint8_t* data,
    uint16_t len,
    const uint8_t ip[4],
    uint16_t port);
W5500SendResult sock_send_poll(uint8_t s, bool* done);
void sock_get_dhar(uint8_t s, uint8_t mac[6]);
/* MACRAW send of a full Ethernet frame. */
W5500SendResult sock_send_raw(uint8_t s, const uint8_t* data, uint16_t len);
