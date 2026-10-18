#include "w5500.h"

#include <furi.h>
#include <furi_hal.h>

/* Wiring (same as the [W5500] Ethernet app):
 * MOSI A7 (2), MISO A6 (3), CS A4 (4), SCK B3 (5), RESET C3 (7), 3V3 (9), GND (8/11) */
#define W5500_SPI     (&furi_hal_spi_bus_handle_external)
#define W5500_RST_PIN (&gpio_ext_pc3)
#define SPI_TIMEOUT   100

#define BLOCK_COMMON 0x00
#define BLOCK_SREG(s) ((uint8_t)(((s) * 4) + 1))
#define BLOCK_TX(s)   ((uint8_t)(((s) * 4) + 2))
#define BLOCK_RX(s)   ((uint8_t)(((s) * 4) + 3))

/* Socket buffer sizes in KB (16 KB RX and 16 KB TX in total). */
/* s0 MACRAW, s1 DHCP, s2 DNS, s3 ICMP, s4..s7 ARP scan */
static const uint8_t rx_kb[8] = {8, 2, 1, 1, 1, 1, 1, 1};
static const uint8_t tx_kb[8] = {2, 2, 2, 2, 2, 2, 2, 2};

void w5500_bus_init(void) {
    furi_hal_spi_bus_handle_init(W5500_SPI);
    furi_hal_gpio_init_simple(W5500_RST_PIN, GpioModeOutputPushPull);
    furi_hal_gpio_write(W5500_RST_PIN, true);
}

void w5500_bus_deinit(void) {
    furi_hal_gpio_init_simple(W5500_RST_PIN, GpioModeAnalog);
    furi_hal_spi_bus_handle_deinit(W5500_SPI);
}

void w5500_hw_reset(void) {
    furi_hal_gpio_write(W5500_RST_PIN, false);
    furi_delay_ms(2);
    furi_hal_gpio_write(W5500_RST_PIN, true);
    furi_delay_ms(60);
}

static void w5500_xfer(uint16_t addr, uint8_t ctrl, const uint8_t* tx, uint8_t* rx, size_t len) {
    uint8_t hdr[3] = {(uint8_t)(addr >> 8), (uint8_t)addr, ctrl};
    furi_hal_spi_acquire(W5500_SPI);
    furi_hal_spi_bus_tx(W5500_SPI, hdr, 3, SPI_TIMEOUT);
    if(tx) furi_hal_spi_bus_tx(W5500_SPI, tx, len, SPI_TIMEOUT);
    if(rx) furi_hal_spi_bus_rx(W5500_SPI, rx, len, SPI_TIMEOUT);
    furi_hal_spi_release(W5500_SPI);
}

void w5500_write(uint16_t addr, uint8_t block, const uint8_t* data, size_t len) {
    w5500_xfer(addr, (uint8_t)((block << 3) | 0x04), data, NULL, len);
}

void w5500_read(uint16_t addr, uint8_t block, uint8_t* data, size_t len) {
    w5500_xfer(addr, (uint8_t)(block << 3), NULL, data, len);
}

uint8_t w5500_read8(uint16_t addr) {
    uint8_t v = 0;
    w5500_read(addr, BLOCK_COMMON, &v, 1);
    return v;
}

void w5500_write8(uint16_t addr, uint8_t value) {
    w5500_write(addr, BLOCK_COMMON, &value, 1);
}

uint8_t w5500_version(void) {
    return w5500_read8(W5500_VERSIONR);
}

uint8_t w5500_phy(void) {
    return w5500_read8(W5500_PHYCFGR);
}

void w5500_phy_set_mode(uint8_t opmdc) {
    uint8_t v = (uint8_t)(PHY_OPMD | ((opmdc & 0x07) << 3));
    w5500_write8(W5500_PHYCFGR, v); /* RST=0: reset PHY with new mode */
    furi_delay_ms(1);
    w5500_write8(W5500_PHYCFGR, v | PHY_RST);
}

bool w5500_init(const uint8_t mac[6]) {
    w5500_hw_reset();
    if(w5500_version() != 0x04) return false;
    w5500_write8(W5500_MR, 0x80);
    for(int i = 0; i < 20 && (w5500_read8(W5500_MR) & 0x80); i++) furi_delay_ms(1);
    if(w5500_version() != 0x04) return false;

    for(uint8_t s = 0; s < 8; s++) {
        sock_write8(s, Sn_RXBUF, rx_kb[s]);
        sock_write8(s, Sn_TXBUF, tx_kb[s]);
    }
    w5500_write(W5500_SHAR, BLOCK_COMMON, mac, 6);
    /* 200 ms x 3 tries: ARP for a dead host fails in ~0.8 s */
    w5500_set_retry(2000, 3);
    return true;
}

void w5500_set_net(const uint8_t ip[4], const uint8_t mask[4], const uint8_t gw[4]) {
    w5500_write(W5500_SIPR, BLOCK_COMMON, ip, 4);
    w5500_write(W5500_SUBR, BLOCK_COMMON, mask, 4);
    w5500_write(W5500_GAR, BLOCK_COMMON, gw, 4);
}

void w5500_set_retry(uint16_t rtr_100us, uint8_t rcr) {
    uint8_t r[2] = {(uint8_t)(rtr_100us >> 8), (uint8_t)rtr_100us};
    w5500_write(W5500_RTR, BLOCK_COMMON, r, 2);
    w5500_write8(W5500_RCR, rcr);
}

uint8_t sock_read8(uint8_t s, uint16_t reg) {
    uint8_t v = 0;
    w5500_read(reg, BLOCK_SREG(s), &v, 1);
    return v;
}

void sock_write8(uint8_t s, uint16_t reg, uint8_t value) {
    w5500_write(reg, BLOCK_SREG(s), &value, 1);
}

static uint16_t sock_read16_raw(uint8_t s, uint16_t reg) {
    uint8_t b[2];
    w5500_read(reg, BLOCK_SREG(s), b, 2);
    return (uint16_t)((b[0] << 8) | b[1]);
}

uint16_t sock_read16(uint8_t s, uint16_t reg) {
    /* RX_RSR and TX_FSR change while being read: read until two values match */
    uint16_t a, b = sock_read16_raw(s, reg);
    for(int i = 0; i < 8; i++) {
        a = b;
        b = sock_read16_raw(s, reg);
        if(a == b) break;
    }
    return b;
}

void sock_write16(uint8_t s, uint16_t reg, uint16_t value) {
    uint8_t b[2] = {(uint8_t)(value >> 8), (uint8_t)value};
    w5500_write(reg, BLOCK_SREG(s), b, 2);
}

static void sock_cmd(uint8_t s, uint8_t cmd) {
    sock_write8(s, Sn_CR, cmd);
    for(int i = 0; i < 100 && sock_read8(s, Sn_CR); i++) furi_delay_us(50);
}

uint8_t sock_status(uint8_t s) {
    return sock_read8(s, Sn_SR);
}

void sock_close(uint8_t s) {
    sock_cmd(s, Sn_CR_CLOSE);
    sock_write8(s, Sn_IR, 0xFF);
}

bool sock_open(uint8_t s, uint8_t mode, uint16_t port, uint8_t proto) {
    sock_close(s);
    sock_write8(s, Sn_MR, mode);
    if((mode & 0x0F) == Sn_MR_IPRAW) sock_write8(s, Sn_PROTO, proto);
    if((mode & 0x0F) == Sn_MR_UDP) sock_write16(s, Sn_PORT, port);
    sock_cmd(s, Sn_CR_OPEN);
    uint8_t want = (mode & 0x0F) == Sn_MR_UDP   ? SOCK_UDP :
                   (mode & 0x0F) == Sn_MR_IPRAW ? SOCK_IPRAW :
                                                  SOCK_MACRAW;
    for(int i = 0; i < 20; i++) {
        if(sock_status(s) == want) return true;
        furi_delay_ms(1);
    }
    return false;
}

uint16_t sock_rx_size(uint8_t s) {
    return sock_read16(s, Sn_RX_RSR);
}

void sock_rx_read(uint8_t s, uint16_t offset, uint8_t* data, uint16_t len) {
    uint16_t ptr = sock_read16_raw(s, Sn_RX_RD);
    /* Buffer addressing wraps on 16 bit in the RX block */
    w5500_read((uint16_t)(ptr + offset), BLOCK_RX(s), data, len);
}

void sock_rx_consume(uint8_t s, uint16_t n) {
    uint16_t ptr = sock_read16_raw(s, Sn_RX_RD);
    sock_write16(s, Sn_RX_RD, (uint16_t)(ptr + n));
    sock_cmd(s, Sn_CR_RECV);
}

static bool sock_send_begin(uint8_t s, const uint8_t* data, uint16_t len) {
    uint32_t start = furi_get_tick();
    while(sock_read16(s, Sn_TX_FSR) < len) {
        if(furi_get_tick() - start > 500) return false;
        furi_delay_ms(1);
    }
    uint16_t ptr = sock_read16_raw(s, Sn_TX_WR);
    w5500_write(ptr, BLOCK_TX(s), data, len);
    sock_write16(s, Sn_TX_WR, (uint16_t)(ptr + len));
    sock_write8(s, Sn_IR, Sn_IR_SENDOK | Sn_IR_TIMEOUT);
    sock_cmd(s, Sn_CR_SEND);
    return true;
}

W5500SendResult sock_send_poll(uint8_t s, bool* done) {
    uint8_t ir = sock_read8(s, Sn_IR);
    *done = true;
    if(ir & Sn_IR_SENDOK) {
        sock_write8(s, Sn_IR, Sn_IR_SENDOK);
        return W5500SendOk;
    }
    if(ir & Sn_IR_TIMEOUT) {
        sock_write8(s, Sn_IR, Sn_IR_TIMEOUT);
        return W5500SendTimeout;
    }
    if(sock_status(s) == SOCK_CLOSED) return W5500SendError;
    *done = false;
    return W5500SendError;
}

static W5500SendResult sock_send_common(uint8_t s, const uint8_t* data, uint16_t len) {
    if(!sock_send_begin(s, data, len)) return W5500SendError;
    uint32_t start = furi_get_tick();
    while(true) {
        bool done;
        W5500SendResult r = sock_send_poll(s, &done);
        if(done) return r;
        if(furi_get_tick() - start > 3000) return W5500SendError;
        furi_delay_ms(1);
    }
}

bool sock_sendto_begin(
    uint8_t s,
    const uint8_t* data,
    uint16_t len,
    const uint8_t ip[4],
    uint16_t port) {
    w5500_write(Sn_DIPR, BLOCK_SREG(s), ip, 4);
    sock_write16(s, Sn_DPORT, port);
    return sock_send_begin(s, data, len);
}

void sock_get_dhar(uint8_t s, uint8_t mac[6]) {
    w5500_read(Sn_DHAR, BLOCK_SREG(s), mac, 6);
}

W5500SendResult sock_sendto(
    uint8_t s,
    const uint8_t* data,
    uint16_t len,
    const uint8_t ip[4],
    uint16_t port) {
    w5500_write(Sn_DIPR, BLOCK_SREG(s), ip, 4);
    sock_write16(s, Sn_DPORT, port);
    return sock_send_common(s, data, len);
}

W5500SendResult sock_send_raw(uint8_t s, const uint8_t* data, uint16_t len) {
    return sock_send_common(s, data, len);
}
