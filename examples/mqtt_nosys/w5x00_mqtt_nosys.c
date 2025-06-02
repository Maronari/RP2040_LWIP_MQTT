/**
 * Copyright (c) 2022 WIZnet Co.,Ltd
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * ----------------------------------------------------------------------------------------------------
 * Includes
 * ----------------------------------------------------------------------------------------------------
 */
#include <stdio.h>

#include "port_common.h"

#include "wizchip_conf.h"
#include "socket.h"
#include "w5x00_spi.h"
#include "w5x00_lwip.h"

#include "lwip/apps/mqtt.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"

#include "lwip/apps/lwiperf.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"

#include <string.h>
#include "hardware/adc.h"

/**
 * ----------------------------------------------------------------------------------------------------
 * Macros
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Socket */
#define SOCKET_MACRAW 0

/* Port */
#define PORT_LWIPERF 5001

/**
 * ----------------------------------------------------------------------------------------------------
 * Variables
 * ----------------------------------------------------------------------------------------------------
 */
/* Network */
extern uint8_t mac[6];

/* LWIP */
struct netif g_netif;

/* DNS */
static uint8_t g_dns_target_domain[] = "www.wiznet.io";
static uint8_t g_dns_get_ip_flag = 0;
static uint32_t g_ip;
static ip_addr_t g_resolved;

/* MQTT */
static mqtt_client_t *mqtt_client;
static const struct mqtt_connect_client_info_t mqtt_client_info =
    {
        "test",
        NULL, /* user */
        NULL, /* pass */
        100,  /* keep alive */
        NULL, /* will_topic */
        NULL, /* will_msg */
        0,    /* will_msg_len */
        0,    /* will_qos */
        0     /* will_retain */
#if LWIP_ALTCP && LWIP_ALTCP_TLS
        ,
        NULL
#endif
};

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
static void set_clock_khz(void);

static void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status);
static void mqtt_pub_request_cb(void *arg, err_t result);
void init_mqtt();
float read_temperature();

/**
 * ----------------------------------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------------------------------------
 */
int main()
{
    /* Initialize */
    int8_t retval = 0;
    uint8_t *pack = malloc(ETHERNET_MTU);
    uint16_t pack_len = 0;
    struct pbuf *p = NULL;

    set_clock_khz();

    // Initialize stdio after the clock change
    stdio_init_all();

    sleep_ms(1000 * 3); // wait for 3 seconds

    wizchip_spi_initialize();
    wizchip_cris_initialize();

    wizchip_reset();
    wizchip_initialize();
    wizchip_check();

    // Set ethernet chip MAC address
    setSHAR(mac);
    ctlwizchip(CW_RESET_PHY, 0);

    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(0);

    // Initialize LWIP in NO_SYS mode
    lwip_init();

    netif_add(&g_netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL, netif_initialize, netif_input);
    g_netif.name[0] = 'e';
    g_netif.name[1] = '0';

    // ip_addr_t ip, nm, gw;
    // IP4_ADDR(&ip, 192, 168, 1, 100);
    // IP4_ADDR(&nm, 255, 255, 255, 0);
    // IP4_ADDR(&gw, 192, 168, 1, 1);
    // netif_set_addr(&g_netif, &ip, &nm, &gw);

    // Assign callbacks for link and status
    netif_set_link_callback(&g_netif, netif_link_callback);
    netif_set_status_callback(&g_netif, netif_status_callback);

    // MACRAW socket open
    retval = socket(SOCKET_MACRAW, Sn_MR_MACRAW, PORT_LWIPERF, 0x00);

    if (retval < 0)
    {
        printf(" MACRAW socket open failed\n");
    }

    // Set the default interface and bring it up
    netif_set_default(&g_netif);
    netif_set_link_up(&g_netif);
    netif_set_up(&g_netif);

    // Start DHCP configuration for an interface
    dhcp_start(&g_netif);

    // dns_init();

    /* Infinite loop */

    while (1)
    {
        getsockopt(SOCKET_MACRAW, SO_RECVBUF, &pack_len);

        if (pack_len > 0)
        {
            pack_len = recv_lwip(SOCKET_MACRAW, (uint8_t *)pack, pack_len);

            if (pack_len)
            {
                p = pbuf_alloc(PBUF_RAW, pack_len, PBUF_POOL);
                pbuf_take(p, pack, pack_len);
                free(pack);

                pack = malloc(ETHERNET_MTU);
            }
            else
            {
                printf(" No packet received\n");
            }

            if (pack_len && p != NULL)
            {
                LINK_STATS_INC(link.recv);

                if (g_netif.input(p, &g_netif) != ERR_OK)
                {
                    pbuf_free(p);
                }
            }
        }
        /* Cyclic lwIP timers check */
        sys_check_timeouts();

        if ((g_netif.ip_addr.addr > 0) && (g_netif.netmask.addr > 0) && (g_netif.gw.addr > 0) && !mqtt_client)
        {
            init_mqtt();
        }
    }
}

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
void init_mqtt()
{
    err_t err;
    ip_addr_t broker_addr;
    if (!ipaddr_aton(MQTT_BROKER, &broker_addr))
    {
        printf("Invalid broker IP\n");
        return;
    }
    struct eth_addr pc_mac;
    pc_mac.addr[0] = 0x8C;
    pc_mac.addr[1] = 0xC6;
    pc_mac.addr[2] = 0x81;
    pc_mac.addr[3] = 0x87;
    pc_mac.addr[4] = 0x06;
    pc_mac.addr[5] = 0xE5;

    err = etharp_add_static_entry(&broker_addr, &pc_mac);
    if (err != ERR_OK)
    {
        printf("Failed to add ARP entry: %d\n", err);
    }

    struct mqtt_connect_client_info_t ci = {
        .client_id = "pico_eth",
        .keep_alive = 60,
        .client_user = NULL,
        .client_pass = NULL};

    mqtt_client = mqtt_client_new();
    if (!mqtt_client)
    {
        printf("Failed to create client\n");
        return;
    }

    err = mqtt_client_connect(mqtt_client, &broker_addr, MQTT_PORT,
                              mqtt_connection_cb, NULL, &ci);
    if (err != ERR_OK)
    {
        printf("Connect error: %d\n", err);
    }
}

static void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status)
{
    const char *pub_payload = "HELLO, it's PICO";
    err_t err;
    u8_t qos = 0;    /* 0 1 or 2, see MQTT specification */
    u8_t retain = 0; /* No don't retain such crappy payload... */
    err = mqtt_publish(client, "pico", pub_payload, strlen(pub_payload), qos, retain, mqtt_pub_request_cb, arg);
    if (err != ERR_OK)
    {
        printf("Publish err: %d\n", err);
    }
}

// Callback после публикации
static void mqtt_pub_request_cb(void *arg, err_t result)
{
    err_t err;
    if (result == ERR_OK)
    {
        printf("Message published successfully\n");
        sleep_ms(1000 * 3); // wait for 3 seconds
        char pub_payload[10];
        sprintf(pub_payload, "%f", read_temperature());
        err_t err;
        u8_t qos = 0;    /* 0 1 or 2, see MQTT specification */
        u8_t retain = 0; /* No don't retain such crappy payload... */
        err = mqtt_publish(mqtt_client, "pico", pub_payload, strlen(pub_payload), qos, retain, mqtt_pub_request_cb, NULL);
        if (err != ERR_OK)
        {
            printf("Publish err: %d\n", err);
        }
    }
    else
    {
        printf("Publish failed: %d\n", result);
    }
}

float read_temperature()
{
    uint16_t raw = adc_read();
    const float conversion_factor = 3.3f / (4096 - 1);
    float result = raw * conversion_factor;
    if (adc_get_selected_input() == 4)
    {
        
        float temp = 27 - (result - 0.706)/0.001721;
        return temp;
    }
    else
    {
        float temp = (result - 1.25)/0.005;
        return temp;
    }
}

/* Clock */
static void set_clock_khz(void)
{
    // set a system clock frequency in khz
    set_sys_clock_khz(PLL_SYS_KHZ, true);

    // configure the specified clock
    clock_configure(
        clk_peri,
        0,                                                // No glitchless mux
        CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
        PLL_SYS_KHZ * 1000,                               // Input frequency
        PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
    );
}