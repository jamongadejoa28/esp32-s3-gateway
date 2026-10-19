/* W5500 Ethernet on SPI2 (espressif/w5500 2.0.1 API as found in managed_components/; DESIGN.md §0).
 * Pins/clock: board_pins.h. INT is GPIO12 (the component default 4 is DI1 on this board). RST is
 * GPIO39 per the pin matrix but unverified, so a failed driver install is retried once without a
 * hardware reset. The chip has no burned MAC: the ESP32 Ethernet MAC from eFuse is set with
 * ETH_CMD_S_MAC_ADDR. */
#include <string.h>

#include "board_pins.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_eth.h"
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "net_priv.h"

static const char *TAG = "eth";

#define ETH_RX_TASK_STACK 4096
#define ETH_RX_TASK_PRIO 15
#define ETH_SPI_QUEUE 20
#define ETH_ROUTE_PRIO 100 /* above the SoftAP (10): Ethernet stays the default route */

static esp_eth_handle_t s_eth;
static esp_eth_netif_glue_handle_t s_glue;
static esp_netif_t *s_netif;

static esp_err_t install(spi_device_interface_config_t *dev, int rst_gpio) {
    eth_w5500_config_t w5500 = ETH_W5500_DEFAULT_CONFIG(BOARD_ETH_SPI_HOST, dev);
    w5500.base.int_gpio_num = BOARD_ETH_INT_GPIO;

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    mac_cfg.rx_task_stack_size = ETH_RX_TASK_STACK;
    mac_cfg.rx_task_prio = ETH_RX_TASK_PRIO;
    mac_cfg.flags |= ETH_MAC_FLAG_PIN_TO_CORE; /* rx task on the installing core (0, with tcpip) */

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.reset_gpio_num = rst_gpio;

    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500, &mac_cfg);
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_cfg);
    if (!mac || !phy) {
        if (mac) {
            mac->del(mac);
        }
        if (phy) {
            phy->del(phy);
        }
        return ESP_ERR_NO_MEM;
    }
    esp_eth_config_t cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_err_t err = esp_eth_driver_install(&cfg, &s_eth);
    if (err != ESP_OK) {
        s_eth = NULL;
        mac->del(mac);
        phy->del(phy);
    }
    return err;
}

esp_err_t net_eth_create(esp_netif_t **netif_out, uint8_t mac_out[GW_MAC_LEN]) {
    if (s_eth) {
        return ESP_ERR_INVALID_STATE;
    }
    /* The W5500 driver attaches its INT handler through the shared GPIO ISR service. */
    esp_err_t err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "gpio_install_isr_service: %s", esp_err_to_name(err));
        return err;
    }
    const spi_bus_config_t bus = {
        .mosi_io_num = BOARD_ETH_MOSI_GPIO,
        .miso_io_num = BOARD_ETH_MISO_GPIO,
        .sclk_io_num = BOARD_ETH_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    err = spi_bus_initialize(BOARD_ETH_SPI_HOST, &bus, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SPI%d bus init: %s", BOARD_ETH_SPI_HOST + 1, esp_err_to_name(err));
        return err;
    }
    /* Must outlive the driver: the W5500 driver keeps the pointer only during creation, but keep it
     * static so a retry starts from the same values. */
    static spi_device_interface_config_t dev;
    memset(&dev, 0, sizeof(dev));
    dev.mode = 0;
    dev.clock_speed_hz = BOARD_ETH_SPI_MHZ * 1000 * 1000;
    dev.queue_size = ETH_SPI_QUEUE;
    dev.spics_io_num = BOARD_ETH_CS_GPIO;

    err = install(&dev, BOARD_ETH_RST_GPIO);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "W5500 install with RST GPIO%d failed (%s); retrying without hardware reset",
                 BOARD_ETH_RST_GPIO, esp_err_to_name(err));
        err = install(&dev, -1);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "W5500 not available: %s", esp_err_to_name(err));
        spi_bus_free(BOARD_ETH_SPI_HOST);
        return err;
    }

    uint8_t mac[GW_MAC_LEN];
    err = esp_read_mac(mac, ESP_MAC_ETH);
    if (err == ESP_OK) {
        err = esp_eth_ioctl(s_eth, ETH_CMD_S_MAC_ADDR, mac);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set MAC: %s", esp_err_to_name(err));
        goto fail_driver;
    }

    esp_netif_inherent_config_t base = *ESP_NETIF_BASE_DEFAULT_ETH;
    base.route_prio = ETH_ROUTE_PRIO;
    const esp_netif_config_t ncfg = {.base = &base, .driver = NULL, .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH};
    s_netif = esp_netif_new(&ncfg);
    if (!s_netif) {
        err = ESP_ERR_NO_MEM;
        goto fail_driver;
    }
    s_glue = esp_eth_new_netif_glue(s_eth);
    if (!s_glue) {
        err = ESP_ERR_NO_MEM;
        goto fail_netif;
    }
    err = esp_netif_attach(s_netif, s_glue);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "netif attach: %s", esp_err_to_name(err));
        goto fail_glue;
    }
    memcpy(mac_out, mac, GW_MAC_LEN);
    *netif_out = s_netif;
    ESP_LOGI(TAG, "W5500 ready (SPI %d MHz, INT GPIO%d, MAC %02x:%02x:%02x:%02x:%02x:%02x)", BOARD_ETH_SPI_MHZ,
             BOARD_ETH_INT_GPIO, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ESP_OK;

fail_glue:
    esp_eth_del_netif_glue(s_glue);
    s_glue = NULL;
fail_netif:
    esp_netif_destroy(s_netif);
    s_netif = NULL;
fail_driver: {
    esp_eth_mac_t *mac_drv = NULL;
    esp_eth_phy_t *phy_drv = NULL;
    esp_eth_get_mac_instance(s_eth, &mac_drv);
    esp_eth_get_phy_instance(s_eth, &phy_drv);
    if (esp_eth_driver_uninstall(s_eth) == ESP_OK) {
        if (mac_drv) {
            mac_drv->del(mac_drv);
        }
        if (phy_drv) {
            phy_drv->del(phy_drv);
        }
    }
    s_eth = NULL;
    spi_bus_free(BOARD_ETH_SPI_HOST);
}
    return err;
}

esp_err_t net_eth_start(void) {
    if (!s_eth) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_eth_start(s_eth);
}
