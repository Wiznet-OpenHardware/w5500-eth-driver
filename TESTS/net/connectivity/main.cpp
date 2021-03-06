#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"

#include "W5500Interface.h"

using namespace utest::v1;

#ifndef MBED_CFG_W5500_SPI_MOSI
#define MBED_CFG_W5500_SPI_MOSI	D11
#endif

#ifndef MBED_CFG_W5500_SPI_MISO
#define MBED_CFG_W5500_SPI_MISO	D12
#endif

#ifndef MBED_CFG_W5500_SPI_SCLK
#define MBED_CFG_W5500_SPI_SCLK	D13
#endif

#ifndef MBED_CFG_W5500_SPI_CS
#define MBED_CFG_W5500_SPI_CS	D10
#endif

#ifndef MBED_CFG_W5500_SPI_RST
#define MBED_CFG_W5500_SPI_RST	NC
#endif

#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x


// Bringing the network up and down
template <int COUNT>
void test_bring_up_down() {
	W5500Interface net(MBED_CFG_W5500_SPI_MOSI, MBED_CFG_W5500_SPI_MISO, MBED_CFG_W5500_SPI_SCLK, MBED_CFG_W5500_SPI_CS, MBED_CFG_W5500_SPI_RST);

    for (int i = 0; i < COUNT; i++) {
        int err = net.connect();
        TEST_ASSERT_EQUAL(0, err);

        printf("MBED: IP Address %s\r\n", net.get_ip_address());
        printf("MBED: Netmask %s\r\n", net.get_netmask());
        printf("MBED: Gateway %s\r\n", net.get_gateway());
        TEST_ASSERT(net.get_ip_address());
        TEST_ASSERT(net.get_netmask());
        TEST_ASSERT(net.get_gateway());

        UDPSocket udp;
        err = udp.open(&net);
        TEST_ASSERT_EQUAL(0, err);
        err = udp.close();
        TEST_ASSERT_EQUAL(0, err);

        TCPSocket tcp;
        err = tcp.open(&net);
        TEST_ASSERT_EQUAL(0, err);
        err = tcp.close();
        TEST_ASSERT_EQUAL(0, err);

        err = net.disconnect();
        TEST_ASSERT_EQUAL(0, err);
    }
}


// Test setup
utest::v1::status_t test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(120, "default_auto");
    return verbose_test_setup_handler(number_of_cases);
}

Case cases[] = {
    Case("Bringing the network up and down", test_bring_up_down<1>),
    Case("Bringing the network up and down twice", test_bring_up_down<2>),
};

Specification specification(test_setup, cases);

int main() {
    return !Harness::run(specification);
}
