set(TARGET_NAME w5x00_mqtt_nosys)

add_executable(${TARGET_NAME}
        ${TARGET_NAME}.c
        )

# This is required to include lwipopts.h
target_include_directories(pico_lwip INTERFACE        
        ${PORT_DIR}/lwip
        )

target_link_libraries(${TARGET_NAME} PRIVATE
        pico_stdlib
        hardware_spi
        hardware_dma
        ETHERNET_FILES
        IOLIBRARY_FILES
        LWIP_FILES
        pico_lwip_mqtt
        hardware_adc
        )

pico_enable_stdio_usb(${TARGET_NAME} 1)
pico_enable_stdio_uart(${TARGET_NAME} 0)

pico_add_extra_outputs(${TARGET_NAME})
