#include <stdint.h>

uint8_t sensor_value = 0;
uint16_t temperature = 2500;
uint32_t counter = 0;
float voltage = 3.3f;
double precision_val = 1.23456789;

int8_t signed_byte = -10;
int16_t signed_word = -1000;
int32_t signed_long = -100000;

const uint16_t calibration_offset = 100;
const uint32_t max_threshold = 5000;

static uint8_t internal_buffer[64];

void update_sensor(uint16_t raw_value) {
    sensor_value = (uint8_t)(raw_value & 0xFF);
    temperature = raw_value;
    counter++;
}

uint32_t get_counter(void) {
    return counter;
}

int main(void) {
    update_sensor(512);
    while(1) {
        if (counter > max_threshold) {
            counter = 0;
        }
        update_sensor(temperature);
    }
    return 0;
}
