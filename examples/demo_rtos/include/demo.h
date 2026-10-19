#ifndef DEMO_H
#define DEMO_H

#include <stdint.h>

/* 板级初始化 */
void bsp_init(void);

/* 传感器采样（mA） */
uint16_t sensor_sample(void);

/* 帧打包与发送 */
void comm_send_frame(const char *tag);

#endif /* DEMO_H */
