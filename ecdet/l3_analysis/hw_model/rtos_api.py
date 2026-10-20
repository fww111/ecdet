"""RTOS API 语义标注表（方案 3.3.2）。

为 FreeRTOS / RT-Thread / CMSIS-OS2 关键 API 建立语义标注：
阻塞点、ISR 安全变体。供"ISR 中调用阻塞 API"检查消费。
通用 libc 忙等（HAL_Delay）一并标注。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RTOSApiSem:
    name: str
    is_blocking: bool              # 调用可能阻塞调度/长时间占用
    isr_safe_variant: str | None   # ISR 中应使用的替代 API


# 阻塞类 API：任务上下文合法，ISR 上下文禁止（见 _build 的显式清单）


def _build() -> tuple[dict[str, RTOSApiSem], set[str]]:
    blocking: dict[str, RTOSApiSem] = {}
    blocking_list = [
        # FreeRTOS
        RTOSApiSem("vTaskDelay", True, None),
        RTOSApiSem("vTaskDelayUntil", True, None),
        RTOSApiSem("vTaskSuspend", True, None),
        RTOSApiSem("xQueueSend", True, "xQueueSendFromISR"),
        RTOSApiSem("xQueueSendToFront", True, "xQueueSendToFrontFromISR"),
        RTOSApiSem("xQueueReceive", True, "xQueueReceiveFromISR"),
        RTOSApiSem("xQueuePeek", True, "xQueuePeekFromISR"),
        RTOSApiSem("xSemaphoreTake", True, "xSemaphoreTakeFromISR"),
        RTOSApiSem("xSemaphoreGive", False, "xSemaphoreGiveFromISR"),
        RTOSApiSem("ulTaskNotifyTake", True, "vTaskNotifyGiveFromISR"),
        RTOSApiSem("xEventGroupWaitBits", True, None),
        RTOSApiSem("xEventGroupSync", True, None),
        # RT-Thread
        RTOSApiSem("rt_thread_mdelay", True, None),
        RTOSApiSem("rt_thread_delay", True, None),
        RTOSApiSem("rt_sem_take", True, None),
        RTOSApiSem("rt_mutex_take", True, None),
        RTOSApiSem("rt_mb_recv", True, None),
        RTOSApiSem("rt_mb_send_wait", True, None),
        # CMSIS-OS2
        RTOSApiSem("osDelay", True, None),
        RTOSApiSem("osDelayUntil", True, None),
        RTOSApiSem("osMutexAcquire", True, None),
        RTOSApiSem("osSemaphoreAcquire", True, None),
        RTOSApiSem("osMessageQueueGet", True, None),
        RTOSApiSem("osMessageQueuePut", False, None),
        RTOSApiSem("osThreadFlagsWait", True, None),
        RTOSApiSem("osEventFlagsWait", True, None),
        RTOSApiSem("osThreadTerminate", True, None),
        # 通用忙等
        RTOSApiSem("HAL_Delay", True, None),
    ]
    for api in blocking_list:
        blocking[api.name] = api
    # 临界区宏：进入/退出配对，供按行区间的保护判定
    enter = {
        "taskENTER_CRITICAL", "portENTER_CRITICAL",
        "OS_CRITICAL_ENTER", "rt_enter_critical", "rt_hw_interrupt_disable",
        "osal_irq_lock", "__disable_irq", "portDISABLE_INTERRUPTS",
        "ATOMIC_ENTER", "osKernelLock",
    }
    exit_ = {
        "taskEXIT_CRITICAL", "portEXIT_CRITICAL",
        "OS_CRITICAL_EXIT", "rt_exit_critical", "rt_hw_interrupt_enable",
        "osal_irq_unlock", "__enable_irq", "portENABLE_INTERRUPTS",
        "ATOMIC_EXIT", "osKernelUnlock",
    }
    return blocking, enter, exit_


BLOCKING_APIS, CRITICAL_ENTER_MACROS, CRITICAL_EXIT_MACROS = _build()
CRITICAL_MACROS = CRITICAL_ENTER_MACROS | CRITICAL_EXIT_MACROS
