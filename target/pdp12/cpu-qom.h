/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PDP12_CPU_QOM_H
#define PDP12_CPU_QOM_H

#include "hw/core/cpu.h"

#define TYPE_PDP12_CPU "pdp12-cpu"
#define PDP12_CPU_TYPE_SUFFIX "-" TYPE_PDP12_CPU
#define PDP12_CPU_TYPE_NAME(name) (name PDP12_CPU_TYPE_SUFFIX)

typedef struct PDP12CPUClass {
    CPUClass parent_class;
} PDP12CPUClass;

OBJECT_DECLARE_CPU_TYPE(PDP12CPU, PDP12CPUClass, PDP12_CPU)

#endif
