#pragma once

#ifdef DEVICE_pacman
#include "../devices/pacman.h"
#elif DEVICE_tetris  
#include "../devices/tetris.h"
#else
#error "Unknown device. Add your device to device_config.h"
#endif

#ifndef STAGE1_BASE
#error "STAGE1_BASE not defined for this device"
#endif

#ifndef STAGE2_BASE
#error "STAGE2_BASE not defined for this device"
#endif

#ifndef STAGE3_BASE
#error "STAGE3_BASE not defined for this device"
#endif