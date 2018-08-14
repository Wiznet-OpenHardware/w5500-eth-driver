
#pragma once

//#include "mbed.h"
//#include "mbed_debug.h"

#define USE_W5500
//#define USE_W5200 // don't use this library
//#define USE_W5100 // don't use this library

#if defined(USE_W5500)
#include "W5500.h"
//#define USE_WIZ550IO_MAC    // want to use the default MAC address stored in the WIZ550io
#endif

/*
// current library don't want to support old chips.
#if defined(USE_W5200)
#include "W5200.h"
#endif

#if defined(USE_W5100)
#include "W5100.h"
#endif
*/