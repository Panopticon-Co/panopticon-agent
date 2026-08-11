#include <windows.h>
#include <winevt.h>

#include <iostream>

int main() {
    // The next milestone will use EvtQuery, EvtNext, and EvtRender from winevt.h.
    std::cout << "EyeTrace Query 0.1: Windows Event Log API build is ready.\n";
    return 0;
}
