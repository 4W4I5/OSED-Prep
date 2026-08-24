#include <iostream>
#include <Windows.h>
int main(int argc, char **argv)
{
    std::cout << "Press ENTER to start...\n";
    // std::cin.get();
    printf("This is your input: 0x%x, 0x%x, 0x%x, 0x%x\n", 65, 66);
    DebugBreak();
    return 0;
}

