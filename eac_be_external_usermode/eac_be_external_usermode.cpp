#include "driver.hpp"
#include <cstdio>

void error_handler(const char* message)
{
    printf("[error] %s\n", message);

    system("pause");
    while (true) {}
}

int main()
{
    if (!driver::initialize("notepad.exe"))
    {
        error_handler("driver failed to initailize (is it mapped?)");
        return 1;
    }

    printf("waiting for %s\n", driver::detail::process_name.c_str());

    while (!driver::attach()) {}

    printf("attached to process %s (0x%llx)\n", driver::detail::process_name.c_str(), driver::detail::process_id);

    printf("base address = %p\n", driver::detail::process_base);

    /*
    example usage:

    uint64_t local_player = driver::read<uint64_t>(driver::detail::process_base + 0x1234);
    if (!driver::valid_address(local_player))
    {
        printf("local player invalid!\n");
        return;
    }

    */

    while (true) {}
}

