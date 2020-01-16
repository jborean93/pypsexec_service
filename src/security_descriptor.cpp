#include "security_descriptor.h"


uint32_t generate_access_mask(uint32_t security_info, bool read_only)
{
    uint32_t access = 0;

    if (security_info & ATTRIBUTE_SECURITY_INFORMATION)
    {
        access |= READ_CONTROL | (read_only ? 0 : WRITE_DAC);
    }

    if (security_info & BACKUP_SECURITY_INFORMATION)
    {
        uint32_t write_bits = WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
        access |= READ_CONTROL | ACCESS_SYSTEM_SECURITY | (read_only ? 0 : write_bits);
    }

    if (security_info & DACL_SECURITY_INFORMATION)
    {
        access |= READ_CONTROL | (read_only ? 0 : WRITE_DAC);
    }

    if (security_info & GROUP_SECURITY_INFORMATION)
    {
        access |= READ_CONTROL | (read_only ? 0 : WRITE_OWNER);
    }

    if (security_info & LABEL_SECURITY_INFORMATION)
    {
        access |= READ_CONTROL | (read_only ? 0 : WRITE_OWNER);
    }

    if (security_info & OWNER_SECURITY_INFORMATION)
    {
        access |= READ_CONTROL | (read_only ? 0 : WRITE_OWNER);
    }

    if (security_info & SACL_SECURITY_INFORMATION)
    {
        access |= ACCESS_SYSTEM_SECURITY;
    }

    return access;
}

namespace sd
{
    template <typename handle_t, SE_OBJECT_TYPE object_type>
    security_descriptor<handle_t, object_type>::security_descriptor(handle_t handle,
        uint32_t security_info) : m_handle(std::move(handle)), security_information(security_info)
    {
        auto [sd, owner, group, dacl, sacl] = win32::get_security_info(m_handle.get(), object_type,
            security_information);

        m_sd = std::move(sd);
        m_owner = owner;
        m_group = group;
        m_dacl = dacl;
        m_sacl = sacl;
    }

    sd::desktop_sd open_desktop_sd(const std::string &name, uint32_t security_info, bool read_only)
    {
        uint32_t access = generate_access_mask(security_info, read_only);

        return sd::desktop_sd(win32::open_desktop(name, 0, false, access), security_info);
    }

    sd::station_sd open_window_station_sd(const std::string &name, uint32_t security_info, bool read_only)
    {
        uint32_t access = generate_access_mask(security_info, read_only);

        return sd::station_sd(win32::open_window_station(name, false, access), security_info);
    }
}
