#ifndef SECURITY_DESCRIPTOR_H
#define SECURITY_DESCRIPTOR_H
#include <vector>
#include "win32.h"

namespace sd
{
    struct ace_entry
    {
        PSID sid;
        uint32_t access_mask;
        ACCESS_MODE access_mode;
        uint32_t inheritance;
    };

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    class security_descriptor
    {
        public:
            security_descriptor(handle_t handle, uint32_t security_info);

            void add_ace_to_dacl(ace_entry ace);
            void add_aces_to_dacl(std::vector<ace_entry> aces);
            PACL get_dacl();
            PSID get_group();
            PSID get_owner();
            PACL get_sacl();
            void persist(uint32_t security_info = 0);

        private:
            handle_t m_handle;
            uint32_t security_information;
            wil::unique_hlocal_security_descriptor m_sd;

            // Raw pointer to the m_sd buffer for each element.
            PACL m_dacl;
            PSID m_group;
            PSID m_owner;
            PACL m_sacl;

            // Stores any modified entries in the SD in a smart pointer.
            wil::unique_hlocal m_new_dacl;
            wil::unique_hlocal m_new_group;
            wil::unique_hlocal m_new_owner;
            wil::unique_hlocal m_new_sacl;
    };

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline void security_descriptor<handle_t, object_type>::add_ace_to_dacl(ace_entry ace)
    {
        std::vector<ace_entry> entries;
        entries.push_back(ace);
        add_aces_to_dacl(entries);
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline void security_descriptor<handle_t, object_type>::add_aces_to_dacl(std::vector<ace_entry> aces)
    {
        uint32_t ace_count = aces.size();
        std::unique_ptr<EXPLICIT_ACCESS_W[]> ea_buffer (new EXPLICIT_ACCESS_W[ace_count]());
        auto ea = ea_buffer.get();
        
        for (std::vector<ace_entry>::size_type i = 0; i != ace_count; i++)
        {
            ace_entry entry = aces[i];

            ea[i].grfAccessPermissions = entry.access_mask;
            ea[i].grfAccessMode = entry.access_mode;
            ea[i].grfInheritance = entry.inheritance;
            ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[i].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            ea[i].Trustee.ptstrName = (LPWSTR)entry.sid;
        }

        this->m_new_dacl = win32::set_entries_in_acl(ace_count, (PEXPLICIT_ACCESS_W)ea, this->get_dacl());
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline PACL security_descriptor<handle_t, object_type>::get_dacl()
    {
        return this->m_new_dacl.is_valid() ? (PACL)this->m_new_dacl.get() : this->m_dacl;
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline PSID security_descriptor<handle_t, object_type>::get_group()
    {
        return this->m_new_group.is_valid() ? (PSID)this->m_new_group.get() : this->m_group;
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline PSID security_descriptor<handle_t, object_type>::get_owner()
    {
        return this->m_new_owner.is_valid() ? (PSID)this->m_new_owner.get() : this->m_owner;
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline PACL security_descriptor<handle_t, object_type>::get_sacl()
    {
        return this->m_new_sacl.is_valid() ? (PACL)this->m_new_sacl.get() : this->m_sacl;
    }

    template <typename handle_t, SE_OBJECT_TYPE object_type>
    inline void security_descriptor<handle_t, object_type>::persist(uint32_t security_info)
    {
        if (!security_info)
        {
            security_info = this->security_information;
        }

        win32::set_security_info(m_handle.get(), object_type, security_info, this->get_owner(), this->get_group(),
            this->get_dacl(), this->get_sacl());
    }

    using desktop_sd = security_descriptor<wil::unique_hdesk, SE_WINDOW_OBJECT>;

    using station_sd = security_descriptor<wil::unique_hwinsta, SE_WINDOW_OBJECT>;

    sd::desktop_sd open_desktop_sd(const std::string &name, uint32_t security_info, bool read_only = false);

    sd::station_sd open_window_station_sd(const std::string &name, uint32_t security_info, bool read_only = false);

}

#endif  // SECURITY_DESCRIPTOR_H