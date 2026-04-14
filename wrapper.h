#if defined(__has_include)

#  if __has_include(<openvpn-plugin.h>)
     // SUSE
#    include <openvpn-plugin.h>

#  elif __has_include(<openvpn/openvpn-plugin.h>)
     // Debian
#    include <openvpn/openvpn-plugin.h>

#  else
#    error "Could not find openvpn-plugin.h in any known location."

#  endif

#else
     // Should not happen
#    error "Macro __has_include is not defined."

#endif
