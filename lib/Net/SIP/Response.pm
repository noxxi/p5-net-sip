###########################################################################
# package Net::SIP::Response
# subclass from Net::SIP::Packet for managing the response packets
###########################################################################

use strict;
use warnings;

package Net::SIP::Response;
use base 'Net::SIP::Packet';

###########################################################################
# Redefine methods from Net::SIP::Packet, no need to find out dynamically
###########################################################################
sub is_request  {0}
sub is_response {1}

###########################################################################
# Accessors for numerical code and text 
# (e.g. "407 Authorization required" )
###########################################################################
sub code        { return (shift->as_parts())[0] }
sub msg         { return (shift->as_parts())[1] }


1;
