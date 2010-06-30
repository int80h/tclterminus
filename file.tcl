proc open_default_device {} {
    set promisc 0
    if {$promisc == 0} {
        set promisc_string "-nopromisc"
    } else {
        set promisc_string "-promisc"
    }

	set device [pcap::lookupdev]
	set pcapChannel [pcap::pcap_open $promisc_string -filter "tcp" $device]
	set datalink_type [pcap::datalink $pcapChannel]
	if {[lindex $datalink_type 0] != "DLT_EN10MB"} {
	    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
	    exit
	}
	set addrlist [pcap::lookupnet $device]
    set addr [lindex $addrlist 0]
    set netmask [lindex $addrlist 1]
    set mac_addr "Not Acquired"
	
    dict set app_info host [info hostname]
    dict set app_info mac_addr $mac_addr
	dict set app_info device $device
	dict set app_info datalink_type $datalink_type
	dict set app_info pcapChannel $pcapChannel
	dict set app_info addr $addr
	dict set app_info netmask $netmask
	dict set app_info promisc_string $promisc_string
	
	fconfigure $pcapChannel -blocking 0 -translation binary
    return $app_info
}


