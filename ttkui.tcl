package require Tcl 8.4
package require msgcat 1.3
package require tooltip

source file.tcl 

proc update_display packet_id {
    global unfiltered app_info
    #puts "packet id is $packet_id. unfiltered is size [dict size $unfiltered]."
    #puts "unfiltered looks like [dict keys $unfiltered]."
    #puts "unfiltered vals [dict values $unfiltered]."
    set packet [dict get $unfiltered $packet_id]
    set packet_w [dict get $app_info packet_w]

    update_header_w $packet $packet_w link
    update_header_w $packet $packet_w trans
    #update_trans_w $packet $packet_w
    #update_net_w $packet $packet_w
    puts "updating display"
}

proc update_ipv4_display {packet container} {
    puts "ipv4 container $container"
    ${container}.version configure -text "VER [dict get $packet trans version]"
    ${container}.header_len configure -text "HDR [dict get $packet trans header_len]"
    ${container}.tos configure -text "TOS [dict get $packet trans tos]"
    ${container}.total_len configure -text "LEN [dict get $packet trans total_len]"
    ${container}.id configure -text "ID  [dict get $packet trans id]"
    ${container}.flags configure -text "ID  [dict get $packet trans flags]"
    ${container}.fragment_offset configure -text "ID  [dict get $packet trans fragment_offset]"
    ${container}.ttl configure -text "TTL [dict get $packet trans ttl]"
    ${container}.protocol configure -text "PRO [dict get $packet trans protocol]"
    ${container}.checksum configure -text "CHK [dict get $packet trans checksum]"
    ${container}.src configure -text "SRC [dict get $packet trans pretty_src]"
    ${container}.dest configure -text "DEST [dict get $packet trans pretty_dest]"
}

proc update_ether_display {packet container} {
    puts "ether container $container"
    ${container}.src configure -text "SRC [dict get $packet link pretty_src]"
    ${container}.dest configure -text "DST [dict get $packet link pretty_dest]"
    ${container}.len configure -text "LEN [dict get $packet len]"
}

proc update_header_w {packet packet_w type} {
    set display [dict get $packet $type display]
    puts " cmd: $display $packet ${packet_w}.headers.${type}_w"
    $display $packet ${packet_w}.headers.${type}_w
    #exit
}

proc update_link_w {packet packet_w} {
    set display [dict get $packet link display]
    $display $packet ${packet_w}.headers.link_w
}

proc create_tcp_view {parent} {
    set net_w ${parent}.network_w
    grid [ttk::labelframe $net_w -text "Network Header (TCP)" -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::label ${net_w}.src -text "0"] -column 0 -row 1 -sticky we
    tooltip::tooltip ${net_w}.src "Source TCP Port"

    grid [ttk::label ${net_w}.dest -text "0xffff"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${net_w}.dest "Destination TCP Port"

    grid [ttk::label ${net_w}.seq_num -text "0xffff:ffff"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${net_w}.seq_num "Sequence Number"

    grid [ttk::label ${net_w}.ack_num -text "0x0000:0000"] -column 1 -row 3 -sticky we
    tooltip::tooltip ${net_w}.ack_num "Ack Number"

    grid [ttk::label ${net_w}.data_offset -text "0xffff"] -column 1 -row 4 -sticky we
    tooltip::tooltip ${net_w}.data_offset "Data Offset (Number of 32-bit words)"

    grid [ttk::label ${net_w}.options -text "SYN ACK"] -column 2 -row 4 -sticky we
    tooltip::tooltip ${net_w}.options "Options"

    grid [ttk::label ${net_w}.window_size -text "32768"] -column 3 -row 4 -sticky we
    tooltip::tooltip ${net_w}.window_size "Window Size"

    grid [ttk::label ${net_w}.checksum -text "0f0ab88cd"] -column 1 -row 5 -sticky we
    tooltip::tooltip ${net_w}.checksum "Checksum"

    grid [ttk::label ${net_w}.urgent_ptr -text "0"] -column 2 -row 5 -sticky we
    tooltip::tooltip ${net_w}.urgent_ptr "Urgent Pointer"

    return $net_w
}

proc create_ipv4_view {parent} {
    set trans_w ${parent}.trans_w
    grid [ttk::labelframe $trans_w -text "Transport Header (IP)" -padding "2 2 6 6"] -column 0 -row 1 -sticky nwes

    grid [ttk::label ${trans_w}.version -text "4"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${trans_w}.version "Version (4 for IPv4)"

    grid [ttk::label ${trans_w}.header_len -text "5"] -column 2 -row 1 -sticky we
    tooltip::tooltip ${trans_w}.header_len "Header Length in 32-bit words"

    grid [ttk::label ${trans_w}.tos -text "0"] -column 3 -row 1 -sticky we
    tooltip::tooltip ${trans_w}.tos "TOS Field"

    grid [ttk::label ${trans_w}.total_len -text "0xffff"] -column 4 -row 1 -sticky we
    tooltip::tooltip ${trans_w}.total_len "Total Length"

    grid [ttk::label ${trans_w}.id -text "32768"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${trans_w}.id "IPv4 Packet ID"

    grid [ttk::label ${trans_w}.flags -text "000"] -column 2 -row 2 -sticky we
    tooltip::tooltip ${trans_w}.flags "IPv4 Flags"

    grid [ttk::label ${trans_w}.fragment_offset -text "0"] -column 3 -row 2 -sticky we
    tooltip::tooltip ${trans_w}.fragment_offset "Fragment Offset"

    grid [ttk::label ${trans_w}.ttl -text "20"] -column 1 -row 3 -sticky we
    tooltip::tooltip ${trans_w}.ttl "TTL (Time to Live, decremented by 1 by each router that handles this packet)"

    grid [ttk::label ${trans_w}.protocol -text "6"] -column 2 -row 3 -sticky we
    tooltip::tooltip ${trans_w}.protocol "Protocol (6: TCP, ...)"

    grid [ttk::label ${trans_w}.checksum -text "0"] -column 3 -row 3 -sticky we
    tooltip::tooltip ${trans_w}.checksum "Checksum"

    grid [ttk::label ${trans_w}.src -text "0.0.0.0"] -column 1 -row 4 -sticky we
    tooltip::tooltip ${trans_w}.src "Source IP Address"

    grid [ttk::label ${trans_w}.dest -text "255.255.255.255"] -column 2 -row 4 -sticky we
    tooltip::tooltip ${trans_w}.dest "Destination IPv4 Address"

    return $trans_w
}

proc create_ether_encap_view {parent link_type} {
    set link_w ${parent}.link_w
    grid [ttk::labelframe $link_w -text "Data Link Header $link_type" -padding "2 2 6 6"] -column 0 -row 2 -sticky nwes

    grid [ttk::label ${link_w}.src -text "00:00:00:00:00:00"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${link_w}.src "Source MAC Address"

    grid [ttk::label ${link_w}.dest -text "ff:ff:ff:ff:ff:ff"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${link_w}.dest "Destination MAC Address"

    grid [ttk::label ${link_w}.len -text "0"] -column 1 -row 3 -sticky we
    tooltip::tooltip ${link_w}.len "Length/Type"
    return $link_w
}

proc create_app_w {parent} {
    return [create_app_w $parent]
}

proc create_net_w {parent} {
    return [create_tcp_view $parent]
}

proc create_trans_w {parent} {
    return [create_ipv4_view $parent]
}

proc create_link_w {parent link_type} {
    return [create_ether_encap_view $parent $link_type]
}

proc create_packet_w {parent datalink_type} {
    global app_info
    #TODO: may want to pass in $packetNum to have .packet$packetNum as the name of the frame below
    set tkpacket ${parent}.packet
    grid [ttk::frame ${tkpacket} -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::labelframe ${tkpacket}.app_data -text "Application Data" -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::frame ${tkpacket}.headers -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    set app_w ${tkpacket}.headers.app_header
    grid [ttk::labelframe $app_w -text "Application Header" -padding "2 2 6 6"] -column 0 -row 1 -sticky nwes

    set link_w [create_link_w ${tkpacket}.headers $datalink_type]
#    set link_w ${tkpacket}.headers.datalink_header

    set trans_w [create_trans_w ${tkpacket}.headers]

    set net_w [create_net_w ${tkpacket}.headers]

    dict set $app_info link_w $link_w
    dict set $app_info trans_w $trans_w
    dict set $app_info net_w $net_w
    return $tkpacket
}

proc create_physical_view {app_info parent} {
    global pkt_t_delta sent_count recv_count local_time
    grid [ttk::labelframe .phys -text "Status and Host Information" -padding "13 3 12 12"] -column 0 -row 1 -sticky nwes

    grid [ttk::label .phys.host -text "[dict get $app_info host]"] -column 1 -padx 10 -row 2 -sticky we
    tooltip::tooltip .phys.host "Host: IP [dict get $app_info addr] NM [dict get $app_info netmask] MAC [dict get $app_info mac_addr]"
    grid [ttk::label .phys.channel -text "[dict get $app_info pcapChannel]"] -column 2 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.channel  "PCAP Channel"
    grid [ttk::label .phys.device_type -text "[dict get $app_info datalink_type]"] -column 3 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.device_type "Link Type"
    grid [ttk::label .phys.device -text "[dict get $app_info device]"] -column 4 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.device Device
    grid [ttk::label .phys.promisc -text "[dict get $app_info promisc_string]"] -column 5 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.promisc "Promiscuous?"
    grid [ttk::label .phys.t_delta -textvariable pkt_t_delta] -column 6 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.t_delta Delta
    grid [ttk::label .phys.sent_count -textvariable sent_count] -column 7 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.sent_count Sent
    grid [ttk::label .phys.recv_count -textvariable recv_count] -column 8 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.recv_count Recv
    grid [ttk::label .phys.local_time -textvariable local_time] -column 9 -row 2 -padx 10 -sticky we
    tooltip::tooltip .phys.local_time "Local Time"
    return .phys
}

proc create_ui {} {
    global app_info
	wm title . "Tcl Terminus"
    set topframe .c

	grid [ttk::frame $topframe -padding "3 3 12 12"] -column 0 -row 0 -sticky nwes
	grid columnconfigure . 0 -weight 1
	grid rowconfigure . 0 -weight 1
    dict set app_info physical_w [create_physical_view $app_info $topframe]
    dict set app_info packet_w [create_packet_w $topframe [dict get $app_info datalink_type]]
	
    #puts "link_w: $link_w. app_info $app_info"
    #puts "keys: [dict keys $app_info]"
    #puts "dict link_w: [dict get $app_info packet_w]"
    #puts "dict phys_w: [dict get $app_info physical_w]"
	foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
}

