package require Tcl 8.4
package require msgcat 1.3
package require tooltip

source file.tcl 

proc create_tcp_view {parent} {
    set net_h ${parent}.network_header
    grid [ttk::labelframe $net_h -text "Network Header (TCP)" -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::label ${net_h}.src -text "0"] -column 0 -row 1 -sticky we
    tooltip::tooltip ${net_h}.src "Source TCP Port"

    grid [ttk::label ${net_h}.dest -text "0xffff"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${net_h}.dest "Destination TCP Port"

    grid [ttk::label ${net_h}.seq_num -text "0xffff:ffff"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${net_h}.seq_num "Sequence Number"

    grid [ttk::label ${net_h}.ack_num -text "0x0000:0000"] -column 1 -row 3 -sticky we
    tooltip::tooltip ${net_h}.ack_num "Ack Number"

    grid [ttk::label ${net_h}.data_offset -text "0xffff"] -column 1 -row 4 -sticky we
    tooltip::tooltip ${net_h}.data_offset "Data Offset (Number of 32-bit words)"

    grid [ttk::label ${net_h}.options -text "SYN ACK"] -column 2 -row 4 -sticky we
    tooltip::tooltip ${net_h}.options "Options"

    grid [ttk::label ${net_h}.window_size -text "32768"] -column 3 -row 4 -sticky we
    tooltip::tooltip ${net_h}.window_size "Window Size"

    grid [ttk::label ${net_h}.checksum -text "0f0ab88cd"] -column 1 -row 5 -sticky we
    tooltip::tooltip ${net_h}.checksum "Checksum"

    grid [ttk::label ${net_h}.urgent_ptr -text "0"] -column 2 -row 5 -sticky we
    tooltip::tooltip ${net_h}.urgent_ptr "Urgent Pointer"

    return $net_h
}

proc create_ipv4_view {parent} {
    set trans_h ${parent}.transport_header
    grid [ttk::labelframe $trans_h -text "Transport Header (IP)" -padding "2 2 6 6"] -column 0 -row 1 -sticky nwes

    grid [ttk::label ${trans_h}.version -text "4"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${trans_h}.version "Version (4 for IPv4)"

    grid [ttk::label ${trans_h}.header_len -text "5"] -column 2 -row 1 -sticky we
    tooltip::tooltip ${trans_h}.header_len "Header Length in 32-bit words"

    grid [ttk::label ${trans_h}.tos -text "0"] -column 3 -row 1 -sticky we
    tooltip::tooltip ${trans_h}.tos "TOS Field"

    grid [ttk::label ${trans_h}.total_len -text "0xffff"] -column 4 -row 1 -sticky we
    tooltip::tooltip ${trans_h}.total_len "Total Length"

    grid [ttk::label ${trans_h}.id -text "32768"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${trans_h}.id "IPv4 Packet ID"

    grid [ttk::label ${trans_h}.flags -text "000"] -column 2 -row 2 -sticky we
    tooltip::tooltip ${trans_h}.flags "IPv4 Flags"

    grid [ttk::label ${trans_h}.fragment_offset -text "0"] -column 3 -row 2 -sticky we
    tooltip::tooltip ${trans_h}.fragment_offset "Fragment Offset"

    grid [ttk::label ${trans_h}.ttl -text "20"] -column 1 -row 3 -sticky we
    tooltip::tooltip ${trans_h}.ttl "TTL (Time to Live, decremented by 1 by each router that handles this packet)"

    grid [ttk::label ${trans_h}.protocol -text "6"] -column 2 -row 3 -sticky we
    tooltip::tooltip ${trans_h}.protocol "Protocol (6: TCP, ...)"

    grid [ttk::label ${trans_h}.checksum -text "0"] -column 3 -row 3 -sticky we
    tooltip::tooltip ${trans_h}.checksum "Checksum"

    grid [ttk::label ${trans_h}.src -text "0.0.0.0"] -column 1 -row 4 -sticky we
    tooltip::tooltip ${trans_h}.src "Source IP Address"

    grid [ttk::label ${trans_h}.dest -text "255.255.255.255"] -column 2 -row 4 -sticky we
    tooltip::tooltip ${trans_h}.dest "Destination IPv4 Address"

    return $trans_h
}

proc create_ether_encap_view {parent link_type} {
    set link_h ${parent}.ether_header
    grid [ttk::labelframe $link_h -text "Data Link Header $link_type" -padding "2 2 6 6"] -column 0 -row 2 -sticky nwes

    grid [ttk::label ${link_h}.src -text "00:00:00:00:00:00"] -column 1 -row 1 -sticky we
    tooltip::tooltip ${link_h}.src "Source MAC Address"

    grid [ttk::label ${link_h}.dest -text "ff:ff:ff:ff:ff:ff"] -column 2 -row 1 -sticky we
    tooltip::tooltip ${link_h}.dest "Destination MAC Address"

    grid [ttk::label ${link_h}.len -text "0"] -column 1 -row 2 -sticky we
    tooltip::tooltip ${link_h}.len "Length/Type"
    return $link_h
}

proc create_app_header_view {parent} {
    return [create_app_header_view $parent]
}

proc create_net_header_view {parent} {
    return [create_tcp_view $parent]
}

proc create_transport_view {parent} {
    return [create_ipv4_view $parent]
}

proc create_datalink_view {parent link_type} {
    return [create_ether_encap_view $parent $link_type]
}

proc create_packet_view {parent datalink_type} {
    #TODO: may want to pass in $packetNum to have .packet$packetNum as the name of the frame below
    set tkpacket ${parent}.packet
    grid [ttk::frame ${tkpacket} -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::labelframe ${tkpacket}.app_data -text "Application Data" -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::frame ${tkpacket}.headers -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    set app_h ${tkpacket}.headers.app_header
    grid [ttk::labelframe $app_h -text "Application Header" -padding "2 2 6 6"] -column 0 -row 1 -sticky nwes

    set link_h [create_datalink_view ${tkpacket}.headers $datalink_type]
#    set link_h ${tkpacket}.headers.datalink_header

    set trans_h [create_transport_view ${tkpacket}.headers]

    set net_h [create_net_header_view ${tkpacket}.headers]

}

proc create_physical_view {app_info parent} {
    global pkt_t_delta sent_count recv_count local_time
    grid [ttk::labelframe .phys -text "Status and Host Information" -padding "13 3 12 12"] -column 0 -row 1 -sticky nwes

    grid [ttk::label .phys.host -text "[dict get $app_info host]"] -column 1 -row 2 -sticky we
    tooltip::tooltip .phys.host "Host: IP [dict get $app_info addr] NM [dict get $app_info netmask] MAC [dict get $app_info mac_addr]"
    grid [ttk::label .phys.channel -text "[dict get $app_info pcapChannel]"] -column 2 -row 2 -sticky we
    tooltip::tooltip .phys.channel  "PCAP Channel"
    grid [ttk::label .phys.device_type -text "[dict get $app_info datalink_type]"] -column 3 -row 2 -sticky we
    tooltip::tooltip .phys.device_type "Link Type"
    grid [ttk::label .phys.device -text "[dict get $app_info device]"] -column 4 -row 2 -sticky we
    tooltip::tooltip .phys.device Device
    grid [ttk::label .phys.promisc -text "[dict get $app_info promisc_string]"] -column 5 -row 2 -sticky we
    tooltip::tooltip .phys.promisc "Promiscuous?"
    grid [ttk::label .phys.t_delta -textvariable pkt_t_delta] -column 6 -row 2 -sticky we
    tooltip::tooltip .phys.t_delta Delta
    grid [ttk::label .phys.sent_count -textvariable sent_count] -column 7 -row 2 -sticky we
    tooltip::tooltip .phys.sent_count Sent
    grid [ttk::label .phys.recv_count -textvariable recv_count] -column 8 -row 2 -sticky we
    tooltip::tooltip .phys.recv_count Recv
    grid [ttk::label .phys.local_time -textvariable local_time] -column 9 -row 2 -sticky we
    tooltip::tooltip .phys.local_time "Local Time"
}

proc create_ui {app_info} {
	wm title . "Tcl Terminus"
    set topframe .c

	grid [ttk::frame $topframe -padding "3 3 12 12"] -column 0 -row 0 -sticky nwes
	grid columnconfigure . 0 -weight 1
	grid rowconfigure . 0 -weight 1
    create_physical_view $app_info $topframe
    create_packet_view $topframe [dict get $app_info datalink_type]
	
	foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
}

