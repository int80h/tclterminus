package require Tcl 8.4
package require msgcat 1.3
package require tooltip

set pkt_t_delta 0
set sent_count 0
set recv_count 0
set local_time [clock format [clock seconds]]

proc calculate {} {
    if {[catch { set ::meters [expr {round($::feet*0.3048*10000.0)/10000.0}]}] != 0} {
        set ::meters ""
    }
}

proc create_ui {app_info} {
	wm title . "Tcl Terminus"
	grid [ttk::frame .c -padding "3 3 12 12"] -column 0 -row 0 -sticky nwes
	grid columnconfigure . 0 -weight 1
	grid rowconfigure . 0 -weight 1
    create_physical_status $app_info .c
	
	foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
}

proc create_physical_status {app_info parent} {
    global pkt_t_delta, sent_count, recv_count, local_time
    grid [ttk::frame .phys -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes

    grid [ttk::label .phys.host_lbl -justify center -text Host] -column 1 -row 1 -sticky we
    tooltip::tooltip .phys.host_lbl "IP [dict get $app_info addr] NM [dict get $app_info netmask] MAC [dict get $app_info mac_addr]"
    grid [ttk::label .phys.channel_lbl -justify center -text "PCAP Channel"] -column 2 -row 1 -sticky we
    grid [ttk::label .phys.device_type_lbl -justify center -text "Link Type"] -column 3 -row 1 -sticky we
    grid [ttk::label .phys.device_lbl -justify center -text Device] -column 4 -row 1 -sticky we
    grid [ttk::label .phys.promisc_lbl -justify center -text "Promiscuous?"] -column 5 -row 1 -sticky we
    grid [ttk::label .phys.t_delta_lbl -justify center -text Delta] -column 6 -row 1 -sticky we
    grid [ttk::label .phys.sent_count_lbl -justify center -text Sent] -column 7 -row 1 -sticky we
    grid [ttk::label .phys.recv_count_lbl -justify center -text Recv] -column 8 -row 1 -sticky we
    grid [ttk::label .phys.local_time_lbl -justify center -text "Local Time"] -column 9 -row 1 -sticky we

    grid [ttk::label .phys.host -text "[dict get $app_info host]"] -column 1 -row 2 -sticky we
    tooltip::tooltip .phys.host "IP [dict get $app_info addr] NM [dict get $app_info netmask] MAC [dict get $app_info mac_addr]"
    grid [ttk::label .phys.channel -text "[dict get $app_info pcapChannel]"] -column 2 -row 2 -sticky we
    grid [ttk::label .phys.device_type -text "[dict get $app_info datalink_type]"] -column 3 -row 2 -sticky we
    grid [ttk::label .phys.device -text "[dict get $app_info device]"] -column 4 -row 2 -sticky we
    grid [ttk::label .phys.promisc -text "[dict get $app_info promisc_string]"] -column 5 -row 2 -sticky we
    grid [ttk::label .phys.t_delta -textvariable pkt_t_delta] -column 6 -row 2 -sticky we
    grid [ttk::label .phys.sent_count -textvariable sent_count] -column 7 -row 2 -sticky we
    grid [ttk::label .phys.recv_count -textvariable recv_count] -column 8 -row 2 -sticky we
    grid [ttk::label .phys.local_time -textvariable local_time] -column 9 -row 2 -sticky we
}

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

