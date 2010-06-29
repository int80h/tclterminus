set pkt_t_delta 0

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
	
	#grid [ttk::label .c.devlbl -text "Device [dict get $app_info device]"] -column 1 -row 1 -sticky we
	#grid [ttk::label .c.pcapchanlbl -text "Channel [dict get $app_info pcapChannel]"] -column 2 -row 1 -sticky we
	#grid [ttk::label .c.addr -text "addr [lindex [dict get $app_info addrlist] 0]"] -column 1 -row 2 -sticky we
	#grid [ttk::label .c.netmask -text "netmask [lindex [dict get $app_info addrlist] 1]"] -column 2 -row 2 -sticky we
	#grid [ttk::label .c.filterlbl -text "Filter:"] -column 1 -row 3 -sticky we
	#grid [ttk::combobox .c.filterentry -width 7 -textvariable filter] -column 2 -row 3 -sticky we
	#grid [ttk::button .c.calc -text "calculate" -command calculate] -column 3 -row 3 -sticky w
	
	foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
	#focus .c.filterentry
}

proc create_physical_status {app_info} {
    global pkt_t_delta
    grid [ttk::frame .phys -padding "2 2 6 6"] -column 0 -row 0 -sticky nwes
    grid [ttk::label .phys.host -text "[dict get $app_info host]"] -column 1 -row 1 -sticky we
    grid [ttk::label .phys.channel -text "[dict get $app_info pcapChannel]"] -column 2 -row 1 -sticky we
    grid [ttk::label .phys.device_type -text "[dict get $app_info datalink_type]"] -column 3 -row 1 -sticky we
    grid [ttk::label .phys.device -text "[dict get $app_info device]"] -column 4 -row 1 -sticky we
    grid [ttk::label .phys.promisc -text "[dict get $app_info device]"] -column 4 -row 1 -sticky we
    grid [ttk::label .phys.t_delta -textvariable pkt_t_delta] -column 4 -row 1 -sticky we
}

proc open_default_device {} {
    set promisc 0
    if [$promisc == 0] {
        set $promisc_string "-nopromisc"
    } else {
        set $promisc_string "-promisc"
    }

	set device [pcap::lookupdev]
	set pcapChannel [pcap::pcap_open $promisc_string -filter "tcp" $device]
	set datalink_type [pcap::datalink $pcapChannel]
	if {[lindex $datalink_type 0] != "DLT_EN10MB"} {
	    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
	    exit
	}
	set addrlist [pcap::lookupnet $device]
	
	dict set app_info device $device
	dict set app_info datalink_type $datalink_type
	dict set app_info pcapChannel $pcapChannel
	dict set app_info addrlist $addrlist
	
	fconfigure $pcapChannel -blocking 0 -translation binary
    return $app_info
}

