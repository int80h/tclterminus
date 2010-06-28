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
	
	grid [ttk::label .c.devlbl -text "Device [dict get $app_info device]"] -column 1 -row 1 -sticky we
	grid [ttk::label .c.pcapchanlbl -text "Channel [dict get $app_info pcapChannel]"] -column 2 -row 1 -sticky we
	grid [ttk::label .c.addr -text "addr [lindex [dict get $app_info addrlist] 0]"] -column 1 -row 2 -sticky we
	grid [ttk::label .c.netmask -text "netmask [lindex [dict get $app_info addrlist] 1]"] -column 2 -row 2 -sticky we
	grid [ttk::label .c.filterlbl -text "Filter:"] -column 1 -row 3 -sticky we
	grid [ttk::combobox .c.filterentry -width 7 -textvariable filter] -column 2 -row 3 -sticky we
	#grid [ttk::button .c.calc -text "calculate" -command calculate] -column 3 -row 3 -sticky w
	
	foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
	focus .c.filterentry
}


