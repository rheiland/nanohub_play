#
# @package      hubzero-filexfer
# @file         utils.tcl
# @copyright    Copyright (c) 2004-2020 The Regents of the University of California.
# @license      http://opensource.org/licenses/MIT MIT
#
# Copyright (c) 2004-2020 The Regents of the University of California.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# HUBzero is a registered trademark of The Regents of the University of California.
#

# ----------------------------------------------------------------------
#  FILEXFER UTILITIES
#
#  This file contains utility procedures that are used across the
#  server.tcl and its clients.

namespace eval filexfer {
    variable installdir [file dirname [file normalize [info script]]]
}

# ----------------------------------------------------------------------
#  USAGE: filexfer::connect <port> <handler>
#
#  Used internally to create a connection to the filexfer server.
#  Returns the file descriptor for the socket connection.  Sets up
#  the connection so that if a message comes back from the server,
#  it is handled by the <handler> proc.
# ----------------------------------------------------------------------
proc filexfer::connect {port callback} {
    variable installdir

    if {[catch {socket "127.0.0.1" $port} sid] == 0} {
        fconfigure $sid -buffering line
        fileevent $sid readable [list server_mesg $sid]
        return $sid
    }

    # oops! have to spawn the server...
    exec nohup /usr/bin/tclsh [file join $installdir server.tcl] > /dev/null 2> /dev/null &

    for {set tries 10} {$tries > 0} {incr tries -1} {
        after 1000  ;# wait a minute for new server to start

        if {[catch {socket "127.0.0.1" $port} sid] == 0} {
            fconfigure $sid -buffering line
            fileevent $sid readable [list server_mesg $sid]
            return $sid
        }
    }
    error "tried to spawn server, but it doesn't respond"
}

# ----------------------------------------------------------------------
# RESOURCE LOADING
# ----------------------------------------------------------------------
namespace eval filexfer {
    #
    # Set up a safe interpreter for loading filexfer options...
    #
    variable optionParser [interp create -safe]
    foreach cmd [$optionParser eval {info commands}] {
        $optionParser hide $cmd
    }
    # this lets us ignore unrecognized commands in the file:
    $optionParser invokehidden proc unknown {args} {}

    foreach {name proc} {
        filexfer_port filexfer::set_filexfer_port
        filexfer_cookie filexfer::set_filexfer_cookie
        hub_name filexfer::set_hub_name
        session_token filexfer::set_session_token
        hub_template filexfer::set_hub_template
    } {
        $optionParser alias $name $proc
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::resources
#
# Loads a list of resources from the $SESSIONDIR/resources file
# and returns a list of the form {key1 value1 key2 value2 ...}
# for all resources related to filexfer.
# ----------------------------------------------------------------------
proc filexfer::resources {} {
    global env
    variable resources
    variable optionParser

    if {![info exists env(SESSIONDIR)]} {
        error "\$SESSIONDIR undefined"
    }
    set rfile [file join $env(SESSIONDIR) resources]
    if {![file exists $rfile]} {
        error "file $rfile not found"
    }

    set fid [open $rfile r]
    set rinfo [read $fid]
    close $fid

    catch {unset resources}
    $optionParser eval $rinfo

    return [array get resources]
}

# ----------------------------------------------------------------------
# RESOURCE: filexfer_port
# ----------------------------------------------------------------------
proc filexfer::set_filexfer_port {port} {
    variable resources

    if {![string is integer $port]} {
        error "bad value \"$port\" for filexfer_port: should be integer"
    }
    set resources(port) $port
}

# ----------------------------------------------------------------------
# RESOURCE: filexfer_cookie
# ----------------------------------------------------------------------
proc filexfer::set_filexfer_cookie {cookie} {
    variable resources
    set resources(cookie) $cookie
}

# ----------------------------------------------------------------------
# RESOURCE: hub_name
# ----------------------------------------------------------------------
proc filexfer::set_hub_name {text} {
    variable resources
    set resources(hubname) $text
}

proc filexfer::set_hub_template {text} {
    variable resources
    set resources(hubtemplate) $text
}

# ----------------------------------------------------------------------
# RESOURCE: session_token
# ----------------------------------------------------------------------
proc filexfer::set_session_token {text} {
    variable resources
    set resources(session) $text
}

