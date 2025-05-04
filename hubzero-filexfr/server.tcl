#
# @package      hubzero-filexfer
# @file         server.tcl
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
#  FILEXFER SERVER - support for file transfer with user's desktop
#
#  This is the server that manages filexfer operations for the
#  "exportfile" and "importfile" client commands.  Clients communicate
#  with the server via a socket and send along a series of file
#  transfer requests.  The server then dispatches "open url" requests
#  to one or more viewers in the user's web browser.

package require Tclx

# load util procedures from this path
set installdir [file dirname [info script]]
if {"." == $installdir} {
    set installdir [pwd]
}
lappend auto_path $installdir

# Fork here and run the rest as a background daemon so the parent who
# launches it the first time doesn't have to wait for this to finish.

proc daemonize {} {
    close stdin
    close stdout
    close stderr

    if {[fork]} { exit 0 }

    set pid2 [id process]

    id process group set

    if {[fork]} { exit 0 }

    # @TODO: This shouldn't be necessary
    catch { kill $pid2 }

    set fd [open /dev/null r]
    set fd [open /dev/null w]
    set fd [open /dev/null w]

    cd /
    umask 022

    return [id process]
}

#daemonize

namespace eval filexfer {
    variable fxport 0           ;# server is running on this port
    variable fxcookie ""        ;# magic cookie used to auth clients
    variable buffer             ;# request buffer for each client
    variable address            ;# incoming address for each client
    variable downloads          ;# array of all known download tokens
    variable downloadInfo       ;# maps download token => file, timeout, etc.
    variable uploads            ;# maps upload token => interested client
    variable countdown ""       ;# countdown to auto-shutdown
    variable log ""             ;# handle to log file for debug messages
    variable fileprog ""        ;# std "file" program for MIME types
    variable unique 0           ;# unique counter for /tmp files

    variable cookieChars {
        a b c d e f g h i j k l m n o p q r s t u v w x y z
        A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
        0 1 2 3 4 5 6 7 8 9
    }

    # keeps track of active clients
    variable clients

    variable clientaction ""
    foreach clientaction {
          /usr/bin/clientaction
          /usr/lib/hubzero/bin/clientaction
          /usr/lib/mw/bin/clientaction
          clientaction
          /apps/bin/clientaction
          /apps/xvnc/bin/clientaction
          ""
    } {
        if {"" != [auto_execok $clientaction]} {
            break
        }
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::init <port> <cookie>
#
# Called in the main application to start listening to a particular
# port and start acting like a filexfer server.
# ----------------------------------------------------------------------
proc filexfer::init {port cookie} {
    variable fxport
    variable fxcookie
    variable clients

    #
    # The port setting should have been set properly in the
    # "resources" file loaded at the beginning of the app.
    # If it wasn't, then don't do any filexfer.
    #
    if {$port > 0} {
        #
        # If the prescribed port is busy, then exit with a special
        # status code so the middleware knows to try again with another
        # port.
        #
        # OH NO! THE DREADED ERROR CODE 9!
        #
        if {[catch {socket -server filexfer::accept $port}]} {
            filexfer::log "init: port $port busy"
            exit 9
        }
        set fxport $port
        set fxcookie $cookie

        #
        # Clean up all files marked for deletion when this program
        # shuts down.  If we're running in a Hubzero tool session we'll get a
        # SIGHUP signal when it's time to quit.  We should also
        # catch SIGINT in case this gets killed dead. SIGKILL
        # can't be caught.
        signal trap SIGHUP  filexfer::sighup_handler
        signal trap SIGINT filexfer::sigint_handler

        #
        # Kick off the housekeeping option that will check all
        # timeouts and clean up files that are no longer needed.
        #
        filexfer::housekeeping
    }
}

proc filexfer::sighup_handler {} {
    filexfer::cleanup
    exit
}

proc filexfer::sigint_handler {} {
    filexfer::cleanup
    exit
}

# ----------------------------------------------------------------------
# USAGE: filexfer::trigger <token>
#
# Used internally to trigger the download of the file associated
# with <token>.  Sends a message to all clients connected to this
# server telling them to fetch the URL for the file.
# ----------------------------------------------------------------------
proc filexfer::trigger {token} {
    variable resources
    variable fxcookie
    variable downloadInfo
    variable clientaction

    set tail [file tail $downloadInfo($token-file)]
    regsub -all {\?\&\;} $tail "" tail  ;# get rid of confusing chars

    set path [format "/filexfer/%s/download/%s?token=%s" \
        $fxcookie $tail $token]
    if {[catch {exec $clientaction url $path} result]} {
        filexfer::log "$clientaction url $path"
        filexfer::log "failed: $result"
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::cleanup ?<token> <token> ...?
#
# Used to clean up one or more tokens, which represent files being
# kept for download.  Forgets all information associated with each
# token.  If the file was marked for deletion, then it is deleted
# at this time.
#
# Note that if this procedure is called with no tokens, then it cleans
# up all tokens.  This is useful, for example, when the server is
# being killed by a SIGHUP.
# ----------------------------------------------------------------------
proc filexfer::cleanup {args} {
    variable downloads
    variable downloadInfo

    # no specific tokens?  then clean up all tokens
    if {[llength $args] == 0} {
        set args [array names downloads]
    }

    # run through all tokens and clean them up
    foreach t $args {
        if {$downloadInfo($t-delete)} {
            catch {file delete -force $downloadInfo($t-file)}
        }
        foreach tag [array names downloadInfo $t-*] {
            unset downloadInfo($tag)
        }
        unset downloads($t)
#       filexfer::log "cleaned up $t"
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::accept <clientId> <address> <port>
#
# Invoked automatically whenever a client tries to connect to this
# server.  Sets up callbacks to handle further communication.
# ----------------------------------------------------------------------
proc filexfer::accept {cid addr port} {
#   filexfer::log "accepting $port $cid on $addr"
    fileevent $cid readable [list filexfer::handler $cid]
    #
    # Use binary mode for both input and output, so the
    # byte counts (as in Content-Length:) are correct.
    #
    fconfigure $cid -buffering line -translation binary

    # we accept clients from any where, but only let them
    # speak FILEXFER protocol when they come from 127.0.0.1 [localhost]
    variable address
    set address($cid) $addr
#   filexfer::log "accepted client $cid on $addr"
}

# ----------------------------------------------------------------------
# USAGE: filexfer::handler <clientId>
#
# Invoked automatically whenever a message comes in from a client
# to handle the message.
# ----------------------------------------------------------------------
proc filexfer::handler {cid} {
    variable buffer

    if {[gets $cid line] < 0} {
        # eof from client -- clean up
        shutdown $cid
    } else {
        # clip out trailing carriage returns
        regsub -all {\r$} $line "" line

        #
        # Is the first line of the request?  Then make sure
        # that it's properly formed.
        #
        if {![info exists buffer($cid)]
               && [regexp {^ *[A-Z]+ +[^ ]+ +HTTP/1\.[01]$} $line]} {
            set buffer($cid) $line
            return   ;# wait for more lines to dribble in...
        } elseif {[info exists buffer($cid)]} {
            set line [string trim $line]
            if {"" == $line} {
                regexp {^ *([A-Z]+) +} $buffer($cid) match type
                if {$type == "POST"} {
                    if {[regexp {Content-Length: *([0-9]+)} $buffer($cid) match len]} {
                        set buffer($cid-postfile) [tmpfile]
                        set fid [open $buffer($cid-postfile) w]
                        fconfigure $fid -translation binary -encoding binary

                        # uploaded file may be huge -- read in chunks
                        # store in /tmp
                        set chunksize 1000000
                        while {$len > 0} {
                            if {$len > $chunksize} {
                                set chunk $chunksize
                                set len [expr {$len-$chunksize}]
                            } else {
                                set chunk $len
                                set len 0
                            }
                            set str [read $cid $chunk]
                            catch {puts -nonewline $fid $str}
                        }
                        close $fid
                    }
                    # finished post... process below...
                } else {
                    # finished get or other op... process below...
                }
            } else {
                append buffer($cid) "\n" $line
                return
            }
            # blank line -- process below...
        } elseif {[regexp { +(RAPPTURE|FILEXFER)(/[0-9\.]+)?$} $line]} {
            set buffer($cid) $line
            # special Filexfer request -- process below...
        } else {
            response $cid error -message "Your browser sent a request that this server could not understand.<P>Malformed request: $line"
            shutdown $cid
            return
        }

        #
        # We've seen a blank line at the end of a request.
        # Time to process it...
        #
        set errmsg ""
        set lines [split $buffer($cid) \n]
        unset buffer($cid)
        set headers(Connection) close

        # extract the TYPE and URL from the request line
        set line [lindex $lines 0]
        set lines [lrange $lines 1 end]
#       filexfer::log "REQUEST: $line"

        if {![regexp {^ *([A-Z]+) +([^ ]+) +(HTTP/1\.[01])$} $line \
              match type url proto]
            && ![regexp { +((RAPPTURE|FILEXFER)(/[0-9\.]+)?)$} $line match proto]} {
            set errmsg "Malformed request: $line"
        }

        if {[string match HTTP/* $proto]} {
            #
            # HANDLE HTTP/1.x REQUESTS...
            #
            while {"" == $errmsg && [llength $lines] > 0} {
                # extract the "Header: value" lines
                set line [lindex $lines 0]
                set lines [lrange $lines 1 end]

                if {[regexp {^ *([-a-zA-Z0-9_]+): *(.*)} $line \
                      match key val]} {
                    set headers($key) $val
                } else {
                    set errmsg [format "Request header field is missing colon separator.<P>\n<PRE>\n%s</PRE>" $line]
                }
            }

            if {"" != $errmsg} {
                # errors in the header
                response $cid header -status "400 Bad Request" \
                    -connection $headers(Connection)
                response $cid error -message "Your browser sent a request that this server could not understand.<P>$errmsg"
                flush $cid
            } else {
                # process the request...
                switch -- $type {
                    GET {
                        request_GET $cid $url headers
                    }
                    POST {
                        set postfile ""
                        if {[info exists buffer($cid-postfile)]} {
                            set postfile $buffer($cid-postfile)
                            unset buffer($cid-postfile)
                        }

                        request_POST $cid $url headers $postfile

                        # clean up the tmp file with POST data
                        if {[file exists $postfile]} {
                            catch {file delete $postfile}
                        }
                    }
                    default {
                        response $cid header \
                            -status "400 Bad Request" \
                            -connection $headers(Connection)
                        response $cid error -message "Your browser sent a request that this server could not understand.<P>Invalid request type <b>$type</b>"
                        flush $cid
                    }
                }
            }
        } elseif {[string match FILEXFER* $proto]} {
            #
            # HANDLE REQUESTS FROM exportfile/importfile CLIENTS...
            #
            if {[regexp {^ *EXPORT +(.+) ([^ ]+) +FILEXFER(/[0-9\.]+)?$} \
                  $line match args token vers]} {
                request_EXPORT $cid $args $token $vers
            } elseif {[regexp {^ *IMPORT +(.+) ([^ ]+) +FILEXFER(/[0-9\.]+)?$} \
                  $line match template token vers]} {
                request_IMPORT $cid $template $token
            } elseif {[regexp {^ *BYE +([^ ]+) +FILEXFER(/[0-9\.]+)?$} \
                  $line match token vers]} {
                request_BYE $cid $token
            }
        }
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::request_GET <clientId> <url> <headerVar>
#
# Used internally to handle GET requests on this server.  Looks for
# the requested <url> and sends it back to <clientId> according to
# the headers in the <headerVar> array in the calling scope.
# ----------------------------------------------------------------------
proc filexfer::request_GET {cid url headerVar} {
    global env
    variable downloads
    variable downloadInfo
    upvar $headerVar headers

    # we're busy -- no auto-shutdown
    countdown cancel

    # hold off closing the connection if we're still downloading
    set stilldownloading 0

    #
    # Look for any ?foo=1&bar=2 data embedded in the URL...
    #
    if {[regexp -indices {\?[a-zA-Z0-9_]+\=} $url match]} {
        foreach {s0 s1} $match break
        set args [string range $url [expr {$s0+1}] end]
        set url [string range $url 0 [expr {$s0-1}]]

        foreach part [split $args &] {
            if {[llength [split $part =]] == 2} {
                foreach {key val} [split $part =] break
                set post($key) [urlDecode $val]
            }
        }
    }

    #
    # Interpret the URL and fulfill the request...
    #
    if {[regexp {^(/filexfer/[0-9a-fA-F]+)?/?download/} $url]} {
        # NOTE: ^^^ /filexfer/xxxxxx part comes through only when using
        #       the deprecated filexfer clients, who post directly to
        #       this client without appropriate firewall transit.
        #
        # Send back an exported file...
        #
        if {![info exists post(token)]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  Missing file token."
        } elseif {![info exists downloads($post(token))]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  File token not recognized.  Perhaps the download took too long and the file has been forgotten.  Try your download again."
        } else {
            set t $post(token)

            #
            # If we have a special message for the top of the page,
            # send along a wrapper with internal frames.
            #
            if {[llength $downloadInfo($t-dlpage)] > 0} {
                variable fxcookie
                set ftail [file tail $downloadInfo($t-file)]
                set wrapper [format {<html><frameset id="container" rows="400,100%%"><frame src="/filexfer/%s/dltop/?token=%s"><frame name="file" src="/filexfer/%s/dlfile/%s?token=%s"></frameset><noframes>Oops!  Your browser doesn't handle frames.  <a href="/filexfer/%s/dlfile/%s?token=%s">Click here</a> to download your file.</noframes></html>} $fxcookie $t $fxcookie $ftail $t $fxcookie $ftail $t]
                response $cid header -status "200 OK"
                response $cid body \
                    -string $wrapper -type text/html

            } elseif {$downloadInfo($t-format) == "html"} {
                #
                # If the format is "html", then treat the body as
                # HTML data.  Be careful to rewrite any embedded
                # paths, so that images can be downloaded and links
                # can be traversed with respect to the original file.
                #

            } else {
                #
                # Otherwise, send the raw file itself.
                #
                response $cid file \
                    -path $downloadInfo($t-file) \
                    -connection $headers(Connection)
                set stilldownloading 1
            }
        }
    } elseif {[regexp {^(/filexfer/[0-9a-fA-F]+)?/?dlfile/} $url]} {
        # NOTE: ^^^ /filexfer/xxxxxx part comes through only when using
        #       the deprecated filexfer clients, who post directly to
        #       this client without appropriate firewall transit.
        #
        # Send back an exported file...
        #
        if {![info exists post(token)]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  Missing file token."
        } elseif {![info exists downloads($post(token))]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  File token not recognized.  Perhaps the download took too long and the file has been forgotten.  Try your download again."
        } else {
            set t $post(token)
            if {[info exists post(saveas)]} {
                set saveas $post(saveas)
            } else {
                set saveas 0
            }

            if {$downloadInfo($t-format) == "html"
                  && [regexp {^(/filexfer/[0-9a-fA-F]+)?/?dlfile/(.+)} $url match dummy tail]} {
                set dir [file dirname $downloadInfo($t-file)]
                foreach {mime type} [filexfer::mimetype [file join $dir $tail]] break
                filexfer::log "translating HTML within: $tail ($mime $type)"
                if {$mime == "text/html"} {
                    if {[catch {filexfer::loadHTML $t $dir $tail} result]} {
                        filexfer::log "error loading HTML: $result"
                        response $cid header \
                            -status "500 Internal Server Error" \
                            -connection $params(-connection)
                        response $cid error -status "500 Internal Server Error" -message "error while processing HTML file: $result"
                    } else {
                        response $cid header -status "200 OK"
                        response $cid body \
                            -string $result -type text/html
                    }
                } else {
                    response $cid file \
                        -path [file join $dir $tail] \
                        -connection $headers(Connection)
                    set stilldownloading 1
                }
            } else {
                response $cid file \
                    -path $downloadInfo($t-file) \
                    -connection $headers(Connection) \
                    -saveas $saveas
                set stilldownloading 1
            }
        }
    } elseif {[regexp {^(/filexfer/[0-9a-fA-F]+)?/?dltop/} $url]} {
        # NOTE: ^^^ /filexfer/xxxxxx part comes through only when using
        #       the deprecated filexfer clients, who post directly to
        #       this client without appropriate firewall transit.
        #
        # Send back the heading for the download page...
        #
        if {![info exists post(token)]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  Missing file token."
        } elseif {![info exists downloads($post(token))]} {
            response $cid header -status "401 Unauthorized"
            response $cid error -status "401 Unauthorized" -message "You do not have the proper credentials to access file $post(token).  File token not recognized.  Perhaps the download took too long and the file has been forgotten.  Try your download again."
        } else {
            set t $post(token)

            set cmds {
                global installdir
                set fid [open [file join $installdir download.html] r]
                set html [read $fid]
                close $fid

                array set replacements $downloadInfo($t-dlpage)
                variable fxcookie
                set replacements(@PREFIX@) /filexfer/$fxcookie
                set replacements(@TOKEN@) $t
                set replacements(@FILE@) [file tail $downloadInfo($t-file)]
                if {![info exists replacements(@MESSAGE@)]} {
                    set replacements(@MESSAGE@) ""
                } elseif {[string length $replacements(@MESSAGE@)] > 0} {
                    set replacements(@MESSAGE@) "<p id=\"description\">$replacements(@MESSAGE@)</p>"
                }

                # If the file is binary, then add a warning to the
                # user about the blank area they'll see where the
                # document normally sits.
                set replacements(@WARNING@) ""
                foreach {mime type} [filexfer::mimetype $downloadInfo($t-file)] break
                if {$type == "binary" && ![string match image/* $mime]} {
                    set replacements(@WARNING@) "<p id=\"warning\">This type of file may not appear in the preview area below.  Your browser may decide to save it directly to your desktop.</p>"
                }

                # replace the embedded message first, in case it has
                # other @STRING@ strings embedded within it.
                set html [string map \
                    [list @MESSAGE@ $replacements(@MESSAGE@)] $html]

                set html [string map [array get replacements] $html]
            }
            if {[catch $cmds result]} {
                filexfer::log "can't create download wrapper: $result"
                response $cid header \
                    -status "500 Internal Server Error" \
                    -connection $params(-connection)
                response $cid error -status "500 Internal Server Error" -message "can't create download heading: $result"
            } else {
                response $cid header -status "200 OK" \
                    -connection $headers(Connection)
                response $cid body -string $html -type text/html
            }
        }
    } else {
        #
        # BAD FILE REQUEST:
        #   The user is trying to ask for a file outside of
        #   the normal filexfer installation.  Treat it the
        #   same as file not found.
        response $cid header \
            -status "404 Not Found" \
            -connection $headers(Connection)
        response $cid error -status "404 Not Found" -message "The requested URL $url was not found on this server."
    }

    flush $cid
    if {$headers(Connection) == "close" && !$stilldownloading} {
        shutdown $cid
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::request_POST <clientId> <url> \
#          <headerVar> <postfile>
#
# Used internally to handle POST requests on this server.  Looks for
# the requested <url> and sends it back to <clientId> according to
# the headers in the <headerVar> array in the calling scope.
# ----------------------------------------------------------------------
proc filexfer::request_POST {cid url headerVar postFile} {
    global env
    variable uploads
    upvar $headerVar headers
    set post(ALL) ""

    # we're busy -- no auto-shutdown
    countdown cancel

    #
    # Look for any ?foo=1&bar=2 data embedded in the URL...
    #
    if {[regexp -indices {\?[a-zA-Z0-9_]+\=} $url match]} {
        foreach {s0 s1} $match break
        set args [string range $url [expr {$s0+1}] end]
        set url [string range $url 0 [expr {$s0-1}]]

        foreach part [split $args &] {
            if {[llength [split $part =]] == 2} {
                foreach {key val} [split $part =] break
                lappend post(ALL) $key
                set post($key-type) "string"
                set post($key-data) [urlDecode $val]
            }
        }
    } elseif {[string length $postFile] > 0} {
        #
        # If we have explicit POST data, then it is one of two
        # kinds.  It is either key=value&key=value&... or a
        # multipart key/value assignment with -------boundary
        # separators.
        #
        set part "single"
        if {[info exists headers(Content-Type)]} {
            set data $headers(Content-Type)
            regsub -all { *; *} $data "\n" data
            set type [lindex [split $data \n] 0]
            if {$type == "multipart/form-data"} {
                set part "multi"
                foreach assmt [lrange [split $data \n] 1 end] {
                    foreach {key val} [split $assmt =] break
                    if {$key == "boundary"} {
                        set boundary [string trimleft $val -]
                    }
                }
            }
        }

        switch -- $part {
            single {
                # simple key=value&key=value&... case
                # data is small, so suck it all up at once and process
                set fid [open $postFile r]
                set postData [read $fid]
                close $fid

                foreach assmt [split $postData &] {
                    if {[regexp {([^=]+)=(.*)} $assmt match key val]} {
                        set post($key) [urlDecode $val]
                    }
                }
            }
            multi {
                #
                # Multipart data:
                #  ----------------------------406765868666254505654602083
                #  Content-Disposition: form-data; name="key"
                #
                #  value
                #  ----------------------------406765868666254505654602083
                #  ...
                #
                set fid [open $postFile r]
                fconfigure $fid -translation binary -encoding binary

                set mode "searching"
                set formname "???"
                set chunksize 1000000
                set chunk [read $fid $chunksize]

                while {[string length $chunk] > 0} {
                  switch -- $mode {
                    searching {
                        if {[regexp -indices "(^|\r?\n)-+$boundary\r?\n" \
                               $chunk match]} {
                            foreach {b0 b1} $match break
                            set chunk [string range $chunk [expr {$b1+1}] end]
                            append chunk [read $fid $chunksize]
                            set mode "header"
                            catch {unset element}
                            continue
                        }
                        if {![eof $fid]} {
                            set chunk [read $fid $chunksize]
                        } else {
                            set chunk ""
                        }
                        continue
                    }
                    header {
                        if {[regexp -indices {^([-+A-Za-z0-9_]+): +([^\r\n]+)\r?\n} $chunk match token arglist]} {
                            # found a header line like...
                            # Content-Disposition: form-data; name="file1"
                            foreach {t0 t1} $token break
                            set token [string range $chunk $t0 $t1]
                            foreach {a0 a1} $arglist break
                            set arglist [string range $chunk $a0 $a1]

                            switch -- $token {
                              Content-Disposition {
                                regsub -all { *; *} $arglist "\n" arglist
                                foreach assmt [lrange [split $arglist \n] 1 end] {
                                  foreach {key val} [split $assmt =] break
                                  set element($key) [string trim $val \"]
                                }
                              }
                              Content-Type {
                                regsub -all { *; *} $arglist "\n" arglist
                                set element(mime) [lindex [split $arglist \n] 0]
                              }
                            }

                            # continue processing more headers after this line
                            foreach {s0 s1} $match break
                            set chunk [string range $chunk [expr {$s1+1}] end]
                            if {[string length $chunk] < 1024} {
                                # chunk is getting small -- add more
                                append chunk [read $fid $chunksize]
                            }
                            continue

                        } elseif {[regexp -indices {^\r?\n} $chunk match]} {
                            # found a blank line -- start saving content

                            set mode "content"
                            foreach {s0 s1} $match break
                            set chunk [string range $chunk [expr {$s1+1}] end]
                            append chunk [read $fid $chunksize]

                            if {[info exists element(name)]} {
                                set formname $element(name)
                                lappend post(ALL) $formname
                            } else {
                                set formname "???"
                            }
                            set post($formname-type) "empty"
                            set post($formname-data) ""
                            set post($formname-format) "ascii"

                            if {[info exists element(filename)]} {
                                set post($formname-filename) $element(filename)
                            }
                            if {[info exists element(mime)]} {
                                set post($formname-mime) $element(mime)
                            }

                            continue
                        } else {
                            filexfer::log "couldn't parse header line: \"[string range $chunk 0 60]\""
                            break
                        }
                    }
                    content {
                        set str ""
                        if {[regexp -indices "(^|\r?\n)-+${boundary}(\r?\n|--)" $chunk match]} {
                            foreach {s0 s1} $match break
                            set str [string range $chunk 0 [expr {$s0-1}]]

                            # found bottom boundary -- search for next part
                            set chunk [string range $chunk [expr {$s1+1}] end]
                            set mode "header"
                            catch {unset element}
                        } else {
                            if {[string length $chunk] > $chunksize} {
                                set s0 [expr {[string length $chunk]-1024}]
                                set str [string range $chunk 0 $s0]
                                set chunk [string range $chunk [expr {$s0+1}] end]
                            }
                        }

                        # add the latest string chunk to the post data
                        if {$post($formname-type) == "empty"} {
                            if {[string length $str] > 8096} {
                                # big string -- save in a tmp file
                                set post($formname-type) "file"
                                set post($formname-data) [tmpfile]
                            } else {
                                # small string -- keep in memory
                                set post($formname-type) "string"
                            }
                        }

                        # see if this is ascii or binary data
                        if {$post($formname-format) == "ascii"
                              && [isbinary $str]} {
                            set post($formname-format) "binary"
                        }

                        switch -- $post($formname-type) {
                            file {
                                set f [open $post($formname-data) a]
                                fconfigure $f -translation binary -encoding binary
                                puts -nonewline $f $str
                                close $f
                            }
                            string {
                                append post($formname-data) $str
                            }
                            default {
                                filexfer::log "unknown form element data type \"$post($formname-type)\" for $formname"
                                break
                            }
                        }

                        # nothing more to read? then something went wrong
                        if {$mode == "content" && [eof $fid]} {
                            filexfer::log "couldn't find bottom boundary for form element $formname"
                            break
                        }
                        append chunk [read $fid $chunksize]
                        continue
                    }
                  }
                }
                close $fid
            }
            default {
                filexfer::log "unknown content type \"$part\": should be single or multi"
            }
        }
    }

    #
    # Interpret the URL and fulfill the request...
    #
    if {[regexp {^(/filexfer/[0-9a-fA-F]+)?/upload$} $url]} {
        set cname [getPostVar post client]
        if {[info exists uploads($cname)]} {

            set client $uploads($cname)
            set saved ""

            set i 1
            while {[set which [getPostVar post which$i]] != ""} {
                # figure out the MIME type and the translation mode
                set mtype "text/plain"
                if {[info exists post($which-mime)]} {
                    set mtype $post($which-mime)
                }
                set mode [getPostVar post mode$i "auto"]
                if {$mode == "auto"} {
                    if {[string match text/* $mtype]
                          && $post($which-format) == "ascii"} {
                        set mode "ascii"
                    } else {
                        set mode "binary"
                    }
                }
#               filexfer::log "translation mode $mode for $which = $mtype"

                # figure out the name for this new file
                set newfile [getPostVar post dest$i]
                if {[file tail $newfile] == "@USE_REMOTE@"} {
                    set dir [file dirname $newfile]
                    if {[info exists post($which-filename)]} {
                        set newfile [file join $dir $post($which-filename)]
                    } else {
                        set newfile [file join $dir "file$i"]
                    }
                }

                # save the content in the file
                switch -- $post($which-type) {
                    file {
                        set fname $post($which-data)
                        if {$mode == "ascii"} {
                            filexfer::log "translated newlines in $fname for $which"
                            set fname2 [xlateNewlinesInFile $fname]
                            file delete -force $fname
                            set post($which-data) $fname2
                            set fname $fname2
                        }

                        set fsize [getPostVar post fsize$i]
                        set cksum [getPostVar post cksum$i]

                        set cmds {file rename -force $fname $newfile}

                        if {$cksum > 0} {
                            filexfer::log "source md5sum $fname $cksum"
                            if {[catch {exec md5sum $fname} result]} {
                                filexfer::log "md5sum $fname"
                                filexfer::log "failed: $result"
                                set cmds {file delete -force $fname}
                            } else {
                                foreach {hostCksum hostFilename} $result break
                                if {$hostCksum != $cksum} {
                                    filexfer::log "Checksums do not match $hostFilename  $cksum  $hostCksum"
                                    set cmds {file delete -force $fname}
                                }
                            }
                        }
                    }
                    string {
                        set data $post($which-data)
                        if {[string length $data] == 0} {
                            filexfer::log "no file specified for $which -- skipping"
                            incr i
                            continue
                        }

                        set fsize [getPostVar post fsize$i]
                        set cksum [getPostVar post cksum$i]

                        if {$mode == "ascii"} {
                            # for ascii data, map Windows newlines => Linux
                            filexfer::log "translated newlines for $which"
                            regsub -all "\r\n" $data "\n" data
                        }

                        set textFile [tmpfile]
                        set fid [open $textFile w]
                        fconfigure $fid -translation binary -encoding binary
                        puts -nonewline $fid $data
                        close $fid

                        set cmds {file rename -force $textFile $newfile}

                        if {$cksum > 0} {
                            filexfer::log "source md5sum $cksum"
                            if {[catch {exec md5sum $textFile} result]} {
                                filexfer::log "md5sum $textFile"
                                filexfer::log "failed: $result"
                                set cmds {file delete -force $textFile}
                            } else {
                                foreach {hostCksum hostFilename} $result break
                                if {$hostCksum != $cksum} {
                                    filexfer::log "Checksums do not match $hostFilename  $cksum  $hostCksum"
                                    set cmds {file delete -force $textFile}
                                }
                            }
                        }
                    }
                    default {
                        set cmds {error "form element $which is not file/string"}
                    }
                }
                if {[catch $cmds result]} {
                    catch {
                      filexfer::log "problem saving data: $result"
                      puts $client [list ERROR "problem saving data to $newfile: $result"]
                      flush $client
                    }
                } else {
                    set rec [list $newfile]
                    if {[info exists post($which-filename)]} {
                        lappend rec -filename $post($which-filename)
                    }
                    lappend saved $rec
                    filexfer::log "imported: $rec"
                }
                incr i
            }
            catch {
                puts $client "IMPORTED $saved"
                flush $client
            }
            shutdown $client

            #
            # Free up any tmp files for form elements
            #
            foreach elem $post(ALL) {
                if {$post($elem-type) == "file"} {
                    set fname $post($elem-data)
                    if {[file exists $fname]} {
                        file delete -force $fname
                        filexfer::log "cleaned up $fname for $elem"
                    }
                }
            }

            #
            # Send back a response that closes the window that
            # posted this form.
            #
            response $cid header -status "200 OK" \
                -connection $headers(Connection)
            set s [clock seconds]
            set date [clock format $s -format {%a, %d %b %Y %H:%M:%S %Z}]
            catch { puts $cid "Last-Modified: $date" }
            response $cid body -type text/html -string {<html>
<head>
  <title>Upload Complete</title>
  <script language="JavaScript">
    function setup() {
        window.close()
    }
    window.onload = setup;
  </script>
</head>
<body>
<b>Data uploaded successfully.  This window will now close.</b><br/>
If this window doesn't close automatically, feel free to close it manually.
</body>
</html>}
            flush $cid
        } else {
            #
            # No client ID within the form.  What happened?
            #
            response $cid header \
                -status "403 Forbidden" \
                -connection $headers(Connection)
            if {![info exists post(client)]} {
                response $cid error -status "403 Forbidden" -message "This form was missing the \"client\" element which authorizes the transaction and directs the posted data."
            } else {
                response $cid error -status "403 Forbidden" -message "The command-line program that initiated this action seems to have exited.  Try your upload operation again."
            }
            flush $cid
        }
    } else {
        #
        # BAD FILE REQUEST:
        #   The user is trying to ask for a file outside of
        #   the normal filexfer installation.  Treat it the
        #   same as file not found.
        response $cid header \
            -status "404 Not Found" \
            -connection $headers(Connection)
        response $cid error -status "404 Not Found" -message "The requested URL $url was not found on this server."
        flush $cid
    }

    if {$headers(Connection) == "close"} {
        shutdown $cid
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::getPostVar <postArray> <elem> ?<defVal>?
#
# Used internally by request_POST to pull the value of a slot in the
# given <postArray>.  Looks for a slot called <elem> and returns its
# value.  If the slot does not exist, it returns <defVal>.
# ----------------------------------------------------------------------
proc filexfer::getPostVar {postArray elem {defval ""}} {
    upvar $postArray post
    if {[info exists post($elem-type)]} {
        set data ""
        switch -- $post($elem-type) {
            file {
                set fname $post($elem-data)
                set fid [open $fname r]
                set data [read $fid]
                close $fid
            }
            string {
                set data $post($elem-data)
            }
        }
        regsub -all "\r\n" $data "\n" data
        return $data
    }
    return $defval
}

# ----------------------------------------------------------------------
# USAGE: filexfer::xlateNewlinesInFile <fileName>
#
# Used internally to convert the newlines in the given <fileName> from
# the Windows convention to the Linux convention.  Creates a new tmp
# file with the translated file contents and returns the name of the
# new file.
# ----------------------------------------------------------------------
proc filexfer::xlateNewlinesInFile {fname} {
    set chunksize 1000000

    set fid [open $fname r]
    fconfigure $fid -translation binary -encoding binary

    set fname2 [tmpfile]
    set fid2 [open $fname2 w]
    fconfigure $fid2 -translation binary -encoding binary

    while {![eof $fid]} {
        set str [read $fid $chunksize]
        if {[string index $str end] == "\r"} {
            # last char is \r -- add one more to look for \r\n
            append str [read $fid 1]
        }
        regsub -all "\r\n" $str "\n" str

        puts -nonewline $fid2 $str
    }
    close $fid
    close $fid2

    return $fname2
}

# ----------------------------------------------------------------------
# USAGE: request_EXPORT <clientId> <arglist> <cookie> <protocol>
#
# Used internally to handle EXPORT requests on this server.  A client
# sends EXPORT requests when it wants to send a file out to other
# receiving clients.  The <args> are a proper Tcl list with:
#
#   FILEXFER/1.0
#     <filename> <timeoutSecs> <delete> <subs>
#
#   FILEXFER/1.1
#     <filename> <timeoutSecs> <delete> raw|html <subs>
#
# The <filename> is immediately sent out to listening clients via
# "clientaction url".  After <timeoutSecs>, the file is forgotten,
# and if the <delete> flag is set, it is deleted at that time.
#
# If the format is "html", then the server automatically rewrites
# embedded file paths for images and links so that those items can
# be downloaded with respect to the original file.
# ----------------------------------------------------------------------
proc filexfer::request_EXPORT {cid arglist cookie proto} {
    variable fxcookie
    variable address

    # clients must come from 127.0.0.1 [localhost] and share a secret
    if {![string equal $address($cid) "127.0.0.1"]} {
        puts $cid [list ERROR "unauthorized access -- must come from 127.0.0.1 [localhost]"]
        flush $cid
        shutdown $cid
        return
    }
    if {![string equal $cookie $fxcookie]} {
        puts $cid [list ERROR "unauthorized access"]
        flush $cid
        shutdown $cid
        return
    }

    if {$proto == "FILEXFER/1.0"} {
        if {[llength $arglist] < 3 || [llength $arglist] > 4} {
            puts $cid [list ERROR "wrong # args for EXPORT: expected \"file timeout delete ?subs?\""]
            flush $cid
            return
        }
        if {[llength $arglist] == 3} {
            lappend arglist "raw"
        } else {
            set arglist [linsert $arglist 3 "raw"]
        }
    } else {
        if {[llength $arglist] < 4 || [llength $arglist] > 5} {
            puts $cid [list ERROR "wrong # args for EXPORT: expected \"file timeout delete format ?subs?\""]
            flush $cid
            return
        }
    }

    set file [lindex $arglist 0]
    if {![file readable $file]} {
        puts $cid [list ERROR "EXPORT file not readable: $file"]
        flush $cid
        return
    }

    set timeout [lindex $arglist 1]
    if {![string is integer $timeout]} {
        puts $cid [list ERROR "bad EXPORT timeout \"$timeout\": should be integer"]
        flush $cid
        return
    }

    set del [lindex $arglist 2]
    if {![string is boolean $del]} {
        puts $cid [list ERROR "bad EXPORT delete flag \"$del\": should be boolean"]
        flush $cid
        return
    }

    set fmt [lindex $arglist 3]
    if {[lsearch {raw html} $fmt] < 0} {
        puts $cid [list ERROR "bad EXPORT format flag \"$fmt\": should be raw, html"]
        flush $cid
        return
    }

    # If an optional substitution list is specified, then substitute
    # these parameters into the download.html file with framesets and
    # display it above the download.
    set subs [lindex $arglist 4]

    # Create a unique token for this export file.
    # Make sure that it's not already being used.
    variable downloads
    variable downloadInfo
    while {1} {
        set t [bakeCookie]
        if {![info exists downloads($t)]} {
            break
        }
    }
    set downloads($t) 1
    set downloadInfo($t-file) $file
    set downloadInfo($t-time) [clock seconds]
    set downloadInfo($t-timeout) $timeout
    set downloadInfo($t-delete) $del
    set downloadInfo($t-format) $fmt
    set downloadInfo($t-dlpage) $subs

    countdown cancel

    #
    # Tell the clients to download this file
    #
    if {[catch {trigger $t} result]} {
        puts $cid [list ERROR "EXPORT error: $result"]
        flush $cid
    }
}

# ----------------------------------------------------------------------
# USAGE: request_IMPORT <clientId> <template> <cookie>
#
# Used internally to handle IMPORT requests on this server.  The
# <template> is the file containing the template for the form that
# this operation will post to the user.  This form should contain
# @FORM-START@ and @FORM-END@ placeholders within the text.  These
# are roughly equivalent to the <form> and </form> tags within the
# template, but they are substituted with the proper URL and other
# manditory form information before the form is posted.
# ----------------------------------------------------------------------
proc filexfer::request_IMPORT {cid template cookie} {
    variable fxcookie
    variable uploads
    variable downloads
    variable downloadInfo

    # clients must come from 127.0.0.1 [localhost] and share a secret
    variable fxcookie
    variable address

    if {![string equal $address($cid) "127.0.0.1"]} {
        puts $cid [list ERROR "unauthorized access -- must come from 127.0.0.1 [localhost]"]
        flush $cid
        shutdown $cid
        return
    }
    if {![string equal $cookie $fxcookie]} {
        puts $cid [list ERROR "unauthorized access"]
        flush $cid
        shutdown $cid
        return
    }

    # Create a unique token for this import operation.
    # Make sure that it's not already being used.
    while {1} {
        set t [bakeCookie]
        if {![info exists downloads($t)]} {
            break
        }
    }
    set downloads($t) 1
    set uploads($t) $cid  ;# when info comes back, tell this client

    #
    # Load the text from the template file so we can make substitutions.
    #
    if {[catch {
        set fid [open $template r]
        set tinfo [read $fid]
        close $fid
    } result]} {
        puts $cid [list ERROR "error reading IMPORT template: $result"]
        flush $cid
        return
    }


    set fstart [format "<form action=\"/filexfer/%s/upload\" enctype=\"multipart/form-data\" method=\"post\">" $fxcookie]

    if {[regsub -all {@FORM-START@} $tinfo $fstart tinfo] == 0} {
        puts $cid [list ERROR "missing @FORM-START@ spec in IMPORT template"]
        flush $cid
        return
    }

    set fend [format "<input type=\"hidden\" name=\"client\" value=\"%s\">\n    </form>" $t]
    if {[regsub -all {@FORM-END@} $tinfo $fend tinfo] == 0} {
        puts $cid [list ERROR "missing @FORM-END@ spec in IMPORT template"]
        flush $cid
        return
    }

    if {[catch {
        set fid [open $template w]
        puts -nonewline $fid $tinfo
        close $fid
    } result]} {
        puts $cid [list ERROR "error updating IMPORT template: $result"]
        flush $cid
        return
    }

    # Create a unique token for this export file.
    # Make sure that it's not already being used.
    set downloadInfo($t-file) $template
    set downloadInfo($t-time) [clock seconds]
    set downloadInfo($t-timeout) 600
    set downloadInfo($t-delete) 1
    set downloadInfo($t-format) raw
    set downloadInfo($t-dlpage) ""

    countdown cancel

    #
    # Tell the clients to download this file
    #
    if {[catch {trigger $t} result]} {
        puts $cid [list ERROR "IMPORT error: $result"]
        flush $cid
    }
}

# ----------------------------------------------------------------------
# USAGE: request_BYE <clientId> <cookie>
#
# Used internally to handle BYE requests on this server.  Clients
# send this when they're done, and then they wait for the server
# to disconnect them.  That way, they get all of the information
# coming to them queued up on various requests.
# ----------------------------------------------------------------------
proc filexfer::request_BYE {cid cookie} {
    # clients must come from 127.0.0.1 [localhost] and share a secret
    variable fxcookie
    variable address

    if {![string equal $address($cid) "127.0.0.1"]} {
        puts $cid [list ERROR "unauthorized access -- must come from 127.0.0.1 [localhost]"]
        flush $cid
        shutdown $cid
        return
    }
    if {![string equal $cookie $fxcookie]} {
        puts $cid [list ERROR "unauthorized access"]
        flush $cid
        shutdown $cid
        return
    }

    # okay, service the client -- shutdown as requested
    shutdown $cid
}

# ----------------------------------------------------------------------
# USAGE: filexfer::shutdown <clientId>
#
# Used internally to close and clean up a client connection.
# Clears any data associated with the client.
# ----------------------------------------------------------------------
proc filexfer::shutdown {cid} {
    variable clients
    variable buffer
    variable address
    variable uploads

    catch {close $cid}

    # did client give up on upload?  then forget about it
    foreach {key val} [array get uploads] {
        if {[string equal $cid $val]} {
            unset uploads($key)
        }
    }

    if {[info exists clients($cid)]} {
        unset clients($cid)
    }

    if {[info exists buffer($cid)] && "" != $buffer($cid)} {
        unset buffer($cid)
    }
    unset address($cid)

    filexfer::log "disconnected client $cid"
}

# ----------------------------------------------------------------------
# USAGE: filexfer::housekeeping
#
# This gets set up to get invoked at regular intervals for housekeeping
# tasks.  During each invocation, this procedure checks for items that
# have timed out and removes them from the active list.  Items that
# are marked for deletion are cleaned up at that time.  If it's been
# a long time since any client has connected and there are no more
# pending requests, then the server shuts itself down.
# ----------------------------------------------------------------------
proc filexfer::housekeeping {} {
    variable downloads
    variable downloadInfo

    set status [catch {
        set now [clock seconds]
        foreach t [array names downloads] {
            if {$now >= $downloadInfo($t-time) + $downloadInfo($t-timeout)} {
                filexfer::cleanup $t
            }
        }

        if {[array size downloads] == 0} {
            countdown continue
        }
    } result]
    if {$status != 0} {
        filexfer::log "error in housekeeping: $result"
    }

    # invoke this at regular intervals according to the delay below
    after 5000 filexfer::housekeeping
}

# ----------------------------------------------------------------------
# USAGE: filexfer::countdown continue|cancel
#
# Usually invoked during the housekeeping step when there are no
# more files being tracked.  When the countdown reaches 0, the
# server exits.  Any new export or download operation cancels
# the countdown.
# ----------------------------------------------------------------------
proc filexfer::countdown {option} {
    variable countdown
    switch -- $option {
        continue {
            if {"" == $countdown} {
                set countdown 60
            } elseif {[incr countdown -1] <= 0} {
                filexfer::cleanup
                filexfer::log "inactive for a while -- shutting down..."
                exit
            }
        }
        cancel {
            set countdown ""
        }
        default {
            error "bad option \"$option\": should be continue or cancel"
        }
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::loadHTML <token> <directory> <file>
#
# Used in the GET operation to load a file in format "html".  Looks
# for the <file> within the <directory> context.  Loads the file and
# rewrites all embedded file references (for images and links) so that
# they can be served up properly from this server.  This allows the
# user to view not only an HTML page, but all of the resources embedded
# and linked by the page as well.
# ----------------------------------------------------------------------
proc filexfer::loadHTML {token dir file} {
    package require tdom
    variable fxcookie

    set fid [open [file join $dir $file] r]
    set info [read $fid]
    close $fid

    set doc [dom parse -html $info]
    set queue [$doc documentElement]

    while {[llength $queue] > 0} {
        set node [lindex $queue 0]
        set queue [lrange $queue 1 end]

        switch -- [string tolower [$node nodeName]] {
            a {
                if {[catch {$node getAttribute href} val] == 0 && "" != $val} {
                    if {![regexp -nocase {^https?://} $val]} {
                        set val [string trimleft $val /]
                        set newurl [format "/filexfer/%s/dlfile/%s?token=%s" \
                            $fxcookie $val $token]
                        $node setAttribute href $newurl
                    }
                }
            }
            img {
                if {[catch {$node getAttribute src} val] == 0 && "" != $val} {
                    if {![regexp -nocase {^https?://} $val]} {
                        set val [string trimleft $val /]
                        set newurl [format "/filexfer/%s/dlfile/%s?token=%s" \
                            $fxcookie $val $token]
                        $node setAttribute src $newurl
                    }
                }
            }
        }

        eval lappend queue [$node childNodes]
    }

    set html [$doc asHTML]
    $doc delete

    return $html
}

# ----------------------------------------------------------------------
# USAGE: response <channel> header -status <s> -connection <c>
# USAGE: response <channel> body -string <s> -type <t>
# USAGE: response <channel> error -message <m>
# USAGE: response <channel> file -path <f>
#
# Used internally to generate responses to the client.  Returns a
# string representing the requested response.
# ----------------------------------------------------------------------
proc filexfer::response {cid what args} {
    switch -- $what {
        header {
            filexfer::getopts args params {
                value -status ""
                value -connection close
            }
            set s [clock seconds]
            set date [clock format $s -format {%a, %d %b %Y %H:%M:%S %Z}]
            catch {
                puts $cid [format "HTTP/1.1 %s
Date: %s
Server: hubzero-filexfer
Connection: %s" $params(-status) $date $params(-connection)]
            }
        }

        body {
            filexfer::getopts args params {
                value -string ""
                value -type "auto"
            }
            if {$params(-type) == "auto"} {
                if {[isbinary $params(-string)]} {
                    set params(-type) "application/octet-stream"
                } else {
                    set params(-type) "text/plain"
                }
            }
            catch {
                puts $cid [format "Content-type: %s\nContent-length: %d\n" \
                    $params(-type) [string length $params(-string)]]
            }

            # treat all data as binary -- doesn't hurt if it's ascii
            set olde [fconfigure $cid -encoding]
            fconfigure $cid -buffering none -encoding binary
            catch {
                puts -nonewline $cid $params(-string)
                flush $cid
            }
            fconfigure $cid -buffering line -encoding $olde
        }

        error {
            filexfer::getopts args params {
                value -status "400 Bad Request"
                value -message ""
            }
            set heading [lrange $params(-status) 1 end]
            set html [format "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">
<HTML><HEAD>
<TITLE>%s</TITLE>
</HEAD><BODY>
<H1>%s</H1>
%s
</BODY></HTML>" $params(-status) $heading $params(-message)]
            response $cid body -type text/html -string $html
        }

        file {
            filexfer::getopts args params {
                value -path ""
                value -connection close
                value -saveas 0
            }
            if {![file readable $params(-path)]} {
                #
                # FILE NOT FOUND:
                #   The user is requesting some file that is not part of
                #   the standard filexfer installation.
                #
                response $cid header \
                    -status "404 Not Found" \
                    -connection $params(-connection)

                response $cid error -status "404 Not Found" -message "The requested file $params(-path) was not found on this server."
                return
            }

            response $cid header \
                -status "200 OK" \
                -connection $params(-connection)

            if {$params(-saveas)} {
                set ftail [file tail $params(-path)]
                catch { puts $cid "Content-Disposition: attachment; filename=\"$ftail\"" }
            }

            set s [file mtime $params(-path)]
            set date [clock format $s -format {%a, %d %b %Y %H:%M:%S %Z}]
            catch { puts $cid "Last-Modified: $date" }

            foreach {mime type} [filexfer::mimetype $params(-path)] break
            set s [file size $params(-path)]
            catch {
                puts $cid [format "Content-type: %s\nContent-length: %d\n" \
                    $mime $s]
            }

            set fid [open $params(-path) r]
            fconfigure $fid -translation binary -encoding binary
            fileevent $fid readable [list filexfer::sendfile $cid $fid]
            # wait until we're idle, then send back a chunk at a time...
        }
    }
}

# ----------------------------------------------------------------------
# USAGE: sendfile <client> <fileHandle>
#
# Used by the filexfer::response routine to send back the contents of
# a file over a given <client> socket.  We send the file back in small
# chunks so we don't run out of memory if the file is huge (gigabytes).
# This procedure gets called again and again from the event loop to
# send back a chunk at a time until the entire file has been read and
# sent.  At that point, the <fileHandle> is closed.
# ----------------------------------------------------------------------
proc filexfer::sendfile {cid fid} {
    #
    # BE CAREFUL:  Client may have closed the socket while we're in the
    #   midst of transferring the file.  If so, we'll just close the
    #   file and stop the transfer.
    #
    if {[catch {eof $cid} ceof] || $ceof || [catch {eof $fid} feof] || $feof} {
        catch {close $fid}
        # now that this is closed, we'll stop getting callbacks
    } else {
        # send the next chunk to the client
        set data [read $fid 1000000]
        catch {puts -nonewline $cid $data; flush $cid}
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::urlDecode <string>
#
# Used internally to decode a string in URL-encoded form back to
# its normal ASCII equivalent.  Returns the input string, but with
# any %XX characters translated back to their ASCII equivalents.
# ----------------------------------------------------------------------
proc filexfer::urlDecode {string} {
    while {[regexp -indices {%[0-9A-Fa-f][0-9A-Fa-f]} $string match]} {
        foreach {p0 p1} $match break
        set hex [string range $string [expr {$p0+1}] $p1]
        set char [binary format c [scan $hex "%x"]]
        set string [string replace $string $p0 $p1 $char]
    }
    return $string
}

# ----------------------------------------------------------------------
# USAGE: isbinary <string>
#
# Used internally to see if the given <string> has binary data.
# If so, then it must be treated differently.  Normal translation
# of carriage returns and line feeds must be suppressed.
# ----------------------------------------------------------------------
proc filexfer::isbinary {string} {
    # look for binary characters, but avoid things like \t \n etc.
    return [regexp {[\000-\006\016-\037\177-\377]} $string]
}

# ----------------------------------------------------------------------
# USAGE: mimetype <file> <data>
#
# Used internally to determine the MIME type and ascii/binary
# nature of the data in <file>.
# ----------------------------------------------------------------------
proc filexfer::mimetype {file} {
    variable fileprog

    if {"" == $fileprog || [catch {exec $fileprog -i $file} out]} {
        set mtype application/octet-stream
    } elseif {[regexp {^.+: +([-+\.a-zA-Z0-9]+/[-+\.a-zA-Z0-9]+)} $out x y]} {
        set mtype $y
    } else {
        set mtype application/octet-stream
    }
    if { $mtype == "application/xml" } {
        return [list "text/plain" "ascii"]
    }
    if {[string match text/* $mtype]} {
        set aorb "ascii"
    } else {
        set aorb "binary"
    }
    return [list $mtype $aorb]
}

# ----------------------------------------------------------------------
# USAGE: bakeCookie
#
# Used internally to create a one-time use cookie, passed to clients
# to secure file transfer.  Only clients should know the cookie, so
# only clients will have access to files.
# ----------------------------------------------------------------------
proc filexfer::bakeCookie {} {
    variable cookieChars

    set cmax [expr {[llength $cookieChars]-1}]
    set cookie ""
    while {[string length $cookie] < 20} {
        set rindex [expr {round(rand()*$cmax)}]
        append cookie [lindex $cookieChars $rindex]
    }
    return $cookie
}

# ----------------------------------------------------------------------
# USAGE: tmpfile
#
# Returns a unique name for a /tmp file.  Usually used for POST data.
# ----------------------------------------------------------------------
proc filexfer::tmpfile {} {
    variable unique

    while {1} {
        set fname [file join /tmp filexfer[pid]-[incr unique]]
        if {![file exists $fname]} {
            return $fname
        }
    }
}

# ----------------------------------------------------------------------
# USAGE: filexfer::log -init
# USAGE: filexfer::log <message>
#
# Used to send log messages to some file for debugging.
# ----------------------------------------------------------------------
proc filexfer::log {mesg} {
    global env
    variable log
    if {"-init" == $mesg} {
        if {"" != $log} {
            catch {close $log}
        }
        set log ""

        if {[info exists env(SESSIONDIR)]} {
            set logfile [file join $env(SESSIONDIR) filexfer[pid].log]
        } elseif {[info exists env(HOME)] && [info exists env(SESSION)]} {
            set logfile [file join $env(HOME) data sessions $env(SESSION) filexfer[pid].log]
        } elseif {[file writable [pwd]]} {
            set logfile [file join [pwd] filexfer[pid].log]
        }
        if {[catch {open $logfile w} result] == 0} {
            set log $result
        }
    } elseif {"" != $log} {
        catch {
            puts $log $mesg
            flush $log
        }
    }
}

# ----------------------------------------------------------------------
#  MAIN SCRIPT
# ----------------------------------------------------------------------
# Load the settings from the user's resources file.
# In particular, figure out filexfer_port so we know how to talk
# to the filexfer server.
#
filexfer::log -init
filexfer::log "started on [clock format [clock seconds]]"

if {[string compare "" filexfer::clientaction] == 0} {
    filexfer::log "can't find an executable version of the file clientaction"
    filexfer::log "exiting..."
    exit 1
}

if {[catch {filexfer::resources} result]} {
    filexfer::log "can't load resource configuration: $result"
    filexfer::log "exiting..."
    exit 1
}
array set settings $result
if {[catch {filexfer::init $settings(port) $settings(cookie)} result]} {
    filexfer::log "can't start server: $result"
    filexfer::log "exiting..."
    exit 1
}

# make sure standard "file" command is installed, to handle MIME type
set filexfer::fileprog [auto_execok "file"]
if {"" == $filexfer::fileprog} {
    filexfer::log "can't find \"file\" program used to determine MIME type"
    filexfer::log "all files will be treated as unknown binary type"
}

filexfer::log "listening on port $settings(port)"
vwait forever

