<?php
# --------------------------------------------------------------------------
# Copyright (C) 2010 
# Edward Fjellskål <edward.fjellskaal@gmail.com>>
# Dave Lowe <seclistinbox@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; withhead even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# --------------------------------------------------------------------------

$menu = "<div id=\"myslidemenu\" class=\"jqueryslidemenu\">\n";
$menu .= "        <ul>\n";
$menu .= "          <li><a href=\"index.php\" class=\"current\">OpenFPC</a></li>\n";
$menu .= "          <li><a href=\"#\">Packets</a>\n";
$menu .= "                           <ul style=\"display: none; visibility: visible;\">\n";
$menu .= "                             <li><a href=\"index.php?op=DisplayLogLine\">From Event</a></li>\n";
$menu .= "                             <li><a href=\"index.php?op=Extract pcap\">From Criteria</a></li>\n";
$menu .= "                             <li><a href=\"index.php?op=DisplayBPF\">From BPF</a></li>\n";
$menu .= "                           </ul><!--END submenu packets-->\n";
$menu .= "          </li>\n";

    $menu .= "          <li><a href=\"#\">Sessions</a>\n";
if ($enable_session) {
    $menu .= "                           <ul style=\"display: none; visibility: visible;\">\n";
    $menu .= "                             <li><a href=\"index.php?op=Search Sessions\">Search</a></li>\n";
    //$menu .= "                             <li><a href=\"index.php\">Most Recent</a></li>\n";
    $menu .= "                           </ul><!--END submenu sessions-->\n";
} else {
    $menu .= "                           <ul style=\"display: none; visibility: visible;\">\n";
    $menu .= "                             <li><a href=\"index.php\">Session Disabled</a></li>\n";
    $menu .= "                           </ul><!--END submenu sessions-->\n";
}
    $menu .= "           </li>\n";

$menu .= "          <li><a href=\"#\">Users</a>\n";
$menu .= "                           <ul style=\"display: none; visibility: visible;\">\n";
$menu .= "                             <li><a href=\"useradd.php?op=list\">List / Edit users</a></li>\n";
$menu .= "                             <li><a href=\"useradd.php\">New User</a></li>\n";
$menu .= "                           </ul><!--END submenu Help-->\n";
$menu .= "           </li>\n";
    
$menu .= "          <li><a href=\"#\">Help</a>\n";
$menu .= "                           <ul style=\"display: none; visibility: visible;\">\n";
$menu .= "                             <li><a href=\"index.php?op=about\">About</a></li>\n";
$menu .= "                             <li><a href=\"index.php?op=guide\">User Guide</a></li>\n";
$menu .= "                           </ul><!--END submenu Help-->\n";
$menu .= "           </li>\n";

$menu .= "          <li><a href=\"login.php?op=dologout\">Logout</a></li>\n";

$menu .= "        </ul>\n";
$menu .= "</div><!--END jqueryslidemenu-->\n";
echo $menu;
