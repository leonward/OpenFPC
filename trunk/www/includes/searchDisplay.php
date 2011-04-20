<?php
# --------------------------------------------------------------------------
# Copyright (C) 2010 
# Edward Fjellskål <edward.fjellskaal@gmail.com>
# Dave Lowe <seclistinbox@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# --------------------------------------------------------------------------

global $config, $major, $minor, $build, $pollTime, $dbname, $start_date, $end_date;
global $srcip, $dstip, $srcport, $dstport, $ipv, $protocol;
global $notdstip, $notsrcip, $notsrcport, $notdstport;

$out = "";
$out .= "  <form method=\"get\" name=\"search\" action=\"\">\n";
    $out .= "    <div class=\"span-6 \">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Source Address</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"srcip\">Source IP</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"srcip\" type=\"text\" class=\"text\" id=\"srcip\" maxlength=\"39\" value=\"";
    if ($notsrcip) $out .= "!";
    if (!empty($srcip) && isip4($srcip)) $out .= $srcip;
    $out .= "\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"srcport\">Source Port</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"srcport\" type=\"text\" class=\"text\" id=\"srcport\" maxlength=\"5\" value=\"";
    if ($notsrcport) $out .= "!";
    if (!empty($srcport) && isport($srcport)) $out .= $srcport;
    $out .= "\">\n";
    $out .= "        </p>\n";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    <div class=\"span-6  \">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Destination Address</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"dstip\">Dest IP</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"dstip\" type=\"text\" class=\"text\" id=\"dstip\" maxlength=\"39\" value=\"";
    if ($notdstip) $out .= "!";
    if (!empty($dstip) && isip4($dstip)) $out .= $dstip;
    $out .= "\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"dstport\">Dest Port</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"dstport\" type=\"text\" class=\"text\" id=\"dstport\" maxlength=\"5\" value=\"";
    if ($notdstport) $out .= "!";
    if (!empty($dstport) && isport($dstport)) $out .= $dstport;
    $out .= "\">\n";
    $out .= "        </p>\n";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    <div class=\"span-6 \">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Date/Time</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"start_date\">Start Date/Time</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"start_date\" type=\"text\" class=\"text\" id=\"start_date\" maxlength=\"21\" value=\"" . $start_date . "\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"end_date\">End Date/Time</label>\n";
    $out .= "          <br>\n";
    $out .= "          <input name=\"end_date\" type=\"text\" class=\"text\" maxlength=\"21\" id=\"end_date\" value=\"". $end_date . "\">\n";
    $out .= "        </p>\n";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    <div class=\"span-6 last\">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Protocol</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"ipv\">IP Version</label>\n";
    $out .= "          <br>\n";
    $out .= "          <select name=\"ipv\" id=\"ipv\">\n";
    $out .= "            <option value=\"2\" ";
    if ($ipv == 2) $out .= "selected";
    $out .= ">IPv4</option>\n";
    $out .= "            <option value=\"10\" ";
    if ($ipv == 10) $out .= "selected";
    $out .= ">IPv6</option>\n";
    $out .= "            <option value=\"12\" "; 
    if ($ipv == 12) $out .= "selected";
    $out .= ">IPv4/6</option>\n";
    $out .= "        </select>\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"protocol\">Transport</label>\n";
    $out .= "          <br>\n";
    $out .= "          <select name=\"protocol\" id=\"protocol\">\n";
    $out .= "            <option value=\"any\"";
    if ($protocol == "any") $out .= "selected";
    $out .= ">Any</option>\n";
    $out .= "            <option value=\"6\" ";
    if ($protocol == "6") $out .= "selected";
    $out .= ">TCP</option>\n";
    $out .= "            <option value=\"17\" ";
    if ($protocol == "17") $out .= "selected";
    $out .= ">UDP</option>\n";
    $out .= "            <option value=\"1\" ";
    if ($protocol == "1" || $protocol == "58") $out .= "selected";
    $out .= ">ICMP</option>\n";
    $out .= "          </select>\n";
    $out .= "        </p>\n";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    <div class=\"span-6 \">&nbsp; </div>\n";
    $out .= "    <div class=\"span-6 \">&nbsp; </div>\n";
    $out .= "    <div class=\"span-6 \">&nbsp; </div>\n";
    $out .= "    <div class=\"span-6 last\" align=\"right\">\n";
    if ($config["ENABLE_SESSION"] == 1) { # Only show search button if search is enabled
        $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Search Sessions\">";
    } 
    $out .= "    </div>\n";
    $out .= "  </form>\n";
    $out .= "</div>\n";
    return $out;

