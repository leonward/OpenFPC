<?php
# --------------------------------------------------------------------------
# Copyright (C) 2011
# Leon Ward leon@openfpc.org
# Edward FjellskŒl <edward.fjellskaal@gmail.com>
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

require "includes/functions.php";
require "includes/config.inc.php";


$op    = sanitize("op");        if (empty($op))        $op = "entry";
$user  = sanitize("username");      if (empty($user))      $user = "";
$pass  = sanitize("password");      if (empty($pass))      $pass = "";

switch ($op) {
    // process login input
    case "Login":
        dologin();
        break;

    // show login form
    case "showentry":
        showentry();
        break;
    
    // Show logout page
    case "showlogout":
        showlogout();
        break;
    
    // process logout request
    case "Logout":
        dologout();
        break;
    
    default:
        showentry();
        break;
}

function showentry(){
    
    include "includes/header.php";
    $out .= "  <form method=\"post\" name=\"login\" action=\"\">\n";
    $out .= "    <div class=\"span-10 \">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Login</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"username\">Username</label>\n";
    $out .= "          <input name=\"username\" type=\"text\" class=\"text\" id=\"srcip\" maxlength=\"39\" value=\"f\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"password\">Password</label>\n";
    $out .= "          <input name=\"password\" type=\"password\" class=\"text\" id=\"srcip\" maxlength=\"39\" value=\"g\">\n";
    $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Login\">";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    </div>\n";
    $out .= "  </form>\n";
    $out .= "</div>\n";
    echo $out;
}

function showlogout(){
    
    include "includes/header.php";
    $out .= "  <form method=\"post\" name=\"logout\" action=\"\">\n";
    $out .= "    <div class=\"span-10 \">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Logout</legend>\n";
    $out .= "        <p>\n";
    $out .= "        <p>\n";
    $out .= "        Logout?<br>\n";
    $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Logout\">";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    </div>\n";
    $out .= "  </form>\n";
    $out .= "</div>\n";
    echo $out;
}


function dologin() {
    global $user, $pass;
    $testuser="bob";
    $testpass="pass";

    
    if ($user == $testuser && $pass == $testpass) {
        session_start();
        $_SESSION['user'] = $user;
        $_SESSION['auth'] = 1;
        header ("Location: gui2.php");
    } else {
        header ("Location: login.php");
    }
}

function dologout() {
    global $user, $pass;
    session_start();
    $_SESSION['user'] = 0;
    $_SESSION['auth'] = 0;
    header ("Location: login.php");
}