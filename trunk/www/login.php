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
$username  = sanitize("username");      if (empty($username))      $username = "";
$password  = sanitize("password");      if (empty($password))      $password = "";

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
    $out .= "          <input name=\"username\" type=\"text\" class=\"text\" id=\"srcip\" maxlength=\"39\" value=\"\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"password\">Password</label>\n";
    $out .= "          <input name=\"password\" type=\"password\" class=\"text\" id=\"srcip\" maxlength=\"39\" value=\"\">\n";
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
    global $username, $password, $guilink;
    $guilink=guiDB();
    $query="SELECT username, password, timezone FROM users WHERE username='$username' and password='$password'";
    
    $result=mysql_query($query, $guilink) or errorpage("GUI DB Eror: ".mysql_error());
    
    if(mysql_num_rows($result)==1) {
        session_start();
        while ( $row = mysql_fetch_assoc($result)) {
            $_SESSION['timezone'] = $row['timezone'];
        }
        
        $_SESSION['username'] = $username;
        $_SESSION['password'] = $password;
        $_SESSION['auth'] = 1;
        header ("Location: index.php");
    } else {
        header ("Location: login.php");
    }
}

function dologout() {
    global $username, $password;
    session_start();
    $_SESSION['username'] = 0;
    $_SESSION['auth'] = 0;
    header ("Location: login.php");
}