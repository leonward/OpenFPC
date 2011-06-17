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


$op    = sanitize("op");                  	if (empty($op))        $op = "entry";
$username  = sanitize("username");            	if (empty($username))      $username = "";
$password1  = sanitize("password1");      	if (empty($password1))      $password1 = "";
$password2  = sanitize("password2");      	if (empty($password2))      $password2 = "";
$defaultnode  = sanitize("defaultnode");  	if (empty($defaultnode))      $defaultnode = "";
$description  = sanitize("description");  	if (empty($description))      $description = "";
$email  = sanitize("email");  			if (empty($email))      $email = "";
$realname  = sanitize("realname");  		if (empty($realname))      $realname = "";
$usertimezone  = sanitize("usertimezone"); 	if (empty($usertimezone))      $usertimezone= "Europe/London";


switch ($op) {
    // Add new user details as submitted 
    case "Add User":
        adduser();
        break;

    // show edit user form
    case "newuser":
	showhead();
        newuser();
        break;
    
    // Delete user
    case "Delete User":
	deluser();
        break;
    
    // List users
    case "list":
        showhead();
        showusertable();
        break;
    
    // Update user with new details
    case "Update User":
	updateuser();
	break;
    
    // default is to show "new" user form
    default:
        showhead();
        newuser();
        break;
}



function showsuccess($message){
    $out .= infobox("Success: $message");
    echo $out;
}

function showerror($error){
    $out .= infobox("Error: $error");
    echo $out;
}

function showhead(){
    checkauth();
    include "includes/header.php";
}

function newuser(){
    global $username,$timezone, $defaultnode,$realname,$email,$description;
    $out = "  <form method=\"post\" name=\"login\" action=\"\">\n";
    $out .= "    <div class=\"span-10 \" align=\"right\">\n";
    $out .= "      <fieldset>\n";
    $out .= "        <legend>Add / Update Users</legend>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"username\">Username</label>\n";
    $out .= "          <input name=\"username\" type=\"text\" class=\"text\" id=\"username\" maxlength=\"39\" value=\"$username\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"password1\">Password</label>\n";
    $out .= "          <input name=\"password1\" type=\"password\" class=\"text\" id=\"password1\" maxlength=\"39\" value=\"\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"password2\">Re-enter Password</label>\n";
    $out .= "          <input name=\"password2\" type=\"password\" class=\"text\" id=\"password2\" maxlength=\"39\" value=\"\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"realname\">Real Name</label>\n";
    $out .= "          <input name=\"realname\" type=\"text\" class=\"text\" id=\"realname\" maxlength=\"39\" value=\"$realname\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"email\">Email address</label>\n";
    $out .= "          <input name=\"email\" type=\"text\" class=\"text\" id=\"email\" maxlength=\"39\" value=\"$email\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"description\">Description</label>\n";
    $out .= "          <input name=\"description\" type=\"text\" class=\"text\" id=\"description\" maxlength=\"39\" value=\"$description\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"usertimezone\">Time zone</label>\n";
    $out .= "          <input name=\"usertimezone\" type=\"text\" class=\"text\" id=\"usertimezone\" maxlength=\"39\" value=\"$timezone\">\n";
    $out .= "        </p>\n";
    $out .= "        <p>\n";
    $out .= "          <label for=\"defaultnode\">Default Node</label>\n";
    $out .= "          <input name=\"defaultnode\" type=\"text\" class=\"text\" id=\"defaultnode\" maxlength=\"39\" value=\"$defaultnode\">\n";
    $out .= "        </p>\n";
    $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Add User\">";
    $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Update User\">";
    $out .= "      <input TYPE=\"submit\" NAME=\"op\" VALUE=\"Delete User\">";
    $out .= "      </fieldset>\n";
    $out .= "    </div>\n";
    $out .= "    </div>\n";
    $out .= "  </form>\n";
    $out .= "</div>\n";
    echo $out;
}

function iscurrentuser($username){
    $guilink=guiDB();
    $query="SELECT * FROM users WHERE username='$username'";
    $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
    
    if(mysql_num_rows($result)==1) {
        return(1);
    } else {
        return(0);
    }
}

function countusers(){
    $guilink=guiDB();
    $query="SELECT * from users";
    
    $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
    return(mysql_num_rows($result));
}

function deluser() {
    global $username, $password1, $password2, $timezone, $deafultnode, $realname, $description, $email, $guilink;
    checkauth();

    if ( ! iscurrentuser($username) ) {
        showhead();
        showerror("User Doesn't exist! How can I delete them");
        newuser();
	// check we are not the last user
    } elseif ( countusers() == 1){
	showhead();
        showerror("Won't delete last user. <br>You don't want to lock yourself out!");
	showusertable();
    } else {
        showhead();
        $guilink=guiDB();
        $query="DELETE FROM users WHERE
	    username = '$username'";
        $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
        showsuccess("User $username deleted");
        showusertable();
    }
}


function adduser() {
    global $username, $password1, $password2, $timezone, $deafultnode, $realname, $description, $email, $guilink, $usertimezone;
    checkauth();

    if ( iscurrentuser($username) ) {
        showhead();
        showerror("User already exists");
        newuser();
    } elseif ($password1 == "") {
        showhead();
        showerror("Error: Blank password not allowed.");
        newuser();
    } elseif ( $password1 == $password2 ) {
        showhead();
        $guilink=guiDB();
        $query="INSERT INTO users (username,password,realname,email,description,timezone,defaultnode)
            VALUES ('$username', '$password1','$realname','$email','$description','$usertimezone','$deafultnode')";
        $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
        showsuccess("User Added");
        showusertable();
        
    } else {
        showhead();
        showerror("Passwords do not match.");
        newuser();
    }
}

function updateuser() {
    global $username, $password1, $password2, $timezone, $deafultnode, $realname, $description, $email, $guilink,$usertimezone;
    checkauth();

    if ( ! iscurrentuser($username) ) {
        showhead();
        showerror("User Doesn't exist! Are you trying to create a new user?");
        newuser();
    } elseif ($password1 == "") {
        showhead();
        showerror("Error: Blank password not allowed.");
        newuser();
    } elseif ( $password1 == $password2 ) {
        showhead();
        $guilink=guiDB();
        $query="UPDATE users SET password = '$password1',
				realname = '$realname',
				email = '$email',
				description = '$description',
				timezone = '$usertimezone',
				defaultnode = '$deafultnode'
	    WHERE username = '$username'";
        $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
        showsuccess("User Updated");
        showusertable();
        
    } else {
        showhead();
        showerror("Passwords do not match.");
        newuser();
    }
}


function listusers(){
    global $guilink;
    $guilink=guiDB();
    $out = "";
    $query="SELECT username,realname,email,description,timezone,defaultnode from users";
    $result=mysql_query($query, $guilink) or die("GUI DB Eror: ".mysql_error());
   
    while ( $row = mysql_fetch_assoc($result)) {
        $out .= userRowFormat($row);
    }
    return($out);
}

function userRowFormat($data) {
    $out = "";
    $out .= "<tr onmouseover=\"this.style.cursor=&#39;hand&#39;\" ";
    $out .= "onclick=\"EditUser('" . $data["username"] .
				"','" . $data["realname"] .
				"','" . $data["email"] .
				"','" . $data["description"] .
				"','" . $data["timezone"] .
				"','" . $data["defaultnode"] .
				"');\"";
    $out .= "> \n";

    // User
    $out .= "<td>" . $data["username"] . "</td>";
    $out .= "<td>" . $data["realname"] . "</td>";
    $out .= "<td>" . $data["email"] . "</td>";
    $out .= "<td>" . $data["description"] . "</td>";
    $out .= "<td>" . $data["timezone"] . "</td>";
    $out .= "<td>" . $data["defaultnode"] . "</td>";
    $out .= "</tr>";

    return $out;
    
}

function showusertable(){
    
    checkauth();
    print "User List \n"; 
    $out = "<table summary=\"OpenFPC GUI user accounts\"  border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n";
    $out .= "  <caption>\n";
    $out .= "  <em>OpenFPC Users</em>\n";
    $out .= "  </caption>\n";
    $out .= "  <thead>\n";
    $out .= "    <tr>\n";
    $out .= "      <th class=\"span-4\">Username</th>\n";
    $out .= "      <th class=\"span-4\">Full Name</th>\n";
    $out .= "      <th class=\"span-4\">Email address</th>\n";
    $out .= "      <th class=\"span-4\">Description</th>\n";
    $out .= "      <th class=\"span-4\">Time Zone</th>\n";
    $out .= "      <th class=\"span-4\">Default OFPC Node</th>\n";
    $out .= "    </tr>\n";
    $out .= "  </thead>\n";
    $out .= "  <tfoot>\n";
    $out .= "    <tr>\n";
    $out .= "      <td colspan=\"15\">Table listing results of OpenFPC Users</td>\n";
    $out .= "    </tr>\n";
    $out .= "  </tfoot>\n";
    $out .= "  <tbody>\n";
    $out .= listusers();
    $out .= "  </tbody>\n";
    $out .= "</table>\n";
    $out .= "</div>\n";
    echo $out;
}
