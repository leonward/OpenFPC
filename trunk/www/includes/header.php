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

require "includes/config.inc.php";

$head = "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n";
$head .= "<head>\n";
$head .= "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n";
$head .= "<title>OpenFPC Web Interface</title>\n";
$head .= "<link href=\"css/style.css\" rel=\"stylesheet\" type=\"text/css\" media=\"screen\" />\n";
$head .= "<script src=\"javascript/jquery-1.5.1.min.js\" type=\"text/javascript\"></script>\n";
$head .= "<script src=\"javascript/jqueryslidemenu.js\" type=\"text/javascript\"></script>\n\n";
$head .= "<script type=\"text/javascript\" src=\"javascript/jquery-ui-1.8.13.custom.min.js\"></script>\n";
$head .= "<script type=\"text/javascript\" src=\"javascript/jquery-ui-timepicker-addon.js\"></script>\n";


$head .= "<!-- Color hover JavaScript Files -->\n";
$head .= "<script type=\"text/javascript\">\n";
$head .= "        $(document).ready(function(){\n";
$head .= "                $(\"li a\").hover(function() {\n";
$head .= "                $(this).stop().animate({ backgroundColor: \"#eb692b\" }, 200);\n";
$head .= "        },function() {\n";
$head .= "                 $(this).stop().animate({ backgroundColor: \"#333333\" }, 400);\n";
$head .= "        });\n";
$head .= "  });\n";
$head .= "</script>\n";
$head .= "<!-- Framework CSS -->\n";
$head .= "<link rel=\"stylesheet\" href=\"css/screen.css\" type=\"text/css\" media=\"screen, projection\" />\n";
$head .= "<link rel=\"stylesheet\" href=\"css/print.css\" type=\"text/css\" media=\"print\" />\n";
$head .= "<!--[if lt IE 8]><link rel=\"stylesheet\" href=\"css/ie.css\" type=\"text/css\" media=\"screen, projection\"><![endif]-->\n";
$head .= "<script type=\"text/javascript\">";

$head .= "
function SessionWindow(cid,p) {
window.open( '?op=dump&cxtid='+cid+'&sessp='+p+'&' );
}
";

$head .= "
function EditUser(username,realname,email,description,timezone,defaultnode) {
window.open( '?op=newuser&username='+username+'&realname='+realname+'&email='+email+'&description='+description+'&timezone='+timezone+'&defaultnode='+defaultnode+'&' );
}
";
$head .= "</script>";

$head .= "<script>\n";
$head .= "        $(function() {\n";
$head .= "                $( \"#start_date\" ).datetimepicker({showSecond: true,timeFormat:'hh:mm:ss',dateFormat: 'yy-mm-dd'});\n";
$head .= "                $( \"#end_date\" ).datetimepicker({showSecond: true,timeFormat:'hh:mm:ss',dateFormat: 'yy-mm-dd'});\n";
$head .= "        });\n";
$head .= "</script>\n";
$head .= "<link rel=\"stylesheet\" media=\"all\" type=\"text/css\" href=\"css/ui-darkness/jquery-ui-1.8.13.custom.css\" />";

$head .= "<style type=\"text/css\">
        .ui-timepicker-div .ui-widget-header{ margin-bottom: 8px; }
        .ui-timepicker-div dl{ text-align: left; }
        .ui-timepicker-div dl dt{ height: 25px; }
        .ui-timepicker-div dl dd{ margin: -25px 10px 10px 65px; }
        .ui-timepicker-div td { font-size: 90%; }
</style>";


$head .= "</head>\n";
$head .= "<body>\n"; 
$head .= "<div id=\"spotlight\">\n";
$head .= "<div id=\"logo\"></div><!--END logo-->\n";
$head .= "<div class=\"container\">\n";
echo $head;
