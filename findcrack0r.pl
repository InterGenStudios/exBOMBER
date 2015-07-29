#!/usr/bin/env perl
#
# Coydogsoftware.net's Repository:
#
#          https://repo.coydogsoftware.net/coydog/rxtools/tree/master
#
# TODO: learn perl.
# TODO TODO TODO: Verify that we are scanning every file. Got one
# disturbing report of a false negative that should have been
# detected
#
# Copyright 2014 Coydog Software. All rights reserved. Copying is prohibited
# except as specified by the terms of the GPLv3.
#
#   This program is distributed in the hope that it will be useful, but WITHOUT
#   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
#   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#   more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program.  If not, see <http://www.gnu.org/licenses/>.
# TODO: flag to optionally include regex's with high false positive rates


use strict;
use warnings;
use Data::Dumper;
use Getopt::Std;
use Cwd;
use File::Path qw(make_path);
use File::Find;
use Term::ANSIColor;     # lol

# constants (let's pretend anyway)
my $default_bytes = 5000000;

our ($opt_t, $opt_a, $opt_b, $opt_p, $opt_S, $opt_d, $opt_q, $opt_o, $opt_D, $opt_h, $opt_u, $opt_N, $opt_e);
sub main::HELP_MESSAGE {
    print STDERR "Usage:\n";
    print STDERR "  -t\t" . "ticket number for output dir\n";
    # TODO: Use the cPanel API to grab real docroots?
    print STDERR "  -a <accounts>\t" . "account list, comma-delimited. Will search only public_html\n";
    print STDERR "  -b <bytes>\t" . "Number of bytes per file to scan. Default is $default_bytes\n";
    print STDERR "  -p\t" . "restrict searches to *.php (faster but may miss stuff)\n";
    #print STDERR "  -s\t" . "check for potentially evil symlinks (target owner different from link owner)\n";
    print STDERR "  -S\t" . "Skip checking symlinks\n";
    print STDERR "  -d\t" . "grep for defacements\n";
    print STDERR "  -q\t" . "dump databases, include in greps. Not implemented.\n"; #TODO: arg to specify which?
    print STDERR "  -o\t" . "other directories to search, independently of -a docroots. May be needed for addon/subdomains\n";
    print STDERR "  -u\t",  "user homedir prefix (default /home)\n";
    print STDERR "  -D\t",  "Debug mode. Output a more detailed log which identifies signature matches.\n";
    print STDERR "  -N\t",  "Show files which do NOT match on stderr (debug feature only)\n";
    print STDERR "  -e <extension>\t", "exclude files wth names ending in <extension>. Workaround if scan hangs on js\n";
    print STDERR "  -h\t",  "print this help message and quit\n";
    exit 1;
}

# malware signatures. Needs cleanup, maybe an init function.
my @sigs;
#push @sigs, "foo";

# heuristic matches:
# TODO: write a script to generate these and pipe it the PHP core API
#push @sigs, '(?!GLOBALS)(G|\\x47|\\?046)(L|\\x4[Cc]|\\107)(O|\\x4[Ff]|\\?041)(B|\\x42|\\117)(A|\\x41|\\?046)(L|\\x4[Cc]|\\101)(S|\\x53|\\?0?05).*';
push @sigs, qr{(?!GLOBALS)(G|\\x47|\\107)(L|\\x4[Cc]|\\114)(O|\\x4[Ff]|\\117)(B|\\x42|\\102)(A|\\x41|\\101)(L|\\x4[Cc]|\\114)(S|\\x53|\\101).*};
push @sigs, qr{(?!eval)(e|\\x65|\\145)(v|\\x76|\\166)(a|\\x61|\\141)(l|\\x6[Cc]|\\154)};
push @sigs, qr{(?!COOKIE)(C|\\x43|\\103)(O|\\x4[Ff]|\\117)(O|\\x4[Ff]|\\117)(K|\\x4[Bb]|\\113)(I|\\x49|\\111)(E|\\x45|\\105)};
push @sigs, qr{(?!base64_decode)(b|\\x62|\\142)(a|\\x61|\\141)(s|\\x73|\\163)(e|\\x65|\\145)(6|\\x36|\\?066)(4|\\x34|\\?064)(_|\\x5[Ff]|\\137)(d|\\x64|\\144)(e|\\x65|\\145)(c|\\x63|\\143)(o|\\x6[Ff]|\\157)(d|\\x64|\\144)(e|\\x65|\\145)};
# one for encode? push @sigs, qr{(?!base64_decode)(b|\\x62|\\142)(a|\\x61|\\141)(s|\\x73|\\163)(e|\\x65|\\145)(6|\\x36|\\?066)(4|\\x34|\\?064)(_|\\x5[Ff]|\\137)};
# TODO str_rot13 push @sigs, qr{(?!)(C|\\x43|\\103)(O|\\x4[Ff]|\\117)(O|\\x4[Ff]|\\117)(K|\\x4[Bb]|\\113)(I|\\x49|\\111)(E|\\x45|\\105)};
# TODO: gzuncompress push @sigs, qr{(?!)(C|\\x43|\\103)(O|\\x4[Ff]|\\117)(O|\\x4[Ff]|\\117)(K|\\x4[Bb]|\\113)(I|\\x49|\\111)(E|\\x45|\\105)};
# TODO: PHP_SELF push @sigs, qr{(?!PHP_SELF)(C|\\x43|\\103)(O|\\x4[Ff]|\\117)(O|\\x4[Ff]|\\117)(K|\\x4[Bb]|\\113)(I|\\x49|\\111)(E|\\x45|\\105)};

# TODO: one for error_ like above
# TODO: one for ini_set like above.
# TODO: Consider adding chr() to the above
# Need one for _COOKIE as well
# TODO: found these in the wild obfuscated as above: base64_decode str_rot13 gzuncompress

push @sigs, qr{GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS.*GLOBALS}; # Needs work. May hit on phpBB


push @sigs, qr{eval\s*\(stripslash};
push @sigs, qr{eval\(gzuncompress\s*\(base64_decode};
#consider if I really want to get in the business of tracking every false positive in the regex
push @sigs, qr{eval\s*\(base64_decode\s*\((!IGlmKCEkY292ZXJ0c3RvcmVidWlsZGVyX29wdGlvbnMtPmlzX2xpY2V)};

# avoid false positives from Smarty function.mailto, SpiffyCal
# TODO: We could check for a script tag. But this will make us
# miss potentially malicious JS.
push @sigs, qr{eval\s*\(unescape(?!.*\$js_encode)(?!\(this.JS)}; # avoid false positives from Smarty function.mailto

push @sigs, qr{eval\s*\(gzinflate\s*\(base64_decode};
push @sigs, qr{eval\s*\(gzinflate\s*\(str_rot13\s*\(base64_};
# high potential for false positives on this one
push @sigs, qr{eval\s*\(\s*base64_decode\s*\(.*\?\>};
push @sigs, qr{eval\("\?\>"\.base64_decode\(};
# just what were the PHP devs thinking when they came up with PREG_REPLACE_EVAL? who in their right mind would design this?
push @sigs, qr{if \(!isset\(\$_REQUEST\['\w\w\w\w'\]\)\) header\("HTTP/1.0 404 Not Found"\); \@preg_replace\('/\(\.\*\)/e', \@\$_REQUEST\['\w\w\w\w'\]}; # sadly, I fear this will result in false positives


# next expected iterations of CryptoPHP: expect some false positives maybe:
# we can tighten this up with quotes, end paren, semicolon if need be.
#push @sigs, qr{include\s*\(.*\.(?i)(png|jpg|jpeg|gif|svg|bmp|pdf)(?-i)};
push @sigs, qr{include\s*\(\s*['"][\w/]*(?i)(png|jpg|jpeg|gif|svg|bmp|pdf)(?-i)['"]\s*\)};

push @sigs, qr{base'\.\(32\*2\)\.'_de'\.'code};
push @sigs, qr{base'\.\(2\*32\)\.'_de'\.'code};  # ugh
push @sigs, qr{base'\.\(16\*4\)\.'_de'\.'code};  # LOL
push @sigs, qr{base'\.\(4\*16\)\.'_de'\.'code};  # I can do this all day you know.

# symlink bombs hopefully
push @sigs, qr{symlink.*home.*public_html.*config\.php};

# known false positive:
#eval(base64_decode('IGlmKCEkY292ZXJ0c3RvcmVidWlsZGVyX29wdGlvbnMtPmlzX2xpY2Vuc2VfdmFsaWQoIm5idmFkZjk4N2ZhZGZhIikgJiYgJF9HRVRbJ3BhZ2UnXSAhPSAnaW13Yl96b25wcmVzc190aGVtZV9vcHRpb25zJykNCiAgICAgIGFkZF9hY3Rpb24oJ2FkbWluX25vdGljZXMnLCAnaW13Yl96b25wcmVzc19hZG1pbl91cGRhdGVfbm90aWNlJyk7'));


# plaintext or unobfuscated PHP stuff
push @sigs, qr{FilesMan(?!age)};     # watch for false positives.
push @sigs, qr{DirectoryIndex\s*Sux.htm};     # found in .htaccess made by webshells and symlink bombers.
push @sigs, qr{DirectoryIndex\s*cp\.html};     # another symlink bomb .htaccess
push @sigs, qr{DirectoryIndex\s*z0mbie.htm};  # haven't seen in the wild yet, but associated with symlink bombs.
push @sigs, qr{webshell.*[o0]rb}i;  # web shell by Orb and a million derivatives
push @sigs, qr{(?<!doubl)eval\(\$_(POST|GET|REQUEST|COOKIE)};      # some botnets keep it simple

# hax0ring groups / individuals / defacement mirrors that like to tag their stuff
# Av3LoXiS
push @sigs, qr{RAB3OUN}i;
push @sigs, qr{IndiShell};
push @sigs, qr{AnonGhost};
push @sigs, qr{Ryu-BangsatCrew};
push @sigs, qr{CYBER ARMY}i;
push @sigs, qr{ELECTRONIC ARMY}i;
push @sigs, qr{Pro-Hack.ru}i;
push @sigs, qr{Teamroot.*Bruteforce}i;
push @sigs, qr{Yogyakarta\s*Blackhat}i;
push @sigs, qr{MrAtoms};
push @sigs, qr{Rizki24};
push @sigs, qr{Dr\.FaisaL};
push @sigs, qr{Mohajer22(?!",  "r57 iFX",)};
push @sigs, qr{Tryag.Cc};
push @sigs, qr{Hacked By Wongbodo};
push @sigs, qr{Kobra Crew:};
push @sigs, qr{DarkCrewFriends};
push @sigs, qr{Virgous of D}; #WHMCS hax0r
push @sigs, qr{dulldusk\@gmail.com}; # shell author, probably clueless rather than l33t
push @sigs, qr{darksnoopy\@shaw.ca}; # shell author, probably clueless rather than l33t
push @sigs, qr{Pakcyberattackers};
push @sigs, qr{sec4ever\.com};
push @sigs, qr{is-sec\.com};
push @sigs, qr{s3c-k\.com};
push @sigs, qr{v4-team\.com};
push @sigs, qr{madleets\.com};
push @sigs, qr{B0K4_B4B4}i;
push @sigs, qr{ubhteam\.org}i;
push @sigs, qr{prappo-prince\.me}i;
push @sigs, qr{United Bangladeshi Hackers}i;
push @sigs, qr{FathurFreakz};
push @sigs, qr{d2mysilent}i;
push @sigs, qr{Andela1C3};  # Indonesian
push @sigs, qr{Mr.HaurgeulisX196};
push @sigs, qr{cyber173 enc0de};
push @sigs, qr{X-1N73CT};
push @sigs, qr{S1T1 B4RC0D3};
push @sigs, qr{s3n4t00r};
push @sigs, qr{BY MOJAT DLAM};
push @sigs, qr{Hitl[ae]r Hacker GaZa}i;
push @sigs, qr{CCTeaM\.};
push @sigs, qr{http://ccteam.ru};
push @sigs, qr{Sec4ever};
push @sigs, qr{Lagripe-Dz};
push @sigs, qr{ApOcalYpse};
push @sigs, qr{RaYm0n};
push @sigs, qr{Pwnd\! by FR13ND};
push @sigs, qr{Indonesian Blackhat}; #questionable to include this but these folks love to tag.
push @sigs, qr{Xnuxer Research}; # probably white- or grey- hats active 2002-2004. Their innocent PoC's and IRC mayhem tools were incorporated into malware.
push @sigs, qr{SecretColony Lab N Research Project}; # binary backdoor shell authors

#www.cyber-force.org
# http://turk-h.org/ - find as REFERER on defaced sites

# maildrops
push @sigs, qr{solevisible\@gmail.com}i;
push @sigs, qr{ibliskecil2\@gmail.com}i;  # Korang Gagal maildrop
push @sigs, qr{tia.chengfong\@gmail.com}i; # spammer maildrop for spam reports
push @sigs, qr{naropbarop\@yahoo.com}i;
push @sigs, qr{talktupumpin\@gmail.com}i; # spammer?
push @sigs, qr{v.b-4\@hotmail.com}i; # Rabeoun maildrop

# algorithmically generated or other domains linked from payloads
# example: http://com-qi24.net/phzzm.php?a=314759&c=wl_con&s=03
push @sigs, qr{r57.gen.tr};
push @sigs, qr{com-..\d\d\.net};
push @sigs, qr{com-...\.net};
push @sigs, qr{mobilesecurityhub.ru};
push @sigs, qr{andsecurity.ru};
push @sigs, qr{pill-shop};
push @sigs, qr{pillsmarket.ru};
push @sigs, qr{grandscenter\.ru};

# matches for specific samples:
push @sigs, qr{WHMCS KILLER};
push @sigs, qr{eval\(\$GLOB};
push @sigs, qr{\@error_reporting(0); \@ini_set};
push @sigs, qr{##\[ POWERED BY};
push @sigs, qr{\$OOO000000=urldecode};
push @sigs, qr{\<\?\$f49\=|\$dewwpZ};   # lose it when generic version is tested
push @sigs, qr{root\:toor};
push @sigs, qr{I6ShOSm1};               # can probably lose it; was for eval POST IIRC
push @sigs, qr{b374k};
push @sigs, qr{DDoS\s+Perl\s+by\s+Dasilva}i;
push @sigs, qr{\[dork\]}; # if this produces falsies, try the below
push @sigs, qr{Joomla CE Vuln}; # redundant with [dork] above
push @sigs, qr{Upload SUKSES};
push @sigs, qr{Upload GAGAL};
push @sigs, qr{priv8 cgi shell}; # perl CGI shell
push @sigs, qr{AddHandler\scgi-script\s\.cin}; # .htaccess handler for CGI shell
push @sigs, qr{cPanel Bruteforce};
push @sigs, qr{AnGeR_HacKeR\.php};
push @sigs, qr{ANgEr_HaCkEr};
push @sigs, qr{xhahax909};
push @sigs, qr{chmod\("404.cgi", 0755\);};
push @sigs, qr{killall -9 "\.basename\("/usr/bin/host};
push @sigs, qr{\$SO32="\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03\\x00\\x03\\x00\\x01\\x00\\x00\\x00\\x54\\x0d\\x00};
# TODO: another falsie   <?php $n = $m%3;?>
push @sigs, qr{array = array.*;function x\(\$string\)\{\$b64 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65";\$r13 = "\\x73\\x74\\x72\\x5f\\x72\\x6f\\x74\\x31\\x33";\$gzc = "\\x67\\x7a\\x75\\x6e\\x63\\x6f\\x6d\\x70\\x72\\x65\\x73\\x73";return "" . \$gzc\(\$b64\(\$r13\(\$string\)\)\);\}eval\(x\(\$x\)\);};
push @sigs, qr{if\(\$_GET\['mode'\]=='.*'\)\{echo'\{.*" value="'\.\$_GET\['.*'\]\.'"\}';die\(\);\}};       # russian pharma redirect
push @sigs, qr{Auto SQL Injection =D};
push @sigs, qr{\$\w\w\w\w\w\w=gzinflate\(base64_decode\(\$\w\w\w\w\w\w\)\); for\(\$i=0;\$i\<strlen\(\$\w\w\w\w\w\w\);\$i\+\+};
push @sigs, qr{\$remote = "tcp://\$host:\$port";}; # chance for false positives
push @sigs, qr{\$ifs = array\('/sbin/ifconfig', '/usr/sbin/ifconfig', '/usr/local/sbin/ifconfig', '/bin/ifconfig', '/usr/bin/ifconfig', '/usr/local/bin/ifconfig' \);}; # # chance for false positives
push @sigs, qr{\$ifconfig = \@shell_exec\('/sbin/ifconfig eth0'\);}; # chance for false positives
push @sigs, qr{GET \"\.o0o0o0o0o0o0o0O0O0o0O0O0o0\(\$att_web,\$att_blqs,\$att_bljs\)\." HTTP\/1\.1\\r\\n}; # Chinese DDoS client
push @sigs, qr{\@\$_=\"s\"\.\"s\"\.\/\*-\/\*-\*\/\"e\"\.\/\*-\/\*-\*\/\"r\";};


#(?^:\<\?php\ \$n\ \=\ )
#push @sigs, qr{\<\?php\ \$n\ \=\ };     # TODO: false positive <?php $n = 0; $postslist = get_posts('numberposts='.$sho.'&order=DESC'); foreach ($postslist as $post) : setup_postdata($post); $n++; ?>
push @sigs, qr{\<\?php\ \$n\ \=\ (!\$m\%3;)(!0; \$postslist)};     # TODO: false positive <?php $n = 0; $postslist = get_posts('numberposts='.$sho.'&order=DESC'); foreach ($postslist as $post) : setup_postdata($post); $n++; ?>
push @sigs, qr{preg_r5c%x7825hOh};
push @sigs, qr{^\<\?\$\w+.*\=.+};        # *** TODO: still prone to false positives on gzipped data
#push @sigs, qr{\Q<?$};                 # *** false positives on gzipped data
push @sigs, qr{problem_decription};
#push @sigs, qr{^.*=.*\S{32}.*isset.*eval.*exit.*fopen.*fwrite.*fclose.*exit.*$};
push @sigs, qr{^.*=.*[a-f0-9]{32,40}.*isset.*eval.*exit.*fopen.*fwrite.*fclose.*exit.*$};
push @sigs, qr{strtolower.*\;.*=\$.*strtoupper.*isset.*eval}; # might be redundant or broken. Below sig seems better
push @sigs, qr{\w\w=\".*\";.*\w\w\w=strtolower\(.*\).*=strtoupper.*if.*isset.*eval};
push @sigs, qr{\$\w+=.+;\$\w+=strto.+\(.+\)if.+isset.+eval}; # a more generic match for one-liner eval() backdoors with case-shifted lookup tables
push @sigs, qr{if\(\@md5\(\$_SERVER\['HTTP_PATH'\]\)==='\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w\w'\)\{ \@extract\(\$_REQUEST\); \@die\(\$stime\(\$mtime\)\);};

# match r_reporting(0); @ini_set(chr(101).chr(114).'ror_log',NULL); @ini_set('log_errors',0); if (count($_POST)
push @sigs, qr{error_reporting\s*\(\s*0\s*\);\s*\@ini_set\s*\(.+\)\s*;.*_POST};
#push @sigs, qr{\=.*isset.*eval.*exit.*fopen.*fwrite.*fclose.*exit};

push @sigs, qr{Korang Gagal Upload};
#push @sigs, qr{for\(\$kd\=0/;\$kd\<18\;\$kd\+\+\)\{};	# perl symlink bomb
push @sigs, qr{symlink.*home.*public_html.*configure.php.*};    # perl symlink bomb
push @sigs, qr{public_html/wp-config.php',.*\$kola.'-wordpres};	# perl symlink bomb
push @sigs, qr{\$subject = isset\(\$subjects\)\?\(Randomizer::randomizeWithCells\(\$subjects\[array_rand\(\$subjects\)\]};	# perl symlink bomb # this one's iffy.
push @sigs, qr{function\s\w\w\w\w\w\w\w\(.*\)\{.*=.*;\sfor.*strlen.*isset.*\?.*\:.*\}};
push @sigs, qr{\w\w="stop_";.*=strtoupper\(.*;if\(isset\(\{eval\(.*\}};
push @sigs, qr{include.*images/social.png}; # CryptoPHP. Not perfect. Working on a generic replacement under "heuristic matches" above
push @sigs, qr{php error_reporting\(0\); ini_set\('display_errors', 0\);\@ini_set\('max_execution_time', 300\);\@set_time_limit\(0\);function XJmVaOhvhAQNoaACoDOM\(\) \{    if \(\!defined\('WP_OPTION_KEY'\)\) \{        define\('WP_OPTION_KEY', 'wp_data_newa'\)};
push @sigs, qr{vanus = stripslashes\(\$_POST\["order_em"\]\);};
push @sigs, qr{\$result = mail\(stripslashes\(\$.*\), stripslashes\(\$.*\), stripslashes\(\$.*\)\);};   # more generic match for above
push @sigs, qr{stop_.*=strtoupper.*if\(isset\(.*\)\)\{eval\(};
push @sigs, qr{exit\(eval\(base64_decode\(file_get_contents\('php://input};
push @sigs, qr{array_diff_ukey\(\@array\(\(string\).*_REQUEST.*array\(\(string\)stripslashes.*_REQUEST.*_REQUEST};
push @sigs, qr{ASDJSA OPDJAS ODPASJ OPGJSD IGDHO DSHG IOSDJGIO SDGNJISDNG KDSGO IDSGHISDGN IODG};
push @sigs, qr{echo \$result.' del success<br/>';};
push @sigs, qr{if\(move_uploaded_file\(\$_FILES\[\$uploaded\]\[\$tmp_name\], \$target_path\)\) \{echo \$uploaded;\}\}\}};
push @sigs, qr{fwrite\(\$II11II11II11II11};
push @sigs, qr{\$\w\w\w\w = \$\w\w\w\w\('', \$\w\w\w\w\(\$\w\w\w\w\("\w\w", "", \$\w\w\w\w.\$\w\w\w\w.\$\w\w\w\w\.\$\w\w\w\w\)\)\); \$\w\w\w\w\(\);}; # found alongside binary malware
push @sigs, qr{\$data = json_decode\(base64_decode\(str_replace\(' ', '\+', \$_POST\['data'\]\)\), true\);}; # spammer, may produce false positives
push @sigs, qr{LD_PRELOAD=\./libworker\.so};
push @sigs, qr{if\(array_keys\(\$_GET\)\[-1\] == '\w\w\w\w\w'\)\{}; # upload shell
push @sigs, qr{if\(\!\$whoami\)\$whoami=exec\("whoami"\)}; # "injector" shell
push @sigs, qr{Simple PHP Injection - \*nix & \*BSD OnLy}; # same as above, in case of false positives
push @sigs, qr{\$\w+ = mail\(stripslashes\(\$\w+\), stripslashes\(\$\w+\), stripslashes\(\$\w+\)\);};
push @sigs, qr{\@error_reporting\(0\);\@ini_set\('error_log',NULL\);\@ini_set\('log_errors',0\);\@ini_set\('html_errors',0\);\@ini_set\('max_execution_time',0\);\@ini_set\('output_buffering',0\);\@ini_set\('display_errors', 0\);\@ini_set\('file_uploads',1\)};
push @sigs, qr{Simple SOCKS5 Server for Perl}; # perl SOCKS5 impl. not really malicious, but no place on a webserver
push @sigs, qr{socks5\.so/snew\.tar}; # dropper for perl SOCKS above
push @sigs, qr{http://ssspl\.svn\.sourceforge\.net/viewvc/ssspl/sss\.pl}; # dropper for perl SOCKS above
push @sigs, qr{http://socks5\.so/checksocks\.php}; # dropper for perl SOCKSabove
push @sigs, qr{_SERVER.*DOCUMENT_ROOT.*index.php.*function.*is_writable.*\@file_get_contents.*if\(\!preg_match.*error_reporting};
push @sigs, qr{if\(isset.*GET.*\)\)\{echo.*\[uname\]"\.php_uname\(\).*\@ini_get.*disable_functions.*DisablePHP.*ini_get.*disable_functions};
push @sigs, qr{Source code obfuscated  by Code Eclipse}; # old obfuscator, may produce false positives. Keep an eye on this one.
push @sigs, qr{http://javaterm.com/php.txt}; # "rar.php"

# TODO TODO TODO TODO  BAD SIG
push @sigs, qr{if.*isset.*GET.*\{.*_GET.*=\s*fopen.*;.*while.*\!feof.*\{.*fread.*\}.*fclose.*create_function.*\}}; # "rar.php"


push @sigs, qr{function smtpmail\(\$host, \$port, \$smtp_login, \$smtp_passw, \$mail_to, \$message, \$SEND\) \{}; # spammer, potential for false positives
# TODO: need a more generic form of the following for the heuristic sigs
push @sigs, qr{.e.\..v.\..a.\..l\(b.\..a.\..s.\..e.\..6.\..4_d.\..e.\..c.\..o.\..d.\..e}; # if (!isset($indf8e7ff5a)) { $indf8e7ff5a = TRUE;assert("e"."v"."a"."l(b"."a"."s"."e"."6"."4_d"."e"."c"."o"."d"."e('ICRHTE9CQUxTWyd
push @sigs, qr{if \(\!isset\(\$\w\w\w\w\w\w\w\w\w\w\w\)\) \{ \$indf8e7ff5a = TRUE;assert\("e"\."v"\."a"\."l\(b"\."a"\."s"\."e"\."6"\."4_d"\."e"\."c"\."o"\."d"\."e\(}; # "rar.php"
push @sigs, qr{\@copy\(\$_FILES\[file\]\[tmp_name\], \$_FILES\[file\]\[name\]\); exit;};
push @sigs, qr{SMTP CLOSED AND ATTEMPTS TO RECONNECT NEW CONNECTION SEASON};
push @sigs, qr{PHP Shell by};
push @sigs, qr{Nome do Servidor: <\?php echo \$UNAME = \@php_uname\(\);};
push @sigs, qr{GR5yYXp3YH17ejRne3h9cGdgdWBxPDB5dX9xYWQ9NG8ZHjQ0NDQweHt4NCk0MzMvGR40NDQ0cntmPDB9KSQvMH00KDRnYGZ4cXo8MHl1f3FhZD0vMH0};
push @sigs, qr{\$O00OO0=urldecode\(".*\);\$O00O0O=\$O00OO0\{.*\}\.\$O00OO0\{.*\}\.\$O00OO0\{.*\}.\$O00OO0\{.*\};\$O0OO00=\$O00OO0\{.*\}\.\$O00OO0\{.*\}\.\$O00OO0\{.*\}};
push @sigs, qr{\$.*=.*realpath.*\.php.*if.*\!empty.*_POST.*and strlen.*_POST.*>.*and isset.*_POST.*eval.*file_put_contents.*unlink};
push @sigs, qr{for\(\$i=0; \$i<strlen\(\$\S+\); \$i\+\+\)\{\$\S+\[\$i\]=chr\( ord\(\$\S+\[\$i\]\)\^\(\(\d+\)\%\d+\)\);\}};
push @sigs, qr{\$headers \.= "--\$strSid--";}; # spammer, ripped from a phpBB extension so might have false positives on phpBB boards.

# these next 4 are from a single sample with almost virus-like replication.	Watch for false positives.
push @sigs, qr{\$names = array\("local","sys","old","htaccess","cache"\);};
push @sigs, qr{\$fn = \$dirs\[0\]\."/"\.\$names\[0\]\."\.php";};
push @sigs, qr{fwrite\(\$fp,base64_decode\(\$qq\)\);};
push @sigs, qr{echo 'pre00'\.\(str_replace\("..","",\$fn\)\)\.'77do';};
push @sigs, qr{This May Hack The Server};
push @sigs, qr{\$option\("/438/e",\$\w\w,438\); die\(\);};
push @sigs, qr{eval\("\?\>"\.gzuncompress\(base64_decode\(};
push @sigs, qr{cyber173_decode};
push @sigs, qr{file_put_contents\(.*php.*base64_decode\(.*echo\s+file_get_contents\(.*php.*\)};
push @sigs, qr{php error_reporting\(0\); if \(!defined\('WP_OPTION_KEY'\)\) \{ function \w+\(\) \{ define\('WP_OPTION_KEY','wp_data_newa'\); new}; # CryptoPHP social.png variant
push @sigs, qr{if \( 1 == 1\) \{}; # "Aria cPanel cracker" as encoded and bundled with Hitlar's WP plugin
push @sigs, qr{ndkzipfiles}; # download shell
push @sigs, qr{if \(\(isset\(\$_GET\['step'\]\)\)\&\&\(\!empty\(\$_GET\['step'\]\)\)\) \$step=\$_GET\['step'\]; else \$step=0;}; # download shell
push @sigs, qr{\Q..:::aKpuMPiN::::..}; # a pumpkin, apparently. (spam)
push @sigs, qr{GetSpamTOol}i; # http://getspamtool.com/
my $tmp = '\w' x 33;
push @sigs, qr{<\?php if\(isset\(\$_GET\[\w\w\w\w\w\w\]\)\)\s*\{\$$tmp="}; # yet another encoded FilesMan
push @sigs, qr{if\(\!empty\(\$_SERVER\['HTTP_USER_AGENT'\]\)\) \{ \$\w\w\w\w\w\w\w\w\w \= array\("Google", "Slurp", "MSNBot", "ia_archiver", "Yandex", "Rambler", "StackRambler"\); if\(preg_match\('\/' \. implode\('\|', \$\w\w\w\w\w\w\w\w\w\) \. '\/i', \@\$_SERVER\['HTTP_USER_AGENT'\]\)\) \{ header\('HTTP/1\.0 404 Not Found'\); exit; \} \} \@ini_set\('error_log'}; # upload shell hiding from search crawlers
push @sigs, qr{function\s+getContent\(\$host,\s*\$path,\s*\$template,\s*\$pathToDor\)}; # some sort of cookie-based user tracker or caching proxy found on compromised site
push @sigs, qr{un1xbold\s.*edition}; # "private mailer" spam kiddies
push @sigs, qr{Data Cha0s Connect Back Backdoor\\n\\n}; # perl connectback shell
push @sigs, qr{socket\(SERVER, PF_INET, SOCK_STREAM, \$proto\) \|\| die \("Socket Error\\n"\);}; # perl connectback shell, watch for false positives

# what appears to be a DALnet-based botnet running as "httpd". Incorporates eggdrop and includes TCL scripts
push @sigs, qr{yang harus digunakan nama confilenya adalah djcrew};
push @sigs, qr{XHide - Process Faker}; # they cobbled it together from existing tools, Schizoprenic Xnuxer Research (c) 2002
push @sigs, qr{i\./\w\w -s "/usr/local/apache/sbin/httpd -DSSL" \./httpd -m}; # process faker launcher script
push @sigs, qr{Enj0y y0uR d00r}; # socket listener binary for control
push @sigs, qr{candayotelnet}; # socket listener binary for control
push @sigs, qr{You are a master\.  Many many more commands are}; # not really malware, just eggrop, but it's a red flag on a web server and against many AUP's
push @sigs, qr{This trick is borrowed from Tothwolf's Wolfpack}; # not really malware, just eggrop, but it's a red flag on a web server and against many AUP's
push @sigs, qr{Dynamic Channel File for starts}; # not really malware, just eggrop, but it's a red flag on a web server and against many AUP's

# end what appears to be an IRC-based botnet running as "httpd"
# some sort of spam site redirecting landing page. Thousands of scripts in each installation.

# end some sort of spam site redirecting landing page. Thousands of scripts in each installation.
push @sigs, qr{\<\?php \$user_agent_to_filter = array\( '\#Ask\\s\*Jeeves\#i', '\#HP\\s\*Web\\s\*PrintSmart\#i', '\#HTTrack\#i', '\#IDBot\#i', '\#Indy\\s\*Library\#',}; # payload / landing page
push @sigs, qr{\$redirect = str_replace\("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "\$keyword", \$redirect\);}; # single creator script?
push @sigs, qr{"usha sex boobs images free"}; # used in content templates?
push @sigs, qr{ass"\."ert"; \$\w\(\$\{"_PO"\."ST}; # POST backdoor hidden in an asser
push @sigs, qr{\#p\@\$c\@\#}; # googledork on an upload shell
push @sigs, qr{echo "publish success"}; # upload shell



# end malware signatures

# globals
my $info_bytes = 0;
my $info_scarylinks = 0;
my $scan_symlink;
my $scan_phponly; # TODO: expand this to include *.pl, .htaccess, maybe *.html?
my $scan_exclude;
my $scan_bytes;
my $scan_debug;
my $scan_outfile;
my $scan_linkfile;
my $scan_debugfile;
my $scan_nonmatches;
my $SCANOUT;
my $DEBUGOUT;
my $LINKOUT;


# output to scan and debug output file handles, opening first if needed
sub scanout {
    if (!$SCANOUT) {
        open $SCANOUT, '>>', $scan_outfile or die $!;
    }
    my $oldfh = select $SCANOUT;
    $| = 1;
    my $out = shift;
    print $SCANOUT $out;
    select $oldfh;
}

sub debugout {
    if ($scan_debug) {
        if (!$DEBUGOUT) {
            open $DEBUGOUT, '>>', $scan_debugfile or die $!;
        }
        my $oldfh = select $DEBUGOUT;
        $| = 1;
        my $out = shift;
        print $DEBUGOUT $out;
        select $oldfh;
    }
}

# want a separate log for symlinks since they're handled differently
sub linkout {
    if ($scan_symlink) {
      if (!$LINKOUT) {
          open $LINKOUT, '>>', $scan_linkfile or die $!;
      }
      my $oldfh = select $LINKOUT;
      $| = 1;
      my $out = shift;
      print $LINKOUT $out;
      select $oldfh;
    }
}
# end file handle accessors


# callback and its children for File::Find API
sub wanted {
    #print "$_\n";
    my ($dev,$ino,$mode,$nlink,$uid,$gid);

    ($dev,$ino,$mode,$nlink,$uid,$gid) = lstat($_);

        (($scan_symlink
          && -l _ # symlink scan
          && match_link($_)))
        || (-f _
          && ( /^.*php\z/si || !$scan_phponly )
          #&& !( /^.*$scan_exclude\z/si || $scan_exclude ne "" )
          #&& ((int(((-s _) + 511) / 512) <= 52428800) || $scan_bytes)
          && match_file($_));  #, 'foo')
    return;
}

sub match_file {
    my $file = shift;
    #print "file: $file\n";

    # loop over malware signatures. Probably less efficient than a combined
    # alternation regex with | but easier to maintain signature list.

    progress_tick();
    #open my $fh, "<", $file or die $!;
    open my $fh, "<", $file or return $!; # TODO handle error gracefully
    binmode $fh;
    local $/;
    # read the max size, then process that line by line.
    my ($n, $buf);
    $n = read $fh, $buf, $scan_bytes;

    # open string as a file so we can process it by line, without array.
    open my $bufh, '<', \$buf or die $!;

    # TODO: outer loop here for transforms (remove comments, etc).
    while (<$bufh>) {
        for my $sig (@sigs) {
            #debugout "input >$_<\n";
            #debugout "for loop iteration beginning. Matching $sig\n";
            if ($_ =~ $sig) {
                # TODO: check whitelist sigs here.
                # TODO: a whilelist match should only negate a given sig, since
                # a common false-positive could still be backdoored with something
                # else whose signature we haven't matched yet

                print "\b$File::Find::name matched $sig\n";
                scanout "$File::Find::name\n";
                debugout "$File::Find::name matched $sig\n";
                return 1;
            }
            #debugout "done matching line\n";
        }
        if ($scan_nonmatches) { # TODO: figure out if this is going in scan log, debug log, or what.
            print STDERR "\b$File::Find::name      DID NOT MATCH\n";
        }
    }
    #undef @lines;
    undef $buf;
}

sub match_link {
    # check if target owner different.
    # maybe only flag if owner is another cPanel user
    # TODO: will need a separate log for links
    my $link = shift;

    # TODO: kind of silly to stat again, try to avoid this? But we basically
    # need to do this to get link and link target owner uid
    # TODO: if needed with can get clever with UID ranges to weed out false
    # positives.
    my ($t_foo, $t_baz, $t_quux, $t_xyzzy, $t_uid) = stat($link);
    my ($l_foo, $l_baz, $l_quux, $l_xyzzy, $l_uid) = lstat($link);
    my $target = readlink($link);
    #print "$t_uid $l_uid\n";


	# Is the link target nonexistent? (could be innocent clutter, or a symlink bomb).
	# we're basically checking for failure of stat() above
	if (!defined $t_uid) {
      print "\rSYMLINK: $File::Find::name===>$target (nonexistent target)\n";
      linkout "$File::Find::name===>$target\n";
	  $info_scarylinks++;
	}
	# is the link target owned by a different user (TODO: root or different non-system user?)
    elsif ($t_uid != $l_uid) {
      print "\rSYMLINK: $File::Find::name===>$target (different uid)\n";
      linkout "$File::Find::name===>$target\n";
	  $info_scarylinks++;
    }
}

{
    #TODO: Make sure this is not printed to output file when it's implemented.
    my $count = 0;
    my $throbcount = 0;
    my @throbber = ('|', '/', '-', '\\');
    my @colors = qw(green green blue blue
                cyan cyan yellow yellow
                red red magenta magenta white white );
    my $numcolors = @colors;
    #my @throbber = ('_', '.', ',', '*', 'o', '0', 'O', '0', 'o', '*', ',', '.', '_' );
    my $ticks = @throbber;
    sub progress_tick {
        my $tick = $count % $ticks;
        if ($tick == 0) {
            $throbcount += 1;
        }
        my $color = $throbcount % $numcolors; # needs work
        print STDERR "\r";
        print STDERR colored($throbber[$tick], $colors[$color]);
        $count += 1;
    }
}
# end File::Find callback section

getopts("t:a:psdqo:Duhb:N");

if ($opt_h) {
    main::HELP_MESSAGE();
}

# initialization
my $invoke_cwd = cwd();

# validate input. Make sure we have enough info to proceed.
my $ticket          = $opt_t || $ENV{'TICKET'};
$scan_phponly       = $opt_p || 0;
$scan_bytes         = $opt_b || $default_bytes;
$scan_debug         = $opt_D || 0;
$scan_nonmatches    = $opt_N || 0;
$scan_symlink       = !$opt_S || 0; # symlink scan is default now but can be disabled
$scan_exclude       = $opt_e || "";
my $scan_deface     = $opt_d || 0;
my $homeprefix      = $opt_u || "/home";


# don't continue unless we have directories to scan.
my $in_accts = $opt_a || "";
my $in_otherdirs = $opt_o || "";
if ($in_accts eq "" && $in_otherdirs eq "") {
    print STDERR "Error: can't continue without a scan target in -a or -o!\n";
    main::HELP_MESSAGE();
}

# create output directory; make sure it's writeable
my $outdir = $ENV{"HOME"} . "/support";
if (length $ticket) {
  $outdir .= "/" . $ticket;
}
print STDERR "Output directory: $outdir\n";
if (! (-e $outdir)) {
    make_path $outdir or die $!;
    print STDERR "created output directory\n";
}

my $datestamp = `date +%Y%m%d%H%M%S`;
chomp($datestamp);
$scan_outfile = $outdir . "/scan-" . $datestamp . ".txt";
$scan_linkfile = $outdir . "/symlinks-" . $datestamp . ".txt";
$scan_debugfile = $outdir . "/debug-" . $datestamp . ".txt";

# get list of accounts. Build filesystem paths.
# TODO: does the cPanel API let us grab all docroots for an account?
# TODO: A better option altogether may be to scan the entire home directory, excluding mail.
my @accts = split ',', $in_accts;
my @otherdirs = split ",", $in_otherdirs;

my @scandirs;
for (@accts) {
    push @scandirs, $homeprefix . "/" .  $_ . "/public_html";
}

for (@otherdirs) {
    if (substr($_, 0, 1) ne "/") {
        push @scandirs, $invoke_cwd . "/" . $_;         # absolute path
    } else {
        push @scandirs, $_;
    }
}

$| = 1;     #unbuffered output
print "Scanning the following directories:\n" . join("\n", @scandirs) . "\n";

# do stuff. find malware. rescue kitties out of trees. do the needful.

# regex malware scan
debugout "# Starting regex scan...\n";
scanout "# Starting regex scan...\n";
for (@scandirs) {
    File::Find::find(\&wanted, $_);
}
#print STDERR "\b";

# regex defacement scan

# symlink scan

print "\n# Scan complete. Log is at $scan_outfile\n";
if ($scan_symlink && $info_scarylinks > 0) {
  my $object = "symlink";
  if ($info_scarylinks > 1) {
	  $object = "symlinks";
  }
  print "# Symlink scan results are at $scan_linkfile. Found $info_scarylinks potentially malicious $object.\n";
}
scanout "# Scan complete.\n";
debugout "# Scan complete.\n";
exit 0;
