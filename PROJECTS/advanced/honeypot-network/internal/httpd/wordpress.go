/*
©AngelaMos | 2026
wordpress.go

Fake WordPress login and admin pages for the HTTP honeypot

Serves a realistic WordPress 6.5 login page that captures credential
submissions, a wp-admin redirect, and an xmlrpc.php endpoint that
returns standard fault responses. These are the top three paths
targeted by automated WordPress exploitation tools.
*/

package httpd

import (
	"fmt"
	"net/http"
)

const wpLoginHTML = `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; WordPress &mdash; WordPress</title>
<style type="text/css">
html{background:#f1f1f1}
body{background:#fff;border:1px solid #ccd0d4;color:#444;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;margin:2em auto;padding:26px 24px 46px;max-width:400px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
h1 a{background-image:url(/wp-admin/images/wordpress-logo.svg);width:84px;height:84px;background-size:84px;display:block;margin:0 auto 25px;text-indent:-9999px}
.login form{margin-top:20px;padding:26px 24px 46px;font-weight:400;overflow:hidden;background:#fff;border:1px solid #ccd0d4;box-shadow:0 1px 3px rgba(0,0,0,.04)}
label{font-size:14px;display:block;margin-bottom:3px}
input[type=text],input[type=password]{font-size:24px;width:100%;padding:3px;margin:2px 6px 16px 0;border:1px solid #7e8993;box-sizing:border-box}
.submit input{font-size:13px;padding:0 12px;min-height:32px;background:#0073aa;border-color:#006799;color:#fff;cursor:pointer;border-radius:3px}
</style>
</head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></p>
<p class="forgetmenot"><label><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>`

func handleWPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		http.Redirect(
			w, r,
			"/wp-admin/",
			http.StatusFound,
		)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("X-Powered-By", "PHP/8.1.2-1ubuntu2.19")
	fmt.Fprint(w, wpLoginHTML)
}

func handleWPAdmin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(
		w, r,
		"/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1",
		http.StatusFound,
	)
}

const xmlRPCResponse = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32601</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Requested method not found.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>`

func handleXMLRPC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
	fmt.Fprint(w, xmlRPCResponse)
}
