/*
©AngelaMos | 2026
phpmyadmin.go

Fake phpMyAdmin login page for the HTTP honeypot

Serves a realistic phpMyAdmin 5.2 login page that captures database
credential submissions. phpMyAdmin is one of the most commonly
probed web applications by automated scanning tools targeting
exposed database management interfaces.
*/

package httpd

import (
	"fmt"
	"net/http"
)

const pmaLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>phpMyAdmin</title>
<style>
body{font-family:sans-serif;background:#e7e9ed;margin:0;padding:20px}
.container{max-width:500px;margin:50px auto;background:#fff;border:1px solid #ddd;border-radius:5px;padding:30px}
h1{color:#333;font-size:24px;margin-bottom:20px}
.version{color:#666;font-size:12px;margin-left:5px}
.login-form label{display:block;margin:10px 0 5px;color:#333;font-weight:bold}
.login-form input[type=text],.login-form input[type=password],.login-form select{width:100%;padding:8px;border:1px solid #ccc;border-radius:3px;box-sizing:border-box;font-size:14px}
.login-form .btn{background:#f39c12;color:#fff;border:none;padding:10px 20px;cursor:pointer;border-radius:3px;font-size:14px;margin-top:15px}
.login-form .btn:hover{background:#e08e0b}
.footer{text-align:center;margin-top:20px;color:#999;font-size:12px}
</style>
</head>
<body>
<div class="container">
<h1>phpMyAdmin<span class="version">5.2.1</span></h1>
<form class="login-form" method="post" action="/phpmyadmin/index.php">
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="" autocomplete="username" />
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" value="" autocomplete="current-password" />
<label for="select_server">Server Choice:</label>
<select name="server" id="select_server">
<option value="1">127.0.0.1</option>
</select>
<input class="btn" type="submit" value="Go" />
</form>
<div class="footer">phpMyAdmin 5.2.1 &bull; MySQL 5.7.42</div>
</div>
</body>
</html>`

const pmaErrorHTML = `<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{font-family:sans-serif;padding:40px}.error{color:#721c24;background:#f8d7da;border:1px solid #f5c6cb;padding:15px;border-radius:4px}</style>
</head><body>
<div class="error"><strong>Error:</strong> Cannot log in to the MySQL server</div>
</body></html>`

func handlePMA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(
		"Content-Type", "text/html; charset=UTF-8",
	)
	w.Header().Set("X-Powered-By", "PHP/8.1.2-1ubuntu2.19")

	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, pmaErrorHTML)
		return
	}

	fmt.Fprint(w, pmaLoginHTML)
}
