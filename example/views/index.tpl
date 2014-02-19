<!DOCTYPE html>

<html>
  	<head>
    	<title>Beego</title>
    	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	
		<style type="text/css">
			body {
				margin: 0px;
				font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
				font-size: 15px;
				line-height: 1.6em;
				color: rgb(51, 51, 51);
				background-color: rgb(255, 255, 255);
			}

			.hero-unit {
				padding: 60px;
				margin-bottom: 30px;
				border-radius: 6px 6px 6px 6px;
			}

			.container {
				width: 940px;
				margin-right: auto;
				margin-left: auto;
			}

			.row {
				margin-left: -20px;
			}

			h1 {
				margin: 10px 0px;
				font-family: inherit;
				font-weight: bold;
				text-rendering: optimizelegibility;
			}

			.hero-unit h1 {
				padding: 30px 0;
				font-size: 40px;
				letter-spacing: -1px;
				color: inherit;
			}

			.description {
				padding-top: 5px;
				font-size: 18px;
				font-weight: 200;
				line-height: 30px;
				color: inherit;
			}

			.box {
				padding: 0 10px;
			}

			p {
				margin: 0px 0px 10px;
			}
		</style>
	</head>
  	
  	<body>
  		<header class="hero-unit" style="">
			<div class="container">
			<div class="row">
			  <div class="hero-text">
			    <h1>Welcome to Beego social auth</h1>
			    <div class="box">
				    <p class="description">
				    	Beego social auth is a project use for connect social account with OAuth2.
				    <br />
				    	Click the link below to test social auth
				    </p>
				    <p style="font-weight:bold;">
				    	{{if .IsLogin}}
				    		Now Login (<a href="/login?flag=logout">Logout</a>)
			    		{{else}}
			    			Not login
			    		{{end}}
				    </p>
				    <p style="font-weight:bold;color:red;">{{.Msg}}</p>
				    <ul>
				    	{{range .Types}}
				    		<li><a href="/login/{{.NameLower}}">{{.Name}}</a>{{if index $ .NameLower}}<br>{{index $ .NameLower}}{{end}}</li>
				    	{{end}}
				    </ul>
			    </div>
			  </div>
			</div>
			</div>
		</header>
	</body>
</html>
