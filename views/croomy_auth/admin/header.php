<!DOCTYPE html>
<html lang="en">
<head>
<link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.2.1/css/bootstrap-combined.min.css" rel="stylesheet">
        <style type="text/css">
            body {
                padding-top: 40px;
            }
        </style>
</head>
<body>
    <div class="navbar navbar-inverse navbar-fixed-top">
      <div class="navbar-inner">
        <div class="container">
          <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </a>
          <a class="brand" href="#">Project name</a>
          <div class="nav-collapse collapse">
            <ul class="nav">
              <li class="active"><?php echo anchor('admin/', 'Home'); ?></li>
              <li><?php echo anchor('admin/users/', 'Users'); ?></li>
              <li><?php echo anchor('admin/groups/', 'Groups'); ?></li>
            </ul>
	<ul class="nav pull-right">
		<li><?php echo anchor('auth/logout', 'Logout', ''); ?></li>
                    </ul>
          </div><!--/.nav-collapse -->
        </div>
      </div>
    </div>
