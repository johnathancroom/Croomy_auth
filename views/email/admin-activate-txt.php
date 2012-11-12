Welcome to <?php echo $site_name; ?>,

A new user has just joined <?php echo $site_name; ?>. You can either approve them or deny them with the links below.

To approve the new user, please follow this link:

<?php echo site_url('/auth/admin_approve/' . $admin_key); ?>

To deny the new user, please follow this link:

<?php echo site_url('/auth/admin_deny/' . $admin_key); ?>

<?php if (strlen($username) > 0) { ?>

New username: <?php echo $username; ?>
<?php } ?>

New email address: <?php echo $email; ?>

Thanks!
